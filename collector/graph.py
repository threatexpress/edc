from collections import defaultdict, deque
from collector.models import OplogEntry

def build_attack_graph_data():
    # Parse oplog
    entries = OplogEntry.objects.select_related('target', 'operator')\
                                .prefetch_related('mitigations', 'screenshots')\
                                .order_by('timestamp')

    nodes_raw = {}
    edges_map = {}
    adj = defaultdict(set)
    root_nodes = []
    previous_targets = set()

    def clean_id(val):
        return str(val).strip() if val else ""

    # Extract all systems and connections
    for idx, entry in enumerate(entries, start=1):
        src_ip = clean_id(entry.src_ip)
        src_host = clean_id(entry.src_host)
        src_id = src_ip or src_host or "Operator Host"

        if idx == 1 or src_id not in previous_targets:
            src_type = "attacker" if idx == 1 else "workstation"
            if src_id not in root_nodes:
                root_nodes.append(src_id)
        else:
            src_type = "workstation"

        if src_id not in nodes_raw:
            nodes_raw[src_id] = {
                "id": src_id,
                "host": src_host,
                "ip": src_ip,
                "type": src_type,
                "os": "",
                "actions": []
            }

        dst_ip = ""
        dst_host = ""
        dst_os = ""
        dst_type = "workstation"

        if entry.target:
            dst_ip = clean_id(entry.target.ip_address)
            dst_host = clean_id(entry.target.hostname)
            dst_os = clean_id(entry.target.operating_system)
            if any(k in (dst_os + dst_host).lower() for k in ['dc', 'srv', 'server', 'sql', 'ad']):
                dst_type = "server"

        dst_id = dst_ip or dst_host or f"Target_{entry.pk}"

        if dst_id not in nodes_raw:
            nodes_raw[dst_id] = {
                "id": dst_id,
                "host": dst_host,
                "ip": dst_ip,
                "type": dst_type,
                "os": dst_os,
                "actions": []
            }

        previous_targets.add(dst_id)
        adj[src_id].add(dst_id)

        # Classify protocol
        protocol = "TCP"
        if entry.dst_port:
            port_map = {
                22: "SSH", 80: "HTTP", 443: "HTTPS", 445: "SMB",
                3389: "RDP", 88: "Kerberos", 389: "LDAP", 636: "LDAPS",
                5985: "WinRM", 5986: "WinRM-TLS"
            }
            protocol = port_map.get(entry.dst_port, f"Port {entry.dst_port}")
        elif entry.url:
            protocol = "HTTP(S)"

        is_pivot = (src_id in previous_targets and src_id != (clean_id(entries[0].src_ip) or clean_id(entries[0].src_host)))
        step_label = f"Step {idx}: {protocol}"
        if is_pivot:
            step_label += " (Pivot)"

        mitigations = [m.name for m in entry.mitigations.all()]
        finding = entry.mitigations.first().finding if entry.mitigations.exists() else None

        step_meta = {
            "step": idx,
            "tool": entry.tool or "N/A",
            "command": entry.command,
            "output": entry.output,
            "notes": entry.notes,
            "finding": finding or "None",
            "mitigations": ", ".join(mitigations) if mitigations else "None"
        }

        hop_pair = (src_id, dst_id)
        if hop_pair in edges_map:
            edge = edges_map[hop_pair]
            edge["step_list"].append(step_meta)
            edge["label"] += f"\n{step_label}"
            edge["title"] += (
                f"\n---\nStep: {idx}\nTool: {step_meta['tool']}\n"
                f"Command: {step_meta['command'][:100]}\nFinding: {step_meta['finding']}"
            )
        else:
            edges_map[hop_pair] = {
                "id": f"edge_{src_id}_{dst_id}",
                "from": src_id,
                "to": dst_id,
                "label": step_label,
                "arrows": "to",
                "dashes": True if is_pivot else False,
                "color": {"color": "#e67e22" if is_pivot else "#34495e"},
                "title": (
                    f"Step: {idx}\nTool: {step_meta['tool']}\n"
                    f"Command: {step_meta['command'][:100]}\nFinding: {step_meta['finding']}"
                ),
                "step_list": [step_meta]
            }

        nodes_raw[dst_id]["actions"].append(step_meta)

    # Calculate topological hop levels (BFS from root/initial attacker)
    node_levels = {}
    queue = deque()
    
    start_root = root_nodes[0] if root_nodes else (list(nodes_raw.keys())[0] if nodes_raw else None)
    if start_root:
        node_levels[start_root] = 0
        queue.append(start_root)

    while queue:
        curr = queue.popleft()
        curr_lvl = node_levels[curr]
        for neighbor in adj.get(curr, []):
            if neighbor not in node_levels:
                node_levels[neighbor] = curr_lvl + 1
                queue.append(neighbor)

    # Fallback for disconnected nodes
    for nid in nodes_raw:
        if nid not in node_levels:
            node_levels[nid] = 1

    # Build formatted vis.js structure
    colors = {
        "attacker": {"background": "#e74c3c", "border": "#c0392b"},
        "c2": {"background": "#8e44ad", "border": "#732d91"},
        "server": {"background": "#f39c12", "border": "#d68910"},
        "workstation": {"background": "#2980b9", "border": "#1f618d"},
    }

    final_nodes = []
    for nid, nmeta in nodes_raw.items():
        label_lines = []
        if nmeta["host"] and nmeta["host"] != nmeta["ip"]:
            label_lines.append(f"{nmeta['host']}")
        elif not nmeta["host"] and nmeta["ip"]:
            label_lines.append("Host")

        if nmeta["ip"]:
            label_lines.append(f"[{nmeta['ip']}]")

        if nmeta["os"]:
            label_lines.append(f"({nmeta['os']})")

        display_label = "\n".join(label_lines) if label_lines else nid
        node_color = colors.get(nmeta["type"], colors["workstation"])

        final_nodes.append({
            "id": nid,
            "label": display_label,
            "level": node_levels.get(nid, 0),
            "shape": "box",
            "color": node_color,
            "font": {"color": "#ffffff", "face": "monospace", "multi": True},
            "margin": 10,
            "data": {
                "ip": nmeta["ip"] or "N/A",
                "host": nmeta["host"] or "N/A",
                "type": nmeta["type"],
                "os": nmeta["os"],
                "actions": nmeta["actions"]
            }
        })

    return {
        "nodes": final_nodes,
        "edges": list(edges_map.values())
    }