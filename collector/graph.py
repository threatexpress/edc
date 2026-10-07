# collector/graph.py
from collector.models import OplogEntry
from collections import defaultdict

def build_attack_graph_data():
    """
    Parses all OplogEntry records chronologically to construct
    all branching attack paths, systems, and pivots without label overlaps.
    """
    entries = OplogEntry.objects.select_related('target', 'operator')\
                                .prefetch_related('mitigations', 'screenshots')\
                                .order_by('timestamp')

    nodes = {}
    edges = []
    pair_counts = defaultdict(int)

    def get_or_create_node(node_id, host_name, ip_addr, node_type="workstation", os_info=""):
        if node_id not in nodes:
            label_lines = []
            
            # Format system name
            if host_name and host_name != ip_addr:
                label_lines.append(f"{host_name}")
            elif not host_name and ip_addr:
                label_lines.append("Host")

            # Add IP address
            if ip_addr:
                label_lines.append(f"[{ip_addr}]")

            # Append OS if available
            if os_info:
                label_lines.append(f"({os_info})")

            display_label = "\n".join(label_lines) if label_lines else str(node_id)

            colors = {
                "attacker": {"background": "#e74c3c", "border": "#c0392b"},
                "c2": {"background": "#8e44ad", "border": "#732d91"},
                "server": {"background": "#f39c12", "border": "#d68910"},
                "workstation": {"background": "#2980b9", "border": "#1f618d"},
            }
            node_color = colors.get(node_type, colors["workstation"])
            
            nodes[node_id] = {
                "id": str(node_id),
                "label": display_label,
                "shape": "box",
                "color": node_color,
                "font": {"color": "#ffffff", "face": "monospace", "multi": True},
                "margin": 10,
                "data": {
                    "ip": ip_addr or "N/A",
                    "host": host_name or "N/A",
                    "type": node_type,
                    "os": os_info,
                    "actions": []
                }
            }
        return nodes[node_id]

    previous_targets = set()

    for idx, entry in enumerate(entries, start=1):
        # 1. Source Node Identification
        src_ip = (entry.src_ip or "").strip()
        src_host = (entry.src_host or "").strip()
        src_node_id = src_ip or src_host or "Operator Host"

        if idx == 1 or src_node_id not in previous_targets:
            src_type = "attacker" if idx == 1 else "workstation"
        else:
            src_type = "workstation"

        get_or_create_node(
            node_id=src_node_id,
            host_name=src_host,
            ip_addr=src_ip,
            node_type=src_type
        )

        # 2. Destination / Target Node Identification
        dst_ip = ""
        dst_host = ""
        dst_os = ""
        dst_type = "workstation"

        if entry.target:
            dst_ip = (entry.target.ip_address or "").strip()
            dst_host = (entry.target.hostname or "").strip()
            dst_os = (entry.target.operating_system or "").strip()
            
            if any(k in (dst_os + dst_host).lower() for k in ['dc', 'srv', 'server', 'sql', 'ad']):
                dst_type = "server"

        dst_node_id = dst_ip or dst_host or f"Target_{entry.pk}"
        get_or_create_node(
            node_id=dst_node_id,
            host_name=dst_host,
            ip_addr=dst_ip,
            node_type=dst_type,
            os_info=dst_os
        )
        previous_targets.add(dst_node_id)

        # 3. Classify Action / Edge Attributes
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

        is_pivot = (src_node_id in previous_targets and src_node_id != (entries[0].src_ip or entries[0].src_host))
        edge_label = f"Step {idx}: {protocol}"
        if is_pivot:
            edge_label += " (Pivot)"

        mitigations = [m.name for m in entry.mitigations.all()]
        finding = entry.mitigations.first().finding if entry.mitigations.exists() else None

        # 4. Handle multiple parallel edges between same pair
        hop_pair = (str(src_node_id), str(dst_node_id))
        count = pair_counts[hop_pair]
        pair_counts[hop_pair] += 1

        # Calculate alternate curvature so parallel edges bow away from each other
        if count == 0:
            smooth_config = {"enabled": True, "type": "curvedCW", "roundness": 0.0}
        else:
            # Alternates arcs: +0.25, -0.25, +0.45, -0.45...
            sign = 1 if (count % 2 != 0) else -1
            magnitude = 0.2 + (0.15 * ((count - 1) // 2))
            smooth_config = {
                "enabled": True,
                "type": "curvedCW" if sign > 0 else "curvedCCW",
                "roundness": magnitude
            }

        edges.append({
            "id": f"edge_{entry.pk}_{idx}",
            "from": str(src_node_id),
            "to": str(dst_node_id),
            "label": edge_label,
            "arrows": "to",
            "dashes": True if is_pivot else False,
            "color": {"color": "#e67e22" if is_pivot else "#34495e"},
            "smooth": smooth_config,
            "title": (
                f"Step: {idx}\n"
                f"Tool: {entry.tool or 'N/A'}\n"
                f"Command: {entry.command[:100]}\n"
                f"Finding: {finding or 'None'}\n"
                f"Mitigations: {', '.join(mitigations) if mitigations else 'None'}"
            ),
            "step": idx,
            "command": entry.command,
            "output": entry.output,
            "notes": entry.notes,
        })

        nodes[dst_node_id]["data"]["actions"].append({
            "step": idx,
            "command": entry.command,
            "notes": entry.notes,
            "tool": entry.tool,
            "findings": finding
        })

    return {
        "nodes": list(nodes.values()),
        "edges": edges
    }