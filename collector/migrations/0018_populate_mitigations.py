from django.db import migrations

# Define initial data directly in the migration
mitigation_data = [
  {
    "name": "M1: Configure Sudo for Least Privilege (Linux)",
    "finding": "Insecure SUDO Configuration",
    "description": "Configure sudo rules (`/etc/sudoers`) to grant users only the specific privileges required for their roles, adhering to the principle of least privilege.",
    "category": "Accounts",
    "reference": "CCI: 000366"
  },
  {
    "name": "M2: Manage Linux User Accounts Securely",
    "finding": "Insecure User Accounts",
    "description": "Implement secure user account management practices: regular review, disabling/removing inactive accounts, enforcing role-based access control (RBAC), and managing group memberships.",
    "category": "Accounts",
    "reference": "CCI: 001682"
  },
  {
    "name": "M3: Implement Two-Factor Authentication (2FA) for Linux Logins",
    "finding": "Insecure User Accounts",
    "description": "Enforce the use of two-factor authentication (e.g., using PAM modules like `pam_google_authenticator` or `pam_duo`) for interactive user logins, especially for privileged accounts.",
    "category": "Accounts",
    "reference": "CCI: 000766"
  },
  {
    "name": "M4: Enforce Windows Account Security Policies",
    "finding": "Insecure User Accounts",
    "description": "Configure and enforce strong Windows account security policies via Group Policy (GPO) or local policy, including lockout thresholds, session limits, and auditing requirements.",
    "category": "Accounts",
    "reference": "CCI: 000044"
  },
  {
    "name": "M5: Manage Windows User Accounts Securely",
    "finding": "Insecure User Accounts",
    "description": "Implement secure Windows user account management using Active Directory or local accounts: regular review, disabling/removing inactive accounts, enforcing least privilege (RBAC), and managing group memberships.",
    "category": "Accounts",
    "reference": "CCI: 001682"
  },
  {
    "name": "M6: Implement AppArmor Profiles (Linux)",
    "finding": "Insecure Profile Settings",
    "description": "Utilize AppArmor to confine programs to a limited set of resources using mandatory access control (MAC) profiles, reducing the impact of potential compromises.",
    "category": "Encryption",
    "reference": "CCI: 001084"
  },
  {
    "name": "M7: Implement LUKS Full Disk Encryption (Linux)",
    "finding": "Insecure Disk Encryption or Settings",
    "description": "Encrypt entire block devices (disks or partitions) using Linux Unified Key Setup (LUKS) to protect data at rest from unauthorized physical access.",
    "category": "Encryption",
    "reference": "CCI: 001199"
  },
  {
    "name": "M8: Configure IPsec for Secure Network Communication (Linux)",
    "finding": "Insecure Communication or Protocols",
    "description": "Implement IPsec using tools like strongSwan or Libreswan to encrypt and authenticate IP network communications, securing data in transit.",
    "category": "Encryption",
    "reference": "CCI: 000197"
  },
  {
    "name": "M9: Implement SELinux Policies (Linux)",
    "finding": "Insecure Access Controls",
    "description": "Utilize SELinux to enforce mandatory access control (MAC) policies, strictly defining access rights for users, applications, and system resources to limit compromise impact.",
    "category": "Encryption",
    "reference": "CCI: 001084"
  },
  {
    "name": "M10: Enforce TLS for Secure Services (Linux)",
    "finding": "Insecure Protocols and Services - TLS",
    "description": "Configure services (web servers, mail servers, etc.) running on Linux to use strong Transport Layer Security (TLS) protocols (TLS 1.2 or higher) and ciphers for encrypting data in transit.",
    "category": "Encryption",
    "reference": "CCI: 000197"
  },
  {
    "name": "M11: Implement BitLocker Drive Encryption (Windows)",
    "finding": "Insecure Disk Encryption or Settings",
    "description": "Utilize BitLocker Drive Encryption to encrypt entire volumes on Windows systems, protecting data at rest from unauthorized access, especially on lost or stolen devices.",
    "category": "Encryption",
    "reference": "CCI: 001199"
  },
  {
    "name": "M12: Configure IPsec for Secure Network Communication (Windows)",
    "finding": "Insecure Communication or Protocols",
    "description": "Implement IPsec using Windows Firewall with Advanced Security or Group Policy to encrypt and authenticate IP network communications, securing data in transit.",
    "category": "Encryption",
    "reference": "CCI: 000197"
  },
  {
    "name": "M13: Enforce TLS for Secure Services (Windows)",
    "finding": "Insecure Protocols and Services - TLS",
    "description": "Configure Windows services (IIS, RDP, etc.) and applications to use strong Transport Layer Security (TLS) protocols (TLS 1.2 or higher) and ciphers via registry settings (Schannel) or application-specific configurations.",
    "category": "Encryption",
    "reference": "CCI: 000197"
  },
  {
    "name": "M14: Configure Comprehensive System Logging (Linux)",
    "finding": "Insecure Logging or Monitoring",
    "description": "Configure system logging (e.g., using rsyslog or journald) to capture relevant events (logins, sudo usage, errors, service changes) and forward them to a centralized log management system (SIEM).",
    "category": "Logging",
    "reference": "CCI: 000135"
  },
  {
    "name": "M15: Implement File Integrity Monitoring with AIDE (Linux)",
    "finding": "Insecure Logging or Monitoring",
    "description": "Use Advanced Intrusion Detection Environment (AIDE) or similar tools (like Tripwire) to monitor critical system files and directories for unauthorized changes, alerting administrators.",
    "category": "Logging",
    "reference": "CCI: 001744"
  },
  {
    "name": "M16: Implement Enhanced Auditing with auditd (Linux)",
    "finding": "Insecure Logging or Monitoring",
    "description": "Configure the Linux Audit daemon (auditd) to create detailed logs of security-relevant events based on customizable rules, providing deeper visibility into system activities.",
    "category": "Logging",
    "reference": "CCI: 000130"
  },
  {
    "name": "M17: Configure Comprehensive Windows Event Logging",
    "finding": "Insecure Logging or Monitoring",
    "description": "Configure Windows Event Logging via Group Policy or local policy to capture essential security events (logons, object access, policy changes, process creation) and forward logs to a central SIEM.",
    "category": "Logging",
    "reference": "CCI: 000135"
  },
  {
    "name": "M18: Implement Windows Advanced Audit Policy Configuration",
    "finding": "Insecure Logging or Monitoring",
    "description": "Utilize Advanced Audit Policy Configuration in Windows to enable more granular and detailed logging for specific event categories (e.g., detailed file access, process tracking) beyond basic logging.",
    "category": "Logging",
    "reference": "CCI: 000130"
  },
  {
    "name": "M19: Implement Threat Hunting Procedures",
    "finding": "Insecure Logging or Monitoring",
    "description": "Establish proactive threat hunting processes, leveraging aggregated logs and security tool data to actively search for signs of compromise or malicious activity that may evade automated detection.",
    "category": "Logging",
    "reference": "CCI: 001166"
  },
  {
    "name": "M20: Deploy Intrusion Detection and Prevention Systems (IDPS)",
    "finding": "Insecure Logging or Monitoring",
    "description": "Implement network-based (NIDS/NIPS) and/or host-based (HIDS/HIPS) intrusion detection and prevention systems to monitor for and potentially block malicious network traffic and system activities.",
    "category": "Logging",
    "reference": "CCI: 000667"
  },
  {
    "name": "M21: Enforce Strong Password Policies (Linux)",
    "finding": "Insecure Password Policies",
    "description": "Configure PAM (`pam_pwquality` or similar) to enforce strong password complexity, history, and minimum age requirements for user accounts on Linux systems.",
    "category": "Passwords",
    "reference": "CCI: 000196"
  },
  {
    "name": "M22: Enforce Strong Password Policies (Windows)",
    "finding": "Insecure Password Policies",
    "description": "Configure strong password policies via Group Policy (GPO) or local policy in Windows, enforcing complexity, history, minimum age, and length requirements.",
    "category": "Passwords",
    "reference": "CCI: 000196"
  },
  {
    "name": "M23: Mitigate Credential Theft Risks (Linux)",
    "finding": "Insecure Password Policies",
    "description": "Minimize credential exposure on Linux systems by avoiding storage in plaintext files or scripts, restricting access to sensitive configuration files (e.g., shadow), and disabling unnecessary credential caching.",
    "category": "Passwords",
    "reference": "CCI: 000366"
  },
  {
    "name": "M24: Mitigate Credential Theft Risks (Windows)",
    "finding": "Insecure Password Policies",
    "description": "Implement Windows security features like Credential Guard, LSA Protection (RunAsPPL), and restricting debug privileges to mitigate credential theft attacks (e.g., Mimikatz).",
    "category": "Passwords",
    "reference": "CCI: 000366"
  },
  {
    "name": "M25: Disable or Remove Unnecessary Services",
    "finding": "Insecure Protocols and Services",
    "description": "Disable or uninstall any services, protocols, and features that are not explicitly required for the system's function to reduce the attack surface.",
    "category": "Services",
    "reference": "CCI: 000381"
  },
  {
    "name": "M26: Disable or Secure IPMI/BMC Interfaces",
    "finding": "Insecure Protocols and Services - IPMI/BMC",
    "description": "Secure Intelligent Platform Management Interface (IPMI) / Baseboard Management Controller (BMC) by using dedicated management networks, strong authentication, encryption, and disabling unused features, or disable it if not needed.",
    "category": "Services",
    "reference": "CCI: 000366"
  },
  {
    "name": "M27: Disable or Secure FTP Service (Linux)",
    "finding": "Insecure Protocols and Services - FTP",
    "description": "Disable the FTP service. If required, use secure alternatives like SFTP (SSH File Transfer Protocol) or FTPS (FTP over SSL/TLS) with strong configuration.",
    "category": "Services",
    "reference": "CCI: 000381"
  },
  {
    "name": "M28: Disable LLMNR Protocol (Linux)",
    "finding": "Insecure Protocols and Services - LLMNR",
    "description": "Disable Link-Local Multicast Name Resolution (LLMNR) on Linux systems (often via systemd-resolved configuration) to prevent name resolution poisoning attacks.",
    "category": "Services",
    "reference": "CCI: 000381"
  },
  {
    "name": "M29: Disable mDNS Protocol (Linux)",
    "finding": "Insecure Protocols and Services - mDNS",
    "description": "Disable Multicast DNS (mDNS) (e.g., Avahi daemon) on Linux systems unless specifically required for service discovery in trusted networks.",
    "category": "Services",
    "reference": "CCI: 000381"
  },
  {
    "name": "M30: Secure MySQL Service (Linux)",
    "finding": "Insecure Protocols and Services - MySQL",
    "description": "Harden the MySQL/MariaDB service: remove default accounts, enforce strong passwords, bind to specific interfaces, configure TLS for connections, and apply least privilege principles.",
    "category": "Services",
    "reference": "CCI: 000366"
  },
  {
    "name": "M31: Disable NBT-NS Protocol (Linux)",
    "finding": "Insecure Protocols and Services - NBT-NS",
    "description": "Disable NetBIOS Name Service (NBT-NS) often handled by Samba (smbd/nmbd) on Linux systems to prevent name resolution poisoning.",
    "category": "Services",
    "reference": "CCI: 000381"
  },
  {
    "name": "M32: Disable or Secure NFS Service (Linux)",
    "finding": "Insecure Protocols and Services - NFS",
    "description": "Disable the NFS service if not required. If needed, use NFSv4 with Kerberos authentication (sec=krb5p), restrict exports to specific hosts/subnets, and use appropriate mount options.",
    "category": "Services",
    "reference": "CCI: 000366"
  },
  {
    "name": "M33: Disable Open Relay (SMTP) (Linux)",
    "finding": "Insecure Protocols and Services - Open Relay",
    "description": "Configure mail transfer agents (e.g., Postfix, Sendmail) on Linux to reject mail relaying from unauthorized sources, preventing use as an open relay for spam.",
    "category": "Services",
    "reference": "CCI: 000381"
  },
  {
    "name": "M34: Disable or Secure SNMP Service (Linux)",
    "finding": "Insecure Protocols and Services - SNMP",
    "description": "Disable the SNMP service if unused. If required, use SNMPv3 with strong authentication (authPriv), complex passphrases, and restrict access via ACLs/views.",
    "category": "Services",
    "reference": "CCI: 000381"
  },
  {
    "name": "M35: Disable or Harden SSH Service (Linux)",
    "finding": "Insecure Protocols and Services - SSH",
    "description": "Harden the SSH daemon (sshd): disable root login, enforce key-based authentication, disable protocol 1, use strong ciphers/MACs/KEX, configure idle timeouts, implement 2FA, and restrict access.",
    "category": "Services",
    "reference": "CCI: 000366"
  },
  {
    "name": "M36: Restrict Use of TCPDUMP (Linux)",
    "finding": "Insecure Protocols and Services - TCPDUMP",
    "description": "Restrict the ability to run packet capture tools like tcpdump to authorized administrative accounts only, often managed via file permissions or group memberships.",
    "category": "Services",
    "reference": "CCI: 000366"
  },
  {
    "name": "M37: Disable TELNET Service (Linux)",
    "finding": "Insecure Protocols and Services - TELNET",
    "description": "Disable the Telnet service (client and server) as it transmits credentials and data in plaintext. Use SSH instead.",
    "category": "Services",
    "reference": "CCI: 000381"
  },
  {
    "name": "M38: Disable TFTP Service (Linux)",
    "finding": "Insecure Protocols and Services - TFTP",
    "description": "Disable the Trivial File Transfer Protocol (TFTP) service as it lacks authentication. Use secure alternatives like SFTP or SCP.",
    "category": "Services",
    "reference": "CCI: 000381"
  },
  {
    "name": "M39: Disable or Secure VNC Service (Linux)",
    "finding": "Insecure Protocols and Services - VNC",
    "description": "Disable Virtual Network Computing (VNC) if not needed. If required, ensure strong passwords are used and tunnel VNC traffic over an encrypted channel like SSH.",
    "category": "Services",
    "reference": "CCI: 000197"
  },
  {
    "name": "M40: Disable or Secure X11 Forwarding (Linux)",
    "finding": "Insecure Protocols and Services - X11",
    "description": "Disable X11 forwarding in SSH configuration if not required. If needed, ensure it is securely configured (e.g., using SSH X11 forwarding with appropriate controls).",
    "category": "Services",
    "reference": "CCI: 000381"
  },
  {
    "name": "M41: Harden IIS Service (Windows)",
    "finding": "Insecure Protocols and Services - IIS",
    "description": "Harden Internet Information Services (IIS): remove unused modules/features, configure request filtering, enable detailed logging, enforce TLS, use Application Pool identities correctly, and apply security patches.",
    "category": "Services",
    "reference": "CCI: 000381"
  },
  {
    "name": "M42: Disable LLMNR Protocol (Windows)",
    "finding": "Insecure Protocols and Services - LLMNR",
    "description": "Disable Link-Local Multicast Name Resolution (LLMNR) via Group Policy or local policy on Windows systems to prevent name resolution poisoning attacks.",
    "category": "Services",
    "reference": "CCI: 000381"
  },
  {
    "name": "M43: Disable mDNS Protocol (Windows) - mDNS",
    "finding": "Insecure Protocols and Services",
    "description": "Disable Multicast DNS (mDNS) on Windows systems by disabling related services (e.g., Bonjour Print Services) or via firewall rules, unless specifically required.",
    "category": "Services",
    "reference": "CCI: 000381"
  },
  {
    "name": "M44: Monitor Network Sessions (Windows)",
    "finding": "Insecure Protocols and Services - Network Sessions",
    "description": "Monitor network sessions (e.g., using `net session` or `Get-SmbSession`) as part of security monitoring activities; limit concurrent sessions via policy where appropriate.",
    "category": "Services",
    "reference": "CCI: 000172"
  },
  {
    "name": "M45: Disable NBT-NS Protocol (Windows)",
    "finding": "Insecure Protocols and Services - NBT-NS",
    "description": "Disable NetBIOS Name Service (NBT-NS) via network adapter settings or DHCP options on Windows systems to prevent name resolution poisoning.",
    "category": "Services",
    "reference": "CCI: 000381"
  },
  {
    "name": "M46: Disable or Secure NFS Service (Windows)",
    "finding": "Insecure Protocols and Services - NFS",
    "description": "Disable the 'Services for NFS' feature if not required on Windows. If needed, configure secure access permissions and consider authentication methods.",
    "category": "Services",
    "reference": "CCI: 000381"
  },
  {
    "name": "M47: Disable NTLMv1 Authentication (Windows)",
    "finding": "Insecure Protocols and Services - NTLM",
    "description": "Configure Windows systems via Group Policy or local policy to reject NTLMv1 authentication and require NTLMv2 or Kerberos.",
    "category": "Services",
    "reference": "CCI: 000803"
  },
  {
    "name": "M48: Disable SMBv1 and Harden SMB (Windows)",
    "finding": "Insecure Protocols and Services - SMB",
    "description": "Disable the SMBv1 protocol. Additionally, harden SMB by requiring SMB signing (authentication) and encryption (confidentiality) via Group Policy.",
    "category": "Services",
    "reference": "CCI: 000381"
  },
  {
    "name": "M49: Disable or Secure SNMP Service (Windows)",
    "finding": "Insecure Protocols and Services - SNMP",
    "description": "Disable the SNMP service if unused. If required, configure SNMPv3 with strong authentication (authPriv), complex passphrases, and restrict access to authorized managers.",
    "category": "Services",
    "reference": "CCI: 000381"
  },
  {
    "name": "M50: Restrict Use of Packet Capture Tools (Windows)",
    "finding": "Insecure Protocols and Services - TCPDUMP",
    "description": "Restrict the installation and use of packet capture drivers/tools (like Npcap/WinPcap required by Wireshark/tcpdump) to authorized administrative accounts.",
    "category": "Services",
    "reference": "CCI: 000366"
  },
  {
    "name": "M51: Disable or Restrict Secondary Logon Service (Windows)",
    "finding": "Insecure Protocols and Services - Secondary Logon Service",
    "description": "Consider disabling the 'Secondary Logon' service (`seclogon`) if 'Run as different user' functionality is not required, as it can pose security risks if misused.",
    "category": "Services",
    "reference": "CCI: 000381"
  },
  {
    "name": "M52: Harden TCP/IP Stack (Windows)",
    "finding": "Insecure Protocols and Services - TCP/IP",
    "description": "Harden the Windows TCP/IP stack via registry settings or `netsh` commands (e.g., disable unused features like source routing, enable SYN flood protection) and configure Windows Firewall rules appropriately.",
    "category": "Services",
    "reference": "CCI: 000366"
  },
  {
    "name": "M53: Disable TELNET (Windows)",
    "finding": "Insecure Protocols and Services - TELNET",
    "description": "Ensure the Telnet Client and Telnet Server features are disabled/uninstalled on Windows systems.",
    "category": "Services",
    "reference": "CCI: 000381"
  },
  {
    "name": "M54: Disable WDigest Credential Caching (Windows)",
    "finding": "Insecure Protocols and Services - WDigest",
    "description": "Ensure WDigest authentication is disabled via registry setting (`UseLogonCredential`) to prevent plaintext credentials from being stored in memory.",
    "category": "Services",
    "reference": "CCI: 000196"
  },
  {
    "name": "M55: Disable WinHTTP Proxy Auto-Discovery Service (Windows)",
    "finding": "Insecure Protocols and Services - WinHTTP Proxy Auto-Discovery",
    "description": "Ensure Windows HTTP Services (WinHTTP) proxy settings are configured correctly and securely, typically via Group Policy or `netsh winhttp`, to prevent redirection or man-in-the-middle risks.",
    "category": "Services",
    "reference": "CCI: 000366"
  },
  {
    "name": "M56: Disable Web Proxy Auto-Discovery (WPAD) (Windows)",
    "finding": "Insecure Protocols and Services - WPAD",
    "description": "Disable the Web Proxy Auto-Discovery (WPAD) protocol via DNS and DHCP settings, and ensure WinHTTP/WinINET clients are not configured to auto-detect settings, preventing WPAD spoofing attacks.",
    "category": "Services",
    "reference": "CCI: 000381"
  }
]

def populate_findings(apps, schema_editor):
    """
    Updates the 'finding' field for existing Mitigation objects
    based on the mitigation_data list. (Enhanced Debug Version)
    """
    # Get the specific version of the Mitigation model for this migration
    Mitigation = apps.get_model('collector', 'Mitigation')
    print("\nAttempting to update Mitigation findings (Run 2 - Enhanced Debug)...") # Feedback

    updated_count = 0
    not_found_count = 0
    already_correct_count = 0
    error_count = 0

    for item_data in mitigation_data:
        mitigation_name = item_data.get('name')
        expected_finding = item_data.get('finding', '') # Default to blank if missing

        if not mitigation_name:
            print("  - Warning: Skipping item with no 'name' key.")
            continue

        try:
            # Try to get the object
            mitigation_obj = Mitigation.objects.get(name=mitigation_name)
            # If successful, print that it was found
            print(f"  - Found: '{mitigation_name}' (PK={mitigation_obj.pk})") # <<< Added Found print

            # Now check if update is needed
            if mitigation_obj.finding != expected_finding:
                print(f"    - Updating finding from '{mitigation_obj.finding}' to '{expected_finding}'") # <<< Added Updating print
                mitigation_obj.finding = expected_finding
                # Only save the 'finding' field for efficiency
                mitigation_obj.save(update_fields=['finding'])
                updated_count += 1
            else:
                print(f"    - Finding ('{mitigation_obj.finding}') already correct.") # <<< Added Already Correct print
                already_correct_count += 1

        except Mitigation.DoesNotExist:
            # Explicitly print the DoesNotExist error
            print(f"  - Error: Mitigation.DoesNotExist for name: '{mitigation_name}'") # <<< Added DoesNotExist print
            not_found_count += 1
        except Exception as e:
            # Catch any other errors during get/save
            print(f"  - Error processing '{mitigation_name}': {e}") # <<< Added Other Error print
            error_count += 1

    print(f"\nMitigation findings update complete.")
    print(f"  Updated: {updated_count}")
    print(f"  Already Correct: {already_correct_count}")
    print(f"  Not Found (DoesNotExist): {not_found_count}")
    print(f"  Other Errors: {error_count}")


class Migration(migrations.Migration):

    dependencies = [
        # Add the previous migration file name here
        # e.g., ('collector', '0003_auto_your_previous_migration'),
        # Look in your collector/migrations/ folder for the latest one BEFORE this new file.
        ('collector', '0017_populate_mitigations'), # <<< CHANGE '0001_initial' TO YOUR PREVIOUS MIGRATION FILE NAME
    ]

    operations = [
        migrations.RunPython(populate_findings, migrations.RunPython.noop),
        # migrations.RunPython.noop means this migration is not reversible automatically.
        # If you needed to reverse it, you'd write another function to set findings back to ''.
    ]