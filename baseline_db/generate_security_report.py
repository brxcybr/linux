#!/usr/bin/env python3
"""
Security Posture Report Generator

Generates comprehensive security posture reports from Linux baseline data.
This report can be shared with leadership and used to inform security policies.

Usage:
    python3 generate_security_report.py --db baseline.db --output security_report.txt
    # Output will be: security_report_20240122_143052.txt (timestamp appended)
"""

import sqlite3
import argparse
from pathlib import Path
from datetime import datetime, timezone
import os
import re


def generate_security_posture_report(db_path: Path, output_file: Path, report_timestamp: str) -> None:
    """
    Generate a comprehensive security posture report for leadership.
    """
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row

    report = []

    def add_section(title: str, content: list[str]) -> None:
        report.append(f"\n{'='*80}")
        report.append(f" {title.upper()}")
        report.append(f"{'='*80}")
        report.extend(content)

    def add_subsection(title: str, content: list[str]) -> None:
        report.append(f"\n{title}")
        report.append("-" * len(title))
        report.extend(content)

    def normalize_text(value: str | None) -> str:
        return value.strip() if isinstance(value, str) and value.strip() else "Unknown"

    def parse_uname_arch(uname_a: str | None) -> str | None:
        if not uname_a:
            return None
        match = re.search(r"\b(x86_64|amd64|aarch64|arm64|i[3-6]86)\b", uname_a)
        return match.group(1) if match else None

    def parse_uname_kernel(uname_a: str | None) -> str | None:
        if not uname_a:
            return None
        parts = uname_a.split()
        if len(parts) >= 3:
            return parts[2]
        return None

    def format_gb(bytes_value: int | None) -> str:
        if not bytes_value:
            return "Unknown"
        return f"{bytes_value / (1024 ** 3):.1f} GB"

    # Executive Summary
    summary = [
        "This report provides a comprehensive security posture assessment of the Linux host nodes.",
        "It identifies open ports, security findings, unique configurations, and policy recommendations.",
        "",
        "Key Findings:",
    ]

    # Count findings by severity
    findings_summary = conn.execute("""
        SELECT severity, COUNT(*) as count
        FROM findings
        GROUP BY severity
        ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END
    """).fetchall()

    for severity, count in findings_summary:
        summary.append(f"  - {count} {severity.upper()} severity findings")

    # Count hosts
    host_count = conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
    summary.append(f"  - {host_count} nodes assessed")
    summary.append("")
    summary.append(f"Report Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")

    add_section("EXECUTIVE SUMMARY", summary)

    # Data Collection Timestamps
    data_timestamps = []

    # Query for oldest and newest data collection dates
    date_range = conn.execute("""
        SELECT
            MIN(collected_at_utc) as oldest_collection,
            MAX(collected_at_utc) as newest_collection
        FROM runs
        WHERE collected_at_utc IS NOT NULL
    """).fetchone()

    if date_range and date_range[0]:
        # Parse and format the dates
        oldest_date = datetime.fromisoformat(date_range[0].replace('Z', '+00:00')).strftime('%Y-%m-%d %H:%M:%S UTC')
        newest_date = datetime.fromisoformat(date_range[1].replace('Z', '+00:00')).strftime('%Y-%m-%d %H:%M:%S UTC')

        data_timestamps.extend([
            f"Oldest Data Collection: {oldest_date}",
            f"Newest Data Collection: {newest_date}",
            f"Data Time Span: {(datetime.fromisoformat(date_range[1].replace('Z', '+00:00')) - datetime.fromisoformat(date_range[0].replace('Z', '+00:00'))).days} days"
        ])
    else:
        data_timestamps.append("Data collection timestamps not available")

    add_section("DATA COLLECTION TIMESTAMPS", data_timestamps)

    # Node Overview
    node_overview = []
    node_stats = conn.execute("""
        SELECT
            COUNT(DISTINCT ac.asset_id) as total_hosts,
            AVG(ac.mem_total_bytes / (1024*1024*1024)) as avg_memory_gb,
            COUNT(DISTINCT u.username) as total_users,
            COUNT(DISTINCT p.name) as total_packages
        FROM v_asset_current ac
        LEFT JOIN run_users u ON u.run_id = ac.last_run_id
        LEFT JOIN run_packages p ON p.run_id = ac.last_run_id
    """).fetchone()

    node_overview.extend([
        f"Total Nodes Assessed: {node_stats['total_hosts']}",
        f"Average Memory per Node: {node_stats['avg_memory_gb']:.1f} GB" if node_stats['avg_memory_gb'] else "Average Memory per Node: Unknown",
        f"Total Unique Users Across Nodes: {node_stats['total_users']}",
        f"Total Unique Packages Across Nodes: {node_stats['total_packages']}",
    ])

    add_section("NODE OVERVIEW", node_overview)

    # Per-Host Security Assessment
    hosts = conn.execute("SELECT hostname FROM assets ORDER BY hostname").fetchall()

    for (hostname,) in hosts:
        host_section = [f"\nDetailed Assessment for: {hostname.upper()}"]
        host_section.append("=" * (len(host_section[0]) - 1))

        # Get host details
        host_info = conn.execute("""
            SELECT
                ac.hostname,
                ac.last_run_id,
                ac.last_source_ip,
                ac.operating_system,
                ac.kernel,
                ac.architecture,
                ac.hardware_vendor,
                ac.hardware_model,
                ac.mem_total_bytes,
                hi.memory_capacity_gb
            FROM v_asset_current ac
            LEFT JOIN host_inventory hi ON hi.hostname = ac.hostname
            WHERE ac.hostname = ?
        """, (hostname,)).fetchone()

        if host_info:
            run_id = host_info["last_run_id"]
            hostinfo = conn.execute("""
                SELECT operating_system, kernel, architecture, hardware_vendor, hardware_model
                FROM run_hostinfo
                WHERE run_id = ?
            """, (run_id,)).fetchone()
            uname_row = conn.execute("SELECT uname_a FROM run_uname WHERE run_id = ?", (run_id,)).fetchone()

            os_name = hostinfo["operating_system"] if hostinfo else None
            kernel = hostinfo["kernel"] if hostinfo else None
            architecture = hostinfo["architecture"] if hostinfo else None
            hardware_vendor = hostinfo["hardware_vendor"] if hostinfo else None
            hardware_model = hostinfo["hardware_model"] if hostinfo else None

            if not architecture:
                architecture = host_info["architecture"] or parse_uname_arch(uname_row["uname_a"] if uname_row else None)
            if not kernel:
                kernel = host_info["kernel"] or parse_uname_kernel(uname_row["uname_a"] if uname_row else None)
            if not os_name:
                os_name = host_info["operating_system"]
            if not hardware_vendor:
                hardware_vendor = host_info["hardware_vendor"]
            if not hardware_model:
                hardware_model = host_info["hardware_model"]

            mem_total = format_gb(host_info["mem_total_bytes"])
            inv_mem = f"{host_info['memory_capacity_gb']:.1f} GB" if host_info["memory_capacity_gb"] else None

            dmi = conn.execute("""
                SELECT manufacturer, product_name, version, serial_number, sku_number, family
                FROM run_dmi_system
                WHERE run_id = ?
            """, (run_id,)).fetchone()

            host_section.extend([
                f"IP Address: {normalize_text(host_info['last_source_ip'])}",
                f"Operating System: {normalize_text(os_name)}",
                f"Kernel: {normalize_text(kernel)}",
                f"Architecture: {normalize_text(architecture)}",
                f"Hardware Vendor: {normalize_text(hardware_vendor)}",
                f"Hardware Model: {normalize_text(hardware_model)}",
                f"System Version: {normalize_text(dmi['version'])}" if dmi else "System Version: Unknown",
                f"Serial Number: {normalize_text(dmi['serial_number'])}" if dmi else "Serial Number: Unknown",
                f"Memory (Observed): {mem_total}",
                f"Memory (Inventory): {inv_mem}" if inv_mem else "Memory (Inventory): Unknown",
            ])

            storage_row = conn.execute("""
                SELECT
                    SUM(CASE WHEN type = 'disk' THEN size_bytes ELSE 0 END) as total_disk_bytes,
                    SUM(CASE WHEN type = 'disk' AND (rm IS NULL OR rm = 0) THEN size_bytes ELSE 0 END) as total_fixed_disk_bytes
                FROM run_block_devices d
                WHERE d.run_id = ?
            """, (run_id,)).fetchone()
            if storage_row:
                total_disk = format_gb(storage_row["total_disk_bytes"])
                total_fixed = format_gb(storage_row["total_fixed_disk_bytes"])
                host_section.append(f"Total Disk Capacity (All): {total_disk}")
                host_section.append(f"Total Disk Capacity (Fixed): {total_fixed}")
                host_section.append("Available Disk Capacity: Unknown (not collected)")

        # Open Ports and Services
        ports_section = []
        ports_data = conn.execute("""
            SELECT DISTINCT
                ls.proto,
                ls.state,
                ls.local_addr,
                ls.local_port,
                ls.peer_addr,
                ls.peer_port,
                ls.process_name,
                ls.pid,
                p.uid,
                p.cmd
            FROM run_listening_sockets ls
            JOIN runs r ON r.run_id = ls.run_id
            JOIN assets a ON a.asset_id = r.asset_id
            LEFT JOIN run_processes p ON p.pid = ls.pid AND p.run_id = ls.run_id
            WHERE a.hostname = ?
            ORDER BY ls.local_port
        """, (hostname,)).fetchall()

        firewall_rules = conn.execute("""
            SELECT source, rule
            FROM run_firewall_rules fr
            JOIN runs r ON r.run_id = fr.run_id
            JOIN assets a ON a.asset_id = r.asset_id
            WHERE a.hostname = ?
        """, (hostname,)).fetchall()

        if ports_data:
            ports_section.append("Listening Ports:")
            for row in ports_data:
                proto = row["proto"] or "unknown"
                port = row["local_port"]
                state = row["state"] or "unknown"
                local_addr = row["local_addr"] or "unknown"
                peer_addr = row["peer_addr"]
                peer_port = row["peer_port"]
                process_name = row["process_name"] or "Unknown Process"
                pid = row["pid"]
                uid = row["uid"]
                cmd = row["cmd"] or process_name

                username = None
                groupname = None
                uid_num = None
                if uid is not None:
                    uid_str = str(uid).strip()
                    if uid_str.isdigit():
                        uid_num = int(uid_str)
                        user_row = conn.execute("""
                            SELECT u.username, u.uid, g.groupname
                            FROM run_users u
                            LEFT JOIN run_groups g ON g.run_id = u.run_id AND g.gid = u.gid
                            JOIN runs r ON r.run_id = u.run_id
                            JOIN assets a ON a.asset_id = r.asset_id
                            WHERE a.hostname = ? AND u.uid = ?
                            LIMIT 1
                        """, (hostname, uid_num)).fetchone()
                    else:
                        user_row = conn.execute("""
                            SELECT u.username, u.uid, g.groupname
                            FROM run_users u
                            LEFT JOIN run_groups g ON g.run_id = u.run_id AND g.gid = u.gid
                            JOIN runs r ON r.run_id = u.run_id
                            JOIN assets a ON a.asset_id = r.asset_id
                            WHERE a.hostname = ? AND u.username = ?
                            LIMIT 1
                        """, (hostname, uid_str)).fetchone()
                    if user_row:
                        username = user_row["username"]
                        uid_num = user_row["uid"]
                        groupname = user_row["groupname"]

                addr_scope = "local-only" if local_addr in ("127.0.0.1", "::1") else ("all-interfaces" if local_addr in ("0.0.0.0", "::") else "bound")
                peer_info = f" -> {peer_addr}:{peer_port}" if peer_addr and peer_port else ""
                uid_display = uid_num if uid_num is not None else uid
                user_info = f" (uid={uid_display}, user={username or 'unknown'}, group={groupname or 'unknown'})" if uid is not None else ""

                ports_section.append(f"  {proto.upper()} {local_addr}:{port}{peer_info} [{state}, {addr_scope}]")
                ports_section.append(f"    Process: {cmd}")
                if pid is not None:
                    ports_section.append(f"    PID: {pid}{user_info}")

                # Package correlation (best-effort)
                exe = cmd.split()[0] if cmd else ""
                base = os.path.basename(exe).split(":")[0]
                if base:
                    pkg_rows = conn.execute("""
                        SELECT name, version
                        FROM run_packages p
                        JOIN runs r ON r.run_id = p.run_id
                        JOIN assets a ON a.asset_id = r.asset_id
                        WHERE a.hostname = ? AND (p.name LIKE ? OR p.name LIKE ?)
                        LIMIT 3
                    """, (hostname, f"{base}%", f"%{base}%")).fetchall()
                    if pkg_rows:
                        pkg_list = ", ".join([f"{p['name']} {p['version']}" if p['version'] else p['name'] for p in pkg_rows])
                        ports_section.append(f"    Possible Packages: {pkg_list}")

                # Firewall rule correlation
                if port is not None and firewall_rules:
                    port_patterns = [
                        rf"\bdpt[:=]\s*{port}\b",
                        rf"\b--dport\s+{port}\b",
                        rf"\b{port}/tcp\b",
                        rf"\b{port}/udp\b",
                    ]
                    matched_rules = []
                    for rule_row in firewall_rules:
                        rule_text = rule_row["rule"]
                        if any(re.search(pattern, rule_text) for pattern in port_patterns):
                            matched_rules.append(rule_row)
                    if matched_rules:
                        ports_section.append("    Related Firewall Rules:")
                        for rule_row in matched_rules[:3]:
                            ports_section.append(f"      [{rule_row['source']}] {rule_row['rule']}")

                # Flag unusual ports (non-standard listening services), ignore APIPA
                is_apipa = (local_addr or "").startswith("169.254.") or (peer_addr or "").startswith("169.254.")
                if (not is_apipa) and port and port not in [22, 80, 443, 53, 25, 110, 143, 993, 995, 3306, 5432, 6379, 27017, 2049, 111]:
                    ports_section.append("    ⚠️  UNUSUAL LISTENING PORT - Review service justification and firewall exposure")
        else:
            ports_section.append("No listening ports identified")

        add_subsection("OPEN PORTS AND SERVICES", ports_section)

        # Security Findings
        findings_section = []
        host_findings = conn.execute("""
            SELECT severity, category, title, details
            FROM findings f
            JOIN runs r ON r.run_id = f.run_id
            JOIN assets a ON a.asset_id = r.asset_id
            WHERE a.hostname = ?
            ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END
        """, (hostname,)).fetchall()

        if host_findings:
            for severity, category, title, details in host_findings:
                severity_icon = {"critical": "🚨", "high": "🔴", "medium": "🟡", "low": "🟢"}.get(severity, "ℹ️")
                findings_section.append(f"{severity_icon} {severity.upper()}: {title}")
                if details:
                    findings_section.append(f"   {details}")
        else:
            findings_section.append("✅ No security findings identified")

        add_subsection("SECURITY FINDINGS", findings_section)

        # User and Permission Analysis
        users_section = []

        # Service accounts with shells
        service_accounts = conn.execute("""
            SELECT u.username, u.shell, u.uid, GROUP_CONCAT(gm.groupname) as groups
            FROM run_users u
            JOIN runs r ON r.run_id = u.run_id
            JOIN assets a ON a.asset_id = r.asset_id
            LEFT JOIN run_group_members gm ON gm.run_id = u.run_id AND gm.member_username = u.username AND gm.source = 'getent'
            WHERE a.hostname = ? AND u.shell LIKE '%sh' AND u.uid < 1000 AND u.username NOT IN ('root', 'ubuntu', 'ec2-user')
            GROUP BY u.username, u.shell, u.uid
        """, (hostname,)).fetchall()

        if service_accounts:
            users_section.append("⚠️  SERVICE ACCOUNTS WITH INTERACTIVE SHELLS:")
            for username, shell, uid, groups in service_accounts:
                users_section.append(f"  User: {username} (UID: {uid}, Shell: {shell})")
                if groups:
                    users_section.append(f"    Groups: {groups}")
                users_section.append("    🔒 RECOMMENDATION: Remove shell access or change to /usr/sbin/nologin")

        # Privileged users
        privileged_users = conn.execute("""
            SELECT gm.member_username, GROUP_CONCAT(DISTINCT gm.groupname) as groups, COUNT(*) as group_count
            FROM run_group_members gm
            JOIN runs r ON r.run_id = gm.run_id
            JOIN assets a ON a.asset_id = r.asset_id
            WHERE a.hostname = ? AND gm.groupname IN ('sudo', 'wheel', 'adm', 'admin', 'root')
            GROUP BY gm.member_username
            HAVING group_count > 0
        """, (hostname,)).fetchall()

        if privileged_users:
            users_section.append("\n👑 PRIVILEGED USERS:")
            for username, groups, count in privileged_users:
                users_section.append(f"  {username}: {groups}")

        # Users who have never logged in but have SSH keys
        unused_accounts = conn.execute("""
            SELECT u.username, COUNT(k.key_fingerprint_sha256) as key_count
            FROM run_users u
            JOIN runs r ON r.run_id = u.run_id
            JOIN assets a ON a.asset_id = r.asset_id
            LEFT JOIN run_lastlog ll ON ll.run_id = u.run_id AND ll.username = u.username
            LEFT JOIN run_ssh_authorized_keys k ON k.run_id = u.run_id AND k.username = u.username
            WHERE a.hostname = ?
              AND u.shell LIKE '%sh'
              AND (ll.latest IS NULL OR ll.latest = 'Never logged in')
            GROUP BY u.username
            HAVING key_count > 0
        """, (hostname,)).fetchall()

        if unused_accounts:
            users_section.append("\n🔑 ACCOUNTS WITH SSH KEYS BUT NEVER LOGGED IN:")
            for username, key_count in unused_accounts:
                users_section.append(f"  {username}: {key_count} SSH keys")
                users_section.append("    🧹 RECOMMENDATION: Review and potentially remove unused accounts")

        if not users_section:
            users_section.append("✅ No user permission issues identified")

        add_subsection("USER AND PERMISSION ANALYSIS", users_section)

        # Node-Specific Items
        node_specific_section = []

        # Rare processes
        rare_processes = conn.execute("""
            SELECT cmd, host_count
            FROM v_rare_processes
            WHERE hostname = ? AND host_count <= 2
            ORDER BY host_count, total_instances DESC
            LIMIT 10
        """, (hostname,)).fetchall()

        if rare_processes:
            node_specific_section.append("🔍 RARE PROCESSES ON THIS NODE:")
            for cmd, host_count in rare_processes:
                node_specific_section.append(f"  {cmd} (only on {host_count} node{'s' if host_count > 1 else ''})")

        # Rare packages (unique to this node or one other)
        rare_packages = conn.execute("""
            WITH pkg_counts AS (
                SELECT p.name, COUNT(DISTINCT r.asset_id) as host_count
                FROM run_packages p
                JOIN runs r ON r.run_id = p.run_id
                GROUP BY p.name
                HAVING host_count <= 2
            )
            SELECT p.name, p.version, pc.host_count
            FROM run_packages p
            JOIN runs r ON r.run_id = p.run_id
            JOIN assets a ON a.asset_id = r.asset_id
            JOIN pkg_counts pc ON pc.name = p.name
            WHERE a.hostname = ?
            ORDER BY pc.host_count, p.name
            LIMIT 15
        """, (hostname,)).fetchall()
        if rare_packages:
            node_specific_section.append("\n📦 RARE PACKAGES ON THIS NODE:")
            for pkg in rare_packages:
                version = f" {pkg['version']}" if pkg["version"] else ""
                node_specific_section.append(
                    f"  {pkg['name']}{version} (only on {pkg['host_count']} node{'s' if pkg['host_count'] > 1 else ''})"
                )

        # Rare kernel modules (LKMs)
        rare_modules = conn.execute("""
            SELECT module, host_count, description, license
            FROM v_rare_kernel_modules
            WHERE hostname = ?
            ORDER BY host_count, module
            LIMIT 10
        """, (hostname,)).fetchall()
        if rare_modules:
            node_specific_section.append("\n🧩 RARE KERNEL MODULES (LKMs):")
            for mod in rare_modules:
                desc = f" - {mod['description']}" if mod["description"] else ""
                lic = f" [{mod['license']}]" if mod["license"] else ""
                node_specific_section.append(
                    f"  {mod['module']}{desc}{lic} (only on {mod['host_count']} node{'s' if mod['host_count'] > 1 else ''})"
                )

        # USB devices (list all; servers should typically be USB-free)
        usb_devices = conn.execute("""
            SELECT vendor_id, product_id, vendor_name, product_name, serial_number, bus_number, device_number
            FROM run_usb_devices d
            JOIN runs r ON r.run_id = d.run_id
            JOIN assets a ON a.asset_id = r.asset_id
            WHERE a.hostname = ?
            ORDER BY bus_number, device_number
        """, (hostname,)).fetchall()

        if usb_devices:
            node_specific_section.append("\n🔌 USB DEVICES CONNECTED (REQUIRES AUTHORIZATION REVIEW):")
            for dev in usb_devices:
                vendor = dev["vendor_name"] or "Unknown Vendor"
                product = dev["product_name"] or "Unknown Product"
                vidpid = f"{dev['vendor_id']}:{dev['product_id']}" if dev["vendor_id"] and dev["product_id"] else "unknown"
                serial = dev["serial_number"] or "unknown"
                node_specific_section.append(
                    f"  Bus {dev['bus_number']} Device {dev['device_number']}: {vendor} {product} [{vidpid}] Serial: {serial}"
                )
        else:
            node_specific_section.append("✅ No USB devices detected")

        # Unique mounts
        unique_mounts = conn.execute("""
            SELECT mountpoints, name, type
            FROM v_unique_mounts
            WHERE hostname = ?
            LIMIT 5
        """, (hostname,)).fetchall()

        if unique_mounts:
            node_specific_section.append("\n💾 UNIQUE MOUNT POINTS:")
            for mountpoint, device, fs_type in unique_mounts:
                node_specific_section.append(f"  {mountpoint} ({device}, {fs_type})")

        add_subsection("NODE-SPECIFIC ITEMS", node_specific_section)

        # Configuration Differences
        config_section = []

        # Password complexity differences
        host_passwd_complexity = conn.execute("""
            SELECT
                AVG(CASE WHEN p.status_code = 'P' THEN 1 ELSE 0 END) as pwd_enabled_pct,
                COUNT(*) as total_accounts,
                SUM(CASE WHEN p.status_code = 'L' THEN 1 ELSE 0 END) as locked_accounts
            FROM run_passwd_status p
            JOIN runs r ON r.run_id = p.run_id
            JOIN assets a ON a.asset_id = r.asset_id
            WHERE a.hostname = ?
        """, (hostname,)).fetchone()

        if host_passwd_complexity and host_passwd_complexity[1] > 0:
            pw_accounts = conn.execute("""
                SELECT p.username
                FROM run_passwd_status p
                JOIN runs r ON r.run_id = p.run_id
                JOIN assets a ON a.asset_id = r.asset_id
                WHERE a.hostname = ? AND p.status_code = 'P'
                ORDER BY p.username
            """, (hostname,)).fetchall()
            pw_names = [row["username"] for row in pw_accounts]
            config_section.extend([
                f"Accounts with Passwords Enabled: {len(pw_names)}",
                f"  Users: {', '.join(pw_names) if pw_names else 'None'}",
                f"Locked Accounts: {host_passwd_complexity[2]} accounts are locked",
                f"Total User Accounts: {host_passwd_complexity[1]}"
            ])

        # Audit configuration
        audit_config = conn.execute("""
            SELECT ar.rule_count, ap.audit_enabled, ap.audit_immutable
            FROM (
                SELECT COUNT(*) as rule_count, run_id
                FROM run_audit_rules
                GROUP BY run_id
            ) ar
            JOIN run_audit_posture ap ON ap.run_id = ar.run_id
            JOIN runs r ON r.run_id = ap.run_id
            JOIN assets a ON a.asset_id = r.asset_id
            WHERE a.hostname = ?
        """, (hostname,)).fetchone()

        if audit_config:
            config_section.extend([
                f"Audit Rules: {audit_config[0]} rules configured",
                f"Audit Enabled: {'Yes' if audit_config[1] else 'No'}",
                f"Audit Immutable: {'Yes' if audit_config[2] else 'No'}"
            ])

        # Firewall configuration
        firewall_config = conn.execute("""
            SELECT source, COUNT(*) as rule_count
            FROM run_firewall_rules
            JOIN runs r ON r.run_id = run_firewall_rules.run_id
            JOIN assets a ON a.asset_id = r.asset_id
            WHERE a.hostname = ?
            GROUP BY source
        """, (hostname,)).fetchall()

        if firewall_config:
            config_section.append("Firewall Rules:")
            for source, count in firewall_config:
                config_section.append(f"  {source}: {count} rules")
            custom_rules = conn.execute("""
                SELECT source, rule
                FROM run_firewall_rules fr
                JOIN runs r ON r.run_id = fr.run_id
                JOIN assets a ON a.asset_id = r.asset_id
                WHERE a.hostname = ? AND (fr.rule LIKE '%ACCEPT%' OR fr.rule LIKE '%ALLOW%')
                LIMIT 5
            """, (hostname,)).fetchall()
            if custom_rules:
                config_section.append("  Custom/Allow Rules (review):")
                for rule in custom_rules:
                    config_section.append(f"    [{rule['source']}] {rule['rule']}")

        if not config_section:
            config_section.append("Configuration details not fully available")

        add_subsection("CONFIGURATION ANALYSIS", config_section)

        # Logging configuration (remote shipping)
        logging_section = []
        log_services = conn.execute("""
            SELECT unit, load, active, sub
            FROM run_services_systemctl s
            JOIN runs r ON r.run_id = s.run_id
            JOIN assets a ON a.asset_id = r.asset_id
            WHERE a.hostname = ?
              AND s.unit IN ('rsyslog.service', 'systemd-journald.service')
            ORDER BY s.unit
        """, (hostname,)).fetchall()
        if log_services:
            logging_section.append("Logging services:")
            for svc in log_services:
                logging_section.append(f"  {svc['unit']}: {svc['active']}/{svc['sub']} (load={svc['load']})")

        rsyslog_conf = conn.execute("""
            SELECT output_text
            FROM run_commands c
            JOIN runs r ON r.run_id = c.run_id
            JOIN assets a ON a.asset_id = r.asset_id
            WHERE a.hostname = ? AND c.command LIKE '%rsyslog.conf%'
            LIMIT 1
        """, (hostname,)).fetchone()
        journald_conf = conn.execute("""
            SELECT output_text
            FROM run_commands c
            JOIN runs r ON r.run_id = c.run_id
            JOIN assets a ON a.asset_id = r.asset_id
            WHERE a.hostname = ? AND c.command LIKE '%journald.conf%'
            LIMIT 1
        """, (hostname,)).fetchone()

        targets = []
        if rsyslog_conf and rsyslog_conf["output_text"]:
            text = rsyslog_conf["output_text"]
            targets.extend(re.findall(r"@@([A-Za-z0-9._-]+)", text))
            targets.extend(re.findall(r"@([A-Za-z0-9._-]+)", text))
            targets.extend(re.findall(r"target\\s*=\\s*\"([^\"]+)\"", text))
        if journald_conf and journald_conf["output_text"]:
            text = journald_conf["output_text"]
            targets.extend(re.findall(r"^\\s*ForwardToSyslog\\s*=\\s*(\\S+)", text, flags=re.MULTILINE))
            targets.extend(re.findall(r"^\\s*ForwardToConsole\\s*=\\s*(\\S+)", text, flags=re.MULTILINE))
            targets.extend(re.findall(r"^\\s*ForwardToWall\\s*=\\s*(\\S+)", text, flags=re.MULTILINE))

        targets = [t for t in [t.strip() for t in targets] if t]
        if targets:
            logging_section.append("Remote logging targets detected:")
            for t in sorted(set(targets)):
                logging_section.append(f"  {t}")
        else:
            logging_section.append("Remote logging targets: Not detected in collected config")
            logging_section.append("  (Consider capturing /etc/rsyslog.conf and /etc/systemd/journald.conf if not already collected)")

        add_subsection("LOGGING CONFIGURATION", logging_section)

        # Routes
        routing_section = []
        routes = conn.execute("""
            SELECT destination, gateway, iface, raw_line
            FROM run_routes rr
            JOIN runs r ON r.run_id = rr.run_id
            JOIN assets a ON a.asset_id = r.asset_id
            WHERE a.hostname = ? AND destination NOT IN ('default', '0.0.0.0', '::/0')
            LIMIT 10
        """, (hostname,)).fetchall()
        if routes:
            routing_section.append("Non-default routes (review):")
            for route in routes:
                routing_section.append(f"  {route['destination']} via {route['gateway']} dev {route['iface']}")
        else:
            routing_section.append("No non-default routes detected")
        add_subsection("ROUTES", routing_section)

        # Active accounts
        active_accounts_section = []
        active_accounts = conn.execute("""
            SELECT
                ll.username,
                ll.latest,
                ll.from_host,
                ll.port,
                u.uid,
                u.gid,
                u.gecos,
                u.home,
                u.shell,
                g.groupname
            FROM run_lastlog ll
            JOIN runs r ON r.run_id = ll.run_id
            JOIN assets a ON a.asset_id = r.asset_id
            LEFT JOIN run_users u ON u.run_id = ll.run_id AND u.username = ll.username
            LEFT JOIN run_groups g ON g.run_id = ll.run_id AND g.gid = u.gid
            WHERE a.hostname = ?
              AND ll.latest IS NOT NULL
              AND ll.latest NOT LIKE '%Never%'
            ORDER BY ll.latest DESC
            LIMIT 10
        """, (hostname,)).fetchall()
        if active_accounts:
            active_accounts_section.append("Recent account activity (lastlog):")
            for acc in active_accounts:
                username = acc["username"]
                account_type = "domain" if (username and ("\\" in username or "@" in username)) else "local"
                user_info = f" uid={acc['uid'] if acc['uid'] is not None else 'n/a'} gid={acc['gid'] if acc['gid'] is not None else 'n/a'} group={acc['groupname'] or 'unknown'}"
                profile_info = f" shell={acc['shell'] or 'unknown'} home={acc['home'] or 'unknown'}"
                active_accounts_section.append(
                    f"  {username} ({account_type}): {acc['latest']} from {acc['from_host'] or 'unknown'} ({acc['port'] or 'n/a'})"
                )
                active_accounts_section.append(f"    {user_info}{profile_info}")
        else:
            active_accounts_section.append("No recent account activity detected")
        add_subsection("ACTIVE ACCOUNTS", active_accounts_section)

        report.extend(host_section)

    # Cross-Node Policy Comparison
    comparison_section = []

    # Active accounts by node (lastlog)
    active_by_node = conn.execute("""
        SELECT a.hostname, ll.username, ll.latest
        FROM run_lastlog ll
        JOIN runs r ON r.run_id = ll.run_id
        JOIN assets a ON a.asset_id = r.asset_id
        WHERE ll.latest IS NOT NULL
          AND ll.latest NOT LIKE '%Never%'
        ORDER BY a.hostname, ll.latest DESC
    """).fetchall()
    if active_by_node:
        comparison_section.append("Active accounts by node (lastlog):")
        current_host = None
        host_users = []
        for row in active_by_node:
            if current_host is None:
                current_host = row["hostname"]
            if row["hostname"] != current_host:
                comparison_section.append(f"  {current_host}: {', '.join(host_users) if host_users else 'None'}")
                current_host = row["hostname"]
                host_users = []
            host_users.append(row["username"])
        if current_host is not None:
            comparison_section.append(f"  {current_host}: {', '.join(host_users) if host_users else 'None'}")
    else:
        comparison_section.append("Active accounts by node (lastlog): None detected")

    # Password policy variance (accounts with passwords enabled)
    pw_by_host = conn.execute("""
        SELECT a.hostname, p.username
        FROM run_passwd_status p
        JOIN runs r ON r.run_id = p.run_id
        JOIN assets a ON a.asset_id = r.asset_id
        WHERE p.status_code = 'P'
        ORDER BY a.hostname, p.username
    """).fetchall()
    if pw_by_host:
        comparison_section.append("\nAccounts with passwords enabled by node:")
        host_map = {}
        for row in pw_by_host:
            host_map.setdefault(row["hostname"], []).append(row["username"])
        all_lists = list(host_map.values())
        if all_lists and all(lst == all_lists[0] for lst in all_lists):
            example = ", ".join(all_lists[0]) if all_lists[0] else "None"
            comparison_section.append(f"  Same across all nodes: {example}")
        else:
            for host, users in host_map.items():
                comparison_section.append(f"  {host}: {', '.join(users) if users else 'None'}")
    else:
        comparison_section.append("\nAccounts with passwords enabled by node: None detected")

    if comparison_section:
        add_section("CROSS-NODE POLICY COMPARISON", comparison_section)

    # Policy Recommendations
    recommendations = [
        "\nPOLICY RECOMMENDATIONS:",
        "=" * 50,
        "",
        "🔒 USER ACCESS MANAGEMENT:",
        "  • Remove interactive shells from service accounts (e.g., postgres with /bin/bash)",
        "  • Review and remove unused accounts with SSH keys",
        "  • Implement principle of least privilege for sudo access",
        "",
        "🛡️ SYSTEM HARDENING:",
        "  • Enable SELinux/AppArmor on all systems with enforcing mode",
        "  • Enable and lock audit subsystem with comprehensive rules",
        "  • Review and restrict open ports to only required services",
        "",
        "📊 MONITORING & COMPLIANCE:",
        "  • Implement automated scanning for unusual processes and USB devices",
        "  • Monitor for configuration drift from baseline",
        "  • Regular review of privileged user access",
        "",
        "🔧 OPERATIONAL SECURITY:",
        "  • Standardize system configurations across similar hosts",
        "  • Implement change management for system modifications",
        "  • Regular security assessments and vulnerability scanning"
    ]

    add_section("POLICY RECOMMENDATIONS", recommendations)

    # Write report
    with output_file.open('w', encoding='utf-8') as f:
        f.write('\n'.join(report))

    conn.close()
    print(f"Security posture report generated: {output_file}")


def main():
    parser = argparse.ArgumentParser(description="Generate security posture reports from baseline data")
    parser.add_argument("--db", required=True, type=Path, help="SQLite database file")
    parser.add_argument("--output", required=True, type=Path, help="Base output report file (timestamp will be appended automatically)")

    args = parser.parse_args()

    if not args.db.exists():
        print(f"Error: Database file {args.db} does not exist")
        return 1

    # Generate timestamp for report generation
    report_timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')

    # Modify output filename to include timestamp
    output_file = args.output.parent / f"{args.output.stem}_{report_timestamp}{args.output.suffix}"

    generate_security_posture_report(args.db, output_file, report_timestamp)
    return 0


if __name__ == "__main__":
    exit(main())