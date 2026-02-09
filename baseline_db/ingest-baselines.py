#!/usr/bin/env python3
"""
Linux baseline ETL

Ingests:
  - optional host inventory CSV (CMDB seed)
  - raw baseline outputs: `results/<ip>_YYYYMMDD_HH:MM:SSZ.txt` (or custom path via --results-dir)

Outputs:
  - SQLite DB (default: <script_dir>/baseline.sqlite3)

Design goals:
  - Lossless storage of every command output (run_commands)
  - Best-effort normalization into security-relevant tables, with incremental growth
"""

from __future__ import annotations

import argparse
import base64
import csv
import datetime as dt
import hashlib
import os
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, Optional


PARSER_VERSION = "0.4.0"


@dataclass(frozen=True)
class ParsedCommand:
    section: str
    command_index: int
    command: str
    command_tag: str
    output_text: str


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


_STAR_HEADER_RE = re.compile(r"^\*{5,}(.+?)\*{5,}\s*$")


def _clean_section_name(s: str) -> str:
    s = s.strip()
    # normalize multiple spaces and remove stray asterisks
    s = re.sub(r"\s+", " ", s.replace("*", " ").strip())
    return s


def command_tag_for(command: str) -> str:
    c = command.strip()
    # High-value stable tags (prefer these for joins/queries)
    stable = [
        ("hostnamectl", "hostnamectl"),
        ("uname -a", "uname_a"),
        ("cat /etc/*release*", "etc_release"),
        ("cat /proc/cmdline", "proc_cmdline"),
        ("domainname", "domainname"),
        ("timedatectl", "timedatectl"),
        ("uptime", "uptime"),
        ("free -h", "free_h"),
        ("lsblk -a", "lsblk_a"),
        ("df -B1", "df_B1"),
        ("dmidecode", "dmidecode"),
        ("lshw -disable dmi", "lshw_disable_dmi"),
        ("lspci -v", "lspci_v"),
        ("lsusb -v", "lsusb_v"),
        (
            "sysctl kernel.kptr_restrict kernel.dmesg_restrict kernel.unprivileged_bpf_disabled fs.protected_hardlinks fs.protected_symlinks fs.protected_fifos fs.protected_regular net.ipv4.ip_forward net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter net.ipv6.conf.all.disable_ipv6 net.ipv6.conf.default.disable_ipv6",
            "sysctl_hardening",
        ),
        ("mokutil --sb-state", "mokutil_sb_state"),
        ("who -a", "who_a"),
        ("w", "w"),
        ("tty", "tty"),
        ("lastlog | sort", "lastlog"),
        ("last -f /var/log/wtmp", "last_wtmp"),
        ("last -f /var/log/btmp", "last_btmp"),
        ("last -f /var/run/utmp", "last_utmp"),
        ("journalctl -u ssh -u sshd --since \"7 days ago\" --no-pager", "journalctl_ssh_7d"),
        ("tail -n 200 /var/log/auth.log", "tail_auth_log"),
        ("tail -n 200 /var/log/secure", "tail_secure"),
        ("ssh-keygen -lf /etc/ssh/ssh_host_*_key.pub", "ssh_hostkey_fps"),
        ("auditctl -s", "auditctl_s"),
        ("auditctl -l", "auditctl_l"),
        ("sestatus", "sestatus"),
        ("getsebool -a", "getsebool_a"),
        ("aa-status", "aa_status"),
        ("route -n", "route_n"),
        ("cat /etc/resolv.conf", "resolv_conf"),
        ("ip neigh", "ip_neigh"),
        ("nmcli", "nmcli"),
        ("nft list ruleset", "nft_ruleset"),
        ("ps -elf --sort pid", "ps_elf"),
        ("pstree", "pstree"),
        ("lsmod | sort", "lsmod"),
        ("cat /etc/crontab", "etc_crontab"),
        ("ls -latR /etc/cron.*", "ls_etc_cron"),
        ("ls -latR /etc/cron*", "ls_etc_cron"),
        ("ls -latR /var/spool/cron", "ls_var_spool_cron"),
        ("ls -latR /etc/systemd/system", "ls_etc_systemd_system"),
        ("ls -latR /etc/init.d", "ls_etc_init_d"),
        ("ls -latR /etc/init/*", "ls_etc_init"),
        ("ls -latR /etc/rc.d", "ls_etc_rc_d"),
        ("cat /etc/ld.so.preload", "ld_so_preload"),
        # Backwards-compatible: older baselines used xargs; newer uses -exec ... +
        ("find /bin /sbin /usr/{bin,sbin} /usr/local/{bin,sbin} -maxdepth 1 -mtime 180 | xargs -r ls -l", "recent_bins"),
        ("find /bin /sbin /usr/{bin,sbin} /usr/local/{bin,sbin} -maxdepth 1 -mtime 180 -exec ls -l {} +", "recent_bins"),
        ("getcap -r /", "getcap_r"),
        ("getcap -r /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /opt 2>/dev/null", "getcap_r"),
        ("getcap -r /etc /root 2>/dev/null", "getcap_r"),
        ("cat /root/.bash_history", "root_bash_history"),
        ("printenv", "printenv"),
        ("set", "shell_set"),
        ("cat /etc/passwd", "etc_passwd"),
        ("cat /etc/group", "etc_group"),
        ("getent group sudo root wheel adm admin", "priv_groups"),
        ("cut -d':' -f1 < /etc/passwd | xargs -I {} passwd -S {}", "passwd_status"),
        ("ip a", "ip_addr"),
        ("ss -punt", "ss_punt"),
        ("systemctl list-units -all --full", "systemctl_units"),
        ("systemctl list-timers --all", "systemctl_timers"),
        ("systemctl list-unit-files --state=enabled", "systemctl_enabled_unit_files"),
        ("dpkg -l | sort", "dpkg_list"),
        ("rpm -q --all | sort", "rpm_all"),
        ("iptables -S", "iptables_s"),
        ("iptables -L -n -v", "iptables_list"),
        ("ufw status verbose", "ufw_status"),
        ("ufw show raw", "ufw_raw"),
        ("firewall-cmd --list-all-zones", "firewalld_zones"),
        ("cat /root/.ssh/authorized_keys", "root_authorized_keys"),
        ("sshd -T", "sshd_T"),
        ("cat /etc/ssh/sshd_config", "sshd_config"),
        ("ls -la /etc/ssh/sshd_config.d", "sshd_config_d_ls"),
        ("cat /etc/ssh/sshd_config.d/*", "sshd_config_d_cat"),
        ("cat /etc/sudoers", "sudoers"),
        ("ls -la /etc/sudoers.d", "sudoers_d_ls"),
        ("cat /etc/sudoers.d/*", "sudoers_d_cat"),
        ("cat /etc/rsyslog.conf", "rsyslog_conf"),
        ("cat /etc/systemd/journald.conf", "journald_conf"),
        ("cat /etc/ntp.conf", "ntp_conf"),
        ("cat /etc/chrony.conf", "chrony_conf"),
        ("cat /etc/systemd/timesyncd.conf", "timesyncd_conf"),
        ("cat /etc/chrony/chrony.conf", "chrony_conf"),
        ("cat /etc/login.defs", "login_defs"),
        ("docker ps -a", "docker_ps_a"),
        ("docker info", "docker_info"),
        ("podman ps -a", "podman_ps_a"),
        ("podman info", "podman_info"),
    ]
    for prefix, tag in stable:
        if c == prefix:
            return tag

    # Loop blocks (script prints these as a single "$ for ..." command)
    if c.startswith('for u in $users; do echo "# cat /home/$u/.ssh/authorized_keys"'):
        return "home_authorized_keys"
    if c.startswith('for u in $users; do echo "# cat /home/$u/.ssh/known_hosts"'):
        return "home_known_hosts"
    if c.startswith("for m in $mods; do") and "modinfo" in c:
        return "modinfo_all"

    # Generic slug tag as fallback
    slug = re.sub(r"[^a-zA-Z0-9]+", "_", c.lower()).strip("_")
    slug = re.sub(r"_+", "_", slug)
    return slug[:96] if slug else "unknown"


def parse_collected_at_from_filename(path: Path) -> tuple[str, str]:
    """
    Returns (source_ip, collected_at_utc_iso)

    Expected filename: <ip>_YYYYMMDD_HH:MM:SSZ.txt
    """
    name = path.name
    if not name.endswith(".txt") or "_" not in name:
        raise ValueError(f"Unexpected filename format: {name}")
    stem = name[:-4]
    ip, dtg, hmsz = stem.split("_", 2)
    # hmsz like "21:44:57Z"
    ts = f"{dtg}_{hmsz}"
    when = dt.datetime.strptime(ts, "%Y%m%d_%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
    return ip, when.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_baseline_text(text: str) -> list[ParsedCommand]:
    """
    Parses the raw baseline output into a list of (section, command, output_text).
    Splitting rule: lines starting with "$ " begin a new command block.
    """
    lines = text.splitlines()
    current_section = "LINUX BASELINE"
    commands: list[ParsedCommand] = []

    current_cmd: Optional[str] = None
    current_out: list[str] = []
    cmd_index = -1

    def flush() -> None:
        nonlocal current_cmd, current_out, cmd_index
        if current_cmd is None:
            return
        out_text = "\n".join(current_out).strip("\n")
        commands.append(
            ParsedCommand(
                section=current_section,
                command_index=cmd_index,
                command=current_cmd,
                command_tag=command_tag_for(current_cmd),
                output_text=out_text,
            )
        )
        current_cmd = None
        current_out = []

    for line in lines:
        m = _STAR_HEADER_RE.match(line)
        if m:
            # section header
            section_raw = m.group(1)
            section_clean = _clean_section_name(section_raw)
            if section_clean:
                current_section = section_clean
            continue

        if line.startswith("$ "):
            flush()
            cmd_index += 1
            current_cmd = line[2:].strip()
            current_out = []
            continue

        # ignore the baseline delimiter line but keep surrounding output intact
        if line.strip("=") == "" and line.strip() and set(line.strip()) == {"="}:
            continue

        if current_cmd is not None:
            current_out.append(line)

    flush()
    return commands


def _parse_hostname_from_hostnamectl(output: str) -> Optional[str]:
    for line in output.splitlines():
        # Ubuntu uses "Static hostname: xyz"
        if "Static hostname:" in line:
            return line.split("Static hostname:", 1)[1].strip() or None
    return None


def _parse_hostnamectl_kv(output: str) -> dict[str, str]:
    kv: dict[str, str] = {}
    for line in output.splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k = k.strip()
        v = v.strip()
        if not k:
            continue
        kv[k] = v
    return kv


def _parse_os_release_kv(output: str) -> dict[str, str]:
    kv: dict[str, str] = {}
    for line in output.splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        v = v.strip().strip('"')
        if k:
            kv[k] = v
    return kv


def _parse_proc_cmdline_kv(output: str) -> dict[str, str]:
    """
    Parses a kernel cmdline like:
      BOOT_IMAGE=/vmlinuz-... root=UUID=... ro quiet splash audit=1
    into key/value pairs. Flags without "=" are stored with value "1".
    """
    line = (output.strip().splitlines() or [""])[0].strip()
    kv: dict[str, str] = {}
    if not line:
        return kv
    for tok in line.split():
        if "=" in tok:
            k, v = tok.split("=", 1)
            k = k.strip()
            if k:
                kv[k] = v
        else:
            kv[tok] = "1"
    return kv


def _parse_sysctl_kv(output: str) -> dict[str, str]:
    """
    Parses output like:
      kernel.kptr_restrict = 2
    """
    kv: dict[str, str] = {}
    for line in output.splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        v = v.strip()
        if k:
            kv[k] = v
    return kv


def _parse_mokutil_sb_state(output: str) -> Optional[int]:
    """
    Returns 1 if SecureBoot enabled, 0 if disabled, None if unknown.
    """
    t = output.lower()
    if "secureboot enabled" in t or "secure boot enabled" in t:
        return 1
    if "secureboot disabled" in t or "secure boot disabled" in t:
        return 0
    return None


def _parse_sshd_T_kv(output: str) -> dict[str, str]:
    """
    Parses `sshd -T` output lines like:
      passwordauthentication yes
      permitrootlogin prohibit-password
    """
    kv: dict[str, str] = {}
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if not parts:
            continue
        k = parts[0].strip()
        v = parts[1].strip() if len(parts) > 1 else ""
        if k:
            kv[k] = v
    return kv


_SSH_KEYGEN_LF_RE = re.compile(r"^\s*(\d+)\s+(\S+)\s+(\S+)\s+\(([^)]+)\)\s*$")


def _parse_ssh_keygen_lf(output: str) -> list[dict[str, Optional[str]]]:
    rows: list[dict[str, Optional[str]]] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        m = _SSH_KEYGEN_LF_RE.match(line)
        if not m:
            continue
        bits, fp, key_file, key_type = m.groups()
        rows.append(
            {
                "bits": bits,
                "fingerprint": fp,
                "key_file": key_file,
                "key_type": key_type,
                "raw_line": line,
            }
        )
    return rows


def _parse_getcap_r(output: str) -> list[tuple[str, str]]:
    """
    Parses getcap output lines like:
      /usr/bin/ping = cap_net_raw+ep
    Skips "getcap not installed", errors, and lines without capability syntax (cap_*).
    """
    rows: list[tuple[str, str]] = []
    for line in output.splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        if "not installed" in line.lower() or line.startswith("getcap:"):
            continue
        left, right = line.split("=", 1)
        path = left.strip()
        caps = right.strip()
        if not path or not caps:
            continue
        if "cap_" not in caps and "=" not in caps:
            continue
        rows.append((path, caps))
    return rows


def _parse_systemctl_table(output: str, *, min_cols: int) -> list[list[str]]:
    """
    systemctl tables generally use 2+ spaces between columns.
    """
    rows: list[list[str]] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        if line.strip().startswith("NEXT ") or line.strip().startswith("UNIT FILE"):
            continue
        if line.strip().startswith("N/A"):
            # allow as part of row parsing
            pass
        if line.strip().startswith("0 timers listed") or line.strip().startswith("No timers"):
            continue
        if line.strip().startswith("UNIT "):
            continue
        if line.strip().startswith("PASS"):
            continue
        if line.strip().startswith("--"):
            continue
        cols = re.split(r"\s{2,}", line.strip())
        if len(cols) >= min_cols:
            rows.append(cols)
    return rows


def _parse_systemctl_list_timers(output: str) -> list[dict[str, str]]:
    rows = []
    for cols in _parse_systemctl_table(output, min_cols=6):
        # NEXT, LEFT, LAST, PASSED, UNIT, ACTIVATES
        rows.append(
            {
                "next": cols[0],
                "left": cols[1],
                "last": cols[2],
                "passed": cols[3],
                "unit": cols[4],
                "activates": cols[5],
                "raw_line": "  ".join(cols),
            }
        )
    return rows


def _parse_systemctl_list_unit_files(output: str) -> list[dict[str, str]]:
    rows = []
    for cols in _parse_systemctl_table(output, min_cols=2):
        # UNIT FILE, STATE, [PRESET]
        unit_file = cols[0]
        state = cols[1] if len(cols) > 1 else ""
        preset = cols[2] if len(cols) > 2 else ""
        rows.append({"unit_file": unit_file, "state": state, "preset": preset, "raw_line": "  ".join(cols)})
    return rows


def _parse_ld_so_preload(output: str) -> list[str]:
    entries: list[str] = []
    for line in output.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        entries.append(s)
    return entries


def _auth_log_counts(output: str) -> dict[str, int]:
    lines = [ln for ln in output.splitlines() if ln.strip()]
    text = "\n".join(lines)
    # best-effort: common authlog/journalctl sshd patterns
    def count(p: str) -> int:
        return len(re.findall(p, text, flags=re.IGNORECASE))

    return {
        "failed_password_count": count(r"\bfailed password\b"),
        "invalid_user_count": count(r"\binvalid user\b"),
        "accepted_password_count": count(r"\baccepted password\b"),
        "accepted_publickey_count": count(r"\baccepted publickey\b"),
        "sudo_count": count(r"\bsudo\b"),
        "error_count": count(r"\berror\b"),
        "raw_line_count": len(lines),
    }


def _parse_colon_kv_lines(output: str) -> dict[str, str]:
    """
    Best-effort parsing for outputs like `docker info` / `podman info`.
    """
    kv: dict[str, str] = {}
    for line in output.splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k = k.strip()
        v = v.strip()
        if k:
            kv[k] = v
    return kv


_HUMAN_SIZE_RE = re.compile(r"^\s*([0-9]+(?:\.[0-9]+)?)\s*([A-Za-z]+)?\s*$")


def _human_size_to_bytes(s: str) -> Optional[int]:
    """
    Parses sizes like: 2.0Ti, 125Gi, 126Mi, 3.6T, 512M, 0B.
    Returns bytes (int) or None if unparseable.
    """
    s = (s or "").strip()
    if not s or s == "-":
        return None
    m = _HUMAN_SIZE_RE.match(s)
    if not m:
        return None
    num = float(m.group(1))
    unit = (m.group(2) or "").strip().lower()
    if unit in ("", "b"):
        return int(num)
    # Normalize common variants (treat as base-2 for our purposes)
    unit = unit.replace("ib", "i").replace("bytes", "b")
    factors = {
        "k": 1024,
        "kb": 1024,
        "ki": 1024,
        "kib": 1024,
        "m": 1024**2,
        "mb": 1024**2,
        "mi": 1024**2,
        "mib": 1024**2,
        "g": 1024**3,
        "gb": 1024**3,
        "gi": 1024**3,
        "gib": 1024**3,
        "t": 1024**4,
        "tb": 1024**4,
        "ti": 1024**4,
        "tib": 1024**4,
        "p": 1024**5,
        "pb": 1024**5,
        "pi": 1024**5,
        "pib": 1024**5,
    }
    factor = factors.get(unit)
    if factor is None:
        return None
    return int(num * factor)


def _parse_timedatectl(output: str) -> dict[str, str]:
    kv: dict[str, str] = {}
    for line in output.splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k = k.strip()
        v = v.strip()
        if k:
            kv[k] = v
    return kv


def _parse_uptime(output: str) -> tuple[Optional[str], Optional[float], Optional[float], Optional[float]]:
    raw = None
    l1 = l5 = l15 = None
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        raw = line
        if "load average:" in line:
            tail = line.split("load average:", 1)[1].strip()
            parts = [p.strip() for p in tail.split(",")]
            if len(parts) >= 3:
                try:
                    l1, l5, l15 = float(parts[0]), float(parts[1]), float(parts[2])
                except ValueError:
                    pass
        break
    return raw, l1, l5, l15


def _parse_free_h(output: str) -> dict[str, Optional[int]]:
    """
    Parses `free -h` output and returns bytes for key fields when possible.
    """
    mem = {"total": None, "used": None, "free": None, "available": None}
    swap = {"total": None, "used": None, "free": None}
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("Mem:"):
            parts = line.split()
            # Mem: total used free shared buff/cache available
            if len(parts) >= 7:
                mem["total"] = _human_size_to_bytes(parts[1])
                mem["used"] = _human_size_to_bytes(parts[2])
                mem["free"] = _human_size_to_bytes(parts[3])
                mem["available"] = _human_size_to_bytes(parts[6])
        elif line.startswith("Swap:"):
            parts = line.split()
            if len(parts) >= 4:
                swap["total"] = _human_size_to_bytes(parts[1])
                swap["used"] = _human_size_to_bytes(parts[2])
                swap["free"] = _human_size_to_bytes(parts[3])
    return {
        "mem_total_bytes": mem["total"],
        "mem_used_bytes": mem["used"],
        "mem_free_bytes": mem["free"],
        "mem_available_bytes": mem["available"],
        "swap_total_bytes": swap["total"],
        "swap_used_bytes": swap["used"],
        "swap_free_bytes": swap["free"],
    }


_LSBLK_TREE_PREFIX_RE = re.compile(r"^[\s├└│\-]+")


def _parse_lsblk_a(output: str) -> list[dict[str, object]]:
    """
    Parse lsblk -a output. Tracks tree prefix (├─, └─, etc.) to set parent_name
    for partitions and other child devices.
    """
    rows: list[dict[str, object]] = []
    parent_by_depth: list[str] = []

    for line in output.splitlines():
        line = line.rstrip("\n")
        if not line.strip():
            continue
        if line.startswith("NAME ") or "MAJ:MIN" in line:
            continue
        # Tree prefix: leading whitespace + ├─ or └─
        prefix_len = len(line) - len(line.lstrip())
        depth_level = 0
        if prefix_len > 0:
            depth_level = min(1 + (prefix_len // 2), 10)

        name_raw = line.lstrip()
        parts = name_raw.split(maxsplit=6)
        if len(parts) < 6:
            continue
        # Strip tree chars from first column to get device name (e.g. └─sda1 -> sda1)
        name = _LSBLK_TREE_PREFIX_RE.sub("", parts[0]).strip() or parts[0]
        rm = None
        ro = None
        try:
            rm = int(parts[2])
        except ValueError:
            pass
        size_bytes = _human_size_to_bytes(parts[3])
        try:
            ro = int(parts[4])
        except ValueError:
            pass
        dev_type = parts[5]
        mountpoints = parts[6] if len(parts) >= 7 else ""

        parent_name = None
        if depth_level > 0 and (depth_level - 1) < len(parent_by_depth):
            parent_name = parent_by_depth[depth_level - 1]

        while len(parent_by_depth) > depth_level:
            parent_by_depth.pop()
        if depth_level >= len(parent_by_depth):
            parent_by_depth.append(name)
        else:
            parent_by_depth[depth_level] = name

        rows.append(
            {
                "name": name,
                "type": dev_type,
                "parent_name": parent_name,
                "size_bytes": size_bytes,
                "rm": rm,
                "ro": ro,
                "mountpoints": mountpoints,
                "raw_line": line,
            }
        )
    return rows


def _parse_df_B1(output: str) -> list[dict[str, object]]:
    """
    Parse `df -B1` output. Columns: Filesystem, 1B-blocks, Used, Available, Use%, Mounted on.
    """
    rows: list[dict[str, object]] = []
    for line in output.splitlines():
        line = line.rstrip("\n")
        if not line.strip():
            continue
        if "1B-blocks" in line or "1K-blocks" in line or line.startswith("Filesystem"):
            continue
        parts = line.split(None, 5)
        if len(parts) < 6:
            continue
        try:
            size_b = int(parts[1])
            used_b = int(parts[2])
            avail_b = int(parts[3])
        except ValueError:
            size_b = used_b = avail_b = None
        use_pct = parts[4] if len(parts) > 4 else ""
        mountpoint = parts[5].strip()
        rows.append({
            "filesystem": parts[0],
            "size_bytes": size_b,
            "used_bytes": used_b,
            "avail_bytes": avail_b,
            "use_pct": use_pct,
            "mountpoint": mountpoint,
        })
    return rows


_RSYSLOG_REMOTE_RE = re.compile(
    r"[*.]+\s+(@@?\[[^\]]+\](?::\d+)?|@@?[^\s#]+)"
)


def _parse_rsyslog_remote_destinations(output: str) -> list[str]:
    """
    Extract remote log destinations from rsyslog.conf.
    *.* @host (UDP), *.* @@host (TCP), *.* @[host]:port, etc.
    """
    dests: list[str] = []
    for line in output.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        for m in _RSYSLOG_REMOTE_RE.finditer(s):
            dests.append(m.group(1).strip())
    return list(dict.fromkeys(dests))  # dedupe, preserve order


def _parse_ntp_conf(output: str) -> list[dict[str, object]]:
    """
    Extract NTP server entries from /etc/ntp.conf.
    Lines: server host [options] or pool host [options]
    """
    servers: list[dict[str, object]] = []
    for line in output.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        parts = s.split()
        if len(parts) < 2:
            continue
        if parts[0] in ("server", "pool"):
            server_addr = parts[1]
            options = " ".join(parts[2:]) if len(parts) > 2 else None
            is_pool = parts[0] == "pool"
            servers.append({
                "server_type": "ntp",
                "server_address": server_addr,
                "options": options,
                "pool": is_pool,
            })
    return servers


def _parse_chrony_conf(output: str) -> list[dict[str, object]]:
    """
    Extract Chrony server entries from /etc/chrony.conf or /etc/chrony/chrony.conf.
    Lines: server host [options] or pool host [options]
    """
    servers: list[dict[str, object]] = []
    for line in output.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        parts = s.split()
        if len(parts) < 2:
            continue
        if parts[0] in ("server", "pool"):
            server_addr = parts[1]
            options = " ".join(parts[2:]) if len(parts) > 2 else None
            is_pool = parts[0] == "pool"
            servers.append({
                "server_type": "chrony",
                "server_address": server_addr,
                "options": options,
                "pool": is_pool,
            })
    return servers


def _parse_timesyncd_conf(output: str) -> list[dict[str, object]]:
    """
    Extract timesyncd NTP servers from /etc/systemd/timesyncd.conf.
    Lines: NTP=host1 host2 ... or FallbackNTP=host1 host2 ...
    """
    servers: list[dict[str, object]] = []
    for line in output.splitlines():
        s = line.strip()
        if not s or s.startswith("#") or s.startswith("["):
            continue
        if "=" not in s:
            continue
        key, _, value = s.partition("=")
        key = key.strip()
        value = value.strip()
        if key in ("NTP", "FallbackNTP"):
            for addr in value.split():
                addr = addr.strip()
                if addr:
                    servers.append({
                        "server_type": "timesyncd",
                        "server_address": addr,
                        "options": None,
                        "pool": False,
                    })
    return servers


def _parse_journald_remote(output: str) -> dict[str, str]:
    """
    Extract [Journal] ForwardToSyslog, ForwardToWall, etc. and remote-related keys.
    Handles both active and commented (#Key=value) lines so defaults are captured.
    """
    kv: dict[str, str] = {}
    in_journal = False
    for line in output.splitlines():
        s = line.strip()
        if not s:
            continue
        # Allow commented lines; strip leading # and whitespace for key=value
        if s.startswith("#"):
            s = s.lstrip("#").strip()
            if not s or "=" not in s:
                continue
        if s == "[Journal]":
            in_journal = True
            continue
        if s.startswith("[") and s != "[Journal]":
            in_journal = False
            continue
        if "=" not in s:
            continue
        k, v = s.split("=", 1)
        k, v = k.strip(), v.strip()
        if not k:
            continue
        if in_journal and (
            "Forward" in k or "Remote" in k or "Syslog" in k or "Audit" in k
        ):
            kv[k] = v
    return kv


def _parse_login_defs_kv(output: str) -> dict[str, str]:
    """
    Parse /etc/login.defs KEY value pairs. Skips # and empty lines.
    """
    kv: dict[str, str] = {}
    for line in output.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        parts = s.split(None, 1)
        if not parts:
            continue
        k = parts[0]
        v = parts[1] if len(parts) > 1 else ""
        if k:
            kv[k] = v
    return kv


# Placeholder values that some vendors (e.g. ASUS) put in DMI when field is not populated
_DMI_PLACEHOLDER_VALUES = frozenset([
    "to be filled by o.e.m.",
    "to be filled by oem",
    "o.e.m.",
    "oem",
    "default string",
    "system product name",
    "system serial number",
    "system manufacturer",
    "system version",
    "base board product",
    "chassis serial number",
    "not specified",
    "none",
    "n/a",
    "",
])


def _normalize_dmi_value(k: str, v: str) -> Optional[str]:
    """Return None if value is placeholder or same as key (e.g. ASUS 'Product Name: Product Name')."""
    if not v or not v.strip():
        return None
    v = v.strip()
    k_lower = k.strip().lower()
    v_lower = v.lower()
    # Value same as key (common when BIOS doesn't populate)
    if v_lower == k_lower:
        return None
    # Known placeholder strings
    if v_lower in _DMI_PLACEHOLDER_VALUES:
        return None
    # "To be filled by O.E.M." style
    if "to be filled" in v_lower and "o.e.m" in v_lower:
        return None
    return v


def _parse_dmidecode_system(output: str) -> dict[str, str]:
    """
    Extracts key identity fields from the first "System Information" (DMI type 1) section.
    Skips placeholder values and "key: key" patterns used by some vendors (e.g. ASUS).
    """
    kv: dict[str, str] = {}
    in_sys = False
    for line in output.splitlines():
        # Start of a new handle block - stop after first System Information block
        if line.startswith("Handle "):
            if in_sys:
                break
            continue
        if line.strip() == "System Information":
            in_sys = True
            continue
        if not in_sys:
            continue
        # dmidecode uses leading tabs for fields
        if ":" in line:
            k, v = line.split(":", 1)
            k = k.strip()
            v = v.strip()
            if not k:
                continue
            normalized = _normalize_dmi_value(k, v)
            if normalized is not None:
                kv[k] = normalized
    return kv


_LSPCI_FIRSTLINE_RE = re.compile(r"^(?P<slot>\S+)\s+(?P<class>[^:]+):\s+(?P<desc>.*)$")


def _parse_lspci_v_gpus(output: str) -> list[dict[str, Optional[str]]]:
    """
    Extract GPU-ish devices (VGA/3D/Display controllers) from `lspci -v` blocks.
    """
    blocks: list[str] = []
    buf: list[str] = []
    for line in output.splitlines():
        if not line.strip():
            if buf:
                blocks.append("\n".join(buf))
                buf = []
            continue
        buf.append(line.rstrip())
    if buf:
        blocks.append("\n".join(buf))

    out: list[dict[str, Optional[str]]] = []
    for b in blocks:
        lines = b.splitlines()
        if not lines:
            continue
        m = _LSPCI_FIRSTLINE_RE.match(lines[0])
        if not m:
            continue
        cls = (m.group("class") or "").strip()
        if not any(k in cls for k in ("VGA", "3D", "Display")):
            continue
        slot = m.group("slot")
        desc = m.group("desc")
        kdrv = None
        for ln in lines[1:]:
            if "Kernel driver in use:" in ln:
                kdrv = ln.split("Kernel driver in use:", 1)[1].strip()
                break
        vendor = None
        if desc.startswith("NVIDIA Corporation"):
            vendor = "NVIDIA Corporation"
        elif desc.startswith("Intel Corporation"):
            vendor = "Intel Corporation"
        elif desc.startswith("Advanced Micro Devices"):
            vendor = "Advanced Micro Devices"
        out.append(
            {
                "slot": slot,
                "class": cls,
                "description": f"{cls}: {desc}",
                "vendor": vendor,
                "device": desc,
                "kernel_driver_in_use": kdrv,
                "raw_block": b,
            }
        )
    return out


_LSHW_NODE_RE = re.compile(r"^\s*\*-(\w+)(?::(\S+))?\s*$")


def _parse_lshw(output: str) -> list[dict[str, object]]:
    """
    Parse `lshw -disable dmi` tree output into one dict per device node.
    Each line is either "  *-class" / "  *-class:logical" (node) or "    key: value" (property).
    """
    rows: list[dict[str, object]] = []
    depth = 0
    class_name = ""
    logical_name: Optional[str] = None
    props: dict[str, str] = {}

    def flush() -> None:
        nonlocal props
        if not class_name:
            return
        size = props.get("size")
        capacity = props.get("capacity")
        width_bits = None
        clock_hz = None
        if size:
            m = re.match(r"^(\d+)\s*[KMGTP]i?B$", size.strip(), re.IGNORECASE)
            if m:
                pass  # keep as text
        if capacity and re.match(r"^\d+\s*[KMG]?Hz", capacity, re.IGNORECASE):
            try:
                clock_hz = int(re.sub(r"\s*[KMG]?Hz.*", "", capacity).replace(" ", ""))
                if "GHz" in capacity.upper():
                    clock_hz *= 1_000_000_000
                elif "MHz" in capacity.upper():
                    clock_hz *= 1_000_000
            except ValueError:
                pass
        width_str = props.get("width")
        if width_str:
            try:
                width_bits = int(re.sub(r"\D", "", width_str))
            except ValueError:
                pass
        rows.append({
            "depth": depth,
            "class": class_name,
            "logical_name": logical_name or None,
            "description": props.get("description") or None,
            "product": props.get("product") or None,
            "vendor": props.get("vendor") or None,
            "physical_id": props.get("physical id") or None,
            "bus_info": props.get("bus info") or None,
            "slot": props.get("slot") or None,
            "size": props.get("size") or None,
            "capacity": props.get("capacity") or None,
            "serial": props.get("serial") or None,
            "version": props.get("version") or None,
            "width_bits": width_bits,
            "clock_hz": clock_hz,
            "raw_line": f"*-{class_name}" + (f":{logical_name}" if logical_name else ""),
        })
        props = {}

    for line in output.splitlines():
        stripped = line.rstrip()
        if not stripped:
            continue
        indent = len(line) - len(line.lstrip())
        d = indent // 2
        m = _LSHW_NODE_RE.match(line)
        if m:
            flush()
            depth = d
            class_name = m.group(1) or ""
            logical_name = m.group(2) if m.group(2) else None
            props = {}
            continue
        if ":" in stripped and class_name:
            k, _, v = stripped.strip().partition(":")
            k = k.strip()
            v = v.strip()
            if k:
                props[k] = v
    flush()
    return rows


def _parse_getent_group(output: str) -> list[tuple[str, Optional[int], str]]:
    """
    getent group output is usually groupname:passwd:gid:members
    """
    rows: list[tuple[str, Optional[int], str]] = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) != 4:
            continue
        groupname = parts[0]
        gid = None
        try:
            gid = int(parts[2])
        except ValueError:
            gid = None
        members = parts[3] or ""
        rows.append((groupname, gid, members))
    return rows


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="replace")).hexdigest()


def _authorized_key_fingerprint_sha256(key_type: str, key_b64: str) -> Optional[str]:
    """
    Produces a stable SHA256 fingerprint hex of the decoded key blob.
    (Not the OpenSSH 'SHA256:...' string; hex is easier for DB joins.)
    """
    try:
        blob = base64.b64decode(key_b64.encode("ascii"), validate=True)
    except Exception:
        return None
    return hashlib.sha256(blob).hexdigest()


def _parse_authorized_keys_block(lines: list[str], username: str) -> list[tuple[str, str, str, Optional[str], str]]:
    """
    Returns rows: (username, key_type, fingerprint_sha256, comment, raw_line_hash_sha256)
    """
    out = []
    for ln in lines:
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        parts = ln.split()
        if len(parts) < 2:
            continue
        key_type, key_b64 = parts[0], parts[1]
        comment = " ".join(parts[2:]) if len(parts) > 2 else None
        fpr = _authorized_key_fingerprint_sha256(key_type, key_b64)
        if not fpr:
            # Fallback: hash the raw line (still useful for change detection)
            fpr = _sha256_hex(ln)
        out.append((username, key_type, fpr, comment, _sha256_hex(ln)))
    return out


def _parse_home_authorized_keys(output: str) -> list[tuple[str, str, str, Optional[str], str]]:
    """
    Parses the loop output:
      # cat /home/<user>/.ssh/authorized_keys
      <keys...>
    """
    results: list[tuple[str, str, str, Optional[str], str]] = []
    current_user: Optional[str] = None
    buf: list[str] = []

    def flush() -> None:
        nonlocal buf, current_user
        if current_user is not None and buf:
            results.extend(_parse_authorized_keys_block(buf, current_user))
        buf = []

    for ln in output.splitlines():
        ln = ln.rstrip()
        if ln.startswith("# cat /home/") and ln.endswith("/.ssh/authorized_keys"):
            flush()
            # extract user between /home/ and /.ssh/authorized_keys
            mid = ln[len("# cat /home/") :]
            current_user = mid.split("/", 1)[0]
            continue
        if ln.startswith("# cat /root/") and ln.endswith("/authorized_keys"):
            flush()
            current_user = "root"
            continue
        if current_user is not None:
            buf.append(ln)
    flush()
    return results


def _parse_who_a(output: str) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    line_no = 0
    for ln in output.splitlines():
        line_no += 1
        raw = ln.rstrip()
        if not raw.strip():
            continue
        record_type = "other"
        username = None
        tty = None
        event_time = None
        pid = None
        remote = None

        if "system boot" in raw:
            record_type = "system_boot"
        elif "run-level" in raw:
            record_type = "run_level"
        elif raw.lstrip().startswith("LOGIN"):
            record_type = "login"
        else:
            # likely a user session line
            toks = raw.split()
            if toks:
                username = toks[0] if toks[0] not in ("system", "run-level", "LOGIN") else None
            if len(toks) >= 2 and toks[1] != "+":
                tty = toks[1]
            # look for remote host in parentheses
            m = re.search(r"\(([^)]+)\)", raw)
            if m:
                remote = m.group(1)
            # look for pid=... pattern
            m2 = re.search(r"\bpid=(\d+)\b", raw)
            if m2:
                try:
                    pid = int(m2.group(1))
                except ValueError:
                    pid = None
            # crude time extraction: YYYY-MM-DD HH:MM or similar
            m3 = re.search(r"\b(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2})\b", raw)
            if m3:
                event_time = m3.group(1)
            else:
                m4 = re.search(r"\b(\d{2}:\d{2})\b", raw)
                if m4:
                    event_time = m4.group(1)
            record_type = "user" if username else record_type

        rows.append(
            {
                "line_no": line_no,
                "record_type": record_type,
                "username": username,
                "tty": tty,
                "event_time": event_time,
                "pid": pid,
                "remote_host": remote,
                "raw_line": raw,
            }
        )
    return rows


def _parse_w(output: str) -> list[dict[str, Optional[str]]]:
    rows: list[dict[str, Optional[str]]] = []
    lines = [ln.rstrip() for ln in output.splitlines() if ln.strip()]
    header_idx = None
    for i, ln in enumerate(lines):
        if ln.strip().startswith("USER") and "TTY" in ln and "FROM" in ln:
            header_idx = i
            break
    if header_idx is None:
        return rows
    for ln in lines[header_idx + 1 :]:
        if ln.strip().startswith("USER"):
            continue
        parts = ln.split(maxsplit=7)
        if len(parts) < 3:
            continue
        username = parts[0] if len(parts) > 0 else None
        tty = parts[1] if len(parts) > 1 else None
        from_host = parts[2] if len(parts) > 2 else None
        login_at = parts[3] if len(parts) > 3 else None
        idle = parts[4] if len(parts) > 4 else None
        jcpu = parts[5] if len(parts) > 5 else None
        pcpu = parts[6] if len(parts) > 6 else None
        what = parts[7] if len(parts) > 7 else None
        rows.append(
            {
                "username": username,
                "tty": tty,
                "from_host": from_host,
                "login_at": login_at,
                "idle": idle,
                "jcpu": jcpu,
                "pcpu": pcpu,
                "what": what,
                "raw_line": ln,
            }
        )
    return rows


def _parse_lastlog(output: str) -> list[dict[str, Optional[str]]]:
    rows: list[dict[str, Optional[str]]] = []
    for ln in output.splitlines():
        raw = ln.rstrip()
        if not raw.strip():
            continue
        if raw.lower().startswith("username"):
            continue
        parts = raw.split(None, 3)
        if len(parts) < 1:
            continue
        username = parts[0]
        port = parts[1] if len(parts) > 1 else None
        from_host = parts[2] if len(parts) > 2 else None
        latest = parts[3] if len(parts) > 3 else None
        rows.append({"username": username, "port": port, "from_host": from_host, "latest": latest, "raw_line": raw})
    return rows


def _parse_last(output: str, source: str) -> list[dict[str, Optional[str]]]:
    rows: list[dict[str, Optional[str]]] = []
    for ln in output.splitlines():
        raw = ln.rstrip()
        if not raw.strip():
            continue
        if raw.startswith("wtmp begins") or raw.startswith("btmp begins") or raw.startswith("utmp begins"):
            continue
        parts = raw.split(None, 3)
        if len(parts) < 3:
            continue
        username = parts[0]
        tty = parts[1]
        remote = parts[2]
        rest = parts[3] if len(parts) > 3 else ""
        start_text = None
        end_text = None
        duration_text = None
        status_text = None

        if "still logged in" in rest:
            status_text = "still_logged_in"
            start_text = rest.replace("still logged in", "").strip()
        elif "gone - no logout" in rest:
            status_text = "gone_no_logout"
            start_text = rest.replace("gone - no logout", "").strip()
        else:
            # typical: "<start> - <end>  (<dur>)"
            if " - " in rest:
                left, right = rest.split(" - ", 1)
                start_text = left.strip()
                # duration in parentheses at end
                m = re.search(r"\(([^)]+)\)\s*$", right)
                if m:
                    duration_text = m.group(1).strip()
                    right = right[: m.start()].strip()
                end_text = right.strip()
            else:
                start_text = rest.strip()

        rows.append(
            {
                "source": source,
                "username": username,
                "tty": tty,
                "remote_host": remote,
                "start_text": start_text,
                "end_text": end_text,
                "duration_text": duration_text,
                "status_text": status_text,
                "raw_line": raw,
            }
        )
    return rows


def normalize_timestamp_with_timezone(text: str, timezone_str: Optional[str], collected_at: str) -> Optional[str]:
    """
    Normalize timestamp to UTC using system timezone from timedatectl.
    Falls back to normalize_timestamp_to_utc if timezone not available.
    """
    if not text or not text.strip():
        return None
    
    # First try with timezone-aware parsing
    if timezone_str:
        try:
            import zoneinfo
            tz = zoneinfo.ZoneInfo(timezone_str)
            # Try parsing the timestamp and converting to UTC
            parsed = None
            # Try common formats
            for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%b %d %H:%M:%S", "%b %d %H:%M"]:
                try:
                    if "%b" in fmt:
                        # Need year
                        reference_year = dt.datetime.fromisoformat(collected_at.replace('Z', '+00:00')).year
                        parsed = dt.datetime.strptime(f"{reference_year} {text.strip()}", f"%Y {fmt}")
                    else:
                        parsed = dt.datetime.strptime(text.strip(), fmt)
                    break
                except ValueError:
                    continue
            
            if parsed:
                # Localize to system timezone, then convert to UTC
                parsed = tz.localize(parsed.replace(tzinfo=None))
                return parsed.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            # Fall through to fallback
            pass
    
    # Fallback to original normalization
    return normalize_timestamp_to_utc(text, collected_at)


def normalize_timestamp_to_utc(text: str, collected_at: str) -> Optional[str]:
    """
    Attempt to normalize various timestamp formats to ISO UTC.
    text: timestamp string from logon data
    collected_at: ISO UTC timestamp when baseline was collected
    Returns ISO UTC string or None if parsing fails.
    """
    if not text or not text.strip():
        return None

    text = text.strip()

    # Parse collected_at to get reference year/month
    try:
        collected_dt = dt.datetime.fromisoformat(collected_at.replace('Z', '+00:00'))
        reference_year = collected_dt.year
        reference_month = collected_dt.month
    except:
        reference_year = dt.datetime.now().year
        reference_month = dt.datetime.now().month

    # Try various common formats (ordered by specificity)
    formats = [
        ("%Y-%m-%d %H:%M:%S", None),      # 2024-01-15 14:30:45
        ("%Y-%m-%d %H:%M", None),          # 2024-01-15 14:30
        ("%Y-%m-%dT%H:%M:%S", None),       # ISO format without TZ
        ("%Y-%m-%dT%H:%M:%SZ", None),      # ISO format with Z
        ("%Y-%m-%dT%H:%M:%S%z", None),     # ISO format with TZ offset
        ("%a %b %d %H:%M:%S %Y", None),    # Mon Jan 15 14:30:45 2024
        ("%a %b %d %H:%M %Y", None),       # Mon Jan 15 14:30 2024
        ("%b %d %H:%M:%S %Y", None),       # Jan 15 14:30:45 2024
        ("%b %d %H:%M %Y", None),          # Jan 15 14:30 2024
        ("%m/%d/%Y %H:%M:%S", None),       # 01/15/2024 14:30:45
        ("%m/%d/%Y %H:%M", None),          # 01/15/2024 14:30
        ("%m/%d/%y %H:%M:%S", None),       # 01/15/24 14:30:45
        ("%m/%d/%y %H:%M", None),          # 01/15/24 14:30
        ("%d/%m/%Y %H:%M:%S", None),       # 15/01/2024 14:30:45 (DD/MM/YYYY)
        ("%d/%m/%Y %H:%M", None),          # 15/01/2024 14:30
        ("%d-%m-%Y %H:%M:%S", None),       # 15-01-2024 14:30:45
        ("%d-%m-%Y %H:%M", None),          # 15-01-2024 14:30
        ("%a %b %d %H:%M:%S", reference_year),  # Mon Jan 15 14:30:45 (assume current year)
        ("%a %b %d %H:%M", reference_year),     # Mon Jan 15 14:30 (assume current year)
        ("%b %d %H:%M:%S", reference_year),     # Jan 15 14:30:45 (assume current year)
        ("%b %d %H:%M", reference_year),        # Jan 15 14:30 (assume current year)
    ]

    for fmt, year_override in formats:
        try:
            if year_override:
                # Format needs year prepended
                parsed = dt.datetime.strptime(f"{year_override} {text}", f"%Y {fmt}")
            else:
                parsed = dt.datetime.strptime(text, fmt)

            # If parsed year is in future relative to collection, assume it's from previous year
            if parsed.year > reference_year:
                parsed = parsed.replace(year=reference_year - 1)
            # If parsed date is more than 6 months in the future relative to collection month,
            # assume it's from previous year (handles year boundary cases)
            elif parsed.year == reference_year:
                month_diff = parsed.month - reference_month
                if month_diff > 6:
                    parsed = parsed.replace(year=reference_year - 1)
                elif month_diff < -6:
                    # More than 6 months in past - might be from next year (unlikely but handle)
                    pass

            # If format already has timezone info, preserve it; otherwise assume UTC
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=dt.timezone.utc)
            else:
                # Convert to UTC if timezone-aware
                parsed = parsed.astimezone(dt.timezone.utc)

            return parsed.strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            continue

    return None  # Could not parse


def extract_failed_login_events(last_events: list[dict]) -> list[dict]:
    """
    Extract and enhance failed login events from btmp data.
    """
    failed_events = []

    for event in last_events:
        if event.get('source') != 'btmp':
            continue

        username = event.get('username', '')
        remote_host = event.get('remote_host', '')
        start_text = event.get('start_text', '')

        # Skip entries that don't look like failed logins
        if username in ('', 'reboot', 'shutdown') or remote_host == ':0':
            continue

        # Normalize timestamp
        normalized_time = normalize_timestamp_to_utc(start_text, '')  # TODO: pass collected_at

        failed_events.append({
            'username': username,
            'remote_host': remote_host,
            'tty': event.get('tty', ''),
            'state_text': event.get('status_text'),
            'attempt_time': normalized_time,
            'raw_start_text': start_text,
            'raw_line': event.get('raw_line', ''),
        })

    return failed_events


def _parse_auditctl_s(output: str) -> dict[str, str]:
    kv: dict[str, str] = {}
    for ln in output.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        parts = ln.split(None, 1)
        if len(parts) == 2:
            kv[parts[0]] = parts[1].strip()
    return kv


def _parse_auditctl_l(output: str) -> list[dict[str, Optional[str]]]:
    rows: list[dict[str, Optional[str]]] = []
    for ln in output.splitlines():
        rule = ln.strip()
        if not rule or rule.startswith("No rules"):
            continue

        # Enhanced parsing for audit rules
        parsed = _parse_audit_rule_detailed(rule)
        parsed["rule_text"] = rule
        rows.append(parsed)
    return rows


def _parse_audit_rule_detailed(rule_text: str) -> dict[str, Optional[str]]:
    """
    Parse audit rule into detailed components for better analysis.
    """
    result = {
        "action": None,
        "list_type": None,
        "arch": None,
        "key_name": None,
        "syscall": None,
        "path": None,
        "permission": None,
        "uid": None,
        "gid": None,
        "auid": None,
        "subj": None,  # SELinux subject
        "rule_type": None,  # syscall, file, user, etc.
    }

    # Extract key name (-k or key=)
    m = re.search(r"(?:-k\s+(\S+))|(?:\bkey=(\S+))", rule_text)
    if m:
        result["key_name"] = m.group(1) or m.group(2)

    # Extract action and list (-a always,exit or -A always,exit)
    m2 = re.search(r"-[aA]\s+([^,]+),([^\s]+)", rule_text)
    if m2:
        result["action"] = m2.group(1)
        result["list_type"] = m2.group(2)

    # Extract architecture
    m3 = re.search(r"\barch=([a-zA-Z0-9_]+)\b", rule_text)
    if m3:
        result["arch"] = m3.group(1)

    # Extract syscall number/name
    m4 = re.search(r"\b(?:syscall|syscall_r)=([^\s]+)", rule_text)
    if m4:
        result["syscall"] = m4.group(1)
        result["rule_type"] = "syscall"

    # Extract file path
    m5 = re.search(r"(?:-F\s+path=|path=)([^\s]+)", rule_text)
    if m5:
        result["path"] = m5.group(1)
        result["rule_type"] = "file"

    # Extract permissions
    m6 = re.search(r"\bperm=([rwx]+)\b", rule_text)
    if m6:
        result["permission"] = m6.group(1)

    # Extract UIDs/GIDs: audit rules use -F auid=, -F auid>=, -F auid!=, -F uid=, -F euid=, -F gid=, -F egid=
    # Capture operator+value (e.g. ">=1000", "!=-1", "=0") so stored value is meaningful
    def _capture_id_filter(prefix: str, text: str) -> Optional[str]:
        # Match prefix followed by optional comparison (=, !=, >=, <=, >, <) and value
        m = re.search(rf"\b{prefix}([<>=!]*=)([^\s]+)", text)
        if m:
            op, val = m.group(1), m.group(2)
            return f"{op}{val}" if op != "=" else val
        return None

    result["auid"] = _capture_id_filter("auid", rule_text)
    # uid= (standalone, not auid/euid); then fallback to euid= for uid column if schema supports it
    result["uid"] = _capture_id_filter("uid", rule_text)
    if not result["uid"]:
        result["uid"] = _capture_id_filter("euid", rule_text)
    result["gid"] = _capture_id_filter("gid", rule_text)
    if not result["gid"]:
        result["gid"] = _capture_id_filter("egid", rule_text)

    # Extract SELinux subject (subj= value can be single token or quoted)
    m8 = re.search(r'\bsubj=("([^"]*)"|([^\s\-][^\s]*))', rule_text)
    if m8:
        result["subj"] = (m8.group(2) or m8.group(3) or "").strip()
    if not result["subj"]:
        m8b = re.search(r"\bsubj=([^\s]+)", rule_text)
        if m8b:
            result["subj"] = m8b.group(1)

    # Determine rule type if not set
    if not result["rule_type"]:
        if result["path"]:
            result["rule_type"] = "file"
        elif result["syscall"]:
            result["rule_type"] = "syscall"
        elif result["auid"] or result["uid"]:
            result["rule_type"] = "user"
        else:
            result["rule_type"] = "other"

    return result


def derive_audit_posture_flags(audit_status: dict[str, str], audit_rules: list[dict]) -> dict[str, bool]:
    """
    Derive security posture flags from audit status and rules.
    """
    flags = {
        "audit_enabled": False,
        "audit_immutable": False,
        "has_critical_auth_rules": False,
        "has_critical_file_rules": False,
        "has_critical_process_rules": False,
        "has_time_change_rules": False,
        "has_sudo_rules": False,
        "has_passwd_rules": False,
        "has_executable_rules": False,
    }

    # Check audit status
    if audit_status.get("enabled", "").lower() == "1":
        flags["audit_enabled"] = True

    if audit_status.get("immutable", "").lower() == "1":
        flags["audit_immutable"] = True

    # Check rules for critical areas
    critical_auth_syscalls = {"execve", "clone", "fork", "vfork"}
    critical_file_paths = {"/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/sudoers.d"}
    critical_process_patterns = {"/bin/su", "/usr/bin/sudo", "/bin/su"}
    time_change_syscalls = {"settimeofday", "stime", "clock_settime"}
    sudo_paths = {"/usr/bin/sudo"}
    passwd_paths = {"/etc/passwd", "/etc/shadow", "/usr/bin/passwd"}
    executable_patterns = {"/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/"}

    for rule in audit_rules:
        if not rule:  # Skip None or empty rules
            continue

        syscall = (rule.get("syscall") or "").lower()
        path = (rule.get("path") or "")
        key = (rule.get("key_name") or "").lower()

        # Auth-related rules
        if (syscall in critical_auth_syscalls or
            key in {"auth", "authentication", "login", "session"} or
            any(p in path for p in critical_process_patterns)):
            flags["has_critical_auth_rules"] = True

        # File integrity rules
        if any(critical_path in path for critical_path in critical_file_paths) or key in {"file_integrity", "config_change"}:
            flags["has_critical_file_rules"] = True

        # Process monitoring rules
        if (syscall in {"execve", "clone", "fork"} or
            key in {"process", "execution", "binary"} or
            any(p in path for p in executable_patterns)):
            flags["has_critical_process_rules"] = True

        # Time change rules
        if syscall in time_change_syscalls or key in {"time", "clock"}:
            flags["has_time_change_rules"] = True

        # Sudo rules
        if any(sudo_path in path for sudo_path in sudo_paths) or key == "sudo":
            flags["has_sudo_rules"] = True

        # Password rules
        if any(passwd_path in path for passwd_path in passwd_paths) or key in {"passwd", "password"}:
            flags["has_passwd_rules"] = True

        # Executable monitoring
        if rule.get("rule_type") == "file" and any(pattern in path for pattern in executable_patterns):
            flags["has_executable_rules"] = True

    return flags


def _parse_sestatus(output: str) -> dict[str, str]:
    kv: dict[str, str] = {}
    for ln in output.splitlines():
        if ":" not in ln:
            continue
        k, v = ln.split(":", 1)
        k = k.strip()
        v = v.strip()
        if k:
            kv[k] = v
    return kv


def _parse_getsebool_a(output: str) -> dict[str, str]:
    kv: dict[str, str] = {}
    for ln in output.splitlines():
        ln = ln.strip()
        if not ln or "-->" not in ln:
            continue
        left, right = ln.split("-->", 1)
        name = left.strip()
        state = right.strip().split()[0].lower()
        if name:
            kv[name] = state
    return kv


def _parse_aa_status(output: str) -> dict[str, Optional[int] | str]:
    raw = output.strip()
    out: dict[str, Optional[int] | str] = {"raw_text": raw}
    def grab(pat: str) -> Optional[int]:
        m = re.search(pat, raw, flags=re.IGNORECASE)
        if not m:
            return None
        try:
            return int(m.group(1))
        except ValueError:
            return None
    out["profiles_loaded"] = grab(r"(\d+)\s+profiles are loaded")
    out["profiles_enforce"] = grab(r"(\d+)\s+profiles are in enforce mode")
    out["profiles_complain"] = grab(r"(\d+)\s+profiles are in complain mode")
    out["processes_enforce"] = grab(r"(\d+)\s+processes have profiles defined")
    out["processes_complain"] = grab(r"(\d+)\s+processes are in enforce mode")
    return out


def derive_selinux_posture(selinux_status: dict[str, str], selinux_booleans: dict[str, str]) -> dict[str, bool]:
    """
    Derive SELinux security posture flags and high-risk boolean states.
    """
    posture = {
        "selinux_enabled": False,
        "selinux_enforcing": False,
        "selinux_permissive": False,
        "selinux_disabled": False,
        "high_risk_booleans_on": [],
        "high_risk_booleans_off": [],
    }

    # Parse SELinux status
    status = selinux_status.get("SELinux status", "").lower()
    mode = selinux_status.get("Current mode", "").lower()

    if status == "enabled":
        posture["selinux_enabled"] = True
        if mode == "enforcing":
            posture["selinux_enforcing"] = True
        elif mode == "permissive":
            posture["selinux_permissive"] = True
    else:
        posture["selinux_disabled"] = True

    # High-risk SELinux booleans (these reduce security when enabled)
    high_risk_booleans = {
        "allow_execheap": "Allows processes to make heap memory executable",
        "allow_execmem": "Allows processes to make memory executable",
        "allow_execstack": "Allows processes to make stack memory executable",
        "allow_ptrace_all_unconfined": "Allows unconfined processes to ptrace all other processes",
        "deny_execmem": "When off, allows executable memory allocations",
        "deny_ptrace": "When off, allows ptracing of all processes",
        "secure_mode_insmod": "When off, allows loading of kernel modules without restrictions",
        "ssh_sysadm_login": "When on, allows SSH logins as sysadm role",
    }

    for bool_name, state in selinux_booleans.items():
        if bool_name in high_risk_booleans:
            if state == "on":
                posture["high_risk_booleans_on"].append(bool_name)
            else:
                posture["high_risk_booleans_off"].append(bool_name)

    return posture


def derive_apparmor_posture(apparmor_status: dict[str, Optional[int] | str]) -> dict[str, bool]:
    """
    Derive AppArmor security posture flags.
    """
    posture = {
        "apparmor_enabled": False,
        "apparmor_profiles_loaded": False,
        "apparmor_all_enforcing": False,
        "apparmor_mixed_mode": False,
        "apparmor_processes_unconfined": False,
    }

    profiles_loaded = apparmor_status.get("profiles_loaded", 0) or 0
    profiles_enforce = apparmor_status.get("profiles_enforce", 0) or 0
    profiles_complain = apparmor_status.get("profiles_complain", 0) or 0
    processes_enforce = apparmor_status.get("processes_enforce", 0) or 0

    if profiles_loaded > 0:
        posture["apparmor_enabled"] = True
        posture["apparmor_profiles_loaded"] = True

        if profiles_complain == 0 and profiles_loaded == profiles_enforce:
            posture["apparmor_all_enforcing"] = True
        elif profiles_complain > 0:
            posture["apparmor_mixed_mode"] = True

    # Check if processes are running without profiles (unconfined)
    # This is a rough heuristic - if we have loaded profiles but fewer enforced processes
    if profiles_loaded > 0 and processes_enforce == 0:
        posture["apparmor_processes_unconfined"] = True

    return posture


def _parse_resolv_conf(output: str) -> list[dict[str, str]]:
    rows = []
    for ln in output.splitlines():
        raw = ln.rstrip()
        s = raw.strip()
        if not s or s.startswith("#") or s.startswith(";"):
            continue
        parts = s.split(None, 1)
        if not parts:
            continue
        etype = parts[0].lower()
        val = parts[1].strip() if len(parts) > 1 else ""
        if etype not in ("nameserver", "search", "options"):
            etype = "other"
        rows.append({"entry_type": etype, "entry_value": val, "raw_line": raw})
    return rows


def _parse_ip_neigh(output: str) -> list[dict[str, Optional[str]]]:
    rows = []
    for ln in output.splitlines():
        raw = ln.rstrip()
        if not raw.strip():
            continue
        toks = raw.split()
        ip = toks[0] if toks else None
        dev = None
        lladdr = None
        state = toks[-1] if toks else None
        if "dev" in toks:
            try:
                dev = toks[toks.index("dev") + 1]
            except Exception:
                dev = None
        if "lladdr" in toks:
            try:
                lladdr = toks[toks.index("lladdr") + 1]
            except Exception:
                lladdr = None
        family = "inet6" if (ip and ":" in ip) else "inet"
        ip_type = _classify_addr_type(family, ip or "") if ip else None
        rows.append({"ip": ip, "dev": dev, "lladdr": lladdr, "state": state, "ip_type": ip_type, "raw_line": raw})
    return rows


def _parse_route_n(output: str) -> list[dict[str, Optional[str] | int]]:
    rows = []
    lines = [ln.rstrip() for ln in output.splitlines() if ln.strip()]
    start = 0
    for i, ln in enumerate(lines):
        if ln.strip().startswith("Destination") and "Gateway" in ln and "Iface" in ln:
            start = i + 1
            break
    for ln in lines[start:]:
        parts = ln.split()
        if len(parts) < 8:
            continue
        def to_int(x: str) -> Optional[int]:
            try:
                return int(x)
            except ValueError:
                return None
        rows.append(
            {
                "destination": parts[0],
                "gateway": parts[1],
                "genmask": parts[2],
                "flags": parts[3],
                "metric": to_int(parts[4]),
                "ref": to_int(parts[5]),
                "use": to_int(parts[6]),
                "iface": parts[7],
                "raw_line": ln,
            }
        )
    return rows


def derive_network_posture(resolv_entries: list[dict], routes: list[dict], neigh_entries: list[dict]) -> dict[str, object]:
    """
    Derive network security posture insights from DNS, routing, and neighbor data.
    """
    posture = {
        "unexpected_nameservers": [],
        "multiple_default_routes": False,
        "suspicious_routes": [],
        "unknown_mac_ouis": [],
        "nameserver_flags": [],
    }

    # Analyze nameservers for unexpected/public IPs
    nameservers = [entry for entry in resolv_entries if entry["entry_type"] == "nameserver"]
    for ns in nameservers:
        ip = ns["entry_value"]
        if not ip:
            continue

        # Check if it's a public IP (not RFC 1918 private, not localhost)
        try:
            import ipaddress
            addr = ipaddress.ip_address(ip)
            if addr.is_global and not addr.is_private:
                posture["unexpected_nameservers"].append(ip)
                posture["nameserver_flags"].append(f"Public nameserver: {ip}")
            elif addr.is_loopback:
                posture["nameserver_flags"].append(f"Localhost nameserver: {ip}")
        except ValueError:
            # Not a valid IP, might be a hostname
            if not any(domain in ip.lower() for domain in ['.local', '.internal', 'localhost']):
                posture["nameserver_flags"].append(f"External hostname nameserver: {ip}")

    # Analyze routes for anomalies
    default_routes = [r for r in routes if r.get("destination") == "0.0.0.0"]
    if len(default_routes) > 1:
        posture["multiple_default_routes"] = True

    # Check for suspicious routes (e.g., routes to unexpected networks)
    suspicious_networks = [
        "127.0.0.0/8",    # Loopback should not have explicit routes
        "169.254.0.0/16", # Link-local should not have explicit routes in most cases
    ]

    for route in routes:
        dest = route.get("destination", "")
        for suspicious_net in suspicious_networks:
            if dest == suspicious_net.split('/')[0]:
                posture["suspicious_routes"].append(f"Suspicious route to {dest} via {route.get('iface', 'unknown')}")

    # Analyze neighbor table for unknown MAC OUIs
    # Common vendor OUIs that might be suspicious if unexpected
    suspicious_ouis = {
        "00:00:00": "Null OUI",
        "ff:ff:ff": "Broadcast OUI",
    }

    for neigh in neigh_entries:
        if not neigh:
            continue

        mac = (neigh.get("lladdr") or "").upper()
        if not mac or mac == "00:00:00:00:00:00":
            continue

        oui = mac[:8]  # First 3 bytes
        dev = neigh.get("dev") or "unknown"
        if oui in suspicious_ouis:
            posture["unknown_mac_ouis"].append(f"{mac} ({suspicious_ouis[oui]}) on {dev}")

    return posture


def _parse_nmcli_summary(output: str) -> dict[str, Optional[str] | str]:
    raw = output.strip()
    lines = [ln.rstrip() for ln in output.splitlines() if ln.strip()]
    header_idx = None
    for i, ln in enumerate(lines):
        if ln.strip().startswith("STATE") and "CONNECTIVITY" in ln:
            header_idx = i
            break
    if header_idx is None or header_idx + 1 >= len(lines):
        return {"raw_text": raw, "state": None, "connectivity": None, "wifi_hw": None, "wifi": None, "wwan_hw": None, "wwan": None}
    vals = lines[header_idx + 1].split()
    # Expected: STATE CONNECTIVITY WIFI-HW WIFI WWAN-HW WWAN
    state = vals[0] if len(vals) > 0 else None
    conn = vals[1] if len(vals) > 1 else None
    wifi_hw = vals[2] if len(vals) > 2 else None
    wifi = vals[3] if len(vals) > 3 else None
    wwan_hw = vals[4] if len(vals) > 4 else None
    wwan = vals[5] if len(vals) > 5 else None
    return {"raw_text": raw, "state": state, "connectivity": conn, "wifi_hw": wifi_hw, "wifi": wifi, "wwan_hw": wwan_hw, "wwan": wwan}


def _extract_process_details(cmd: str) -> tuple[str, str, str]:
    """
    Extract process_name, process_path, and process_arguments from cmd string.
    Returns (process_name, process_path, process_arguments)
    """
    if not cmd:
        return ("", "", "")
    
    cmd = cmd.strip()
    
    # Handle kernel threads [name]
    if cmd.startswith("[") and cmd.endswith("]"):
        return (cmd, cmd, "")
    
    # Split command into executable and arguments
    # Handle quoted paths and arguments
    import shlex
    try:
        parts = shlex.split(cmd, posix=True)
    except (ValueError, AttributeError):
        # Fallback: simple split on spaces
        parts = cmd.split(None, 1)
    
    if not parts:
        return ("", "", "")
    
    process_path = parts[0]
    
    # Extract process name (basename)
    process_name = os.path.basename(process_path)
    
    # Extract arguments (everything after executable)
    process_arguments = " ".join(parts[1:]) if len(parts) > 1 else ""
    
    return (process_name, process_path, process_arguments)


def _parse_ps_elf(output: str) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    lines = [ln.rstrip() for ln in output.splitlines() if ln.strip()]
    start = 0
    for i, ln in enumerate(lines):
        if ln.strip().startswith("F") and "UID" in ln and "PID" in ln and "CMD" in ln:
            start = i + 1
            break
    for ln in lines[start:]:
        parts = ln.split(None, 14)
        if len(parts) < 15:
            continue
        stat = parts[1]
        uid = parts[2]
        pid = None
        ppid = None
        try:
            pid = int(parts[3])
            ppid = int(parts[4])
        except ValueError:
            pid = None
            ppid = None
        start_time = parts[11]
        tty = parts[12]
        cpu_time = parts[13]
        cmd = parts[14]
        
        # Extract process details
        process_name, process_path, process_arguments = _extract_process_details(cmd)
        
        rows.append(
            {
                "pid": pid,
                "ppid": ppid,
                "uid": uid,
                "tty": tty,
                "stat": stat,
                "start": start_time,
                "time": cpu_time,
                "cmd": cmd,
                "process_name": process_name,
                "process_path": process_path,
                "process_arguments": process_arguments,
                "raw_line": ln,
            }
        )
    return rows


def _parse_pstree_lines(output: str) -> list[str]:
    return [ln.rstrip() for ln in output.splitlines() if ln.strip()]


def derive_process_insights(processes: list[dict], sockets: list[tuple]) -> dict[str, object]:
    """
    Derive security insights from process and socket data.
    """
    insights = {
        "suspicious_root_processes": [],
        "unusual_listening_services": [],
        "process_tree_issues": [],
    }

    # Common legitimate services that might be listening
    common_services = {
        22: "ssh",
        80: "http",
        443: "https",
        53: "dns",
        25: "smtp",
        110: "pop3",
        143: "imap",
        993: "imaps",
        995: "pop3s",
        3306: "mysql",
        5432: "postgresql",
        6379: "redis",
        27017: "mongodb",
        2049: "nfs",
        111: "rpcbind",
    }

    # Get listening sockets
    listening_sockets = [s for s in sockets if s[1] == "LISTEN"]
    listening_ports = set()
    for sock in listening_sockets:
        try:
            port = int(sock[4]) if sock[4] else None
            if port:
                listening_ports.add(port)
        except ValueError:
            continue

    # Check for unusual listening services
    for port in listening_ports:
        if port not in common_services and port > 1024:  # Ignore privileged ports in common_services check
            insights["unusual_listening_services"].append(f"Port {port} listening (unusual)")

    # Check for suspicious root processes
    suspicious_root_patterns = [
        r".*nc\s.*-e",  # netcat with execute
        r".*ncat\s.*-e",
        r".*bash\s.*-i",  # bash interactive
        r".*sh\s.*-i",
        r".*python.*-c.*import",  # python with import
        r".*perl.*-e",  # perl execute
        r".*wget.*\|.*bash",  # wget piped to bash
        r".*curl.*\|.*bash",  # curl piped to bash
        r".*base64.*-d.*\|.*bash",  # base64 decode to bash
    ]

    for proc in processes:
        uid = proc.get("uid", "")
        cmd = proc.get("cmd", "").lower()

        # Check for root processes with suspicious commands
        if uid == "0" or uid == "root":
            for pattern in suspicious_root_patterns:
                if re.search(pattern, cmd, re.IGNORECASE):
                    insights["suspicious_root_processes"].append(f"PID {proc.get('pid')}: {cmd[:100]}...")

    return insights


def _parse_lsmod(output: str) -> list[dict[str, object]]:
    rows = []
    for ln in output.splitlines():
        raw = ln.rstrip()
        if not raw.strip():
            continue
        if raw.startswith("Module "):
            continue
        parts = raw.split()
        if len(parts) < 3:
            continue
        module = parts[0]
        size = None
        used_by_count = None
        try:
            size = int(parts[1])
        except ValueError:
            size = None
        try:
            used_by_count = int(parts[2])
        except ValueError:
            used_by_count = None
        used_by = " ".join(parts[3:]) if len(parts) > 3 else ""
        rows.append({"module": module, "size": size, "used_by_count": used_by_count, "used_by": used_by, "raw_line": raw})
    return rows


def derive_kernel_module_insights(lsmod_modules: list[dict], modinfo_data: list[tuple[str, str, str]]) -> dict[str, object]:
    """
    Derive security insights from kernel module data.
    """
    insights = {
        "unusual_modules": [],
        "suspicious_licenses": [],
        "modules_with_unknown_signer": [],
    }

    # Build module info lookup
    module_info = {}
    for module, key, value in modinfo_data:
        if module not in module_info:
            module_info[module] = {}
        module_info[module][key.lower()] = value

    # Common/expected kernel modules (subset - would be more comprehensive in production)
    common_modules = {
        'nf_conntrack', 'iptable_filter', 'iptable_nat', 'xt_conntrack', 'nf_nat',
        'bridge', 'stp', 'llc', 'ebtable_filter', 'ebtables', 'ip_tables', 'x_tables',
        'ipv6', 'crc32c_intel', 'aesni_intel', 'cryptd', 'ghash_clmulni_intel',
        'pcbc', 'lrw', 'gf128mul', 'ablk_helper', 'xts', 'sha256_ssse3', 'sha512_ssse3',
        'i2c_piix4', 'i2c_core', 'button', 'video', 'wmi', 'pcc_cpufreq', 'acpi_cpufreq',
        'mperf', 'kvm_intel', 'kvm', 'snd_hda_intel', 'snd_hda_codec', 'snd_hwdep',
        'snd_pcm', 'snd_timer', 'snd', 'soundcore', 'i915', 'drm_kms_helper', 'drm',
        'fb_sys_fops', 'syscopyarea', 'sysfillrect', 'sysimgblt', 'ahci', 'libahci',
        'sd_mod', 'sr_mod', 'cdrom', 'ata_piix', 'ata_generic', 'pata_acpi', 'e1000e',
        'uhci_hcd', 'ehci_hcd', 'xhci_hcd', 'usbcore', 'usb_common', 'hid', 'hid_generic',
    }

    # Suspicious license patterns
    suspicious_licenses = {'Proprietary', 'Unknown', 'Binary-only'}

    for mod_data in lsmod_modules:
        module = mod_data.get('module', '')
        if not module:
            continue

        # Check if module is unusual (not in common list)
        if module not in common_modules:
            insights["unusual_modules"].append(module)

        # Check module info for suspicious attributes
        if module in module_info:
            info = module_info[module]

            # Check license
            license_info = info.get('license', '').strip()
            if license_info and any(susp in license_info for susp in suspicious_licenses):
                insights["suspicious_licenses"].append(f"{module}: {license_info}")

            # Check signer (modules should be signed by trusted entities)
            signer = info.get('signer', '').strip()
            if signer and signer.lower() in ['unknown', 'unsigned', '']:
                insights["modules_with_unknown_signer"].append(module)

    return insights


def _parse_modinfo_all(output: str) -> list[tuple[str, str, str]]:
    """
    Parses the modinfo loop output:
      # modinfo <module>
      key: value
    Returns (module, key, value) rows.
    """
    rows: list[tuple[str, str, str]] = []
    current_mod: Optional[str] = None
    for ln in output.splitlines():
        raw = ln.rstrip()
        if raw.startswith("# modinfo "):
            current_mod = raw.split("# modinfo ", 1)[1].strip()
            continue
        if current_mod and ":" in raw:
            k, v = raw.split(":", 1)
            k = k.strip()
            v = v.strip()
            if k:
                rows.append((current_mod, k, v))
    return rows


_LS_LONG_RE = re.compile(
    r"^(?P<perms>[dl-][rwxStTs-]{9})(?:[.+])?\s+\d+\s+(?P<owner>\S+)\s+(?P<grp>\S+)\s+(?P<size>\d+)\s+(?P<mon>\S+)\s+(?P<day>\d+)\s+(?P<timeyear>\S+)\s+(?P<name>.+)$"
)


def _rwx_to_octal(perms: str) -> Optional[int]:
    """Convert ls-style perms (e.g. drwxr-xr-x) to octal (e.g. 755). Best-effort."""
    if not perms or len(perms) < 10:
        return None
    try:
        u = (4 if perms[1] == "r" else 0) + (2 if perms[2] == "w" else 0) + (1 if perms[3] in "xsS" else 0)
        g = (4 if perms[4] == "r" else 0) + (2 if perms[5] == "w" else 0) + (1 if perms[6] in "xsS" else 0)
        o = (4 if perms[7] == "r" else 0) + (2 if perms[8] == "w" else 0) + (1 if perms[9] in "xstT" else 0)
        return u * 100 + g * 10 + o
    except (IndexError, TypeError):
        return None


def _normalize_mtime_file(mtime_text: Optional[str], timezone_str: Optional[str], collected_at: Optional[str]) -> Optional[str]:
    """Parse ls-style mtime (e.g. 'Nov 13 2025' or 'Jan  4 22:28') to ISO UTC."""
    if not mtime_text or not collected_at:
        return None
    text = mtime_text.strip()
    if not text:
        return None
    try:
        import zoneinfo
        tz = zoneinfo.ZoneInfo(timezone_str) if timezone_str else dt.timezone.utc
    except Exception:
        return None
    ref_dt = dt.datetime.fromisoformat(collected_at.replace("Z", "+00:00"))
    parsed = None
    for fmt in ["%b %d %Y", "%b %d %H:%M"]:
        try:
            parsed = dt.datetime.strptime(text, fmt)
            break
        except ValueError:
            continue
    if parsed is not None and parsed.year == 1900:
        parsed = parsed.replace(year=ref_dt.year)
    if parsed is None:
        return None
    try:
        localized = parsed.replace(tzinfo=tz)
        return localized.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return None


def _parse_ls_latR(output: str) -> list[dict[str, object]]:
    """
    Parses `ls -latR` output with directory headers like `/etc/cron.d:`.
    """
    rows: list[dict[str, object]] = []
    current_dir: Optional[str] = None
    for ln in output.splitlines():
        raw = ln.rstrip()
        if not raw.strip():
            continue
        if raw.endswith(":") and raw.startswith("/"):
            current_dir = raw[:-1]
            continue
        if raw.startswith("total "):
            continue
        m = _LS_LONG_RE.match(raw)
        if not m:
            continue
        perms = m.group("perms")
        owner = m.group("owner")
        grp = m.group("grp")
        size_bytes = int(m.group("size"))
        mtime_text = f"{m.group('mon')} {m.group('day')} {m.group('timeyear')}"
        name = m.group("name")
        symlink_target = None
        if " -> " in name:
            name, _, symlink_target = name.partition(" -> ")
            name = name.strip()
            symlink_target = symlink_target.strip() or None
        file_type = "dir" if perms.startswith("d") else "link" if perms.startswith("l") else "file"
        is_symlink = 1 if perms.startswith("l") else 0
        path = f"{current_dir}/{name}" if current_dir else name
        filename = name
        rows.append(
            {
                "directory": current_dir,
                "path": path,
                "perms": perms,
                "perm_octal": _rwx_to_octal(perms),
                "owner": owner,
                "grp": grp,
                "size_bytes": size_bytes,
                "mtime_text": mtime_text,
                "name": name,
                "filename": filename,
                "file_type": file_type,
                "is_symlink": is_symlink,
                "symlink_target": symlink_target,
                "raw_line": raw,
            }
        )
    return rows


def _parse_lsusb_v(output: str) -> list[dict[str, object]]:
    """
    Parse lsusb -v output to extract USB device information.
    Focuses on security-relevant fields from device descriptors.
    Optimized to avoid processing excessive configuration details.
    """
    devices = []
    lines = output.splitlines()

    # Limit total devices to prevent excessive processing
    max_devices = 50
    device_count = 0

    current_device = None
    i = 0

    while i < len(lines) and device_count < max_devices:
        line = lines[i].strip()

        # Look for device header line
        if line.startswith("Bus ") and " Device " in line and " ID " in line:
            # Parse header: "Bus 014 Device 001: ID 1d6b:0003 Linux Foundation 3.0 root hub"
            parts = line.split()
            if len(parts) >= 7:
                bus_num = int(parts[1]) if parts[1].isdigit() else None
                dev_num = int(parts[3]) if parts[3].isdigit() else None

                id_part = parts[5]  # "1d6b:0003"
                vendor_id, product_id = id_part.split(':') if ':' in id_part else (None, None)

                # Everything after the ID is the description
                description = ' '.join(parts[6:]) if len(parts) > 6 else ""

                current_device = {
                    "bus_number": bus_num,
                    "device_number": dev_num,
                    "vendor_id": vendor_id,
                    "product_id": product_id,
                    "description": description,
                    "device_class": None,
                    "device_subclass": None,
                    "device_protocol": None,
                    "vendor_name": None,
                    "product_name": None,
                    "manufacturer": None,
                    "product": None,
                    "serial_number": None,
                    "usb_version": None,
                    "max_power": None,
                }

                # Look ahead for device descriptor info (limit processing)
                j = i + 1
                in_device_descriptor = False
                descriptor_lines_processed = 0
                max_descriptor_lines = 20  # Limit descriptor processing

                while (j < len(lines) and not lines[j].strip().startswith("Bus ")
                       and descriptor_lines_processed < max_descriptor_lines):
                    desc_line = lines[j].strip()

                    if desc_line.startswith("Device Descriptor:"):
                        in_device_descriptor = True
                    elif desc_line.startswith("Configuration Descriptor:"):
                        break  # Stop at configuration descriptor to avoid excessive detail
                    elif in_device_descriptor:
                        descriptor_lines_processed += 1

                        if desc_line.startswith("bDeviceClass"):
                            try:
                                current_device["device_class"] = int(desc_line.split()[-1], 16)
                            except (ValueError, IndexError):
                                pass
                        elif desc_line.startswith("bDeviceSubClass"):
                            try:
                                current_device["device_subclass"] = int(desc_line.split()[-1], 16)
                            except (ValueError, IndexError):
                                pass
                        elif desc_line.startswith("bDeviceProtocol"):
                            try:
                                current_device["device_protocol"] = int(desc_line.split()[-1], 16)
                            except (ValueError, IndexError):
                                pass
                        elif desc_line.startswith("bcdUSB"):
                            current_device["usb_version"] = desc_line.split()[-1]
                        elif desc_line.startswith("idVendor"):
                            parts = desc_line.split()
                            if len(parts) >= 3:
                                current_device["vendor_name"] = ' '.join(parts[2:])
                        elif desc_line.startswith("idProduct"):
                            parts = desc_line.split()
                            if len(parts) >= 3:
                                current_device["product_name"] = ' '.join(parts[2:])
                        elif desc_line.startswith("iManufacturer"):
                            parts = desc_line.split()
                            if len(parts) >= 2:
                                current_device["manufacturer"] = ' '.join(parts[1:])
                        elif desc_line.startswith("iProduct"):
                            parts = desc_line.split()
                            if len(parts) >= 2:
                                current_device["product"] = ' '.join(parts[1:])
                        elif desc_line.startswith("iSerial"):
                            parts = desc_line.split()
                            if len(parts) >= 2:
                                current_device["serial_number"] = ' '.join(parts[1:])
                        elif desc_line.startswith("MaxPower"):
                            current_device["max_power"] = desc_line.split()[-1]

                    j += 1

                if current_device:
                    devices.append(current_device)
                    current_device = None
                    device_count += 1

        i += 1

    return devices


def derive_persistence_insights(file_listings: list[dict]) -> dict[str, object]:
    """
    Derive persistence indicators from file listings.
    """
    insights = {
        "suspicious_systemd_units": [],
        "unusual_cron_permissions": [],
        "recently_modified_persistence_files": [],
        "suspicious_cron_locations": [],
    }

    # Common legitimate systemd unit names (subset)
    common_systemd_units = {
        'systemd-networkd.service', 'systemd-resolved.service', 'sshd.service',
        'cron.service', 'rsyslog.service', 'systemd-journald.service',
        'NetworkManager.service', 'dbus.service', 'systemd-logind.service',
        'systemd-timesyncd.service', 'ufw.service', 'apparmor.service',
        'auditd.service', 'irqbalance.service', 'unattended-upgrades.service',
    }

    # Common cron directories that should exist
    expected_cron_dirs = {'/etc/cron.d', '/etc/cron.daily', '/etc/cron.hourly', '/etc/cron.monthly', '/etc/cron.weekly'}

    for file_info in file_listings:
        path = file_info.get('path', '')
        perms = file_info.get('perms', '')
        owner = file_info.get('owner', '')
        source = file_info.get('source', '')
        directory = file_info.get('directory', '')
        name = file_info.get('name', '')
        mtime_text = file_info.get('mtime_text', '')

        # Check systemd units
        if source == 'systemd_dirs' and name.endswith('.service'):
            if name not in common_systemd_units and not name.startswith('user@'):
                insights["suspicious_systemd_units"].append(f"Non-standard service: {path}")

        # Check cron permissions and locations
        if source == 'cron_dirs':
            # Unusual permissions on cron files
            if perms and len(perms) >= 10:
                # Check if group/other has write permissions
                if perms[5] in 'wx' or perms[8] in 'wx':  # group write or other write
                    insights["unusual_cron_permissions"].append(f"World/group-writable cron file: {path} ({perms})")

            # Check for cron files in unusual locations
            if directory and directory not in expected_cron_dirs:
                insights["suspicious_cron_locations"].append(f"Cron file in unusual location: {path}")

        # Check for recently modified files in persistence directories
        # This is a simple heuristic - files modified in the last "few days" (relative to baseline time)
        # In a real implementation, you'd want to parse mtime_text and compare to baseline collection time
        if source in ('cron_dirs', 'systemd_dirs', 'init_dirs'):
            # Simple heuristic: if mtime_text contains current year, it's potentially recent
            import datetime
            current_year = str(datetime.datetime.now().year)
            if current_year in mtime_text:
                insights["recently_modified_persistence_files"].append(f"Recently modified: {path} ({mtime_text})")

    return insights


def generate_security_findings(conn: sqlite3.Connection, run_id: int) -> list[dict]:
    """
    Generate security findings from all parsed data for a run.
    """
    findings = []

    # Audit findings
    audit_posture = conn.execute("SELECT * FROM run_audit_posture WHERE run_id = ?", (run_id,)).fetchone()
    if audit_posture:
        if not audit_posture[1]:  # audit_enabled
            findings.append({
                'severity': 'high',
                'category': 'audit',
                'title': 'Audit subsystem disabled',
                'details': 'The audit subsystem is disabled, preventing security event logging',
                'evidence_ref': f'run_audit_posture.{run_id}'
            })

        if not audit_posture[2]:  # audit_immutable
            findings.append({
                'severity': 'medium',
                'category': 'audit',
                'title': 'Audit rules not immutable',
                'details': 'Audit rules can be modified at runtime, potentially allowing attackers to disable logging',
                'evidence_ref': f'run_audit_posture.{run_id}'
            })

    # SELinux findings
    selinux_posture = conn.execute("SELECT * FROM run_selinux_posture WHERE run_id = ?", (run_id,)).fetchone()
    if selinux_posture:
        if selinux_posture[3]:  # selinux_disabled
            findings.append({
                'severity': 'high',
                'category': 'selinux',
                'title': 'SELinux disabled',
                'details': 'SELinux is disabled, removing mandatory access controls',
                'evidence_ref': f'run_selinux_posture.{run_id}'
            })
        elif selinux_posture[2]:  # selinux_permissive
            findings.append({
                'severity': 'medium',
                'category': 'selinux',
                'title': 'SELinux in permissive mode',
                'details': 'SELinux is in permissive mode, logging violations but not enforcing policy',
                'evidence_ref': f'run_selinux_posture.{run_id}'
            })

    # AppArmor findings
    apparmor_posture = conn.execute("SELECT * FROM run_apparmor_posture WHERE run_id = ?", (run_id,)).fetchone()
    if apparmor_posture:
        if apparmor_posture[3]:  # apparmor_mixed_mode
            findings.append({
                'severity': 'medium',
                'category': 'apparmor',
                'title': 'AppArmor mixed enforcement mode',
                'details': 'Some AppArmor profiles are in complain mode while others are enforcing',
                'evidence_ref': f'run_apparmor_posture.{run_id}'
            })

    # Network findings
    network_posture = conn.execute("SELECT * FROM run_network_posture WHERE run_id = ?", (run_id,)).fetchone()
    if network_posture:
        import json
        if network_posture[2]:  # multiple_default_routes (index 2)
            findings.append({
                'severity': 'medium',
                'category': 'network',
                'title': 'Multiple default routes configured',
                'details': 'Multiple default routes may indicate routing misconfiguration or MITM attempts',
                'evidence_ref': f'run_network_posture.{run_id}'
            })

        unexpected_ns_str = network_posture[1] or '[]'  # unexpected_nameservers (index 1)
        try:
            unexpected_ns = json.loads(unexpected_ns_str)
            if unexpected_ns:
                findings.append({
                    'severity': 'medium',
                    'category': 'network',
                    'title': f'Unexpected nameservers: {", ".join(unexpected_ns[:3])}',
                    'details': f'Found {len(unexpected_ns)} unexpected nameservers that may indicate DNS hijacking',
                    'evidence_ref': f'run_network_posture.{run_id}'
                })
        except (json.JSONDecodeError, TypeError):
            pass  # Skip if JSON parsing fails

    # Process findings
    process_insights = conn.execute("SELECT * FROM run_process_insights WHERE run_id = ?", (run_id,)).fetchone()
    if process_insights:
        import json
        suspicious_procs = json.loads(process_insights[1] or '[]')
        if suspicious_procs:
            findings.append({
                'severity': 'high',
                'category': 'process',
                'title': f'Suspicious root processes detected ({len(suspicious_procs)})',
                'details': 'Root processes with potentially malicious command lines found',
                'evidence_ref': f'run_process_insights.{run_id}'
            })

    # Failed login findings
    failed_logins = conn.execute("SELECT COUNT(*) FROM run_failed_logins WHERE run_id = ?", (run_id,)).fetchone()
    if failed_logins and failed_logins[0] > 10:  # Threshold for concerning
        findings.append({
            'severity': 'medium',
            'category': 'auth',
            'title': f'High number of failed logins ({failed_logins[0]})',
            'details': 'Large number of failed login attempts may indicate brute force attacks',
            'evidence_ref': f'run_failed_logins.{run_id}'
        })

    # Persistence findings
    persistence_insights = conn.execute("SELECT * FROM run_persistence_insights WHERE run_id = ?", (run_id,)).fetchone()
    if persistence_insights:
        import json
        suspicious_units = json.loads(persistence_insights[1] or '[]')
        if suspicious_units:
            findings.append({
                'severity': 'medium',
                'category': 'persistence',
                'title': f'Suspicious systemd units ({len(suspicious_units)})',
                'details': 'Non-standard systemd units that may indicate persistence mechanisms',
                'evidence_ref': f'run_persistence_insights.{run_id}'
            })

    return findings


def _parse_ls_l(output: str) -> list[dict[str, object]]:
    """
    Parses `ls -l` style output (non-recursive). Path is taken from the final name column.
    """
    rows: list[dict[str, object]] = []
    for ln in output.splitlines():
        raw = ln.rstrip()
        if not raw.strip() or raw.startswith("total "):
            continue
        m = _LS_LONG_RE.match(raw)
        if not m:
            continue
        perms = m.group("perms")
        owner = m.group("owner")
        grp = m.group("grp")
        size_bytes = int(m.group("size"))
        mtime_text = f"{m.group('mon')} {m.group('day')} {m.group('timeyear')}"
        name = m.group("name")
        symlink_target = None
        if " -> " in name:
            name, _, symlink_target = name.partition(" -> ")
            name = name.strip()
            symlink_target = symlink_target.strip() or None
        file_type = "dir" if perms.startswith("d") else "link" if perms.startswith("l") else "file"
        is_symlink = 1 if perms.startswith("l") else 0
        rows.append(
            {
                "directory": None,
                "path": name,
                "perms": perms,
                "perm_octal": _rwx_to_octal(perms),
                "owner": owner,
                "grp": grp,
                "size_bytes": size_bytes,
                "mtime_text": mtime_text,
                "name": name,
                "filename": name,
                "file_type": file_type,
                "is_symlink": is_symlink,
                "symlink_target": symlink_target,
                "raw_line": raw,
            }
        )
    return rows


_PASSWD_RE = re.compile(r"^([^:]+):([^:]*):(\d+):(\d+):([^:]*):([^:]*):([^:]*)$")


def _parse_passwd(output: str) -> list[tuple[str, int, int, str, str, str]]:
    rows: list[tuple[str, int, int, str, str, str]] = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _PASSWD_RE.match(line)
        if not m:
            continue
        username = m.group(1)
        uid = int(m.group(3))
        gid = int(m.group(4))
        gecos = m.group(5)
        home = m.group(6)
        shell = m.group(7)
        rows.append((username, uid, gid, gecos, home, shell))
    return rows


def _parse_group(output: str) -> list[tuple[str, int, str]]:
    rows: list[tuple[str, int, str]] = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) != 4:
            continue
        groupname = parts[0]
        try:
            gid = int(parts[2])
        except ValueError:
            gid = None  # type: ignore[assignment]
        members = parts[3] or ""
        rows.append((groupname, gid, members))
    return rows


def _split_members_csv(members_csv: Optional[str]) -> list[str]:
    if not members_csv:
        return []
    out = []
    for m in members_csv.split(","):
        m = m.strip()
        if m:
            out.append(m)
    return out


# Well-known system/daemon group names (service); GID 0-999 typical. Rare = worth flagging for review.
_WELL_KNOWN_GROUP_NAMES: frozenset[str] = frozenset({
    "root", "bin", "daemon", "sys", "adm", "tty", "disk", "lp", "mem", "kmem", "wheel",
    "mail", "uucp", "man", "dbus", "nobody", "nogroup", "messagebus", "polkitd", "rtkit",
    "systemd-journal", "systemd-timesync", "systemd-network", "systemd-resolve", "systemd-bus-proxy",
    "input", "kvm", "render", "crontab", "sasl", "ssh", "colord", "avahi", "usbmux", "geoclue",
    "pulse", "pulse-access", "gdm", "sddm", "lpadmin", "sambashare", "docker", "libvirt",
    "nopasswdlogin", "sudo", "cdrom", "dialout", "dip", "plugdev", "staff", "users", "video",
    "bluetooth", "netdev", "kvm", "libvirt-dnsmasq", "libvirt-qemu",
})


def _classify_group_type(groupname: str, gid: Optional[int]) -> str:
    """Classify group as service (system/daemon), user (user-range), or rare (uncommon)."""
    gn = (groupname or "").strip().lower()
    if gn in _WELL_KNOWN_GROUP_NAMES:
        return "service"
    if gid is not None and gid >= 1000:
        return "user"  # typical user gid range
    return "rare"  # unknown system group or no gid


def _parse_passwd_status(output: str) -> list[tuple[str, Optional[str], Optional[str], Optional[str], Optional[str], Optional[str], Optional[str], Optional[str]]]:
    """
    Ubuntu example:
      root P 11/13/2025 0 99999 7 -1

    We store tokens positionally; keep as text to avoid distro-specific date parsing.
    """
    rows = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        username = parts[0]
        status_code = parts[1] if len(parts) > 1 else None
        last_change = parts[2] if len(parts) > 2 else None
        min_age = parts[3] if len(parts) > 3 else None
        max_age = parts[4] if len(parts) > 4 else None
        warn = parts[5] if len(parts) > 5 else None
        inactive = parts[6] if len(parts) > 6 else None
        expire = parts[7] if len(parts) > 7 else None
        rows.append((username, status_code, last_change, min_age, max_age, warn, inactive, expire))
    return rows


_IP_IFACE_RE = re.compile(r"^\d+:\s+([^:]+):.*\bmtu\s+(\d+)\b.*\bstate\s+(\S+)\b")
_IP_LINK_ETHER_RE = re.compile(r"^\s+link/ether\s+([0-9a-fA-F:]{17})\b")
_IP_INET_RE = re.compile(r"^\s+(inet6?|inet)\s+([0-9a-fA-F\.:]+)/(\d+)\b.*?(?:\bscope\s+(\S+)\b)?")
# Private IPv4 ranges (RFC 1918, etc.)
_IP4_LOOPBACK = re.compile(r"^127\.\d+\.\d+\.\d+$")
_IP4_LINK_LOCAL = re.compile(r"^169\.254\.\d+\.\d+$")
_IP4_PRIVATE = re.compile(r"^(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)$")


def _classify_route_dest(destination: Optional[str]) -> str:
    """Classify route destination: default | host | link | network."""
    if not destination or not destination.strip():
        return "network"
    d = destination.strip()
    if d == "0.0.0.0":
        return "default"
    if d.startswith("127.") or d == "::1":
        return "host"
    if d.startswith("169.254.") or d.lower().startswith("fe80:"):
        return "link"
    return "network"


def _classify_bind_scope(local_addr: Optional[str]) -> str:
    """Classify listening address: loopback | all_interfaces | specific."""
    if not local_addr:
        return "specific"
    a = local_addr.strip()
    if a in ("127.0.0.1", "::1") or a.startswith("127."):
        return "loopback"
    if a in ("0.0.0.0", "::", "*"):
        return "all_interfaces"
    return "specific"


def _unit_type_from_name(unit_name: Optional[str]) -> str:
    """Derive unit type from unit name suffix (.service, .socket, etc.)."""
    if not unit_name:
        return "other"
    u = unit_name.strip()
    for suffix in (".service", ".socket", ".timer", ".path", ".mount", ".target", ".slice", ".scope"):
        if u.endswith(suffix):
            return suffix[1:]
    return "other"


# USB device class codes (common; integer from bDeviceClass)
_USB_CLASS_LABELS: dict[int, str] = {
    0x00: "Device",
    0x01: "Audio",
    0x02: "CDC",
    0x03: "HID",
    0x05: "Physical",
    0x06: "Image",
    0x07: "Printer",
    0x08: "Mass Storage",
    0x09: "Hub",
    0x0A: "CDC-Data",
    0x0B: "Smart Card",
    0x0D: "Content Security",
    0x0E: "Video",
    0x0F: "Healthcare",
    0x10: "Audio/Video",
    0xDC: "Diagnostic",
    0xE0: "Wireless",
    0xEF: "Misc",
    0xFE: "Application",
    0xFF: "Vendor",
}


def _usb_device_class_label(device_class: Optional[int]) -> Optional[str]:
    if device_class is None:
        return None
    return _USB_CLASS_LABELS.get(device_class & 0xFF)


def _sudoers_rule_type(rule_text: Optional[str]) -> str:
    """Derive rule type from first token or alias (Defaults, User_Host, Runas, Cmnd)."""
    if not rule_text or not rule_text.strip():
        return "other"
    s = rule_text.strip()
    if s.startswith("Defaults"):
        return "Defaults"
    if s.startswith("Runas"):
        return "Runas"
    if s.startswith("Cmnd"):
        return "Cmnd"
    if s.startswith("Host"):
        return "Host"
    # User_Host spec: user host = (runas) cmnd
    if "=" in s and not s.startswith("Defaults"):
        return "User_Host"
    return "other"


def _classify_iface_type(ifname: str) -> str:
    """Classify interface by name: loopback, physical, bridge, veth, docker, virtual, other."""
    name = (ifname or "").strip().lower()
    if name == "lo":
        return "loopback"
    if name.startswith("veth") or "@" in name and "veth" in name:
        return "veth"
    if name == "docker0" or name.startswith("docker"):
        return "docker"
    if name.startswith("br-") or name.startswith("bridge"):
        return "bridge"
    if any(name.startswith(p) for p in ("virbr", "vnet", "vb", "tap", "tun")):
        return "virtual"
    if any(name.startswith(p) for p in ("eno", "enp", "ens", "eth", "wlan", "wlp", "wl", "usb", "ib")):
        return "physical"
    return "other"


def _classify_addr_type(family: str, address: str) -> str:
    """Classify address as loopback, link_local, private, or public."""
    addr = (address or "").strip()
    if family == "inet":
        if _IP4_LOOPBACK.match(addr):
            return "loopback"
        if _IP4_LINK_LOCAL.match(addr):
            return "link_local"
        if _IP4_PRIVATE.match(addr):
            return "private"
        return "public"
    if family == "inet6":
        if addr == "::1" or addr.lower().startswith("::1/"):
            return "loopback"
        if addr.lower().startswith("fe80:"):
            return "link_local"
        if addr.lower().startswith("fd") or addr.lower().startswith("fc"):
            return "private"  # RFC 4193 ULA
        return "public"
    return "public"


def _parse_ip_a(output: str) -> tuple[list[tuple[str, Optional[str], Optional[str], Optional[int], str]], list[tuple[str, str, str, int, Optional[str], str]]]:
    """
    Returns:
      interfaces: [(ifname, mac, state, mtu, iface_type)]
      addrs: [(ifname, family, address, prefixlen, scope, addr_type)]
    """
    interfaces: dict[str, dict[str, object]] = {}
    addrs: list[tuple[str, str, str, int, Optional[str], str]] = []
    current_if: Optional[str] = None

    for line in output.splitlines():
        m = _IP_IFACE_RE.match(line)
        if m:
            current_if = m.group(1)
            mtu = int(m.group(2))
            state = m.group(3)
            interfaces.setdefault(current_if, {})
            interfaces[current_if]["mtu"] = mtu
            interfaces[current_if]["state"] = state
            continue

        if current_if:
            m2 = _IP_LINK_ETHER_RE.match(line)
            if m2:
                interfaces.setdefault(current_if, {})
                interfaces[current_if]["mac"] = m2.group(1).lower()
                continue

            m3 = _IP_INET_RE.match(line)
            if m3:
                family = m3.group(1)
                address = m3.group(2)
                prefixlen = int(m3.group(3))
                scope = m3.group(4) if m3.group(4) else None
                if scope is None:
                    scope = "host" if address in ("127.0.0.1", "::1") else ("link" if (family == "inet6" and address.lower().startswith("fe80:")) else "global")
                addr_type = _classify_addr_type(family, address)
                addrs.append((current_if, family, address, prefixlen, scope, addr_type))
                continue

    iface_rows: list[tuple[str, Optional[str], Optional[str], Optional[int], str]] = []
    for ifname, info in interfaces.items():
        iface_rows.append(
            (
                ifname,
                info.get("mac"),  # type: ignore[arg-type]
                info.get("state"),  # type: ignore[arg-type]
                info.get("mtu"),  # type: ignore[arg-type]
                _classify_iface_type(ifname),
            )
        )
    return iface_rows, addrs


_SYSTEMCTL_UNIT_RE = re.compile(r"^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)$")


def _parse_systemctl_list_units(output: str) -> list[tuple[str, str, str, str, str]]:
    rows: list[tuple[str, str, str, str, str]] = []
    for line in output.splitlines():
        line = line.rstrip()
        if not line:
            continue
        if line.startswith("UNIT ") or line.startswith("LOAD ") or line.startswith("  UNIT "):
            continue
        if line.startswith("LIST ") or line.startswith("0 loaded"):
            continue
        m = _SYSTEMCTL_UNIT_RE.match(line)
        if not m:
            continue
        unit, load, active, sub, desc = m.groups()
        rows.append((unit, load, active, sub, desc))
    return rows


_DPKG_LINE_RE = re.compile(r"^(ii|rc|un|iF|iU|pn)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)$")


def _parse_dpkg_list(output: str) -> list[tuple[str, str, str, str, str]]:
    rows: list[tuple[str, str, str, str, str]] = []
    for line in output.splitlines():
        line = line.rstrip()
        if not line:
            continue
        if line.startswith("Desired=") or line.startswith("|") or line.startswith("+++-"):
            continue
        m = _DPKG_LINE_RE.match(line)
        if not m:
            continue
        status, name, version, arch, desc = m.groups()
        rows.append((name, version, arch, status, desc))
    return rows


def _parse_rpm_all(output: str) -> list[tuple[str]]:
    rows: list[tuple[str]] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        if "command not found" in line or line.startswith("rpm:"):
            continue
        rows.append((line,))
    return rows


_SS_LINE_RE = re.compile(
    r"^(?P<netid>\S+)\s+(?P<state>\S+)\s+\S+\s+\S+\s+(?P<local>\S+)\s+(?P<peer>\S+)\s*(?P<users>users:\(\(.*\)\))?\s*$"
)
_SS_ADDRPORT_RE = re.compile(r"^(.*):(\d+)$")
_SS_USERS_PID_RE = re.compile(r'\"(?P<proc>[^\"]+)\".*pid=(?P<pid>\d+)')


def _split_addr_port(s: str) -> tuple[str, Optional[int]]:
    s = s.strip()
    if s == "*" or s == "*:*":
        return "*", None
    # IPv6 like [::]:22
    if s.startswith("[") and "]" in s:
        host = s[1 : s.index("]")]
        rest = s[s.index("]") + 1 :]
        if rest.startswith(":") and rest[1:].isdigit():
            return host, int(rest[1:])
        return host, None
    m = _SS_ADDRPORT_RE.match(s)
    if m:
        host, port = m.group(1), int(m.group(2))
        return host, port
    return s, None


def _parse_ss_punt(output: str) -> list[tuple[Optional[str], Optional[str], Optional[str], Optional[int], Optional[str], Optional[int], Optional[str], Optional[int], str]]:
    rows = []
    for line in output.splitlines():
        line = line.rstrip()
        if not line:
            continue
        if line.startswith("Netid ") or line.startswith("State "):
            continue
        m = _SS_LINE_RE.match(line)
        if not m:
            continue
        netid = m.group("netid")
        state = m.group("state")
        local = m.group("local")
        peer = m.group("peer")
        users = m.group("users") or ""

        local_addr, local_port = _split_addr_port(local)
        peer_addr, peer_port = _split_addr_port(peer)

        proc = None
        pid = None
        m2 = _SS_USERS_PID_RE.search(users)
        if m2:
            proc = m2.group("proc")
            pid = int(m2.group("pid"))

        rows.append((netid, state, local_addr, local_port, peer_addr, peer_port, proc, pid, line))
    return rows


def db_connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA foreign_keys = ON;")
    # WAL is faster but can be problematic on some synced/networked filesystems.
    try:
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
    except sqlite3.OperationalError:
        conn.execute("PRAGMA journal_mode = DELETE;")
        conn.execute("PRAGMA synchronous = FULL;")
    return conn


def db_init(conn: sqlite3.Connection, schema_path: Path) -> None:
    # #region agent log
    import json
    with open('/Users/blane/Library/CloudStorage/OneDrive-WestPoint/Documents/ACI/Topics/WIRE/.cursor/debug.log', 'a') as f:
        f.write(json.dumps({"sessionId":"debug-session","runId":"pre-fix","hypothesisId":"A","location":"ingest-baselines.py:2563","message":"db_init entry","data":{"schema_path":str(schema_path),"schema_exists":schema_path.exists()},"timestamp":int(__import__('time').time()*1000)})+"\n")
    # #endregion
    schema_sql = schema_path.read_text(encoding="utf-8")
    # #region agent log
    with open('/Users/blane/Library/CloudStorage/OneDrive-WestPoint/Documents/ACI/Topics/WIRE/.cursor/debug.log', 'a') as f:
        f.write(json.dumps({"sessionId":"debug-session","runId":"pre-fix","hypothesisId":"A","location":"ingest-baselines.py:2566","message":"schema loaded","data":{"schema_length":len(schema_sql),"has_auth_log_stats":'run_auth_log_stats' in schema_sql,"has_source_column":'source TEXT NOT NULL' in schema_sql or 'source,' in schema_sql},"timestamp":int(__import__('time').time()*1000)})+"\n")
    # #endregion
    conn.executescript(schema_sql)
    conn.commit()
    # #region agent log
    try:
        cols = [r[1] for r in conn.execute("PRAGMA table_info('run_auth_log_stats')").fetchall()]
        with open('/Users/blane/Library/CloudStorage/OneDrive-WestPoint/Documents/ACI/Topics/WIRE/.cursor/debug.log', 'a') as f:
            f.write(json.dumps({"sessionId":"debug-session","runId":"pre-fix","hypothesisId":"A","location":"ingest-baselines.py:2572","message":"table columns after init","data":{"columns":cols,"has_source":"source" in cols},"timestamp":int(__import__('time').time()*1000)})+"\n")
    except Exception as e:
        with open('/Users/blane/Library/CloudStorage/OneDrive-WestPoint/Documents/ACI/Topics/WIRE/.cursor/debug.log', 'a') as f:
            f.write(json.dumps({"sessionId":"debug-session","runId":"pre-fix","hypothesisId":"A","location":"ingest-baselines.py:2575","message":"table check error","data":{"error":str(e)},"timestamp":int(__import__('time').time()*1000)})+"\n")
    # #endregion


def db_migrate(conn: sqlite3.Connection) -> None:
    """
    Lightweight migrations for existing DBs.
    (SQLite can't drop constraints in-place; we rebuild affected tables.)
    """
    # #region agent log
    import json
    # #endregion
    
    # Migration: run_auth_log_stats table schema update
    try:
        cols = [r[1] for r in conn.execute("PRAGMA table_info('run_auth_log_stats')").fetchall()]
        # #region agent log
        with open('/Users/blane/Library/CloudStorage/OneDrive-WestPoint/Documents/ACI/Topics/WIRE/.cursor/debug.log', 'a') as f:
            f.write(json.dumps({"sessionId":"debug-session","runId":"pre-fix","hypothesisId":"D","location":"ingest-baselines.py:2578","message":"checking run_auth_log_stats for migration","data":{"columns":cols,"needs_migration":"source" not in cols},"timestamp":int(__import__('time').time()*1000)})+"\n")
        # #endregion
        if "source" not in cols:
            # Old schema detected - need to recreate table
            # #region agent log
            with open('/Users/blane/Library/CloudStorage/OneDrive-WestPoint/Documents/ACI/Topics/WIRE/.cursor/debug.log', 'a') as f:
                f.write(json.dumps({"sessionId":"debug-session","runId":"pre-fix","hypothesisId":"D","location":"ingest-baselines.py:2582","message":"migrating run_auth_log_stats","data":{"old_columns":cols},"timestamp":int(__import__('time').time()*1000)})+"\n")
            # #endregion
            # Backup existing data (if any)
            existing_data = conn.execute("SELECT * FROM run_auth_log_stats").fetchall()
            # Drop old table
            conn.execute("DROP TABLE IF EXISTS run_auth_log_stats")
            # Recreate with new schema
            conn.execute("""
                CREATE TABLE IF NOT EXISTS run_auth_log_stats (
                  run_id INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
                  source TEXT NOT NULL,  -- journalctl_ssh | auth_log | secure
                  failed_password_count INTEGER NOT NULL DEFAULT 0,
                  invalid_user_count INTEGER NOT NULL DEFAULT 0,
                  accepted_password_count INTEGER NOT NULL DEFAULT 0,
                  accepted_publickey_count INTEGER NOT NULL DEFAULT 0,
                  sudo_count INTEGER NOT NULL DEFAULT 0,
                  error_count INTEGER NOT NULL DEFAULT 0,
                  raw_line_count INTEGER NOT NULL DEFAULT 0,
                  PRIMARY KEY (run_id, source)
                )
            """)
            # Note: We don't migrate old data as the schema is incompatible
            # #region agent log
            with open('/Users/blane/Library/CloudStorage/OneDrive-WestPoint/Documents/ACI/Topics/WIRE/.cursor/debug.log', 'a') as f:
                f.write(json.dumps({"sessionId":"debug-session","runId":"pre-fix","hypothesisId":"D","location":"ingest-baselines.py:2605","message":"migration complete","data":{"old_rows_dropped":len(existing_data)},"timestamp":int(__import__('time').time()*1000)})+"\n")
            # #endregion
            conn.commit()
    except sqlite3.OperationalError:
        # Table doesn't exist yet, will be created by schema
        # #region agent log
        with open('/Users/blane/Library/CloudStorage/OneDrive-WestPoint/Documents/ACI/Topics/WIRE/.cursor/debug.log', 'a') as f:
            f.write(json.dumps({"sessionId":"debug-session","runId":"pre-fix","hypothesisId":"D","location":"ingest-baselines.py:2610","message":"table does not exist yet","data":{},"timestamp":int(__import__('time').time()*1000)})+"\n")
        # #endregion
        pass
    
    # Migration: run_ssh_host_keys table schema update
    try:
        cols = [r[1] for r in conn.execute("PRAGMA table_info('run_ssh_host_keys')").fetchall()]
        if "fingerprint" not in cols or "raw_line" not in cols:
            # Old schema detected
            existing_data = conn.execute("SELECT * FROM run_ssh_host_keys").fetchall()
            conn.execute("DROP TABLE IF EXISTS run_ssh_host_keys")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS run_ssh_host_keys (
                  run_id INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
                  bits INTEGER,
                  fingerprint TEXT NOT NULL,
                  key_file TEXT,
                  key_type TEXT NOT NULL,
                  raw_line TEXT NOT NULL,
                  PRIMARY KEY (run_id, key_type, fingerprint)
                )
            """)
            conn.commit()
    except sqlite3.OperationalError:
        pass
    
    # Migration: run_block_devices add parent_name
    try:
        cols = [r[1] for r in conn.execute("PRAGMA table_info('run_block_devices')").fetchall()]
        if "parent_name" not in cols:
            conn.execute("ALTER TABLE run_block_devices ADD COLUMN parent_name TEXT")
            conn.commit()
    except sqlite3.OperationalError:
        pass

    # Migration: run_failed_logins add state_text
    try:
        cols = [r[1] for r in conn.execute("PRAGMA table_info('run_failed_logins')").fetchall()]
        if "state_text" not in cols:
            conn.execute("ALTER TABLE run_failed_logins ADD COLUMN state_text TEXT")
            conn.commit()
    except sqlite3.OperationalError:
        pass

    # Migration: ref_tty table (for TTY correlation)
    try:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS ref_tty (tty_value TEXT PRIMARY KEY, tty_kind TEXT)"
        )
        conn.commit()
    except sqlite3.OperationalError:
        pass

    # Migration: run_hostinfo add os_name, os_version, os_id
    try:
        cols = [r[1] for r in conn.execute("PRAGMA table_info('run_hostinfo')").fetchall()]
        for col in ("os_name", "os_version", "os_id"):
            if col not in cols:
                conn.execute(f"ALTER TABLE run_hostinfo ADD COLUMN {col} TEXT")
        conn.commit()
    except sqlite3.OperationalError:
        pass

    # Migration: run_group_members add member_uid
    try:
        cols = [r[1] for r in conn.execute("PRAGMA table_info('run_group_members')").fetchall()]
        if "member_uid" not in cols:
            conn.execute("ALTER TABLE run_group_members ADD COLUMN member_uid INTEGER")
            conn.commit()
    except sqlite3.OperationalError:
        pass

    # Migration: run_groups add group_type
    try:
        cols = [r[1] for r in conn.execute("PRAGMA table_info('run_groups')").fetchall()]
        if "group_type" not in cols:
            conn.execute("ALTER TABLE run_groups ADD COLUMN group_type TEXT")
            conn.commit()
    except sqlite3.OperationalError:
        pass

    # Migration: run_interface_addrs add addr_type
    try:
        cols = [r[1] for r in conn.execute("PRAGMA table_info('run_interface_addrs')").fetchall()]
        if "addr_type" not in cols:
            conn.execute("ALTER TABLE run_interface_addrs ADD COLUMN addr_type TEXT")
            conn.commit()
    except sqlite3.OperationalError:
        pass

    # Migration: run_interfaces add iface_type
    try:
        cols = [r[1] for r in conn.execute("PRAGMA table_info('run_interfaces')").fetchall()]
        if "iface_type" not in cols:
            conn.execute("ALTER TABLE run_interfaces ADD COLUMN iface_type TEXT")
            conn.commit()
    except sqlite3.OperationalError:
        pass

    # Migration: run_ip_neigh add ip_type
    try:
        cols = [r[1] for r in conn.execute("PRAGMA table_info('run_ip_neigh')").fetchall()]
        if "ip_type" not in cols:
            conn.execute("ALTER TABLE run_ip_neigh ADD COLUMN ip_type TEXT")
            conn.commit()
    except sqlite3.OperationalError:
        pass

    # Migration: run_containers table (per-container rows from docker/podman ps -a)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS run_containers (
              container_row_id INTEGER PRIMARY KEY,
              run_id INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
              runtime TEXT NOT NULL,
              container_id TEXT,
              image TEXT,
              status TEXT,
              names TEXT,
              created_text TEXT,
              ports_text TEXT,
              raw_line TEXT,
              UNIQUE(run_id, runtime, container_id)
            )
            """
        )
        conn.commit()
    except sqlite3.OperationalError:
        pass

    # Migration: run_routes add dest_type
    try:
        cols = [r[1] for r in conn.execute("PRAGMA table_info('run_routes')").fetchall()]
        if "dest_type" not in cols:
            conn.execute("ALTER TABLE run_routes ADD COLUMN dest_type TEXT")
            conn.commit()
    except sqlite3.OperationalError:
        pass
    # Migration: run_listening_sockets add bind_scope
    try:
        cols = [r[1] for r in conn.execute("PRAGMA table_info('run_listening_sockets')").fetchall()]
        if "bind_scope" not in cols:
            conn.execute("ALTER TABLE run_listening_sockets ADD COLUMN bind_scope TEXT")
            conn.commit()
    except sqlite3.OperationalError:
        pass
    # Migration: run_services_systemctl add unit_type
    try:
        cols = [r[1] for r in conn.execute("PRAGMA table_info('run_services_systemctl')").fetchall()]
        if "unit_type" not in cols:
            conn.execute("ALTER TABLE run_services_systemctl ADD COLUMN unit_type TEXT")
            conn.commit()
    except sqlite3.OperationalError:
        pass
    # Migration: run_systemd_enabled_unit_files add unit_type
    try:
        cols = [r[1] for r in conn.execute("PRAGMA table_info('run_systemd_enabled_unit_files')").fetchall()]
        if "unit_type" not in cols:
            conn.execute("ALTER TABLE run_systemd_enabled_unit_files ADD COLUMN unit_type TEXT")
            conn.commit()
    except sqlite3.OperationalError:
        pass
    # Migration: run_priv_groups add group_type
    try:
        cols = [r[1] for r in conn.execute("PRAGMA table_info('run_priv_groups')").fetchall()]
        if "group_type" not in cols:
            conn.execute("ALTER TABLE run_priv_groups ADD COLUMN group_type TEXT")
            conn.commit()
    except sqlite3.OperationalError:
        pass
    # Migration: run_usb_devices add device_class_label
    try:
        cols = [r[1] for r in conn.execute("PRAGMA table_info('run_usb_devices')").fetchall()]
        if "device_class_label" not in cols:
            conn.execute("ALTER TABLE run_usb_devices ADD COLUMN device_class_label TEXT")
            conn.commit()
    except sqlite3.OperationalError:
        pass
    # Migration: run_sudoers_rules add rule_type
    try:
        cols = [r[1] for r in conn.execute("PRAGMA table_info('run_sudoers_rules')").fetchall()]
        if "rule_type" not in cols:
            conn.execute("ALTER TABLE run_sudoers_rules ADD COLUMN rule_type TEXT")
            conn.commit()
    except sqlite3.OperationalError:
        pass

    # Migration: ref_firewall_type and run_firewall_rules chain/target
    try:
        conn.execute("CREATE TABLE IF NOT EXISTS ref_firewall_type (source_tag TEXT PRIMARY KEY, description TEXT)")
        for tag, desc in [
            ("iptables_s", "iptables save-style rules (-S)"),
            ("iptables_list", "iptables list (-L -n -v)"),
            ("ufw_raw", "UFW raw iptables rules"),
            ("firewalld_zones", "firewalld zone configuration"),
        ]:
            conn.execute("INSERT OR IGNORE INTO ref_firewall_type(source_tag, description) VALUES (?, ?)", (tag, desc))
        conn.commit()
    except sqlite3.OperationalError:
        pass
    try:
        cols = [r[1] for r in conn.execute("PRAGMA table_info('run_firewall_rules')").fetchall()]
        for col, typ in [("chain", "TEXT"), ("target", "TEXT")]:
            if col not in cols:
                conn.execute(f"ALTER TABLE run_firewall_rules ADD COLUMN {col} {typ}")
        conn.commit()
    except sqlite3.OperationalError:
        pass

    # Migration: ref_permissions and run_file_listings new columns
    try:
        conn.execute("CREATE TABLE IF NOT EXISTS ref_permissions (perm_rwx TEXT PRIMARY KEY, perm_octal INTEGER, perm_kind TEXT)")
        conn.commit()
    except sqlite3.OperationalError:
        pass
    try:
        cols = [r[1] for r in conn.execute("PRAGMA table_info('run_file_listings')").fetchall()]
        for col, typ in [("perm_octal", "INTEGER"), ("mtime_normalized_utc", "TEXT"), ("filename", "TEXT"), ("is_symlink", "INTEGER"), ("symlink_target", "TEXT")]:
            if col not in cols:
                conn.execute(f"ALTER TABLE run_file_listings ADD COLUMN {col} {typ}")
        conn.commit()
    except sqlite3.OperationalError:
        pass
    
    # Migration: run_systemd_timers table schema update
    try:
        cols = [r[1] for r in conn.execute("PRAGMA table_info('run_systemd_timers')").fetchall()]
        if "next" not in cols or "left" not in cols or "raw_line" not in cols:
            # Old schema detected
            existing_data = conn.execute("SELECT * FROM run_systemd_timers").fetchall()
            conn.execute("DROP TABLE IF EXISTS run_systemd_timers")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS run_systemd_timers (
                  run_id INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
                  next TEXT,
                  left TEXT,
                  last TEXT,
                  passed TEXT,
                  unit TEXT NOT NULL,
                  activates TEXT,
                  raw_line TEXT NOT NULL,
                  PRIMARY KEY (run_id, unit)
                )
            """)
            conn.commit()
    except sqlite3.OperationalError:
        pass
    
    # Migrate asset_identifiers to v2:
    # - add identifier_id primary key
    # - remove global uniqueness on (id_type,id_value) to tolerate cloned identifiers
    try:
        cols = [r[1] for r in conn.execute("PRAGMA table_info('asset_identifiers')").fetchall()]
        if "identifier_id" not in cols:
            conn.executescript(
            """
            BEGIN;
            ALTER TABLE asset_identifiers RENAME TO asset_identifiers_old;
            CREATE TABLE asset_identifiers (
              identifier_id INTEGER PRIMARY KEY,
              asset_id INTEGER NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
              id_type TEXT NOT NULL,
              id_value TEXT NOT NULL,
              first_seen_utc TEXT NOT NULL,
              last_seen_utc TEXT NOT NULL,
              UNIQUE(asset_id, id_type, id_value)
            );
            CREATE INDEX IF NOT EXISTS idx_asset_identifiers_type_value ON asset_identifiers(id_type, id_value);
            INSERT INTO asset_identifiers(asset_id, id_type, id_value, first_seen_utc, last_seen_utc)
            SELECT asset_id, id_type, id_value, first_seen_utc, last_seen_utc
            FROM asset_identifiers_old;
            DROP TABLE asset_identifiers_old;
            COMMIT;
            """
            )
            conn.commit()
    except sqlite3.OperationalError:
        # Table doesn't exist yet, will be created by schema
        pass


_CATALOG_OVERRIDES: dict[str, dict[str, str]] = {
    # Identity / OS
    "hostnamectl": {
        "short": "Host identity and OS headline metadata.",
        "long": "Collects stable host identity and OS metadata (hostname, OS name, kernel, architecture, vendor/model, machine-id). Useful for asset identification, drift detection, and forensic context.",
        "parse_status": "parsed",
    },
    "etc_release": {
        "short": "Distribution release metadata (/etc/*release*).",
        "long": "Captures distro identifiers and version strings (ID, VERSION_ID, PRETTY_NAME, etc.) used for patching/vuln matching and cross-host comparison.",
        "parse_status": "parsed",
    },
    "timedatectl": {
        "short": "Time sync posture and timezone (timedatectl).",
        "long": "Shows NTP service status, whether the system clock is synchronized, and timezone. Time sync is critical for log integrity, correlation, and incident response timelines.",
        "parse_status": "parsed",
    },
    # Logon / history
    "who_a": {
        "short": "Current and historical login/session context (who -a).",
        "long": "Provides active sessions, runlevel, and boot context. Useful for detecting unexpected users, remote access, and interactive activity at collection time.",
        "parse_status": "parsed",
    },
    "w": {
        "short": "Active user sessions with source IPs (w).",
        "long": "Summarizes who is logged in, from where, and what they’re doing. Useful for spotting unexpected remote sessions and interactive activity.",
        "parse_status": "parsed",
    },
    "lastlog": {
        "short": "Last login per account (lastlog).",
        "long": "Shows last-login time and source for each account. Useful for identifying dormant accounts suddenly used, service accounts with interactive logins, and suspicious access patterns.",
        "parse_status": "parsed",
    },
    "last_wtmp": {
        "short": "Successful login history (wtmp via last).",
        "long": "Shows successful logins and session durations. Useful for detecting lateral movement, unusual login times, and unexpected source hosts.",
        "parse_status": "parsed",
    },
    "last_btmp": {
        "short": "Failed login history (btmp via last).",
        "long": "Shows failed login attempts. Useful for brute-force detection and identifying targeted accounts/hosts.",
        "parse_status": "parsed",
    },
    "last_utmp": {
        "short": "Current sessions snapshot (utmp via last).",
        "long": "Shows current logins (utmp). Useful for verifying active sessions at collection time.",
        "parse_status": "parsed",
    },
    # Audit / MAC
    "auditctl_s": {
        "short": "Audit subsystem status (auditctl -s).",
        "long": "Indicates whether Linux audit is enabled/locked, backlog settings, and failures. Essential for compliance and tamper-resistant logging posture.",
        "parse_status": "parsed",
    },
    "auditctl_l": {
        "short": "Loaded audit rules (auditctl -l).",
        "long": "Lists audit rules currently active. Useful for checking required coverage (e.g., auth, privilege use) and detecting unexpected rule changes.",
        "parse_status": "parsed",
    },
    "df_B1": {
        "short": "Disk free per mount in bytes (df -B1).",
        "long": "Shows filesystem size, used, and available space in bytes per mount. Complements lsblk for available disk space and capacity planning.",
        "parse_status": "parsed",
    },
    "rsyslog_conf": {
        "short": "Rsyslog configuration (/etc/rsyslog.conf).",
        "long": "Captures rsyslog config including remote log destinations (*.* @host, *.* @@host). Parsed for explicit remote-destination extraction.",
        "parse_status": "parsed",
    },
    "journald_conf": {
        "short": "Journald configuration (/etc/systemd/journald.conf).",
        "long": "Captures journald config (ForwardToSyslog, etc.). Parsed for remote-forwarding and logging posture.",
        "parse_status": "parsed",
    },
    "login_defs": {
        "short": "Login defaults (/etc/login.defs).",
        "long": "Password policy and UID/GID ranges (PASS_MAX_DAYS, PASS_MIN_DAYS, UID_MIN, etc.). Parsed as key/value.",
        "parse_status": "parsed",
    },
    "sestatus": {
        "short": "SELinux enablement/enforcement state.",
        "long": "Shows whether SELinux is enabled and in enforcing/permissive/disabled mode, plus policy details. Key host hardening and containment control.",
        "parse_status": "parsed",
    },
    "getsebool_a": {
        "short": "SELinux boolean settings (getsebool -a).",
        "long": "Enumerates SELinux booleans. Useful for detecting risky toggles that widen access (e.g., network connectivity permissions).",
        "parse_status": "parsed",
    },
    "aa_status": {
        "short": "AppArmor status summary (aa-status).",
        "long": "Summarizes AppArmor profile enforcement/complain mode. Useful for verifying MAC posture on Ubuntu/Debian systems.",
        "parse_status": "parsed",
    },
    # Network
    "resolv_conf": {
        "short": "DNS resolver configuration (/etc/resolv.conf).",
        "long": "Captures nameservers, search domains, and resolver options. Useful for detecting DNS hijacking, split-horizon behavior, and policy compliance.",
        "parse_status": "parsed",
    },
    "ip_neigh": {
        "short": "ARP/neighbor cache (ip neigh).",
        "long": "Shows recently resolved neighbors and MAC addresses. Useful for situational awareness and detecting unexpected neighbors/routers.",
        "parse_status": "parsed",
    },
    "route_n": {
        "short": "Routing table (route -n).",
        "long": "Shows routes and default gateway. Useful for detecting unexpected routing (exfil paths, rogue gateways) and confirming segmentation.",
        "parse_status": "parsed",
    },
    "nmcli": {
        "short": "NetworkManager status and connectivity (nmcli).",
        "long": "Shows connectivity state and device radio status when NetworkManager is used. Helpful for laptop/workstation posture and troubleshooting.",
        "parse_status": "parsed",
    },
    # Process / kernel
    "ps_elf": {
        "short": "Full process inventory (ps -elf).",
        "long": "Lists processes with parentage and command lines. Useful for spotting suspicious binaries, anomalous daemons, and unexpected parent/child relationships.",
        "parse_status": "parsed",
    },
    "pstree": {
        "short": "Process tree view (pstree).",
        "long": "Shows process hierarchy visually. Useful for quickly spotting unusual process trees and parentage.",
        "parse_status": "parsed",
    },
    "lsmod": {
        "short": "Loaded kernel modules (lsmod).",
        "long": "Lists loaded kernel modules. Useful for detecting unexpected drivers/rootkits and verifying required modules only.",
        "parse_status": "parsed",
    },
    "modinfo_all": {
        "short": "Kernel module metadata (modinfo for all loaded modules).",
        "long": "Collects module filenames, versions, licenses, descriptions, and aliases. Useful for verifying provenance and detecting anomalous modules.",
        "parse_status": "parsed",
    },
    # Persistence surfaces
    "ls_etc_cron": {
        "short": "Cron directories recursive listing (/etc/cron*).",
        "long": "Captures cron directories and file metadata. Cron is a common persistence mechanism; reviewing unexpected jobs and timestamps is high value.",
        "parse_status": "parsed",
    },
    "ls_var_spool_cron": {
        "short": "User crontabs directory listing (/var/spool/cron).",
        "long": "Captures user crontabs/spool entries. Useful for detecting user-level persistence.",
        "parse_status": "parsed",
    },
    "ls_etc_systemd_system": {
        "short": "Systemd unit directory recursive listing (/etc/systemd/system).",
        "long": "Captures systemd unit overrides and custom services. Systemd is a common persistence mechanism; timestamps and unexpected units matter.",
        "parse_status": "parsed",
    },
    "recent_bins": {
        "short": "Recently modified binaries in PATH locations.",
        "long": "Lists binaries in common PATH directories modified within a window. Useful IOC heuristic for recent tampering or dropped tools.",
        "parse_status": "parsed",
    },
    # Boot / hardening
    "proc_cmdline": {
        "short": "Kernel boot parameters (/proc/cmdline).",
        "long": "Captures the kernel command line (boot parameters). Useful for detecting disabled security controls (e.g., audit=0, selinux=0), unusual mitigations, and boot-time tampering.",
        "parse_status": "parsed",
    },
    "sysctl_hardening": {
        "short": "Targeted sysctl hardening posture.",
        "long": "Captures a focused set of security-relevant sysctls (kernel pointer restrictions, dmesg restrictions, unprivileged BPF, fs.protected_*, rp_filter, forwarding, IPv6 disablement). Useful for posture auditing and drift detection.",
        "parse_status": "parsed",
    },
    "mokutil_sb_state": {
        "short": "Secure Boot state (mokutil --sb-state).",
        "long": "Reports Secure Boot state where supported. Useful for understanding boot chain integrity on UEFI systems. May be unavailable on some systems.",
        "parse_status": "parsed",
    },
    # SSH / sudo
    "sshd_T": {
        "short": "Effective SSH server configuration (sshd -T).",
        "long": "Collects the effective sshd configuration as key/value pairs. High-value for auditing remote access posture (PermitRootLogin, PasswordAuthentication, AllowedUsers/Groups, ciphers/MACs, etc.).",
        "parse_status": "parsed",
    },
    "sshd_config": {
        "short": "Raw sshd_config (/etc/ssh/sshd_config).",
        "long": "Captures the SSH daemon configuration file for audit and troubleshooting. Stored raw; prefer using sshd -T for effective settings.",
        "parse_status": "raw",
    },
    "sshd_config_d_ls": {
        "short": "List sshd_config.d directory (/etc/ssh/sshd_config.d).",
        "long": "Lists sshd drop-in configuration directory. Useful for discovering additional sshd configuration files that may override defaults.",
        "parse_status": "raw",
    },
    "sshd_config_d_cat": {
        "short": "Raw sshd_config drop-ins (/etc/ssh/sshd_config.d/*).",
        "long": "Captures sshd drop-in configuration files. Stored raw; prefer using sshd -T for effective settings.",
        "parse_status": "raw",
    },
    "ssh_hostkey_fps": {
        "short": "SSH host key fingerprints (ssh-keygen -lf).",
        "long": "Captures SSH host key fingerprints (public keys only). Useful to detect unexpected host key changes (potential MITM or host rebuild) and to establish trust anchors.",
        "parse_status": "parsed",
    },
    "sudoers": {
        "short": "Sudo policy (/etc/sudoers).",
        "long": "Captures sudoers rules and Defaults. Useful for detecting NOPASSWD, broad ALL=(ALL) rules, and unexpected privilege grants.",
        "parse_status": "parsed",
    },
    "sudoers_d_ls": {
        "short": "List sudoers.d directory (/etc/sudoers.d).",
        "long": "Lists sudoers drop-in configuration directory. Useful for discovering additional sudo policy files.",
        "parse_status": "raw",
    },
    "sudoers_d_cat": {
        "short": "Sudoers drop-ins (/etc/sudoers.d/*).",
        "long": "Captures sudoers drop-in rules. Useful for detecting NOPASSWD and unexpected privilege grants.",
        "parse_status": "parsed",
    },
    # Firewall / network
    "nft_ruleset": {
        "short": "nftables ruleset (nft list ruleset).",
        "long": "Captures the nftables ruleset where available. Many modern distros use nftables directly or via iptables-nft; this helps validate firewall posture.",
        "parse_status": "parsed",
    },
    # Telemetry / logs (bounded)
    "journalctl_ssh_7d": {
        "short": "Recent SSH-related journal logs (journalctl -u ssh -u sshd).",
        "long": "Captures recent SSH daemon logs (last ~7 days) where journald is used. Useful for spotting brute force, accepted logins, and auth anomalies without full log export.",
        "parse_status": "parsed",
    },
    "tail_auth_log": {
        "short": "Recent auth.log tail (tail -n 200 /var/log/auth.log).",
        "long": "Captures the last 200 lines of /var/log/auth.log on Debian/Ubuntu-style systems. Useful for quick triage of authentication events.",
        "parse_status": "parsed",
    },
    "tail_secure": {
        "short": "Recent secure log tail (tail -n 200 /var/log/secure).",
        "long": "Captures the last 200 lines of /var/log/secure on RHEL-style systems. Useful for quick triage of authentication and sudo events.",
        "parse_status": "parsed",
    },
    # Persistence / privilege surfaces
    "ld_so_preload": {
        "short": "Dynamic linker preload configuration (/etc/ld.so.preload).",
        "long": "Captures /etc/ld.so.preload which can force-load shared objects into processes. High-signal persistence/stealth hook surface.",
        "parse_status": "parsed",
    },
    "getcap_r": {
        "short": "File capabilities (getcap -r /).",
        "long": "Collects Linux file capabilities across the filesystem (best-effort; may be time-bounded). Capabilities can grant privileged operations without SUID and are a common escalation/persistence surface.",
        "parse_status": "parsed",
    },
    # systemd posture
    "systemctl_timers": {
        "short": "Systemd timers (systemctl list-timers --all).",
        "long": "Lists systemd timers which can act as persistence mechanisms or scheduled jobs. Useful for detecting unexpected timers and drift.",
        "parse_status": "parsed",
    },
    "systemctl_enabled_unit_files": {
        "short": "Enabled systemd unit files (systemctl list-unit-files --state=enabled).",
        "long": "Lists enabled unit files. Useful for identifying persistence via enabled services/timers and unexpected startup behavior.",
        "parse_status": "parsed",
    },
    # Containers
    "docker_ps_a": {
        "short": "Docker container inventory (docker ps -a).",
        "long": "Lists all Docker containers. Useful for understanding containerized workloads and spotting unexpected containers.",
        "parse_status": "parsed",
    },
    "docker_info": {
        "short": "Docker daemon info (docker info).",
        "long": "Captures Docker daemon configuration and environment details. Useful for understanding exposure (rootless, cgroup driver, storage) and drift.",
        "parse_status": "parsed",
    },
    "podman_ps_a": {
        "short": "Podman container inventory (podman ps -a).",
        "long": "Lists all Podman containers. Useful for understanding containerized workloads and spotting unexpected containers.",
        "parse_status": "parsed",
    },
    "podman_info": {
        "short": "Podman info (podman info).",
        "long": "Captures Podman runtime configuration and environment details. Useful for understanding exposure and drift.",
        "parse_status": "parsed",
    },
    # Sensitive
    "root_bash_history": {
        "short": "Root shell history (sensitive).",
        "long": "Captures root bash history for triage. May include secrets/tokens/commands. Treat as sensitive and restrict access.",
        "parse_status": "raw",
    },
    "printenv": {
        "short": "Environment variables (sensitive).",
        "long": "Captures environment variables which may include secrets. Treat as sensitive; useful for detecting malicious env injection or misconfigurations.",
        "parse_status": "raw",
    },
}


def upsert_command_catalog(conn: sqlite3.Connection, *, command_tag: str, section: Optional[str], command: str) -> None:
    """
    Ensures a catalog entry exists for this command_tag.
    Unknown tags get a generic description; known tags get richer text.
    """
    o = _CATALOG_OVERRIDES.get(command_tag)
    if o:
        short = o["short"]
        long = o["long"]
        parse_status = o.get("parse_status", "raw")
        sensitivity = "sensitive" if command_tag in ("root_bash_history", "printenv") else "normal"
    else:
        short = f"Baseline command output: {command}"
        long = f"Captured raw output of `{command}` from the host for situational awareness and later analysis. This command is stored losslessly in `run_commands`."
        parse_status = "raw"
        sensitivity = "normal"

    conn.execute(
        """
        INSERT INTO command_catalog(command_tag, section, command, short_desc, long_desc, data_sensitivity, parse_status, updated_at_utc)
        VALUES (?, ?, ?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        ON CONFLICT(command_tag) DO UPDATE SET
          section=excluded.section,
          command=excluded.command,
          short_desc=excluded.short_desc,
          long_desc=excluded.long_desc,
          data_sensitivity=excluded.data_sensitivity,
          parse_status=excluded.parse_status,
          updated_at_utc=excluded.updated_at_utc
        """,
        (command_tag, section, command, short, long, sensitivity, parse_status),
    )


def upsert_assets_from_csv(conn: sqlite3.Connection, csv_path: Path) -> None:
    with csv_path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if not row.get("hostname"):
                continue
            asset_id = int(row["asset_id"]) if row.get("asset_id") else None
            hostname = row.get("hostname") or None
            domain = row.get("domain") or None
            fqdn = row.get("fqdn") or None
            classification = row.get("classification") or None
            location = row.get("location") or None

            if asset_id is None or hostname is None:
                continue

            conn.execute(
                """
                INSERT INTO assets(asset_id, hostname, domain, fqdn, classification, location, updated_at_utc)
                VALUES (?, ?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
                ON CONFLICT(asset_id) DO UPDATE SET
                  hostname=excluded.hostname,
                  domain=excluded.domain,
                  fqdn=excluded.fqdn,
                  classification=excluded.classification,
                  location=excluded.location,
                  updated_at_utc=excluded.updated_at_utc
                """,
                (asset_id, hostname, domain, fqdn, classification, location),
            )

            def to_int(v: Optional[str]) -> Optional[int]:
                if v is None:
                    return None
                v = v.strip()
                if not v:
                    return None
                try:
                    return int(float(v))
                except ValueError:
                    return None

            def to_float(v: Optional[str]) -> Optional[float]:
                if v is None:
                    return None
                v = v.strip()
                if not v:
                    return None
                try:
                    return float(v)
                except ValueError:
                    return None

            # CSV has a couple typos in column names; map them here.
            inv = {
                "server_manufacturer": row.get("server_manufacturer"),
                "server_model_series": row.get("server_model_series"),
                "server_model_no": row.get("server_model_no"),
                "proc_manufacturer": row.get("proc_manufacturer"),
                "proc_model_series": row.get("proc_model_series"),
                "proc_model_no": row.get("proc_model_no"),
                "proc_no_cores": to_int(row.get("proc_no_cores")),
                "proc_count": to_int(row.get("proc_count")),
                "gpu_manufacturer": row.get("gpu_manufacturer"),
                "gpu_model_series": row.get("gpu_model_series"),
                "gpu_model_no": row.get("gpu_model_no"),
                "gpu_count": to_int(row.get("gpu_count")),
                "memory_capacity_gb": to_float(row.get("memory_capacity_gb")),
                "storage_hdd_no_drives": to_int(row.get("storage_hdd_no_drives")),
                "storage_hdd_capacity_gb": to_float(row.get("storage_hdd_capacity_gb")),
                "storage_nvme_no_drives": to_int(row.get("storage_nvme_no_drives")),
                "storage_nvme_capacity_gb": to_float(row.get("storage_nvme_capabity_gb")),
                "storage_ssd_no_drives": to_int(row.get("storage_ssd_no_drives")),
                "storage_ssd_capacity_gb": to_float(row.get("storage_ssd_capabity_gb")),
                "os_name": row.get("os_name"),
                "os_version": row.get("os_version"),
                "arch": row.get("arch"),
                "primary_ip": row.get("primary_ip"),
                "interface": row.get("interface"),
                "mac_addr": row.get("mac_addr"),
                "vlan": row.get("vlan"),
                "last_updated": row.get("last_updated"),
            }

            conn.execute(
                """
                INSERT INTO asset_inventory(
                  asset_id,
                  server_manufacturer, server_model_series, server_model_no,
                  proc_manufacturer, proc_model_series, proc_model_no, proc_no_cores, proc_count,
                  gpu_manufacturer, gpu_model_series, gpu_model_no, gpu_count,
                  memory_capacity_gb,
                  storage_hdd_no_drives, storage_hdd_capacity_gb,
                  storage_nvme_no_drives, storage_nvme_capacity_gb,
                  storage_ssd_no_drives, storage_ssd_capacity_gb,
                  os_name, os_version, arch,
                  primary_ip, interface, mac_addr, vlan, last_updated
                )
                VALUES (
                  ?,
                  ?, ?, ?,
                  ?, ?, ?, ?, ?,
                  ?, ?, ?, ?,
                  ?,
                  ?, ?,
                  ?, ?,
                  ?, ?,
                  ?, ?, ?,
                  ?, ?, ?, ?, ?
                )
                ON CONFLICT(asset_id) DO UPDATE SET
                  server_manufacturer=excluded.server_manufacturer,
                  server_model_series=excluded.server_model_series,
                  server_model_no=excluded.server_model_no,
                  proc_manufacturer=excluded.proc_manufacturer,
                  proc_model_series=excluded.proc_model_series,
                  proc_model_no=excluded.proc_model_no,
                  proc_no_cores=excluded.proc_no_cores,
                  proc_count=excluded.proc_count,
                  gpu_manufacturer=excluded.gpu_manufacturer,
                  gpu_model_series=excluded.gpu_model_series,
                  gpu_model_no=excluded.gpu_model_no,
                  gpu_count=excluded.gpu_count,
                  memory_capacity_gb=excluded.memory_capacity_gb,
                  storage_hdd_no_drives=excluded.storage_hdd_no_drives,
                  storage_hdd_capacity_gb=excluded.storage_hdd_capacity_gb,
                  storage_nvme_no_drives=excluded.storage_nvme_no_drives,
                  storage_nvme_capacity_gb=excluded.storage_nvme_capacity_gb,
                  storage_ssd_no_drives=excluded.storage_ssd_no_drives,
                  storage_ssd_capacity_gb=excluded.storage_ssd_capacity_gb,
                  os_name=excluded.os_name,
                  os_version=excluded.os_version,
                  arch=excluded.arch,
                  primary_ip=excluded.primary_ip,
                  interface=excluded.interface,
                  mac_addr=excluded.mac_addr,
                  vlan=excluded.vlan,
                  last_updated=excluded.last_updated
                """,
                (
                    asset_id,
                    inv["server_manufacturer"],
                    inv["server_model_series"],
                    inv["server_model_no"],
                    inv["proc_manufacturer"],
                    inv["proc_model_series"],
                    inv["proc_model_no"],
                    inv["proc_no_cores"],
                    inv["proc_count"],
                    inv["gpu_manufacturer"],
                    inv["gpu_model_series"],
                    inv["gpu_model_no"],
                    inv["gpu_count"],
                    inv["memory_capacity_gb"],
                    inv["storage_hdd_no_drives"],
                    inv["storage_hdd_capacity_gb"],
                    inv["storage_nvme_no_drives"],
                    inv["storage_nvme_capacity_gb"],
                    inv["storage_ssd_no_drives"],
                    inv["storage_ssd_capacity_gb"],
                    inv["os_name"],
                    inv["os_version"],
                    inv["arch"],
                    inv.get("primary_ip"),
                    inv["interface"],
                    inv["mac_addr"],
                    inv["vlan"],
                    inv["last_updated"],
                ),
            )

    conn.commit()


def find_asset_id_by_hostname(conn: sqlite3.Connection, hostname: str) -> Optional[int]:
    row = conn.execute("SELECT asset_id FROM assets WHERE hostname = ?", (hostname,)).fetchone()
    return int(row[0]) if row else None


def find_asset_id_by_identifier(conn: sqlite3.Connection, id_type: str, id_value: str) -> Optional[int]:
    """
    Returns an asset_id only if the identifier resolves uniquely.
    If multiple assets share the same identifier (possible with cloned images),
    returns None to avoid incorrect merges.
    """
    rows = conn.execute(
        "SELECT DISTINCT asset_id FROM asset_identifiers WHERE id_type = ? AND id_value = ?",
        (id_type, id_value),
    ).fetchall()
    if len(rows) == 1:
        return int(rows[0][0])
    return None


def normalize_hostname(hostname: str) -> str:
    return (hostname or "").strip().lower()


def hostname_slug(hostname: str) -> str:
    """
    Normalizes a hostname to a punctuation-insensitive slug for aliasing/merges
    (e.g., ampere-1 -> ampere1).
    """
    return re.sub(r"[^a-z0-9]+", "", normalize_hostname(hostname))


def is_fake_identifier(id_type: str, id_value: str) -> bool:
    """
    Detect obviously fake/placeholder identifiers that should not be trusted for identity resolution.
    """
    if not id_value or not id_value.strip():
        return True

    value = id_value.strip()

    # Common fake serial numbers
    if id_type in ('serial_number', 'dmi_uuid'):
        fake_patterns = [
            r'^0+$',           # All zeros
            r'^123456789',     # Common placeholder
            r'^00000000',      # All zeros (UUID format)
            r'^[f-]+$',        # All F's or dashes (UUID)
            r'^none$',         # Literal "none"
            r'^null$',         # Literal "null"
            r'^n/a$',          # Not available
            r'^unknown$',      # Unknown
        ]
        if any(re.match(pattern, value.lower()) for pattern in fake_patterns):
            return True

    # Fake machine IDs (all zeros or repeated patterns)
    if id_type == 'machine_id':
        if re.match(r'^0+$', value) or len(set(value)) == 1:
            return True

    return False


def score_identifier(id_type: str, id_value: str, hostname: str) -> int:
    """
    Score an identifier's reliability for asset identity resolution.
    Higher scores = more reliable for unique identification.
    Returns 0 for identifiers that should not be used for identity.
    """
    if is_fake_identifier(id_type, id_value):
        return 0

    base_scores = {
        'primary_mac': 100,      # Most reliable - hardware MAC of baseline IP interface
        'dmi_uuid': 90,          # Very reliable if not fake
        'hostname': 80,          # Usually stable, but can change
        'machine_id': 0,         # Not used for asset resolution - tracked as property only
        'serial_number': 40,     # Often fake or generic
    }

    score = base_scores.get(id_type, 10)

    # Boost score if hostname is consistent with identifier
    if id_type == 'hostname' and hostname and normalize_hostname(id_value) == normalize_hostname(hostname):
        score += 20

    return score


def find_asset_id_by_hostname_slug(conn: sqlite3.Connection, desired_hostname: str, *, exclude_asset_id: Optional[int] = None) -> Optional[int]:
    """
    Best-effort aliasing: if exactly one existing asset matches by slug, return it.
    """
    want = hostname_slug(desired_hostname)
    if not want:
        return None
    rows = conn.execute("SELECT asset_id, hostname FROM assets").fetchall()
    matches = []
    for asset_id, hn in rows:
        if exclude_asset_id is not None and int(asset_id) == int(exclude_asset_id):
            continue
        if hostname_slug(str(hn)) == want:
            matches.append(int(asset_id))
    if len(matches) == 1:
        return matches[0]
    return None

def _asset_has_inventory(conn: sqlite3.Connection, asset_id: int) -> bool:
    row = conn.execute("SELECT 1 FROM asset_inventory WHERE asset_id = ? LIMIT 1", (asset_id,)).fetchone()
    return row is not None


def sync_asset_inventory_from_runs(conn: sqlite3.Connection) -> None:
    """
    Populate or update asset_inventory from run_* tables using v_host_inventory_current.
    Ensures every asset that has at least one baseline run gets inventory derived from that run.
    """
    conn.execute(
        """
        INSERT INTO asset_inventory (
          asset_id, server_manufacturer, server_model_series, server_model_no,
          proc_manufacturer, proc_model_series, proc_model_no, proc_no_cores, proc_count,
          gpu_manufacturer, gpu_model_series, gpu_model_no, gpu_count,
          memory_capacity_gb,
          storage_hdd_no_drives, storage_hdd_capacity_gb,
          storage_nvme_no_drives, storage_nvme_capacity_gb,
          storage_ssd_no_drives, storage_ssd_capacity_gb,
          os_name, os_version, arch,
          primary_ip, interface, mac_addr, vlan, last_updated
        )
        SELECT
          a.asset_id,
          v.server_manufacturer, v.server_model_series, v.server_model_no,
          v.proc_manufacturer, v.proc_model_series, v.proc_model_no, v.proc_no_cores, v.proc_count,
          v.gpu_manufacturer, v.gpu_model_series, v.gpu_model_no, v.gpu_count,
          v.memory_capacity_gb,
          v.storage_hdd_no_drives, v.storage_hdd_capacity_gb,
          v.storage_nvme_no_drives, v.storage_nvme_capabity_gb,
          v.storage_ssd_no_drives, v.storage_ssd_capabity_gb,
          v.os_name, v.os_version, v.arch,
          v.primary_ip, v.interface, v.mac_addr,
          NULL, strftime('%Y-%m-%dT%H:%M:%fZ','now')
        FROM assets a
        JOIN v_host_inventory_current v ON v.hostname = a.hostname
        ON CONFLICT(asset_id) DO UPDATE SET
          server_manufacturer=excluded.server_manufacturer,
          server_model_series=excluded.server_model_series,
          server_model_no=excluded.server_model_no,
          proc_manufacturer=excluded.proc_manufacturer,
          proc_model_series=excluded.proc_model_series,
          proc_model_no=excluded.proc_model_no,
          proc_no_cores=excluded.proc_no_cores,
          proc_count=excluded.proc_count,
          gpu_manufacturer=excluded.gpu_manufacturer,
          gpu_model_series=excluded.gpu_model_series,
          gpu_model_no=excluded.gpu_model_no,
          gpu_count=excluded.gpu_count,
          memory_capacity_gb=excluded.memory_capacity_gb,
          storage_hdd_no_drives=excluded.storage_hdd_no_drives,
          storage_hdd_capacity_gb=excluded.storage_hdd_capacity_gb,
          storage_nvme_no_drives=excluded.storage_nvme_no_drives,
          storage_nvme_capacity_gb=excluded.storage_nvme_capacity_gb,
          storage_ssd_no_drives=excluded.storage_ssd_no_drives,
          storage_ssd_capacity_gb=excluded.storage_ssd_capacity_gb,
          os_name=excluded.os_name,
          os_version=excluded.os_version,
          arch=excluded.arch,
          primary_ip=excluded.primary_ip,
          interface=excluded.interface,
          mac_addr=excluded.mac_addr,
          last_updated=excluded.last_updated
        """
    )


def get_asset_identity_conflicts(conn: sqlite3.Connection) -> list[dict]:
    """
    Diagnostic function: returns identifiers that map to multiple assets,
    indicating potential identity resolution issues.
    """
    conflicts = []

    # Find identifiers shared by multiple assets
    rows = conn.execute("""
        SELECT id_type, id_value, GROUP_CONCAT(asset_id) as asset_ids,
               COUNT(DISTINCT asset_id) as asset_count
        FROM asset_identifiers
        GROUP BY id_type, id_value
        HAVING asset_count > 1
        ORDER BY id_type, id_value
    """).fetchall()

    for id_type, id_value, asset_ids_str, count in rows:
        asset_ids = [int(x) for x in asset_ids_str.split(',')]

        # Get hostnames for these assets
        asset_info = []
        for asset_id in asset_ids:
            row = conn.execute(
                "SELECT hostname FROM assets WHERE asset_id = ?",
                (asset_id,)
            ).fetchone()
            hostname = row[0] if row else "unknown"
            asset_info.append(f"{hostname} (ID: {asset_id})")

        conflicts.append({
            'id_type': id_type,
            'id_value': id_value,
            'assets': asset_info,
            'is_fake': is_fake_identifier(id_type, id_value)
        })

    return conflicts


def find_best_asset_by_identifiers(conn: sqlite3.Connection, identifiers: dict[str, str], hostname: str) -> Optional[int]:
    """
    Use scoring system to find the best asset match from multiple identifier types.
    Returns the asset_id with the highest-scoring identifier that resolves uniquely.
    """
    candidates = {}  # asset_id -> (best_score, best_id_type)

    for id_type, id_value in identifiers.items():
        if not id_value or not id_value.strip():
            continue

        score = score_identifier(id_type, id_value, hostname)
        if score == 0:
            continue  # Skip fake/unreliable identifiers

        asset_id = find_asset_id_by_identifier(conn, id_type, id_value)
        if asset_id is not None:
            if asset_id not in candidates or score > candidates[asset_id][0]:
                candidates[asset_id] = (score, id_type)

    if not candidates:
        return None

    # Return the asset with the highest score
    best_asset = max(candidates.items(), key=lambda x: x[1][0])
    return best_asset[0]


def merge_assets(conn: sqlite3.Connection, *, keep_asset_id: int, drop_asset_id: int) -> None:
    """
    Merge `drop_asset_id` into `keep_asset_id` and delete the dropped asset.
    Preference rule is decided by the caller.
    """
    if keep_asset_id == drop_asset_id:
        return

    # Move runs
    conn.execute("UPDATE runs SET asset_id = ? WHERE asset_id = ?", (keep_asset_id, drop_asset_id))

    # Move inventory if keep has none
    if not _asset_has_inventory(conn, keep_asset_id) and _asset_has_inventory(conn, drop_asset_id):
        conn.execute(
            "UPDATE asset_inventory SET asset_id = ? WHERE asset_id = ?",
            (keep_asset_id, drop_asset_id),
        )

    # Move identifiers: insert-or-ignore into keep, then delete from drop
    rows = conn.execute(
        "SELECT id_type, id_value, first_seen_utc, last_seen_utc FROM asset_identifiers WHERE asset_id = ?",
        (drop_asset_id,),
    ).fetchall()
    for (id_type, id_value, first_seen, last_seen) in rows:
        conn.execute(
            """
            INSERT OR IGNORE INTO asset_identifiers(asset_id, id_type, id_value, first_seen_utc, last_seen_utc)
            VALUES (?, ?, ?, ?, ?)
            """,
            (keep_asset_id, id_type, id_value, first_seen, last_seen),
        )
    conn.execute("DELETE FROM asset_identifiers WHERE asset_id = ?", (drop_asset_id,))

    # Finally drop asset row
    conn.execute("DELETE FROM assets WHERE asset_id = ?", (drop_asset_id,))


def upsert_asset_identifier(conn: sqlite3.Connection, asset_id: int, id_type: str, id_value: str, collected_at_utc: str) -> None:
    """
    Maintain first_seen / last_seen for a stable identifier.
    """
    conn.execute(
        """
        INSERT INTO asset_identifiers(asset_id, id_type, id_value, first_seen_utc, last_seen_utc)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(asset_id, id_type, id_value) DO UPDATE SET
          last_seen_utc=excluded.last_seen_utc
        """,
        (asset_id, id_type, id_value, collected_at_utc, collected_at_utc),
    )


def find_or_create_asset(
    conn: sqlite3.Connection,
    *,
    hostname: str,
    machine_id: Optional[str],
    dmi_uuid: Optional[str],
    primary_mac: Optional[str],
    collected_at_utc: str,
) -> int:
    """
    Asset resolution strategy with improved scoring:
      1) Use scoring system to find best asset match across hardware identifiers
         (machine_id excluded to allow cloned VMs separate asset IDs)
      2) hostname match (fallback for weak/no identifiers)
      3) create new asset

    Note: machine_id is tracked as an asset property but not used for uniqueness
    to ensure each host (including cloned VMs) gets its own asset ID.
    """
    desired_hostname = normalize_hostname(hostname)

    # Build identifier dictionary for scoring
    # Note: machine_id is tracked as an asset property but not used for uniqueness
    # to allow cloned VMs and virtual hosts to have separate asset IDs
    identifiers = {}
    if dmi_uuid and dmi_uuid.strip():
        identifiers['dmi_uuid'] = dmi_uuid.strip()
    if primary_mac and primary_mac.strip():
        identifiers['primary_mac'] = primary_mac.strip().lower()
    # machine_id excluded from asset resolution to ensure each host gets unique asset ID

    asset_id: Optional[int] = None

    # Use scoring system to find best match
    if identifiers:
        asset_id = find_best_asset_by_identifiers(conn, identifiers, desired_hostname)

    # Fallback to hostname match if no strong identifiers found
    if asset_id is None:
        asset_id = find_asset_id_by_hostname(conn, desired_hostname)

    # Last resort: alias match (punctuation-insensitive)
    if asset_id is None:
        slug_match = find_asset_id_by_hostname_slug(conn, desired_hostname)
        if slug_match is not None:
            asset_id = slug_match

    if asset_id is None:
        cur = conn.execute(
            """
            INSERT INTO assets(hostname, updated_at_utc)
            VALUES (?, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
            """,
            (desired_hostname,),
        )
        asset_id = int(cur.lastrowid)

    # If machine_id resolved to an asset whose hostname differs only by variant/case,
    # we may need to merge duplicates before updating the UNIQUE hostname field.
    other = find_asset_id_by_hostname(conn, desired_hostname)
    if other is not None and other != asset_id:
        # Prefer the asset row that already has inventory (typically from CSV/CMDB).
        keep = asset_id
        drop = other
        if _asset_has_inventory(conn, other) and not _asset_has_inventory(conn, asset_id):
            keep, drop = other, asset_id
        elif _asset_has_inventory(conn, other) and _asset_has_inventory(conn, asset_id):
            keep, drop = (min(asset_id, other), max(asset_id, other))
        elif (not _asset_has_inventory(conn, other)) and (not _asset_has_inventory(conn, asset_id)):
            keep, drop = (min(asset_id, other), max(asset_id, other))

        merge_assets(conn, keep_asset_id=keep, drop_asset_id=drop)
        asset_id = keep

    # Also consider slug-based duplicates (e.g., ampere1 vs ampere-1)
    other_slug = find_asset_id_by_hostname_slug(conn, desired_hostname, exclude_asset_id=asset_id)
    if other_slug is not None and other_slug != asset_id:
        keep = asset_id
        drop = other_slug
        if _asset_has_inventory(conn, other_slug) and not _asset_has_inventory(conn, asset_id):
            keep, drop = other_slug, asset_id
        elif _asset_has_inventory(conn, other_slug) and _asset_has_inventory(conn, asset_id):
            keep, drop = (min(asset_id, other_slug), max(asset_id, other_slug))
        elif (not _asset_has_inventory(conn, other_slug)) and (not _asset_has_inventory(conn, asset_id)):
            keep, drop = (min(asset_id, other_slug), max(asset_id, other_slug))
        merge_assets(conn, keep_asset_id=keep, drop_asset_id=drop)
        asset_id = keep

    # Keep assets.hostname current, but don't overwrite an inventory-established hostname
    # when the "new" hostname only differs by punctuation/case.
    current = conn.execute("SELECT hostname FROM assets WHERE asset_id = ?", (asset_id,)).fetchone()
    current_hostname = str(current[0]) if current else ""
    if not (_asset_has_inventory(conn, asset_id) and hostname_slug(current_hostname) == hostname_slug(desired_hostname) and current_hostname != desired_hostname):
        conn.execute(
            "UPDATE assets SET hostname = ?, updated_at_utc = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE asset_id = ?",
            (desired_hostname, asset_id),
        )

    if dmi_uuid:
        upsert_asset_identifier(conn, asset_id, "dmi_uuid", dmi_uuid.strip(), collected_at_utc)
    if primary_mac:
        upsert_asset_identifier(conn, asset_id, "primary_mac", primary_mac.strip().lower(), collected_at_utc)
    if machine_id:
        upsert_asset_identifier(conn, asset_id, "machine_id", machine_id.strip(), collected_at_utc)

    # Track observed hostname variants as identifiers too (helps with renames).
    upsert_asset_identifier(conn, asset_id, "hostname", desired_hostname, collected_at_utc)

    return asset_id


def ingest_baseline_file(conn: sqlite3.Connection, file_path: Path, *, reingest: bool) -> Optional[int]:
    abs_path = str(file_path.resolve())
    existing = conn.execute("SELECT run_id FROM runs WHERE source_path = ?", (abs_path,)).fetchone()
    if existing and not reingest:
        return None
    if existing and reingest:
        conn.execute("DELETE FROM runs WHERE run_id = ?", (existing[0],))
        conn.commit()

    source_ip, collected_at_utc = parse_collected_at_from_filename(file_path)
    src_hash = sha256_file(file_path)
    text = file_path.read_text(encoding="utf-8", errors="replace")
    parsed_cmds = parse_baseline_text(text)

    # Ensure command catalog has entries for every command we observed.
    for pc in parsed_cmds:
        upsert_command_catalog(conn, command_tag=pc.command_tag, section=pc.section, command=pc.command)

    # Determine hostname + machine_id from hostnamectl output (preferred asset identity)
    hostname: Optional[str] = None
    machine_id: Optional[str] = None
    dmi_uuid: Optional[str] = None
    primary_mac: Optional[str] = None
    for pc in parsed_cmds:
        if pc.command_tag == "hostnamectl":
            kv = _parse_hostnamectl_kv(pc.output_text)
            hostname = kv.get("Static hostname") or _parse_hostname_from_hostnamectl(pc.output_text)
            machine_id = kv.get("Machine ID")
            break

    # Pull DMI UUID early (better identity than machine-id on some clones)
    for pc in parsed_cmds:
        if pc.command_tag == "dmidecode":
            dkv = _parse_dmidecode_system(pc.output_text)
            dmi_uuid = dkv.get("UUID")
            break

    # Pull primary MAC early: MAC of interface that owns the baseline filename IP.
    for pc in parsed_cmds:
        if pc.command_tag == "ip_addr":
            try:
                iface_rows, addr_rows = _parse_ip_a(pc.output_text)
                ifname = None
                for (ifn, fam, addr, _pref, _scope, _addr_type) in addr_rows:
                    if fam == "inet" and addr == source_ip:
                        ifname = ifn
                        break
                if ifname:
                    for (ifn, mac, _state, _mtu) in iface_rows:
                        if ifn == ifname and mac:
                            primary_mac = str(mac)
                            break
            except Exception:
                primary_mac = None
            break

    if not hostname:
        # Fallback: use the source IP as a temporary hostname-like value
        hostname = f"unknown_{source_ip}"

    asset_id = find_or_create_asset(
        conn,
        hostname=hostname,
        machine_id=machine_id,
        dmi_uuid=dmi_uuid,
        primary_mac=primary_mac,
        collected_at_utc=collected_at_utc,
    )

    cur = conn.execute(
        """
        INSERT INTO runs(asset_id, source_ip, collected_at_utc, source_path, source_sha256, parser_version)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (asset_id, source_ip, collected_at_utc, abs_path, src_hash, PARSER_VERSION),
    )
    run_id = int(cur.lastrowid)

    # Insert raw command outputs
    conn.executemany(
        """
        INSERT INTO run_commands(run_id, section, command_index, command, command_tag, output_text)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        [
            (run_id, pc.section, pc.command_index, pc.command, pc.command_tag, pc.output_text)
            for pc in parsed_cmds
        ],
    )

    # Parsed tables
    cmd_by_tag: dict[str, str] = {}
    for pc in parsed_cmds:
        # keep first occurrence (script contains some loops that repeat structure)
        if pc.command_tag == "getcap_r":
            # Merge multiple getcap blocks (baseline may run getcap on several paths)
            existing = cmd_by_tag.get("getcap_r", "")
            if existing:
                cmd_by_tag["getcap_r"] = existing + "\n" + pc.output_text
            else:
                cmd_by_tag["getcap_r"] = pc.output_text
        else:
            cmd_by_tag.setdefault(pc.command_tag, pc.output_text)

    # hostnamectl
    hc_out = cmd_by_tag.get("hostnamectl")
    domain = None
    fqdn = None
    if hc_out:
        kv = _parse_hostnamectl_kv(hc_out)
        
        # Extract domain and fqdn from hostnamectl output
        static_hostname = kv.get("Static hostname", "")
        transient_hostname = kv.get("Transient hostname", "")
        # Some systems show "FQDN" field, others we derive from hostname
        fqdn_field = kv.get("FQDN") or kv.get("DNS Domain") or kv.get("Domain")
        
        if fqdn_field:
            fqdn = fqdn_field.strip()
        elif static_hostname and "." in static_hostname:
            fqdn = static_hostname.strip()
        elif transient_hostname and "." in transient_hostname:
            fqdn = transient_hostname.strip()
        
        # Extract domain from FQDN or from separate domain field
        if fqdn:
            if "." in fqdn:
                parts = fqdn.split(".", 1)
                if len(parts) > 1:
                    domain = parts[1].strip()
        elif kv.get("DNS Domain"):
            domain = kv.get("DNS Domain").strip()
        elif kv.get("Domain"):
            domain = kv.get("Domain").strip()
        
        # Parse OS name/version/id from etc_release if available (for normalized fields)
        os_name = None
        os_version = None
        os_id = None
        etc_release = cmd_by_tag.get("etc_release")
        if etc_release:
            release_kv = _parse_os_release_kv(etc_release)
            os_name = release_kv.get("NAME") or release_kv.get("DISTRIB_ID")
            os_version = release_kv.get("VERSION_ID") or release_kv.get("DISTRIB_RELEASE") or release_kv.get("VERSION")
            os_id = release_kv.get("ID") or release_kv.get("DISTRIB_ID")

        conn.execute(
            """
            INSERT INTO run_hostinfo(
              run_id, static_hostname, icon_name, chassis, machine_id, boot_id,
              operating_system, os_name, os_version, os_id, kernel, architecture,
              hardware_vendor, hardware_model
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                kv.get("Static hostname"),
                kv.get("Icon name"),
                kv.get("Chassis"),
                kv.get("Machine ID"),
                kv.get("Boot ID"),
                kv.get("Operating System"),
                os_name,
                os_version,
                os_id,
                kv.get("Kernel"),
                kv.get("Architecture"),
                kv.get("Hardware Vendor"),
                kv.get("Hardware Model"),
            ),
        )
        
        # Update assets table with domain and fqdn
        if domain or fqdn:
            update_fields = []
            update_values = []
            if domain:
                update_fields.append("domain = ?")
                update_values.append(domain)
            if fqdn:
                update_fields.append("fqdn = ?")
                update_values.append(fqdn)
            if update_fields:
                update_values.append(asset_id)
                conn.execute(
                    f"UPDATE assets SET {', '.join(update_fields)}, updated_at_utc = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE asset_id = ?",
                    update_values,
                )

        # Also store a couple easy facts for querying
        if kv.get("Operating System"):
            conn.execute(
                "INSERT OR REPLACE INTO run_facts(run_id, fact_group, fact_key, fact_value) VALUES (?, 'os', 'operating_system', ?)",
                (run_id, kv.get("Operating System")),
            )
        if kv.get("Kernel"):
            conn.execute(
                "INSERT OR REPLACE INTO run_facts(run_id, fact_group, fact_key, fact_value) VALUES (?, 'os', 'kernel', ?)",
                (run_id, kv.get("Kernel")),
            )

        # Reinforce identifier mapping (useful if DB pre-existed without identifiers)
        if kv.get("Machine ID"):
            upsert_asset_identifier(conn, asset_id, "machine_id", kv.get("Machine ID"), collected_at_utc)

    # uname -a
    ua = cmd_by_tag.get("uname_a")
    if ua:
        conn.execute("INSERT INTO run_uname(run_id, uname_a) VALUES (?, ?)", (run_id, ua.strip()))

    # /etc/*release*
    osrel = cmd_by_tag.get("etc_release")
    if osrel:
        os_kv = _parse_os_release_kv(osrel)
        conn.executemany(
            "INSERT OR REPLACE INTO run_os_release_kv(run_id, k, v) VALUES (?, ?, ?)",
            [(run_id, k, v) for k, v in os_kv.items()],
        )

    # /proc/cmdline
    cmdline = cmd_by_tag.get("proc_cmdline")
    if cmdline:
        ckv = _parse_proc_cmdline_kv(cmdline)
        if ckv:
            conn.executemany(
                "INSERT OR REPLACE INTO run_kernel_cmdline_kv(run_id, k, v) VALUES (?, ?, ?)",
                [(run_id, k, v) for k, v in ckv.items()],
            )
            # a couple high-signal facts
            for k in ("audit", "selinux", "enforcing", "lockdown"):
                if k in ckv:
                    conn.execute(
                        "INSERT OR REPLACE INTO run_facts(run_id, fact_group, fact_key, fact_value) VALUES (?, 'boot', ?, ?)",
                        (run_id, k, ckv.get(k)),
                    )

    # Targeted sysctl posture
    sysctl_out = cmd_by_tag.get("sysctl_hardening")
    if sysctl_out:
        skv = _parse_sysctl_kv(sysctl_out)
        if skv:
            conn.executemany(
                "INSERT OR REPLACE INTO run_sysctl_kv(run_id, k, v) VALUES (?, ?, ?)",
                [(run_id, k, v) for k, v in skv.items()],
            )

    # Secure Boot state
    sb = cmd_by_tag.get("mokutil_sb_state")
    if sb:
        enabled = _parse_mokutil_sb_state(sb)
        conn.execute(
            "INSERT OR REPLACE INTO run_secure_boot(run_id, secure_boot_enabled, raw_text) VALUES (?, ?, ?)",
            (run_id, enabled, sb.strip() if sb else None),
        )

    # timedatectl
    td = cmd_by_tag.get("timedatectl")
    if td:
        tkv = _parse_timedatectl(td)
        conn.execute(
            """
            INSERT OR REPLACE INTO run_timedate(
              run_id, local_time, universal_time, rtc_time, time_zone,
              system_clock_synchronized, ntp_service, rtc_in_local_tz
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                tkv.get("Local time"),
                tkv.get("Universal time"),
                tkv.get("RTC time"),
                tkv.get("Time zone") or tkv.get("Time zone"),
                tkv.get("System clock synchronized"),
                tkv.get("NTP service"),
                tkv.get("RTC in local TZ"),
            ),
        )

    # uptime
    up = cmd_by_tag.get("uptime")
    if up:
        raw, l1, l5, l15 = _parse_uptime(up)
        if raw:
            conn.execute(
                "INSERT OR REPLACE INTO run_uptime(run_id, raw_line, load_1, load_5, load_15) VALUES (?, ?, ?, ?, ?)",
                (run_id, raw, l1, l5, l15),
            )

    # free -h
    fr = cmd_by_tag.get("free_h")
    if fr:
        mem = _parse_free_h(fr)
        conn.execute(
            """
            INSERT OR REPLACE INTO run_memory(
              run_id, mem_total_bytes, mem_used_bytes, mem_free_bytes, mem_available_bytes,
              swap_total_bytes, swap_used_bytes, swap_free_bytes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                mem.get("mem_total_bytes"),
                mem.get("mem_used_bytes"),
                mem.get("mem_free_bytes"),
                mem.get("mem_available_bytes"),
                mem.get("swap_total_bytes"),
                mem.get("swap_used_bytes"),
                mem.get("swap_free_bytes"),
            ),
        )

    # lsblk -a
    lb = cmd_by_tag.get("lsblk_a")
    if lb:
        rows = _parse_lsblk_a(lb)
        conn.executemany(
            """
            INSERT OR REPLACE INTO run_block_devices(
              run_id, name, type, parent_name, size_bytes, rm, ro, mountpoints, raw_line
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    run_id,
                    r["name"],
                    r.get("type"),
                    r.get("parent_name"),
                    r.get("size_bytes"),
                    r.get("rm"),
                    r.get("ro"),
                    r.get("mountpoints"),
                    r.get("raw_line"),
                )
                for r in rows
            ],
        )

    # df -B1 (disk free in bytes per mount)
    df_out = cmd_by_tag.get("df_B1")
    if df_out:
        df_rows = _parse_df_B1(df_out)
        if df_rows:
            conn.executemany(
                """
                INSERT OR REPLACE INTO run_df_mounts(
                  run_id, filesystem, size_bytes, used_bytes, avail_bytes, use_pct, mountpoint
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        run_id,
                        r["filesystem"],
                        r.get("size_bytes"),
                        r.get("used_bytes"),
                        r.get("avail_bytes"),
                        r.get("use_pct"),
                        r["mountpoint"],
                    )
                    for r in df_rows
                ],
            )

    # dmidecode -> system identity fields
    dmi = cmd_by_tag.get("dmidecode")
    if dmi:
        dkv = _parse_dmidecode_system(dmi)
        if dkv:
            conn.execute(
                """
                INSERT OR REPLACE INTO run_dmi_system(
                  run_id, manufacturer, product_name, version, serial_number, uuid, sku_number, family
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    dkv.get("Manufacturer"),
                    dkv.get("Product Name"),
                    dkv.get("Version"),
                    dkv.get("Serial Number"),
                    dkv.get("UUID"),
                    dkv.get("SKU Number"),
                    dkv.get("Family"),
                ),
            )
            if dkv.get("UUID"):
                upsert_asset_identifier(conn, asset_id, "dmi_uuid", dkv.get("UUID"), collected_at_utc)
            if dkv.get("Serial Number"):
                upsert_asset_identifier(conn, asset_id, "serial_number", dkv.get("Serial Number"), collected_at_utc)

    # lspci -v -> GPU devices
    pci = cmd_by_tag.get("lspci_v")
    if pci:
        gpus = _parse_lspci_v_gpus(pci)
        conn.executemany(
            """
            INSERT OR REPLACE INTO run_gpu_devices(
              run_id, slot, class, description, vendor, device, kernel_driver_in_use, raw_block
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    run_id,
                    g.get("slot"),
                    g.get("class"),
                    g.get("description"),
                    g.get("vendor"),
                    g.get("device"),
                    g.get("kernel_driver_in_use"),
                    g.get("raw_block"),
                )
                for g in gpus
            ],
        )

    # lshw -disable dmi -> hardware device tree (one row per device)
    lshw_out = cmd_by_tag.get("lshw_disable_dmi")
    if lshw_out:
        lshw_devices = _parse_lshw(lshw_out)
        if lshw_devices:
            conn.executemany(
                """
                INSERT INTO run_lshw_devices(
                  run_id, depth, class, logical_name, description, product, vendor,
                  physical_id, bus_info, slot, size, capacity, serial, version,
                  width_bits, clock_hz, raw_line
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        run_id,
                        d["depth"],
                        d["class"],
                        d.get("logical_name"),
                        d.get("description"),
                        d.get("product"),
                        d.get("vendor"),
                        d.get("physical_id"),
                        d.get("bus_info"),
                        d.get("slot"),
                        d.get("size"),
                        d.get("capacity"),
                        d.get("serial"),
                        d.get("version"),
                        d.get("width_bits"),
                        d.get("clock_hz"),
                        d.get("raw_line"),
                    )
                    for d in lshw_devices
                ],
            )

    # lsusb -v -> USB devices (security-relevant)
    usb = cmd_by_tag.get("lsusb_v")
    if usb:
        usb_devices = _parse_lsusb_v(usb)
        if usb_devices:
            conn.executemany(
                """
                INSERT OR REPLACE INTO run_usb_devices(
                  run_id, bus_number, device_number, vendor_id, product_id,
                  device_class, device_subclass, device_protocol, device_class_label,
                  vendor_name, product_name, manufacturer, product, serial_number, usb_version, max_power
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        run_id,
                        d.get("bus_number"),
                        d.get("device_number"),
                        d.get("vendor_id"),
                        d.get("product_id"),
                        d.get("device_class"),
                        d.get("device_subclass"),
                        d.get("device_protocol"),
                        _usb_device_class_label(d.get("device_class")),
                        d.get("vendor_name"),
                        d.get("product_name"),
                        d.get("manufacturer"),
                        d.get("product"),
                        d.get("serial_number"),
                        d.get("usb_version"),
                        d.get("max_power"),
                    )
                    for d in usb_devices
                ],
            )

    # /etc/passwd, /etc/group
    pw = cmd_by_tag.get("etc_passwd")
    if pw:
        rows = _parse_passwd(pw)
        conn.executemany(
            "INSERT OR REPLACE INTO run_users(run_id, username, uid, gid, gecos, home, shell) VALUES (?, ?, ?, ?, ?, ?, ?)",
            [(run_id, *r) for r in rows],
        )

    grp = cmd_by_tag.get("etc_group")
    if grp:
        rows = _parse_group(grp)
        conn.executemany(
            "INSERT OR REPLACE INTO run_groups(run_id, groupname, gid, members_csv, group_type) VALUES (?, ?, ?, ?, ?)",
            [(run_id, gname, gid, members, _classify_group_type(gname, gid)) for (gname, gid, members) in rows],
        )
        # Normalize membership for joins
        member_rows = []
        for (groupname, _gid, members_csv) in rows:
            for member in _split_members_csv(members_csv):
                member_rows.append((run_id, "etc_group", groupname, member))
        if member_rows:
            conn.executemany(
                "INSERT OR REPLACE INTO run_group_members(run_id, source, groupname, member_username) VALUES (?, ?, ?, ?)",
                member_rows,
            )

    # passwd -S
    ps = cmd_by_tag.get("passwd_status")
    if ps:
        rows = _parse_passwd_status(ps)
        conn.executemany(
            """
            INSERT OR REPLACE INTO run_passwd_status(
              run_id, username, status_code, last_change, min_age, max_age, warn, inactive, expire
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [(run_id, *r) for r in rows],
        )

    # who -a
    whoa = cmd_by_tag.get("who_a")
    if whoa:
        rows = _parse_who_a(whoa)
        conn.executemany(
            """
            INSERT OR REPLACE INTO run_who_lines(
              run_id, line_no, record_type, username, tty, event_time, pid, remote_host, raw_line
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    run_id,
                    int(r["line_no"]),
                    r.get("record_type"),
                    r.get("username"),
                    r.get("tty"),
                    r.get("event_time"),
                    r.get("pid"),
                    r.get("remote_host"),
                    r.get("raw_line"),
                )
                for r in rows
            ],
        )

    # w
    wout = cmd_by_tag.get("w")
    if wout:
        rows = _parse_w(wout)
        conn.executemany(
            """
            INSERT OR REPLACE INTO run_w_sessions(
              run_id, username, tty, from_host, login_at, idle, jcpu, pcpu, what, raw_line
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    run_id,
                    r.get("username"),
                    r.get("tty"),
                    r.get("from_host"),
                    r.get("login_at"),
                    r.get("idle"),
                    r.get("jcpu"),
                    r.get("pcpu"),
                    r.get("what"),
                    r.get("raw_line"),
                )
                for r in rows
            ],
        )

    # lastlog
    ll = cmd_by_tag.get("lastlog")
    if ll:
        rows = _parse_lastlog(ll)
        conn.executemany(
            "INSERT OR REPLACE INTO run_lastlog(run_id, username, port, from_host, latest, raw_line) VALUES (?, ?, ?, ?, ?, ?)",
            [(run_id, r.get("username"), r.get("port"), r.get("from_host"), r.get("latest"), r.get("raw_line")) for r in rows],
        )

    # last (wtmp/btmp/utmp)
    for tag, src in (("last_wtmp", "wtmp"), ("last_btmp", "btmp"), ("last_utmp", "utmp")):
        out = cmd_by_tag.get(tag)
        if out:
            rows = _parse_last(out, src)
            conn.executemany(
                """
                INSERT OR REPLACE INTO run_last_events(
                  run_id, source, username, tty, remote_host, start_text, end_text, duration_text, status_text, raw_line
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        run_id,
                        r.get("source"),
                        r.get("username"),
                        r.get("tty"),
                        r.get("remote_host"),
                        r.get("start_text"),
                        r.get("end_text"),
                        r.get("duration_text"),
                        r.get("status_text"),
                        r.get("raw_line"),
                    )
                    for r in rows
                ],
            )

    # Extract failed login events from btmp data
    btmp_events = []
    for tag, src in (("last_btmp", "btmp"),):
        out = cmd_by_tag.get(tag)
        if out:
            btmp_events.extend(_parse_last(out, src))

    if btmp_events:
        failed_logins = extract_failed_login_events(btmp_events)
        if failed_logins:
            # Get collected_at for timestamp normalization
            collected_at = conn.execute("SELECT collected_at_utc FROM runs WHERE run_id = ?", (run_id,)).fetchone()
            collected_at_str = collected_at[0] if collected_at else ""

            # Normalize timestamps
            for fl in failed_logins:
                if fl['raw_start_text']:
                    fl['attempt_time_utc'] = normalize_timestamp_to_utc(fl['raw_start_text'], collected_at_str)

            conn.executemany(
                """
                INSERT OR REPLACE INTO run_failed_logins(
                  run_id, username, remote_host, tty, state_text, attempt_time_utc, raw_start_text, raw_line
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        run_id,
                        fl.get("username"),
                        fl.get("remote_host"),
                        fl.get("tty"),
                        fl.get("state_text"),
                        fl.get("attempt_time_utc"),
                        fl.get("raw_start_text"),
                        fl.get("raw_line"),
                    )
                    for fl in failed_logins
                ],
            )
            # Upsert observed TTY values into ref_tty for correlation
            for fl in failed_logins:
                tty_val = (fl.get("tty") or "").strip()
                if tty_val:
                    tty_kind = "ssh" if tty_val.lower() == "ssh" else "pts" if "pts" in tty_val else "tty" if tty_val.startswith("tty") else "console" if "console" in tty_val.lower() else "other"
                    conn.execute(
                        "INSERT OR IGNORE INTO ref_tty(tty_value, tty_kind) VALUES (?, ?)",
                        (tty_val, tty_kind),
                    )

    # auditctl -s
    auds = cmd_by_tag.get("auditctl_s")
    if auds:
        kv = _parse_auditctl_s(auds)
        conn.executemany(
            "INSERT OR REPLACE INTO run_audit_status(run_id, k, v) VALUES (?, ?, ?)",
            [(run_id, k, v) for k, v in kv.items()],
        )

    # auditctl -l (enhanced parsing)
    audl = cmd_by_tag.get("auditctl_l")
    audit_rules = []
    if audl:
        audit_rules = _parse_auditctl_l(audl)
        conn.executemany(
            """
            INSERT OR REPLACE INTO run_audit_rules(
              run_id, rule_text, action, list_type, arch, key_name,
              syscall, path, permission, uid, gid, auid, subj, rule_type
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [(
                run_id,
                r.get("rule_text"), r.get("action"), r.get("list_type"), r.get("arch"), r.get("key_name"),
                r.get("syscall"), r.get("path"), r.get("permission"), r.get("uid"), r.get("gid"),
                r.get("auid"), r.get("subj"), r.get("rule_type")
            ) for r in audit_rules],
        )

    # Derive and store audit posture flags
    if auds or audit_rules:
        audit_status_kv = {}
        if auds:
            audit_status_kv = _parse_auditctl_s(auds)

        posture_flags = derive_audit_posture_flags(audit_status_kv, audit_rules)
        conn.execute(
            """
            INSERT OR REPLACE INTO run_audit_posture(
              run_id, audit_enabled, audit_immutable, has_critical_auth_rules,
              has_critical_file_rules, has_critical_process_rules, has_time_change_rules,
              has_sudo_rules, has_passwd_rules, has_executable_rules
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                1 if posture_flags["audit_enabled"] else 0,
                1 if posture_flags["audit_immutable"] else 0,
                1 if posture_flags["has_critical_auth_rules"] else 0,
                1 if posture_flags["has_critical_file_rules"] else 0,
                1 if posture_flags["has_critical_process_rules"] else 0,
                1 if posture_flags["has_time_change_rules"] else 0,
                1 if posture_flags["has_sudo_rules"] else 0,
                1 if posture_flags["has_passwd_rules"] else 0,
                1 if posture_flags["has_executable_rules"] else 0,
            ),
        )

    # rsyslog.conf: remote log destinations (always store, use [] when none)
    rsyslog = cmd_by_tag.get("rsyslog_conf")
    if rsyslog:
        import json
        dests = _parse_rsyslog_remote_destinations(rsyslog)
        conn.execute(
            "INSERT OR REPLACE INTO run_facts(run_id, fact_group, fact_key, fact_value) VALUES (?, 'rsyslog', 'remote_destinations', ?)",
            (run_id, json.dumps(dests)),
        )

    # journald.conf: ForwardToSyslog, etc.
    jd = cmd_by_tag.get("journald_conf")
    if jd:
        jkv = _parse_journald_remote(jd)
        for k, v in jkv.items():
            conn.execute(
                "INSERT OR REPLACE INTO run_facts(run_id, fact_group, fact_key, fact_value) VALUES (?, 'journald', ?, ?)",
                (run_id, k, v),
            )

    # NTP/Chrony/timesyncd server configuration
    ntp_conf = cmd_by_tag.get("ntp_conf")
    if ntp_conf:
        ntp_servers = _parse_ntp_conf(ntp_conf)
        if ntp_servers:
            conn.executemany(
                """
                INSERT OR REPLACE INTO run_ntp_servers(
                  run_id, server_type, server_address, options, pool
                ) VALUES (?, ?, ?, ?, ?)
                """,
                [
                    (
                        run_id,
                        s["server_type"],
                        s["server_address"],
                        s.get("options"),
                        s.get("pool", False),
                    )
                    for s in ntp_servers
                ],
            )

    chrony_conf = cmd_by_tag.get("chrony_conf")
    if chrony_conf:
        chrony_servers = _parse_chrony_conf(chrony_conf)
        if chrony_servers:
            conn.executemany(
                """
                INSERT OR REPLACE INTO run_ntp_servers(
                  run_id, server_type, server_address, options, pool
                ) VALUES (?, ?, ?, ?, ?)
                """,
                [
                    (
                        run_id,
                        s["server_type"],
                        s["server_address"],
                        s.get("options"),
                        s.get("pool", False),
                    )
                    for s in chrony_servers
                ],
            )

    timesyncd_conf = cmd_by_tag.get("timesyncd_conf")
    if timesyncd_conf:
        timesyncd_servers = _parse_timesyncd_conf(timesyncd_conf)
        if timesyncd_servers:
            conn.executemany(
                """
                INSERT OR REPLACE INTO run_ntp_servers(
                  run_id, server_type, server_address, options, pool
                ) VALUES (?, ?, ?, ?, ?)
                """,
                [
                    (
                        run_id,
                        s["server_type"],
                        s["server_address"],
                        s.get("options"),
                        s.get("pool", False),
                    )
                    for s in timesyncd_servers
                ],
            )

    # login.defs: password policy etc.
    login_defs = cmd_by_tag.get("login_defs")
    if login_defs:
        ldkv = _parse_login_defs_kv(login_defs)
        if ldkv:
            conn.executemany(
                "INSERT OR REPLACE INTO run_login_defs_kv(run_id, k, v) VALUES (?, ?, ?)",
                [(run_id, k, v) for k, v in ldkv.items()],
            )

    # SELinux + AppArmor
    se = cmd_by_tag.get("sestatus")
    if se:
        kv = _parse_sestatus(se)
        conn.executemany(
            "INSERT OR REPLACE INTO run_selinux_status(run_id, k, v) VALUES (?, ?, ?)",
            [(run_id, k, v) for k, v in kv.items()],
        )
    sb = cmd_by_tag.get("getsebool_a")
    if sb:
        kv = _parse_getsebool_a(sb)
        conn.executemany(
            "INSERT OR REPLACE INTO run_selinux_booleans(run_id, boolean_name, state) VALUES (?, ?, ?)",
            [(run_id, k, v) for k, v in kv.items()],
        )
    aa = cmd_by_tag.get("aa_status")
    apparmor_status = {}
    if aa:
        apparmor_status = _parse_aa_status(aa)
        conn.execute(
            """
            INSERT OR REPLACE INTO run_apparmor_status(
              run_id, raw_text, profiles_loaded, profiles_enforce, profiles_complain, processes_enforce, processes_complain
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                apparmor_status.get("raw_text"),
                apparmor_status.get("profiles_loaded"),
                apparmor_status.get("profiles_enforce"),
                apparmor_status.get("profiles_complain"),
                apparmor_status.get("processes_enforce"),
                apparmor_status.get("processes_complain"),
            ),
        )

    # Derive and store SELinux posture
    selinux_status_kv = {}
    selinux_booleans_kv = {}
    if se:
        selinux_status_kv = _parse_sestatus(se)
    if sb:
        selinux_booleans_kv = _parse_getsebool_a(sb)

    if selinux_status_kv or selinux_booleans_kv:
        selinux_posture = derive_selinux_posture(selinux_status_kv, selinux_booleans_kv)
        import json
        conn.execute(
            """
            INSERT OR REPLACE INTO run_selinux_posture(
              run_id, selinux_enabled, selinux_enforcing, selinux_permissive, selinux_disabled,
              high_risk_booleans_on, high_risk_booleans_off
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                1 if selinux_posture["selinux_enabled"] else 0,
                1 if selinux_posture["selinux_enforcing"] else 0,
                1 if selinux_posture["selinux_permissive"] else 0,
                1 if selinux_posture["selinux_disabled"] else 0,
                json.dumps(selinux_posture["high_risk_booleans_on"]),
                json.dumps(selinux_posture["high_risk_booleans_off"]),
            ),
        )

    # Derive and store AppArmor posture
    if apparmor_status:
        apparmor_posture = derive_apparmor_posture(apparmor_status)
        conn.execute(
            """
            INSERT OR REPLACE INTO run_apparmor_posture(
              run_id, apparmor_enabled, apparmor_profiles_loaded, apparmor_all_enforcing,
              apparmor_mixed_mode, apparmor_processes_unconfined
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                1 if apparmor_posture["apparmor_enabled"] else 0,
                1 if apparmor_posture["apparmor_profiles_loaded"] else 0,
                1 if apparmor_posture["apparmor_all_enforcing"] else 0,
                1 if apparmor_posture["apparmor_mixed_mode"] else 0,
                1 if apparmor_posture["apparmor_processes_unconfined"] else 0,
            ),
        )

    # Network posture
    rc = cmd_by_tag.get("resolv_conf")
    if rc:
        rows = _parse_resolv_conf(rc)
        conn.executemany(
            "INSERT OR REPLACE INTO run_resolv_conf_entries(run_id, entry_type, entry_value, raw_line) VALUES (?, ?, ?, ?)",
            [(run_id, r.get("entry_type"), r.get("entry_value"), r.get("raw_line")) for r in rows],
        )
    neigh = cmd_by_tag.get("ip_neigh")
    if neigh:
        rows = _parse_ip_neigh(neigh)
        conn.executemany(
            "INSERT OR REPLACE INTO run_ip_neigh(run_id, ip, dev, lladdr, state, ip_type, raw_line) VALUES (?, ?, ?, ?, ?, ?, ?)",
            [(run_id, r.get("ip"), r.get("dev"), r.get("lladdr"), r.get("state"), r.get("ip_type"), r.get("raw_line")) for r in rows],
        )
    rt = cmd_by_tag.get("route_n")
    if rt:
        rows = _parse_route_n(rt)
        for r in rows:
            dest_type = _classify_route_dest(r.get("destination"))
            conn.execute(
                """
                INSERT OR REPLACE INTO run_routes(run_id, destination, gateway, genmask, flags, metric, ref, use, iface, dest_type, raw_line)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    r.get("destination"),
                    r.get("gateway"),
                    r.get("genmask"),
                    r.get("flags"),
                    r.get("metric"),
                    r.get("ref"),
                    r.get("use"),
                    r.get("iface"),
                    dest_type,
                    r.get("raw_line"),
                ),
            )

    # Derive and store network posture insights
    resolv_entries = []
    if rc:
        resolv_entries = _parse_resolv_conf(rc)

    routes = []
    if rt:
        routes = _parse_route_n(rt)

    neigh_entries = []
    if neigh:
        neigh_entries = _parse_ip_neigh(neigh)

    if resolv_entries or routes or neigh_entries:
        network_posture = derive_network_posture(resolv_entries, routes, neigh_entries)
        import json
        conn.execute(
            """
            INSERT OR REPLACE INTO run_network_posture(
              run_id, unexpected_nameservers, multiple_default_routes, suspicious_routes,
              unknown_mac_ouis, nameserver_flags
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                json.dumps(network_posture["unexpected_nameservers"]),
                1 if network_posture["multiple_default_routes"] else 0,
                json.dumps(network_posture["suspicious_routes"]),
                json.dumps(network_posture["unknown_mac_ouis"]),
                json.dumps(network_posture["nameserver_flags"]),
            ),
        )

    nm = cmd_by_tag.get("nmcli")
    if nm:
        s = _parse_nmcli_summary(nm)
        conn.execute(
            """
            INSERT OR REPLACE INTO run_nmcli_summary(
              run_id, state, connectivity, wifi_hw, wifi, wwan_hw, wwan, raw_text
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                s.get("state"),
                s.get("connectivity"),
                s.get("wifi_hw"),
                s.get("wifi"),
                s.get("wwan_hw"),
                s.get("wwan"),
                s.get("raw_text"),
            ),
        )

    # Process inventory
    psout = cmd_by_tag.get("ps_elf")
    if psout:
        rows = _parse_ps_elf(psout)
        
        # Get system timezone for timestamp normalization
        timezone_str = None
        td_row = conn.execute("SELECT time_zone FROM run_timedate WHERE run_id = ?", (run_id,)).fetchone()
        if td_row and td_row[0]:
            timezone_str = td_row[0]
        
        # Get collected_at for timestamp normalization
        collected_at_str = conn.execute("SELECT collected_at_utc FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        collected_at_str = collected_at_str[0] if collected_at_str else ""
        
        # Build parent process lookup dictionary (pid -> process details)
        parent_lookup: dict[int, tuple[str, str]] = {}
        for r in rows:
            pid = r.get("pid")
            if pid:
                parent_lookup[pid] = (r.get("process_name", ""), r.get("process_path", ""))
        
        # Prepare rows with parent process info and normalized timestamps
        process_rows = []
        for r in rows:
            pid = r.get("pid")
            ppid = r.get("ppid")
            start_time = r.get("start", "")
            
            # Look up parent process info
            parent_process_name = ""
            parent_process_path = ""
            if ppid and ppid in parent_lookup:
                parent_process_name, parent_process_path = parent_lookup[ppid]
            
            # Normalize start timestamp
            start_normalized_utc = None
            if start_time:
                start_normalized_utc = normalize_timestamp_with_timezone(start_time, timezone_str, collected_at_str)
            
            process_rows.append((
                run_id,
                pid,
                ppid,
                r.get("uid"),
                r.get("tty"),
                r.get("stat"),
                start_time,
                start_normalized_utc,
                r.get("time"),
                r.get("cmd"),
                r.get("process_name"),
                r.get("process_path"),
                r.get("process_arguments"),
                parent_process_name,
                parent_process_path,
                r.get("raw_line"),
            ))
        
        conn.executemany(
            """
            INSERT OR REPLACE INTO run_processes(
              run_id, pid, ppid, uid, tty, stat, start, start_normalized_utc, time, cmd,
              process_name, process_path, process_arguments,
              parent_process_name, parent_process_path, raw_line
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            process_rows,
        )
    pt = cmd_by_tag.get("pstree")
    if pt:
        lines = _parse_pstree_lines(pt)
        conn.executemany(
            "INSERT OR REPLACE INTO run_pstree_lines(run_id, line_no, raw_line) VALUES (?, ?, ?)",
            [(run_id, i + 1, ln) for i, ln in enumerate(lines)],
        )

    # Kernel modules (optimized processing)
    lsm = cmd_by_tag.get("lsmod")
    loaded_modules = []
    if lsm:
        rows = _parse_lsmod(lsm)
        loaded_modules = [r.get("module") for r in rows]

        # Limit to reasonable number of modules to prevent excessive processing
        max_modules = 200
        if len(rows) > max_modules:
            # Prioritize modules with dependents or unusual names
            prioritized_rows = []
            for r in rows:
                module = r.get("module", "")
                used_by_count = r.get("used_by_count", 0) or 0
                # Prioritize modules that are used by others or have unusual names
                if (used_by_count > 0 or
                    not module.startswith(('i2c_', 'snd_', 'drm_', 'fb_', 'sys_')) or
                    len(module) > 20):  # Unusual length
                    prioritized_rows.append(r)

            # If we still have too many, take the first max_modules
            if len(prioritized_rows) > max_modules:
                prioritized_rows = prioritized_rows[:max_modules]
            rows = prioritized_rows

        conn.executemany(
            "INSERT OR REPLACE INTO run_lsmod(run_id, module, size, used_by_count, used_by, raw_line) VALUES (?, ?, ?, ?, ?, ?)",
            [(run_id, r.get("module"), r.get("size"), r.get("used_by_count"), r.get("used_by"), r.get("raw_line")) for r in rows],
        )

    # Modinfo processing (optimized - only for loaded modules and limited fields)
    mi = cmd_by_tag.get("modinfo_all")
    if mi and loaded_modules:
        rows = _parse_modinfo_all(mi)

        # Filter to only loaded modules and security-relevant fields
        security_fields = {
            'license', 'signer', 'sig_id', 'description', 'author', 'vermagic',
            'filename', 'firmware', 'alias', 'depends', 'retpoline', 'intree'
        }

        filtered_rows = [
            (m, k, v) for (m, k, v) in rows
            if m in loaded_modules and k.lower() in security_fields
        ]

        # Limit total modinfo rows to prevent excessive storage
        max_modinfo_rows = 5000
        if len(filtered_rows) > max_modinfo_rows:
            filtered_rows = filtered_rows[:max_modinfo_rows]

        conn.executemany(
            "INSERT OR REPLACE INTO run_modinfo_kv(run_id, module, k, v) VALUES (?, ?, ?, ?)",
            [(run_id, m, k, v) for (m, k, v) in filtered_rows],
        )

    # Derive and store kernel module insights
    lsmod_modules = []
    if lsm:
        lsmod_modules = _parse_lsmod(lsm)

    modinfo_data = []
    if mi:
        modinfo_data = _parse_modinfo_all(mi)

    if lsmod_modules or modinfo_data:
        kernel_insights = derive_kernel_module_insights(lsmod_modules, modinfo_data)
        import json
        conn.execute(
            """
            INSERT OR REPLACE INTO run_kernel_module_insights(
              run_id, unusual_modules, suspicious_licenses, modules_with_unknown_signer
            ) VALUES (?, ?, ?, ?)
            """,
            (
                run_id,
                json.dumps(kernel_insights["unusual_modules"]),
                json.dumps(kernel_insights["suspicious_licenses"]),
                json.dumps(kernel_insights["modules_with_unknown_signer"]),
            ),
        )

    # Persistence surfaces / file listings
    td_row = conn.execute("SELECT time_zone FROM run_timedate WHERE run_id = ?", (run_id,)).fetchone()
    timezone_str = td_row[0] if td_row else None
    collected_row = conn.execute("SELECT collected_at_utc FROM runs WHERE run_id = ?", (run_id,)).fetchone()
    collected_at_str = collected_row[0] if collected_row else None
    for tag, source in (
        ("ls_etc_cron", "cron_dirs"),
        ("ls_var_spool_cron", "cron_dirs"),
        ("ls_etc_systemd_system", "systemd_dirs"),
        ("ls_etc_init_d", "init_dirs"),
        ("ls_etc_init", "init_dirs"),
        ("ls_etc_rc_d", "init_dirs"),
    ):
        out = cmd_by_tag.get(tag)
        if out:
            rows = _parse_ls_latR(out)
            for r in rows:
                perms = r.get("perms")
                if perms:
                    conn.execute("INSERT OR IGNORE INTO ref_permissions(perm_rwx, perm_octal, perm_kind) VALUES (?, ?, ?)", (perms, r.get("perm_octal"), r.get("file_type")))
                mtime_norm = _normalize_mtime_file(r.get("mtime_text"), timezone_str, collected_at_str)
                conn.execute(
                    """
                    INSERT OR REPLACE INTO run_file_listings(
                      run_id, source, directory, path, perms, perm_octal, owner, grp, size_bytes,
                      mtime_text, mtime_normalized_utc, name, filename, file_type, is_symlink, symlink_target, raw_line
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        run_id, source, r.get("directory"), r.get("path"), r.get("perms"), r.get("perm_octal"),
                        r.get("owner"), r.get("grp"), r.get("size_bytes"), r.get("mtime_text"), mtime_norm,
                        r.get("name"), r.get("filename"), r.get("file_type"), r.get("is_symlink"), r.get("symlink_target"), r.get("raw_line"),
                    ),
                )

    # Derive and store persistence insights
    # Get all file listings for this run
    file_listings = []
    cursor = conn.execute("SELECT source, directory, path, perms, owner, grp, size_bytes, mtime_text, name FROM run_file_listings WHERE run_id = ?", (run_id,))
    for row in cursor.fetchall():
        file_listings.append({
            'source': row[0],
            'directory': row[1],
            'path': row[2],
            'perms': row[3],
            'owner': row[4],
            'grp': row[5],
            'size_bytes': row[6],
            'mtime_text': row[7],
            'name': row[8],
        })

    if file_listings:
        persistence_insights = derive_persistence_insights(file_listings)
        import json
        conn.execute(
            """
            INSERT OR REPLACE INTO run_persistence_insights(
              run_id, suspicious_systemd_units, unusual_cron_permissions,
              recently_modified_persistence_files, suspicious_cron_locations
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                run_id,
                json.dumps(persistence_insights["suspicious_systemd_units"]),
                json.dumps(persistence_insights["unusual_cron_permissions"]),
                json.dumps(persistence_insights["recently_modified_persistence_files"]),
                json.dumps(persistence_insights["suspicious_cron_locations"]),
            ),
        )

    rb = cmd_by_tag.get("recent_bins")
    if rb:
        rows = _parse_ls_l(rb)
        for r in rows:
            perms = r.get("perms")
            if perms:
                conn.execute("INSERT OR IGNORE INTO ref_permissions(perm_rwx, perm_octal, perm_kind) VALUES (?, ?, ?)", (perms, r.get("perm_octal"), r.get("file_type")))
            mtime_norm = _normalize_mtime_file(r.get("mtime_text"), timezone_str, collected_at_str)
            conn.execute(
                """
                INSERT OR REPLACE INTO run_file_listings(
                  run_id, source, directory, path, perms, perm_octal, owner, grp, size_bytes,
                  mtime_text, mtime_normalized_utc, name, filename, file_type, is_symlink, symlink_target, raw_line
                ) VALUES (?, 'recent_bins', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id, r.get("directory"), r.get("path"), r.get("perms"), r.get("perm_octal"),
                    r.get("owner"), r.get("grp"), r.get("size_bytes"), r.get("mtime_text"), mtime_norm,
                    r.get("name"), r.get("filename"), r.get("file_type"), r.get("is_symlink"), r.get("symlink_target"), r.get("raw_line"),
                ),
            )

    # ld.so.preload (high-signal preload hook surface)
    ldp = cmd_by_tag.get("ld_so_preload")
    if ldp:
        entries = _parse_ld_so_preload(ldp)
        if entries:
            conn.executemany(
                "INSERT OR REPLACE INTO run_ld_preload_entries(run_id, entry) VALUES (?, ?)",
                [(run_id, e) for e in entries],
            )

    # File capabilities (getcap -r /)
    caps_out = cmd_by_tag.get("getcap_r")
    if caps_out:
        cap_rows = _parse_getcap_r(caps_out)
        if cap_rows:
            conn.executemany(
                "INSERT OR REPLACE INTO run_file_capabilities(run_id, path, caps) VALUES (?, ?, ?)",
                [(run_id, p, c) for (p, c) in cap_rows],
            )

    # Container runtimes (best-effort summaries + per-container rows)
    def _count_container_rows(out: str) -> int:
        lines = [ln for ln in out.splitlines() if ln.strip()]
        lines = [ln for ln in lines if not ln.upper().startswith("CONTAINER ID")]
        lines = [ln for ln in lines if not ln.startswith("Error:")]
        return max(0, len(lines) - 0)

    def _parse_containers_ps_a(output: str) -> list[dict[str, Optional[str]]]:
        """Parse docker ps -a / podman ps -a output into rows (container_id, image, status, names, ...)."""
        rows: list[dict[str, Optional[str]]] = []
        for line in output.splitlines():
            line = line.strip()
            if not line or line.upper().startswith("CONTAINER ID") or line.startswith("Error:"):
                continue
            m = re.match(r"^([0-9a-f]{12})\s+(.+)", line)
            if not m:
                continue
            cid, rest = m.group(1), m.group(2)
            # Last column is typically NAMES; before that PORTS, then STATUS (Up X / Exited (code) X)
            parts = [p.strip() for p in re.split(r"\s{2,}", rest)]
            names = parts[-1] if parts else None
            image = parts[0] if parts else None
            status = None
            if "Up " in rest:
                sm = re.search(r"(Up\s+[\d]+\s+\w+(?:\s+[\d]+\s+\w+)?)", rest)
                if sm:
                    status = sm.group(1).strip()
            elif "Exited " in rest:
                em = re.search(r"(Exited\s+\([^)]+\)[^0-9]*(?:\d+\s+\w+\s+ago)?)", rest)
                if em:
                    status = em.group(1).strip()
            created_text = None
            cm = re.search(r"(\d+\s+(?:months?|days?|weeks?|hours?)\s+ago)", rest)
            if cm:
                created_text = cm.group(1).strip()
            rows.append({
                "container_id": cid,
                "image": image,
                "status": status,
                "names": names,
                "created_text": created_text,
                "ports_text": None,
                "raw_line": line,
            })
        return rows

    dps = cmd_by_tag.get("docker_ps_a")
    if dps:
        conn.execute(
            "INSERT OR REPLACE INTO run_container_summary(run_id, runtime, k, v) VALUES (?, 'docker', 'containers_ps_a_count', ?)",
            (run_id, str(_count_container_rows(dps))),
        )
        for c in _parse_containers_ps_a(dps):
            conn.execute(
                """
                INSERT OR REPLACE INTO run_containers(run_id, runtime, container_id, image, status, names, created_text, ports_text, raw_line)
                VALUES (?, 'docker', ?, ?, ?, ?, ?, ?, ?)
                """,
                (run_id, c.get("container_id"), c.get("image"), c.get("status"), c.get("names"),
                 c.get("created_text"), c.get("ports_text"), c.get("raw_line")),
            )

    dinfo = cmd_by_tag.get("docker_info")
    if dinfo:
        kv = _parse_colon_kv_lines(dinfo)
        keep = [
            "Server Version", "Operating System", "Kernel Version",
            "Cgroup Driver", "Cgroup Version", "Storage Driver", "Logging Driver",
            "Security Options", "Root Dir", "Docker Root Dir",
            "Containers", "Containers Paused", "Containers Running", "Images",
            "Runtimes", "Default Runtime",
        ]
        for k in keep:
            if k in kv:
                conn.execute(
                    "INSERT OR REPLACE INTO run_container_summary(run_id, runtime, k, v) VALUES (?, 'docker', ?, ?)",
                    (run_id, k, kv.get(k)),
                )

    pps = cmd_by_tag.get("podman_ps_a")
    if pps:
        conn.execute(
            "INSERT OR REPLACE INTO run_container_summary(run_id, runtime, k, v) VALUES (?, 'podman', 'containers_ps_a_count', ?)",
            (run_id, str(_count_container_rows(pps))),
        )
        if "not installed" not in pps.lower():
            for c in _parse_containers_ps_a(pps):
                conn.execute(
                    """
                    INSERT OR REPLACE INTO run_containers(run_id, runtime, container_id, image, status, names, created_text, ports_text, raw_line)
                    VALUES (?, 'podman', ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (run_id, c.get("container_id"), c.get("image"), c.get("status"), c.get("names"),
                     c.get("created_text"), c.get("ports_text"), c.get("raw_line")),
                )

    pinfo = cmd_by_tag.get("podman_info")
    if pinfo:
        kv = _parse_colon_kv_lines(pinfo)
        keep = [
            "host", "version", "store", "registries", "plugins",
            "os", "arch", "cpus", "memTotal", "graphDriverName", "rootless",
        ]
        for k in keep:
            if k in kv:
                conn.execute(
                    "INSERT OR REPLACE INTO run_container_summary(run_id, runtime, k, v) VALUES (?, 'podman', ?, ?)",
                    (run_id, k, kv.get(k)),
                )

    # Privileged groups via NSS (`getent group sudo root wheel adm admin`)
    pg = cmd_by_tag.get("priv_groups")
    if pg:
        rows = _parse_getent_group(pg)
        for (g, gid, members) in rows:
            group_type = _classify_group_type(g, gid)
            conn.execute(
                "INSERT OR REPLACE INTO run_priv_groups(run_id, groupname, gid, members_csv, source, group_type) VALUES (?, ?, ?, ?, 'getent', ?)",
                (run_id, g, gid, members, group_type),
            )
        member_rows = []
        for (groupname, _gid, members_csv) in rows:
            for member in _split_members_csv(members_csv):
                member_rows.append((run_id, "getent", groupname, member))
        if member_rows:
            conn.executemany(
                "INSERT OR REPLACE INTO run_group_members(run_id, source, groupname, member_username) VALUES (?, ?, ?, ?)",
                member_rows,
            )

    # SSH authorized keys (fingerprints only)
    root_keys = cmd_by_tag.get("root_authorized_keys")
    if root_keys:
        rows = _parse_authorized_keys_block(root_keys.splitlines(), "root")
        conn.executemany(
            """
            INSERT OR REPLACE INTO run_ssh_authorized_keys(
              run_id, username, key_type, key_fingerprint_sha256, key_comment, raw_line_hash_sha256
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            [(run_id, *r) for r in rows],
        )

    home_keys = cmd_by_tag.get("home_authorized_keys")
    if home_keys:
        rows = _parse_home_authorized_keys(home_keys)
        conn.executemany(
            """
            INSERT OR REPLACE INTO run_ssh_authorized_keys(
              run_id, username, key_type, key_fingerprint_sha256, key_comment, raw_line_hash_sha256
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            [(run_id, *r) for r in rows],
        )

    # SSH host key fingerprints (public keys only)
    hk = cmd_by_tag.get("ssh_hostkey_fps")
    if hk:
        rows = _parse_ssh_keygen_lf(hk)
        if rows:
            conn.executemany(
                """
                INSERT OR REPLACE INTO run_ssh_host_keys(
                  run_id, bits, fingerprint, key_file, key_type, raw_line
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        run_id,
                        int(r["bits"]) if r.get("bits") and str(r.get("bits")).isdigit() else None,
                        r.get("fingerprint"),
                        r.get("key_file"),
                        r.get("key_type"),
                        r.get("raw_line") or "",
                    )
                    for r in rows
                ],
            )

    # Effective sshd configuration (sshd -T)
    sshd_t = cmd_by_tag.get("sshd_T")
    if sshd_t:
        kv = _parse_sshd_T_kv(sshd_t)
        if kv:
            conn.executemany(
                "INSERT OR REPLACE INTO run_sshd_config_kv(run_id, k, v) VALUES (?, ?, ?)",
                [(run_id, k, v) for k, v in kv.items()],
            )
            # also store a couple high-signal facts
            for k in ("passwordauthentication", "permitrootlogin", "pubkeyauthentication", "allowusers", "allowgroups"):
                if k in kv:
                    conn.execute(
                        "INSERT OR REPLACE INTO run_facts(run_id, fact_group, fact_key, fact_value) VALUES (?, 'sshd', ?, ?)",
                        (run_id, k, kv.get(k)),
                    )

    # Sudoers policy (best-effort parsing)
    sudo_texts = []
    if cmd_by_tag.get("sudoers"):
        sudo_texts.append(cmd_by_tag.get("sudoers") or "")
    if cmd_by_tag.get("sudoers_d_cat"):
        sudo_texts.append(cmd_by_tag.get("sudoers_d_cat") or "")
    sudo_combined = "\n".join([t for t in sudo_texts if t])
    if sudo_combined.strip():
        rules = []
        for line in sudo_combined.splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            # keep Defaults and rule lines; skip obvious "cat: ... No such file" noise
            if s.startswith("cat: ") or "No such file" in s:
                continue
            rules.append(s)
        if rules:
            for r in sorted(set(rules)):
                rule_type = _sudoers_rule_type(r)
                conn.execute(
                    "INSERT OR REPLACE INTO run_sudoers_rules(run_id, rule_text, rule_type) VALUES (?, ?, ?)",
                    (run_id, r, rule_type),
                )
            # derive quick flags
            nopasswd = sum(1 for r in rules if "nopasswd" in r.lower())
            all_all = sum(1 for r in rules if "ALL=(ALL" in r or "ALL = (ALL" in r)
            conn.execute(
                "INSERT OR REPLACE INTO run_facts(run_id, fact_group, fact_key, fact_value) VALUES (?, 'sudo', 'nopasswd_rule_count', ?)",
                (run_id, str(nopasswd)),
            )
            conn.execute(
                "INSERT OR REPLACE INTO run_facts(run_id, fact_group, fact_key, fact_value) VALUES (?, 'sudo', 'all_all_rule_count', ?)",
                (run_id, str(all_all)),
            )

    # Auth log telemetry summary (bounded)
    for tag, src in (
        ("journalctl_ssh_7d", "journalctl_ssh"),
        ("tail_auth_log", "auth_log"),
        ("tail_secure", "secure"),
    ):
        out = cmd_by_tag.get(tag)
        if out:
            c = _auth_log_counts(out)
            # #region agent log
            import json
            try:
                cols = [r[1] for r in conn.execute("PRAGMA table_info('run_auth_log_stats')").fetchall()]
                with open('/Users/blane/Library/CloudStorage/OneDrive-WestPoint/Documents/ACI/Topics/WIRE/.cursor/debug.log', 'a') as f:
                    f.write(json.dumps({"sessionId":"debug-session","runId":"pre-fix","hypothesisId":"C","location":"ingest-baselines.py:4690","message":"before INSERT run_auth_log_stats","data":{"columns":cols,"has_source":"source" in cols,"source_value":src},"timestamp":int(__import__('time').time()*1000)})+"\n")
            except Exception as e:
                with open('/Users/blane/Library/CloudStorage/OneDrive-WestPoint/Documents/ACI/Topics/WIRE/.cursor/debug.log', 'a') as f:
                    f.write(json.dumps({"sessionId":"debug-session","runId":"pre-fix","hypothesisId":"C","location":"ingest-baselines.py:4693","message":"table check error before INSERT","data":{"error":str(e)},"timestamp":int(__import__('time').time()*1000)})+"\n")
            # #endregion
            conn.execute(
                """
                INSERT OR REPLACE INTO run_auth_log_stats(
                  run_id, source, failed_password_count, invalid_user_count,
                  accepted_password_count, accepted_publickey_count,
                  sudo_count, error_count, raw_line_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    src,
                    c["failed_password_count"],
                    c["invalid_user_count"],
                    c["accepted_password_count"],
                    c["accepted_publickey_count"],
                    c["sudo_count"],
                    c["error_count"],
                    c["raw_line_count"],
                ),
            )

    # ip a
    ipa = cmd_by_tag.get("ip_addr")
    if ipa:
        iface_rows, addr_rows = _parse_ip_a(ipa)
        conn.executemany(
            "INSERT OR REPLACE INTO run_interfaces(run_id, ifname, mac_addr, state, mtu, iface_type) VALUES (?, ?, ?, ?, ?, ?)",
            [(run_id, *r) for r in iface_rows],
        )
        conn.executemany(
            "INSERT OR REPLACE INTO run_interface_addrs(run_id, ifname, family, address, prefixlen, scope, addr_type) VALUES (?, ?, ?, ?, ?, ?, ?)",
            [(run_id, *r) for r in addr_rows],
        )

    # ss -punt
    ssout = cmd_by_tag.get("ss_punt")
    if ssout:
        rows = _parse_ss_punt(ssout)
        for r in rows:
            local_addr = r[2] if len(r) > 2 else None
            bind_scope = _classify_bind_scope(local_addr)
            conn.execute(
                """
                INSERT OR REPLACE INTO run_listening_sockets(
                  run_id, proto, state, local_addr, local_port, peer_addr, peer_port, process_name, pid, bind_scope, raw_line
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (run_id, r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], bind_scope, r[8] if len(r) > 8 else ""),
            )

    # Derive and store process insights
    processes = []
    if psout:
        processes = _parse_ps_elf(psout)

    sockets = []
    if ssout:
        sockets = _parse_ss_punt(ssout)

    if processes or sockets:
        process_insights = derive_process_insights(processes, sockets)
        import json
        conn.execute(
            """
            INSERT OR REPLACE INTO run_process_insights(
              run_id, suspicious_root_processes, unusual_listening_services, process_tree_issues
            ) VALUES (?, ?, ?, ?)
            """,
            (
                run_id,
                json.dumps(process_insights["suspicious_root_processes"]),
                json.dumps(process_insights["unusual_listening_services"]),
                json.dumps(process_insights["process_tree_issues"]),
            ),
        )

    # systemctl list-units
    sysu = cmd_by_tag.get("systemctl_units")
    if sysu:
        rows = _parse_systemctl_list_units(sysu)
        for r in rows:
            unit = r[0] if r else None
            unit_type = _unit_type_from_name(unit)
            conn.execute(
                "INSERT OR REPLACE INTO run_services_systemctl(run_id, unit, load, active, sub, description, unit_type) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (run_id, r[0], r[1], r[2], r[3], r[4], unit_type),
            )

    # systemctl list-timers --all
    st = cmd_by_tag.get("systemctl_timers")
    if st:
        rows = _parse_systemctl_list_timers(st)
        if rows:
            conn.executemany(
                """
                INSERT OR REPLACE INTO run_systemd_timers(
                  run_id, next, left, last, passed, unit, activates, raw_line
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        run_id,
                        r.get("next"),
                        r.get("left"),
                        r.get("last"),
                        r.get("passed"),
                        r.get("unit"),
                        r.get("activates"),
                        r.get("raw_line") or "",
                    )
                    for r in rows
                ],
            )

    # systemctl list-unit-files --state=enabled
    suf = cmd_by_tag.get("systemctl_enabled_unit_files")
    if suf:
        rows = _parse_systemctl_list_unit_files(suf)
        if rows:
            for r in rows:
                unit_type = _unit_type_from_name(r.get("unit_file"))
                conn.execute(
                    "INSERT OR REPLACE INTO run_systemd_enabled_unit_files(run_id, unit_file, state, preset, unit_type) VALUES (?, ?, ?, ?, ?)",
                    (run_id, r.get("unit_file"), r.get("state"), r.get("preset"), unit_type),
                )

    # dpkg -l
    dpkg = cmd_by_tag.get("dpkg_list")
    if dpkg:
        rows = _parse_dpkg_list(dpkg)
        conn.executemany(
            "INSERT OR REPLACE INTO run_packages(run_id, source, name, version, arch, status, summary) VALUES (?, 'dpkg', ?, ?, ?, ?, ?)",
            [(run_id, *r) for r in rows],
        )

    # rpm -q --all
    rpm = cmd_by_tag.get("rpm_all")
    if rpm:
        rows = _parse_rpm_all(rpm)
        conn.executemany(
            "INSERT OR REPLACE INTO run_packages(run_id, source, name, version, arch, status, summary) VALUES (?, 'rpm', ?, '', '', '', NULL)",
            [(run_id, r[0]) for r in rows],
        )

    # Firewall (ref_firewall_type populated in db_migrate)
    def _parse_iptables_rule(line: str) -> tuple[Optional[str], Optional[str]]:
        """Extract chain (-A CHAIN) and target (-j TARGET) from iptables -S style rule."""
        chain = None
        target = None
        m_chain = re.search(r"^-A\s+(\S+)", line)
        if m_chain:
            chain = m_chain.group(1)
        m_target = re.search(r"\s-j\s+(\S+)", line)
        if m_target:
            target = m_target.group(1)
        return (chain, target)

    ipt_s = cmd_by_tag.get("iptables_s")
    if ipt_s:
        rules = [ln.strip() for ln in ipt_s.splitlines() if ln.strip()]
        for r in rules:
            chain, target = _parse_iptables_rule(r)
            conn.execute(
                "INSERT OR REPLACE INTO run_firewall_rules(run_id, source, rule, chain, target) VALUES (?, 'iptables_s', ?, ?, ?)",
                (run_id, r, chain, target),
            )
    ipt_l = cmd_by_tag.get("iptables_list")
    if ipt_l:
        rules = [ln.rstrip() for ln in ipt_l.splitlines() if ln.strip()]
        for r in rules:
            chain, target = _parse_iptables_rule(r)
            conn.execute(
                "INSERT OR REPLACE INTO run_firewall_rules(run_id, source, rule, chain, target) VALUES (?, 'iptables_list', ?, ?, ?)",
                (run_id, r, chain, target),
            )
    ufw_raw = cmd_by_tag.get("ufw_raw")
    if ufw_raw:
        rules = [ln.rstrip() for ln in ufw_raw.splitlines() if ln.strip()]
        for r in rules:
            chain, target = _parse_iptables_rule(r)
            conn.execute(
                "INSERT OR REPLACE INTO run_firewall_rules(run_id, source, rule, chain, target) VALUES (?, 'ufw_raw', ?, ?, ?)",
                (run_id, r, chain, target),
            )
    fwz = cmd_by_tag.get("firewalld_zones")
    if fwz:
        rules = [ln.rstrip() for ln in fwz.splitlines() if ln.strip()]
        for r in rules:
            conn.execute(
                "INSERT OR REPLACE INTO run_firewall_rules(run_id, source, rule, chain, target) VALUES (?, 'firewalld_zones', ?, NULL, NULL)",
                (run_id, r),
            )

    # nftables ruleset (best-effort)
    nft = cmd_by_tag.get("nft_ruleset")
    if nft:
        conn.execute(
            "INSERT OR REPLACE INTO run_nft_ruleset(run_id, raw_text) VALUES (?, ?)",
            (run_id, nft),
        )
        # crude posture signal
        has_table = 1 if re.search(r"^\s*table\s", nft, flags=re.MULTILINE) else 0
        conn.execute(
            "INSERT OR REPLACE INTO run_facts(run_id, fact_group, fact_key, fact_value) VALUES (?, 'firewall', 'nft_has_table', ?)",
            (run_id, str(has_table)),
        )

    # Generate and store security findings
    findings = generate_security_findings(conn, run_id)
    if findings:
        conn.executemany(
            """
            INSERT INTO findings(run_id, severity, category, title, details, evidence_ref)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    run_id,
                    f.get("severity"),
                    f.get("category"),
                    f.get("title"),
                    f.get("details"),
                    f.get("evidence_ref"),
                )
                for f in findings
            ],
        )

    # Backfill run_group_members.member_uid from run_users for this run
    try:
        conn.execute(
            """
            UPDATE run_group_members
            SET member_uid = (
              SELECT u.uid FROM run_users u
              WHERE u.run_id = run_group_members.run_id AND u.username = run_group_members.member_username
            )
            WHERE run_id = ?
            """,
            (run_id,),
        )
    except sqlite3.OperationalError:
        pass

    conn.commit()
    return run_id


def import_baseline_csv(conn: sqlite3.Connection, csv_path: Path) -> None:
    """
    Import baseline expectations from host inventory CSV
    """
    if not csv_path.exists():
        print(f"Warning: Baseline CSV not found at {csv_path}")
        return

    with csv_path.open('r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        rows = []
        for row in reader:
            # Create the tuple with exactly 30 values (skip asset_id, vlan, last_updated from CSV)
            row_tuple = (
                row.get('hostname', '').strip(),
                row.get('domain', '').strip() or None,
                row.get('fqdn', '').strip() or None,
                row.get('classification', '').strip() or None,
                row.get('location', '').strip() or None,
                row.get('server_manufacturer', '').strip() or None,
                row.get('server_model_series', '').strip() or None,
                row.get('server_model_no', '').strip() or None,
                row.get('proc_manufacturer', '').strip() or None,
                row.get('proc_model_series', '').strip() or None,
                row.get('proc_model_no', '').strip() or None,
                int(row.get('proc_no_cores') or 0) or None,
                int(row.get('proc_count') or 0) or None,
                row.get('gpu_manufacturer', '').strip() or None,
                row.get('gpu_model_series', '').strip() or None,
                row.get('gpu_model_no', '').strip() or None,
                int(row.get('gpu_count') or 0) or None,
                float(row.get('memory_capacity_gb') or 0) or None,
                int(row.get('storage_hdd_no_drives') or 0) or None,
                float(row.get('storage_hdd_capacity_gb') or 0) or None,
                int(row.get('storage_nvme_no_drives') or 0) or None,
                float(row.get('storage_nvme_capabity_gb') or 0) or None,
                int(row.get('storage_ssd_no_drives') or 0) or None,
                float(row.get('storage_ssd_capabity_gb') or 0) or None,
                row.get('os_name', '').strip() or None,
                row.get('os_version', '').strip() or None,
                row.get('arch', '').strip() or None,
                row.get('primary_ip', '').strip() or None,
                row.get('interface', '').strip() or None,
                row.get('mac_addr', '').strip() or None,
            )

            # Debug: check tuple length
            if len(row_tuple) != 30:
                print(f"ERROR: Tuple has {len(row_tuple)} values, expected 30")
                print(f"Values: {row_tuple}")
                return

            rows.append(row_tuple)

    if rows:
        print(f"Prepared {len(rows)} rows for insertion")
        try:
            conn.executemany("""
                INSERT OR REPLACE INTO host_inventory (
                    hostname, domain, fqdn, classification, location,
                    server_manufacturer, server_model_series, server_model_no,
                    proc_manufacturer, proc_model_series, proc_model_no,
                    proc_no_cores, proc_count,
                    gpu_manufacturer, gpu_model_series, gpu_model_no, gpu_count,
                    memory_capacity_gb,
                    storage_hdd_no_drives, storage_hdd_capacity_gb,
                    storage_nvme_no_drives, storage_nvme_capabity_gb,
                    storage_ssd_no_drives, storage_ssd_capabity_gb,
                    os_name, os_version, arch,
                    primary_ip, interface, mac_addr
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, rows)
            print(f"Imported {len(rows)} baseline records from CSV")
        except Exception as e:
            print(f"Database error: {e}")
            print(f"First row: {rows[0] if rows else 'No rows'}")
            return


def iter_baseline_result_files(results_dir: Path) -> Iterator[Path]:
    yield from sorted(results_dir.glob("*_20??????_??:??:??Z.txt"))


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Ingest Linux baseline results into SQLite")
    p.add_argument(
        "--db",
        type=Path,
        default=None,
        help="SQLite DB path (overrides --db-name)",
    )
    p.add_argument(
        "--db-name",
        type=str,
        default="baseline",
        help="Target database name (creates <script_dir>/<db-name>.sqlite3)",
    )
    p.add_argument("--schema", type=Path, default=Path(__file__).resolve().parent / "schema.sql", help="Schema SQL path")
    p.add_argument("--host-csv", type=Path, default=Path("host_inventory.csv"), help="Host inventory CSV path")
    p.add_argument("--skip-host-csv", action="store_true", help="Do not import host inventory from CSV (baseline-only mode)")
    p.add_argument("--results-dir", type=Path, default=Path("results"), help="Directory with raw baseline *.txt results")
    p.add_argument("--reingest", action="store_true", help="Reingest files already present in DB (delete and replace)")
    p.add_argument("--fresh-db", action="store_true", help="Delete and rebuild the SQLite DB before ingesting (use to recover from bad merges)")
    p.add_argument("--show-identity-conflicts", action="store_true", help="Show diagnostic report of identifier conflicts (multiple assets sharing same identifier)")
    args = p.parse_args(argv)

    # Resolve DB path
    if args.db is None:
        db_name = (args.db_name or "baseline").strip()
        if not db_name:
            db_name = "baseline"
        # keep filename safe-ish; allow letters/numbers/._-
        db_name = re.sub(r"[^A-Za-z0-9._-]+", "_", db_name)
        args.db = Path(__file__).resolve().parent / f"{db_name}.sqlite3"

    if not args.schema.exists():
        raise SystemExit(f"Schema SQL not found: {args.schema}")
    if not args.results_dir.exists():
        raise SystemExit(f"Results directory not found: {args.results_dir}")

    args.db.parent.mkdir(parents=True, exist_ok=True)

    if args.fresh_db and args.db.exists():
        args.db.unlink()
        wal = Path(str(args.db) + "-wal")
        shm = Path(str(args.db) + "-shm")
        if wal.exists():
            wal.unlink()
        if shm.exists():
            shm.unlink()

    conn = db_connect(args.db)
    # #region agent log
    import json
    with open('/Users/blane/Library/CloudStorage/OneDrive-WestPoint/Documents/ACI/Topics/WIRE/.cursor/debug.log', 'a') as f:
        f.write(json.dumps({"sessionId":"debug-session","runId":"pre-fix","hypothesisId":"B","location":"ingest-baselines.py:5026","message":"db connection","data":{"db_path":str(args.db),"db_exists":args.db.exists(),"schema_path":str(args.schema)},"timestamp":int(__import__('time').time()*1000)})+"\n")
    # #endregion
    db_init(conn, args.schema)
    # #region agent log
    try:
        cols = [r[1] for r in conn.execute("PRAGMA table_info('run_auth_log_stats')").fetchall()]
        with open('/Users/blane/Library/CloudStorage/OneDrive-WestPoint/Documents/ACI/Topics/WIRE/.cursor/debug.log', 'a') as f:
            f.write(json.dumps({"sessionId":"debug-session","runId":"pre-fix","hypothesisId":"B","location":"ingest-baselines.py:5030","message":"table columns after db_init","data":{"columns":cols,"has_source":"source" in cols},"timestamp":int(__import__('time').time()*1000)})+"\n")
    except Exception as e:
        with open('/Users/blane/Library/CloudStorage/OneDrive-WestPoint/Documents/ACI/Topics/WIRE/.cursor/debug.log', 'a') as f:
            f.write(json.dumps({"sessionId":"debug-session","runId":"pre-fix","hypothesisId":"B","location":"ingest-baselines.py:5033","message":"table check error","data":{"error":str(e)},"timestamp":int(__import__('time').time()*1000)})+"\n")
    # #endregion
    db_migrate(conn)
    if not args.skip_host_csv and args.host_csv.exists():
        upsert_assets_from_csv(conn, args.host_csv)
    elif not args.skip_host_csv and not args.host_csv.exists():
        print(f"Note: host CSV not found ({args.host_csv}); continuing in baseline-only mode.")

    # Import baseline expectations from host inventory CSV
    baseline_csv_path = args.host_csv
    import_baseline_csv(conn, baseline_csv_path)

    if args.show_identity_conflicts:
        conflicts = get_asset_identity_conflicts(conn)
        if conflicts:
            print("\n=== ASSET IDENTITY CONFLICTS ===")
            print("The following identifiers are shared by multiple assets (potential merge issues):")
            for conflict in conflicts:
                fake_marker = " [FAKE]" if conflict['is_fake'] else ""
                print(f"  {conflict['id_type']}: {conflict['id_value']}{fake_marker}")
                for asset in conflict['assets']:
                    print(f"    -> {asset}")
                print()
        else:
            print("\n=== ASSET IDENTITY CONFLICTS ===")
            print("No identity conflicts found - all identifiers map to unique assets.")

        # Don't ingest if we're just showing conflicts
        return 0

    ingested = 0
    skipped = 0
    for fp in iter_baseline_result_files(args.results_dir):
        rid = ingest_baseline_file(conn, fp, reingest=args.reingest)
        if rid is None:
            skipped += 1
        else:
            ingested += 1

    sync_asset_inventory_from_runs(conn)

    # Lightweight summary for operator feedback
    assets = conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
    runs = conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
    cmds = conn.execute("SELECT COUNT(*) FROM run_commands").fetchone()[0]
    print(f"Assets: {assets} | Runs: {runs} | Commands: {cmds} | Newly ingested: {ingested} | Skipped: {skipped}")

    conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

