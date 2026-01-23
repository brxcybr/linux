## Baseline command catalog (`survey/baseline.sh`)

This document describes **why** each command is run, what it typically reveals, and how it maps into the database.

### How baseline output is structured

- Each command block begins with a line like: `$ <command>`
- The following lines are the command’s stdout/stderr until the next `$ ...`
- Section headers are delimited with asterisks, e.g. `************HOST INFO**************`
  - The exact section names may evolve over time (for example: `EXECUTION CONTEXT`, `SSH & SUDO POSTURE`, `NETWORK & FIREWALL`).
  - In the database, the **stable identifier** for a command is `command_tag` (not the section name).

In the DB:

- **Lossless**: every block is stored in `run_commands` (keyed by `run_id`, `command_tag`).
- **Parsed**: selected commands are additionally extracted into normalized `run_*` tables.
- **Current snapshot**: `v_asset_current` and `v_asset_security_summary` provide one-row-per-host “latest run” views.

---

## HOST INFO

### `hostnamectl`
- **Intent**: stable host identity and OS “headline” metadata.
- **What it reveals**: hostname, OS, kernel, arch, vendor/model, machine-id, boot-id.
- **DB mapping**:
  - Parsed → `run_hostinfo`
  - Identifiers → `asset_identifiers` (`machine_id`, `hostname`)

### `uname -a`
- **Intent**: kernel build + arch string (useful for drift/patch level and forensic context).
- **DB mapping**: parsed → `run_uname`

### `cat /etc/*release*`
- **Intent**: distribution/version facts (`ID`, `VERSION_ID`, `PRETTY_NAME`, etc.).
- **DB mapping**: parsed → `run_os_release_kv`

### `domainname`
- **Intent**: NIS/YP domain (often `(none)` on modern Linux; not DNS domain).
- **DB mapping**: stored raw in `run_commands` (not parsed currently)

### `timedatectl`
- **Intent**: time sync posture (NTP active?), timezone, clock sync status.
- **DB mapping**: parsed → `run_timedate`

### `ntpstat`
- **Intent**: additional NTP sync sanity-check (often missing on Ubuntu).
- **DB mapping**: stored raw in `run_commands` (parsing not implemented; command may be “not found”)

### `who -a`
- **Intent**: current/previous logins, runlevel, and active sessions (quick anomaly hunting).
- **DB mapping**: stored raw in `run_commands` (not parsed currently)

### `uptime`
- **Intent**: uptime + load averages; correlate with maintenance windows and stability.
- **DB mapping**: parsed → `run_uptime` (load averages)

### `free -h`
- **Intent**: memory and swap size/pressure.
- **DB mapping**: parsed → `run_memory` (bytes)

### `lsblk -a`
- **Intent**: block device inventory and mountpoints.
- **DB mapping**: parsed → `run_block_devices` (best-effort)

### `df -B1`
- **Intent**: disk free per mount in bytes (size, used, avail). Complements `lsblk`; `lsblk` does not provide available space.
- **DB mapping**: parsed → `run_df_mounts` (filesystem, size_bytes, used_bytes, avail_bytes, use_pct, mountpoint)

### `cat /proc/partitions`
- **Intent**: kernel’s view of partitions (helps validate storage layout).
- **DB mapping**: stored raw in `run_commands` (not parsed currently)

### `iostat`
- **Intent**: IO throughput and utilization; can reveal contention.
- **DB mapping**: stored raw in `run_commands` (not parsed currently)

### `findmnt --all`
- **Intent**: mounted filesystems and propagation context (useful for persistence checks).
- **DB mapping**: stored raw in `run_commands` (not parsed currently)

### `cat /etc/fstab`
- **Intent**: persistent mounts (attackers sometimes add mounts for persistence/exfil).
- **DB mapping**: stored raw in `run_commands` (not parsed currently)

### `dmidecode`
- **Intent**: hardware identity (UUID/serial/product) and platform metadata.
- **Caveat**: can be inaccurate in VMs.
- **DB mapping**:
  - Parsed subset → `run_dmi_system`
  - Identifiers → `asset_identifiers` (`dmi_uuid`, `serial_number`)

### `lshw -disable dmi`
- **Intent**: hardware inventory without trusting DMI (can be more truthful than dmidecode).
- **DB mapping**: stored raw in `run_commands` (not parsed currently)

### `lsscsi -v`
- **Intent**: storage controller / SCSI topology.
- **DB mapping**: stored raw in `run_commands` (not parsed currently)

### `lspci -v`
- **Intent**: PCI devices + kernel drivers (great for “what hardware is present”).
- **DB mapping**: parsed GPU subset → `run_gpu_devices` (VGA/3D/Display blocks)

### `lsusb -v`
- **Intent**: USB device inventory; can reveal unexpected peripherals.
- **DB mapping**: stored raw in `run_commands` (not parsed currently)

---

## USER INFO

### `whoami`, `id`
- **Intent**: confirms execution context (root vs not; uid/gids).
- **DB mapping**: stored raw (not parsed)

### `cat /root/.bash_history`
- **Intent**: quick triage for suspicious commands.
- **Security note**: may contain secrets; treat as sensitive.
- **DB mapping**: stored raw (not parsed)

### `printenv`, `set`
- **Intent**: environment context; can help detect malicious env injection.
- **Security note**: may contain secrets/tokens; treat as sensitive.
- **DB mapping**: stored raw (not parsed)

### `cat /etc/passwd`
- **Intent**: authoritative local accounts list.
- **DB mapping**: parsed → `run_users`

### `cat /etc/group`
- **Intent**: local groups and membership.
- **DB mapping**:
  - parsed → `run_groups`
  - normalized members → `run_group_members` (source `etc_group`)

### `getent group sudo root wheel adm admin`
- **Intent**: privileged group membership via NSS (captures LDAP/SSSD, not only local `/etc/group`).
- **DB mapping**:
  - parsed → `run_priv_groups`
  - normalized members → `run_group_members` (source `getent`)

### `passwd -S <user>` for all users
- **Intent**: password/lock status and basic aging info.
- **DB mapping**: parsed → `run_passwd_status`

---

## LOGON INFO

### `w`, `tty`
- **Intent**: active sessions, remote IPs, activity.
- **DB mapping**: stored raw (not parsed)

### `lastlog | sort`, `last -f /var/log/wtmp`, `last -f /var/log/btmp`, `last -f /var/run/utmp`
- **Intent**: login history and failed logins (brute force detection).
- **DB mapping**:
  - Parsed → `run_lastlog`, `run_last_events`, `run_who_lines`, `run_w_sessions`
  - Failed logins extracted → `run_failed_logins` (with timestamp normalization)
  - Views → `v_failed_logins_recent`, `v_accounts_never_logged_in_with_keys`

### SSH key material (`known_hosts`, `authorized_keys`)
- **Intent**: detect unexpected trust relationships and persistence via SSH keys.
- **DB mapping**:
  - authorized keys parsed as **fingerprints only** → `run_ssh_authorized_keys`
  - known_hosts currently stored raw (parsing not implemented)

---

## PERSISTENCE INFO

### Shell-enabled users (`cat /etc/passwd | grep 'sh$'`)
- **Intent**: quick list of accounts capable of interactive login.
- **DB mapping**: stored raw (you can also derive from `run_users.shell`)

### Root shell init files (`/root/.bash_profile`, `.bash_login`, `.profile`, `.bashrc`, `.bash_logout`)
- **Intent**: persistence via shell initialization.
- **DB mapping**: stored raw (not parsed)

### `/etc/skel` diffs (root and all users)
- **Intent**: detect modified default shell rc / login scripts compared to defaults.
- **DB mapping**: stored raw (not parsed)

### `rc.local`, `atq`, crontab + cron dirs, init/systemd dirs, recent binaries in PATH
- **Intent**: classic persistence locations; “recent binaries” is a strong IOC heuristic.
- **DB mapping**: stored raw (not parsed yet; good candidate for a future “file_metadata” parser)

---

## NETWORK INFO

### `nmcli`, `ip a`, `resolv.conf`, `ip neigh`, `route -n`
- **Intent**: network interfaces, IPs, DNS config, ARP cache, routing.
- **DB mapping**:
  - `ip a` parsed → `run_interfaces`, `run_interface_addrs`
  - `resolv.conf` parsed → `run_resolv_conf_entries`
  - `ip neigh` parsed → `run_ip_neigh`
  - `route -n` parsed → `run_routes`
  - Posture derived → `run_network_posture` (unexpected nameservers, route anomalies)

### Connection/process exposure (`netstat ...`, `lsof -Pni`, `ss -punt`)
- **Intent**: sockets + process context; quick “what’s exposed” snapshot.
- **DB mapping**:
  - `ss -punt` parsed → `run_sockets` (view over `run_listening_sockets`)
  - netstat/lsof stored raw

### Local services (rpcinfo, smbclient, showmount)
- **Intent**: detect unexpected RPC/NFS/SMB services and exports.
- **DB mapping**: stored raw (not parsed yet)

### Firewall (`iptables`, `firewall-cmd`, `ufw`)
- **Intent**: host firewall posture and rulebase.
- **DB mapping**:
  - rules stored → `run_firewall_rules` (source `iptables_s`, `iptables_list`, `ufw_raw`, `firewalld_zones`)

---

## PROCESS / SERVICE / SOFTWARE INFO

### `ps -elf --sort pid`, `pstree`
- **Intent**: process inventory + parent/child relationships (IOC hunting).
- **DB mapping**:
  - `ps -elf` parsed → `run_processes`
  - `pstree` parsed → `run_pstree_lines`
  - Insights derived → `run_process_insights` (suspicious root processes, unusual listening services)

### `systemctl list-units -all --full`
- **Intent**: services and their active state.
- **DB mapping**: parsed → `run_services_systemctl`

### Packages (`rpm -q --all`, `dpkg -l`)
- **Intent**: installed software inventory (for diffing and vulnerability assessment).
- **DB mapping**: parsed → `run_packages`

### Kernel modules (`lsmod`, `modinfo` for each module)
- **Intent**: loaded drivers/modules; detect unusual modules/rootkits.
- **DB mapping**:
  - `lsmod` parsed → `run_lsmod`
  - `modinfo` parsed → `run_modinfo_kv`
  - Insights derived → `run_kernel_module_insights` (unusual modules, suspicious licenses)

---

## SECURITY POLICY CHECKS

### Auditd (`auditctl -s`, `auditctl -l`)
- **Intent**: audit subsystem enabled/locked? which rules loaded?
- **DB mapping**:
  - `auditctl -s` parsed → `run_audit_status`
  - `auditctl -l` parsed → `run_audit_rules` (action, list_type, arch, key_name, syscall, path, permission, etc.)
  - Posture derived → `run_audit_posture` (enabled/immutable flags, critical area coverage)

### Logging (`rsyslog.conf`, `journald.conf`)
- **Intent**: logging configuration posture; explicit remote log destinations (rsyslog) and journald forwarding (ForwardToSyslog, etc.).
- **DB mapping**:
  - `cat /etc/rsyslog.conf` parsed → `run_facts` (group `rsyslog`, key `remote_destinations`, JSON array of `*.* @host` / `*.* @@host` targets; `[]` when none).
  - `cat /etc/systemd/journald.conf` parsed → `run_facts` (group `journald`); [Journal] keys `ForwardToSyslog`, `ForwardToWall`, `ForwardToKMsg`, `ForwardToConsole`, `MaxLevelSyslog`, `Audit`, etc. (including commented defaults).

### SELinux/AppArmor (`sestatus`, `getsebool -a`, `aa-status`, labeled ps/netstat)
- **Intent**: MAC (mandatory access control) posture; detect unconfined processes.
- **DB mapping**:
  - `sestatus` parsed → `run_selinux_status`
  - `getsebool -a` parsed → `run_selinux_booleans`
  - `aa-status` parsed → `run_apparmor_status`
  - Posture derived → `run_selinux_posture`, `run_apparmor_posture` (high-risk booleans, enforcement mode)

### Password/auth policies (`pam.d/*`, `login.defs`, `useradd`, `adduser.conf`, `/etc/hosts.allow|deny`, `/etc/cron.allow|deny`)
- **Intent**: password complexity/aging, auth hardening, TCP wrappers, cron restrictions.
- **DB mapping**:
  - `cat /etc/login.defs` parsed → `run_login_defs_kv` (key/value: `PASS_MAX_DAYS`, `PASS_MIN_DAYS`, `PASS_WARN_AGE`, `PASS_MIN_LEN`, `UID_MIN`, etc.).
  - PAM, useradd, adduser, hosts.allow/deny, cron.allow/deny: stored raw (parsing not implemented yet).

---

## Additional posture commands (added for deeper security visibility)

### `cat /proc/cmdline`
- **Intent**: boot-time security posture (audit/selinux/lockdown parameters, mitigations).
- **DB mapping**: parsed → `run_kernel_cmdline_kv` (also surfaced as a few `run_facts` in group `boot`).

### Targeted `sysctl ...` hardening set
- **Intent**: capture a focused set of high-signal sysctls without the noise of `sysctl -a`.
- **DB mapping**: parsed → `run_sysctl_kv`

### `mokutil --sb-state`
- **Intent**: Secure Boot state (where supported) to reason about boot chain integrity.
- **DB mapping**: parsed → `run_secure_boot`

### `sshd -T`
- **Intent**: effective SSH daemon configuration (high value for remote-access posture).
- **DB mapping**: parsed → `run_sshd_config_kv` (plus key settings mirrored into `run_facts` group `sshd`).

### `ssh-keygen -lf /etc/ssh/ssh_host_*_key.pub`
- **Intent**: SSH host key fingerprints (trust anchor; detect unexpected key changes).
- **DB mapping**: parsed → `run_ssh_host_keys`

### `cat /etc/sudoers` and `cat /etc/sudoers.d/*`
- **Intent**: privilege escalation surface; detect `NOPASSWD` and broad `ALL=(ALL)` grants.
- **DB mapping**: parsed (best-effort) → `run_sudoers_rules` (plus counts in `run_facts` group `sudo`).

### `nft list ruleset`
- **Intent**: capture nftables posture (many distros use nftables directly or via iptables-nft).
- **DB mapping**: stored raw → `run_nft_ruleset` (plus a small posture fact in `run_facts` group `firewall`).

### `systemctl list-timers --all` and `systemctl list-unit-files --state=enabled`
- **Intent**: identify persistence via timers/services and startup drift.
- **DB mapping**:
  - timers parsed → `run_systemd_timers`
  - enabled units parsed → `run_systemd_enabled_unit_files`

### `getcap -r /`
- **Intent**: file capabilities (privileged operations without SUID); common escalation/persistence surface.
- **DB mapping**: parsed → `run_file_capabilities`

### `cat /etc/ld.so.preload`
- **Intent**: dynamic linker preload hook surface (very high-signal stealth/persistence mechanism).
- **DB mapping**: parsed → `run_ld_preload_entries`

### Bounded auth log telemetry (`journalctl ...`, `tail ... auth.log|secure`)
- **Intent**: quick triage for brute force / accepted logins / sudo events without full log export.
- **DB mapping**: parsed summary counts → `run_auth_log_stats`

### Container runtime posture (`docker ...`, `podman ...`)
- **Intent**: identify container workloads and runtime configuration drift (common source of exposed services and persistence).
- **DB mapping**: parsed summary → `run_container_summary`

---

## Notes on “what we parse vs keep raw”

The current approach is:

- Parse into tables when the output is **high value** and **structured enough** to parse reliably across distros.
- Keep raw output in `run_commands` for everything else, so you can add parsers later without re-collecting data.

