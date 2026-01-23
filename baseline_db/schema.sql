PRAGMA foreign_keys = ON;

-- =========================
-- Core dimensions
-- =========================

-- Baseline command catalog: short/long descriptions per `command_tag`.
CREATE TABLE IF NOT EXISTS command_catalog (
  command_tag TEXT PRIMARY KEY,
  section TEXT,
  command TEXT,
  short_desc TEXT NOT NULL,
  long_desc TEXT NOT NULL,
  data_sensitivity TEXT NOT NULL DEFAULT 'normal', -- normal | sensitive
  parse_status TEXT NOT NULL DEFAULT 'raw',        -- raw | parsed | partial
  created_at_utc TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at_utc TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS assets (
  asset_id INTEGER PRIMARY KEY,
  hostname TEXT NOT NULL UNIQUE,
  domain TEXT,
  fqdn TEXT,
  classification TEXT,
  location TEXT,
  created_at_utc TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at_utc TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

-- Stable identifiers for an asset discovered from baselines.
-- Rationale: hostnames and IPs can change; Machine ID / DMI UUID tends to be stable.
CREATE TABLE IF NOT EXISTS asset_identifiers (
  identifier_id INTEGER PRIMARY KEY,
  asset_id INTEGER NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
  id_type TEXT NOT NULL,   -- e.g. machine_id, dmi_uuid, serial_number
  id_value TEXT NOT NULL,
  first_seen_utc TEXT NOT NULL,
  last_seen_utc TEXT NOT NULL,
  UNIQUE(asset_id, id_type, id_value)
);

CREATE INDEX IF NOT EXISTS idx_asset_identifiers_type_value ON asset_identifiers(id_type, id_value);

CREATE TABLE IF NOT EXISTS asset_inventory (
  asset_id INTEGER PRIMARY KEY REFERENCES assets(asset_id) ON DELETE CASCADE,
  server_manufacturer TEXT,
  server_model_series TEXT,
  server_model_no TEXT,
  proc_manufacturer TEXT,
  proc_model_series TEXT,
  proc_model_no TEXT,
  proc_no_cores INTEGER,
  proc_count INTEGER,
  gpu_manufacturer TEXT,
  gpu_model_series TEXT,
  gpu_model_no TEXT,
  gpu_count INTEGER,
  memory_capacity_gb REAL,
  storage_hdd_no_drives INTEGER,
  storage_hdd_capacity_gb REAL,
  storage_nvme_no_drives INTEGER,
  storage_nvme_capacity_gb REAL,
  storage_ssd_no_drives INTEGER,
  storage_ssd_capacity_gb REAL,
  os_name TEXT,
  os_version TEXT,
  arch TEXT,
  primary_ip TEXT,
  interface TEXT,
  mac_addr TEXT,
  vlan TEXT,
  last_updated TEXT
);

-- One baseline execution on one host.
CREATE TABLE IF NOT EXISTS runs (
  run_id INTEGER PRIMARY KEY,
  asset_id INTEGER REFERENCES assets(asset_id) ON DELETE SET NULL,
  source_ip TEXT,
  collected_at_utc TEXT NOT NULL, -- ISO-8601 UTC, derived from filename
  source_path TEXT NOT NULL UNIQUE,
  source_sha256 TEXT,
  ingested_at_utc TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  parser_version TEXT NOT NULL
);

-- Performance indexes for common query patterns
-- (Moved to end of file after all tables are created)

-- =========================
-- Raw command outputs (lossless baseline storage)
-- =========================

CREATE TABLE IF NOT EXISTS run_commands (
  command_id INTEGER PRIMARY KEY,
  run_id INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  section TEXT,                -- e.g., HOST INFO / USER INFO / NETWORK INFO
  command_index INTEGER NOT NULL,
  command TEXT NOT NULL,       -- as printed in baseline output after "$ "
  command_tag TEXT NOT NULL,   -- normalized tag used for grouping across runs
  output_text TEXT NOT NULL,
  UNIQUE(run_id, command_index)
);

CREATE INDEX IF NOT EXISTS idx_run_commands_run_tag ON run_commands(run_id, command_tag);
CREATE INDEX IF NOT EXISTS idx_run_commands_tag ON run_commands(command_tag);

-- =========================
-- Parsed / normalized tables (incrementally expandable)
-- =========================

-- hostnamectl (and some derived facts)
CREATE TABLE IF NOT EXISTS run_hostinfo (
  run_id INTEGER PRIMARY KEY REFERENCES runs(run_id) ON DELETE CASCADE,
  static_hostname TEXT,
  icon_name TEXT,
  chassis TEXT,
  machine_id TEXT,
  boot_id TEXT,
  operating_system TEXT,
  kernel TEXT,
  architecture TEXT,
  hardware_vendor TEXT,
  hardware_model TEXT
);

-- Time / clock state from `timedatectl`
CREATE TABLE IF NOT EXISTS run_timedate (
  run_id INTEGER PRIMARY KEY REFERENCES runs(run_id) ON DELETE CASCADE,
  local_time TEXT,
  universal_time TEXT,
  rtc_time TEXT,
  time_zone TEXT,
  system_clock_synchronized TEXT,
  ntp_service TEXT,
  rtc_in_local_tz TEXT
);

-- Uptime snapshot from `uptime` (store as raw + best-effort parsed fields)
CREATE TABLE IF NOT EXISTS run_uptime (
  run_id INTEGER PRIMARY KEY REFERENCES runs(run_id) ON DELETE CASCADE,
  raw_line TEXT,
  load_1 REAL,
  load_5 REAL,
  load_15 REAL
);

-- Memory snapshot from `free -h`
CREATE TABLE IF NOT EXISTS run_memory (
  run_id INTEGER PRIMARY KEY REFERENCES runs(run_id) ON DELETE CASCADE,
  mem_total_bytes INTEGER,
  mem_used_bytes INTEGER,
  mem_free_bytes INTEGER,
  mem_available_bytes INTEGER,
  swap_total_bytes INTEGER,
  swap_used_bytes INTEGER,
  swap_free_bytes INTEGER
);

-- Block devices from `lsblk -a` (best-effort)
CREATE TABLE IF NOT EXISTS run_block_devices (
  block_device_id INTEGER PRIMARY KEY,
  run_id INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  type TEXT,
  size_bytes INTEGER,
  rm INTEGER,
  ro INTEGER,
  mountpoints TEXT,
  raw_line TEXT,
  UNIQUE(run_id, name, type, size_bytes, rm, ro, mountpoints, raw_line)
);

-- Key system identity fields from `dmidecode` (best-effort, may be inaccurate in VMs)
CREATE TABLE IF NOT EXISTS run_dmi_system (
  run_id INTEGER PRIMARY KEY REFERENCES runs(run_id) ON DELETE CASCADE,
  manufacturer TEXT,
  product_name TEXT,
  version TEXT,
  serial_number TEXT,
  uuid TEXT,
  sku_number TEXT,
  family TEXT
);

-- GPUs / display controllers from `lspci -v` (best-effort)
CREATE TABLE IF NOT EXISTS run_gpu_devices (
  gpu_device_id INTEGER PRIMARY KEY,
  run_id INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  slot TEXT,
  class TEXT,          -- e.g. VGA compatible controller / 3D controller
  description TEXT,    -- full description line
  vendor TEXT,
  device TEXT,
  kernel_driver_in_use TEXT,
  raw_block TEXT,
  UNIQUE(run_id, slot, class, device, kernel_driver_in_use)
);

-- Privileged group membership from `getent group ...` (captures NSS/LDAP, not just /etc/group)
CREATE TABLE IF NOT EXISTS run_priv_groups (
  run_id INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  groupname TEXT NOT NULL,
  gid INTEGER,
  members_csv TEXT,
  source TEXT NOT NULL DEFAULT 'getent',
  PRIMARY KEY (run_id, source, groupname)
);

-- Authorized SSH keys stored as *fingerprints only* (no key material).
CREATE TABLE IF NOT EXISTS run_ssh_authorized_keys (
  run_id INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  username TEXT NOT NULL,
  key_type TEXT,
  key_fingerprint_sha256 TEXT NOT NULL,
  key_comment TEXT,
  raw_line_hash_sha256 TEXT NOT NULL,
  PRIMARY KEY (run_id, username, key_fingerprint_sha256)
);

-- /etc/*release* (key/value)
CREATE TABLE IF NOT EXISTS run_os_release_kv (
  run_id INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  k TEXT NOT NULL,
  v TEXT,
  PRIMARY KEY (run_id, k)
);

-- uname -a (raw)
CREATE TABLE IF NOT EXISTS run_uname (
  run_id INTEGER PRIMARY KEY REFERENCES runs(run_id) ON DELETE CASCADE,
  uname_a TEXT
);

-- /etc/passwd
CREATE TABLE IF NOT EXISTS run_users (
  run_id INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  username TEXT NOT NULL,
  uid INTEGER,
  gid INTEGER,
  gecos TEXT,
  home TEXT,
  shell TEXT,
  PRIMARY KEY (run_id, username)
);

-- /etc/group
CREATE TABLE IF NOT EXISTS run_groups (
  run_id INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  groupname TEXT NOT NULL,
  gid INTEGER,
  members_csv TEXT,
  PRIMARY KEY (run_id, groupname)
);

-- Normalized group membership (splits members_csv for joining)
CREATE TABLE IF NOT EXISTS run_group_members (
  run_id INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  source TEXT NOT NULL,           -- etc_group | getent
  groupname TEXT NOT NULL,
  member_username TEXT NOT NULL,
  PRIMARY KEY (run_id, source, groupname, member_username)
);

-- passwd -S (password status & aging)
CREATE TABLE IF NOT EXISTS run_passwd_status (
  run_id INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  username TEXT NOT NULL,
  status_code TEXT, -- e.g., P, L, NP
  last_change TEXT, -- typically MM/DD/YYYY on Ubuntu, leave as text for now
  min_age TEXT,
  max_age TEXT,
  warn TEXT,
  inactive TEXT,
  expire TEXT,
  PRIMARY KEY (run_id, username)
);

-- `who -a` lines (best-effort; retains raw for fidelity)
CREATE TABLE IF NOT EXISTS run_who_lines (
  who_line_id INTEGER PRIMARY KEY,
  run_id INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  line_no INTEGER NOT NULL,
  record_type TEXT,   -- system_boot | run_level | login | user | other
  username TEXT,
  tty TEXT,
  event_time TEXT,
  pid INTEGER,
  remote_host TEXT,
  raw_line TEXT NOT NULL,
  UNIQUE(run_id, line_no)
);

-- `w` sessions (best-effort)
CREATE TABLE IF NOT EXISTS run_w_sessions (
  w_session_id INTEGER PRIMARY KEY,
  run_id INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  username TEXT,
  tty TEXT,
  from_host TEXT,
  login_at TEXT,
  idle TEXT,
  jcpu TEXT,
  pcpu TEXT,
  what TEXT,
  raw_line TEXT NOT NULL,
  UNIQUE(run_id, raw_line)
);

-- `lastlog` (best-effort)
CREATE TABLE IF NOT EXISTS run_lastlog (
  lastlog_id INTEGER PRIMARY KEY,
  run_id INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  username TEXT,
  port TEXT,
  from_host TEXT,
  latest TEXT,
  raw_line TEXT NOT NULL,
  UNIQUE(run_id, raw_line)
);

-- `last` events (wtmp/btmp/utmp) best-effort
CREATE TABLE IF NOT EXISTS run_last_events (
  last_event_id INTEGER PRIMARY KEY,
  run_id INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  source TEXT NOT NULL,     -- wtmp | btmp | utmp
  username TEXT,
  tty TEXT,
  remote_host TEXT,
  start_text TEXT,
  end_text TEXT,
  duration_text TEXT,
  status_text TEXT,
  raw_line TEXT NOT NULL,
  UNIQUE(run_id, source, raw_line)
);

-- Enhanced failed login events (derived from btmp)
CREATE TABLE IF NOT EXISTS run_failed_logins (
  failed_login_id INTEGER PRIMARY KEY,
  run_id INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  username TEXT NOT NULL,
  remote_host TEXT,
  tty TEXT,
  attempt_time_utc TEXT,  -- normalized ISO UTC timestamp
  raw_start_text TEXT,
  raw_line TEXT NOT NULL,
  UNIQUE(run_id, username, remote_host, tty, attempt_time_utc, raw_line)
);

-- `auditctl -s` audit subsystem status
CREATE TABLE IF NOT EXISTS run_audit_status (
  run_id INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  k TEXT NOT NULL,
  v TEXT,
  PRIMARY KEY (run_id, k)
);

-- `auditctl -l` audit rules (enhanced parsing)
CREATE TABLE IF NOT EXISTS run_audit_rules (
  audit_rule_id INTEGER PRIMARY KEY,
  run_id INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  rule_text TEXT NOT NULL,
  action TEXT,
  list_type TEXT,
  arch TEXT,
  key_name TEXT,
  syscall TEXT,
  path TEXT,
  permission TEXT,
  uid TEXT,
  gid TEXT,
  auid TEXT,
  subj TEXT,
  rule_type TEXT,
  UNIQUE(run_id, rule_text)
);

-- Derived audit posture flags
CREATE TABLE IF NOT EXISTS run_audit_posture (
  run_id INTEGER PRIMARY KEY REFERENCES runs(run_id) ON DELETE CASCADE,
  audit_enabled INTEGER NOT NULL DEFAULT 0,  -- 1=true, 0=false
  audit_immutable INTEGER NOT NULL DEFAULT 0,
  has_critical_auth_rules INTEGER NOT NULL DEFAULT 0,
  has_critical_file_rules INTEGER NOT NULL DEFAULT 0,
  has_critical_process_rules INTEGER NOT NULL DEFAULT 0,
  has_time_change_rules INTEGER NOT NULL DEFAULT 0,
  has_sudo_rules INTEGER NOT NULL DEFAULT 0,
  has_passwd_rules INTEGER NOT NULL DEFAULT 0,
  has_executable_rules INTEGER NOT NULL DEFAULT 0
);

-- SELinux status (`sestatus`) kv
CREATE TABLE IF NOT EXISTS run_selinux_status (
  run_id INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  k TEXT NOT NULL,
  v TEXT,
  PRIMARY KEY (run_id, k)
);

-- SELinux booleans (`getsebool -a`)
CREATE TABLE IF NOT EXISTS run_selinux_booleans (
  run_id INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  boolean_name TEXT NOT NULL,
  state TEXT NOT NULL, -- on/off
  PRIMARY KEY (run_id, boolean_name)
);

-- Derived SELinux posture flags
CREATE TABLE IF NOT EXISTS run_selinux_posture (
  run_id INTEGER PRIMARY KEY REFERENCES runs(run_id) ON DELETE CASCADE,
  selinux_enabled INTEGER NOT NULL DEFAULT 0,
  selinux_enforcing INTEGER NOT NULL DEFAULT 0,
  selinux_permissive INTEGER NOT NULL DEFAULT 0,
  selinux_disabled INTEGER NOT NULL DEFAULT 0,
  high_risk_booleans_on TEXT,  -- JSON array of boolean names
  high_risk_booleans_off TEXT  -- JSON array of boolean names
);

-- Baseline expectations imported from CSV (optional host inventory)
CREATE TABLE IF NOT EXISTS host_inventory (
  hostname TEXT PRIMARY KEY,
  domain TEXT,
  fqdn TEXT,
  classification TEXT,
  location TEXT,
  server_manufacturer TEXT,
  server_model_series TEXT,
  server_model_no TEXT,
  proc_manufacturer TEXT,
  proc_model_series TEXT,
  proc_model_no TEXT,
  proc_no_cores INTEGER,
  proc_count INTEGER,
  gpu_manufacturer TEXT,
  gpu_model_series TEXT,
  gpu_model_no TEXT,
  gpu_count INTEGER,
  memory_capacity_gb REAL,
  storage_hdd_no_drives INTEGER,
  storage_hdd_capacity_gb REAL,
  storage_nvme_no_drives INTEGER,
  storage_nvme_capabity_gb REAL,  -- Note: matches CSV typo
  storage_ssd_no_drives INTEGER,
  storage_ssd_capabity_gb REAL,   -- Note: matches CSV typo
  os_name TEXT,
  os_version TEXT,
  arch TEXT,
  primary_ip TEXT,
  interface TEXT,
  mac_addr TEXT
);

-- USB devices from `lsusb -v` (security-relevant device inventory)
CREATE TABLE IF NOT EXISTS run_usb_devices (
  usb_device_id INTEGER PRIMARY KEY,
  run_id INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  bus_number INTEGER,
  device_number INTEGER,
  vendor_id TEXT,
  product_id TEXT,
  device_class INTEGER,
  device_subclass INTEGER,
  device_protocol INTEGER,
  vendor_name TEXT,
  product_name TEXT,
  manufacturer TEXT,
  product TEXT,
  serial_number TEXT,
  usb_version TEXT,
  device_speed TEXT,
  max_power TEXT,
  UNIQUE(run_id, bus_number, device_number, vendor_id, product_id)
);

-- AppArmor status (`aa-status`) summary (best-effort)
CREATE TABLE IF NOT EXISTS run_apparmor_status (
  run_id INTEGER PRIMARY KEY REFERENCES runs(run_id) ON DELETE CASCADE,
  raw_text TEXT NOT NULL,
  profiles_loaded INTEGER,
  profiles_enforce INTEGER,
  profiles_complain INTEGER,
  processes_enforce INTEGER,
  processes_complain INTEGER
);

-- Derived AppArmor posture flags
CREATE TABLE IF NOT EXISTS run_apparmor_posture (
  run_id INTEGER PRIMARY KEY REFERENCES runs(run_id) ON DELETE CASCADE,
  apparmor_enabled INTEGER NOT NULL DEFAULT 0,
  apparmor_profiles_loaded INTEGER NOT NULL DEFAULT 0,
  apparmor_all_enforcing INTEGER NOT NULL DEFAULT 0,
  apparmor_mixed_mode INTEGER NOT NULL DEFAULT 0,
  apparmor_processes_unconfined INTEGER NOT NULL DEFAULT 0
);

-- resolv.conf entries
CREATE TABLE IF NOT EXISTS run_resolv_conf_entries (
  resolv_entry_id INTEGER PRIMARY KEY,
  run_id INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  entry_type TEXT NOT NULL, -- nameserver | search | options | other
  entry_value TEXT,
  raw_line TEXT NOT NULL,
  UNIQUE(run_id, raw_line)
);

-- ip neigh entries
CREATE TABLE IF NOT EXISTS run_ip_neigh (
  ip_neigh_id INTEGER PRIMARY KEY,
  run_id INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  ip TEXT,
  dev TEXT,
  lladdr TEXT,
  state TEXT,
  raw_line TEXT NOT NULL,
  UNIQUE(run_id, raw_line)
);

-- route -n table
CREATE TABLE IF NOT EXISTS run_routes (
  route_id INTEGER PRIMARY KEY,
  run_id INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  destination TEXT,
  gateway TEXT,
  genmask TEXT,
  flags TEXT,
  metric INTEGER,
  ref INTEGER,
  use INTEGER,
  iface TEXT,
  raw_line TEXT NOT NULL,
  UNIQUE(run_id, raw_line)
);

-- nmcli summary (best-effort)
CREATE TABLE IF NOT EXISTS run_nmcli_summary (
  run_id INTEGER PRIMARY KEY REFERENCES runs(run_id) ON DELETE CASCADE,
  state TEXT,
  connectivity TEXT,
  wifi_hw TEXT,
  wifi TEXT,
  wwan_hw TEXT,
  wwan TEXT,
  raw_text TEXT NOT NULL
);

-- Derived network posture insights
CREATE TABLE IF NOT EXISTS run_network_posture (
  run_id INTEGER PRIMARY KEY REFERENCES runs(run_id) ON DELETE CASCADE,
  unexpected_nameservers TEXT,      -- JSON array of suspicious nameserver IPs
  multiple_default_routes INTEGER NOT NULL DEFAULT 0,
  suspicious_routes TEXT,           -- JSON array of suspicious route descriptions
  unknown_mac_ouis TEXT,            -- JSON array of unknown MAC OUI issues
  nameserver_flags TEXT             -- JSON array of nameserver analysis flags
);

-- ps -elf process inventory (best-effort)
CREATE TABLE IF NOT EXISTS run_processes (
  process_id INTEGER PRIMARY KEY,
  run_id INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  pid INTEGER,
  ppid INTEGER,
  uid TEXT,
  tty TEXT,
  stat TEXT,
  start TEXT,
  time TEXT,
  cmd TEXT,
  raw_line TEXT NOT NULL,
  UNIQUE(run_id, raw_line)
);

-- pstree lines (raw; useful for later graph parsing)
CREATE TABLE IF NOT EXISTS run_pstree_lines (
  run_id INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  line_no INTEGER NOT NULL,
  raw_line TEXT NOT NULL,
  PRIMARY KEY (run_id, line_no)
);

-- Derived process security insights
CREATE TABLE IF NOT EXISTS run_process_insights (
  run_id INTEGER PRIMARY KEY REFERENCES runs(run_id) ON DELETE CASCADE,
  suspicious_root_processes TEXT,    -- JSON array of suspicious root process descriptions
  unusual_listening_services TEXT,   -- JSON array of unusual listening service descriptions
  process_tree_issues TEXT           -- JSON array of process tree issues
);

-- lsmod module inventory
CREATE TABLE IF NOT EXISTS run_lsmod (
  lsmod_id INTEGER PRIMARY KEY,
  run_id INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  module TEXT,
  size INTEGER,
  used_by_count INTEGER,
  used_by TEXT,
  raw_line TEXT NOT NULL,
  UNIQUE(run_id, raw_line)
);

-- modinfo output key/value per module
CREATE TABLE IF NOT EXISTS run_modinfo_kv (
  modinfo_kv_id INTEGER PRIMARY KEY,
  run_id INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  module TEXT NOT NULL,
  k TEXT NOT NULL,
  v TEXT,
  UNIQUE(run_id, module, k, v)
);

-- Derived kernel module security insights
CREATE TABLE IF NOT EXISTS run_kernel_module_insights (
  run_id INTEGER PRIMARY KEY REFERENCES runs(run_id) ON DELETE CASCADE,
  unusual_modules TEXT,                -- JSON array of unusual module names
  suspicious_licenses TEXT,            -- JSON array of modules with suspicious licenses
  modules_with_unknown_signer TEXT     -- JSON array of modules with unknown signers
);

-- File listings for persistence surfaces (ls -latR, recent binaries)
CREATE TABLE IF NOT EXISTS run_file_listings (
  listing_id INTEGER PRIMARY KEY,
  run_id INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  source TEXT NOT NULL,        -- cron_dirs | systemd_dirs | recent_bins | other
  directory TEXT,
  path TEXT,
  perms TEXT,
  owner TEXT,
  grp TEXT,
  size_bytes INTEGER,
  mtime_text TEXT,
  name TEXT,
  file_type TEXT,
  raw_line TEXT NOT NULL,
  UNIQUE(run_id, source, directory, raw_line)
);

-- Derived persistence security insights
CREATE TABLE IF NOT EXISTS run_persistence_insights (
  run_id INTEGER PRIMARY KEY REFERENCES runs(run_id) ON DELETE CASCADE,
  suspicious_systemd_units TEXT,         -- JSON array of suspicious systemd unit descriptions
  unusual_cron_permissions TEXT,         -- JSON array of unusual cron permission issues
  recently_modified_persistence_files TEXT, -- JSON array of recently modified persistence files
  suspicious_cron_locations TEXT         -- JSON array of cron files in unusual locations
);

-- Interfaces & addresses from `ip a` (best-effort parsing)
CREATE TABLE IF NOT EXISTS run_interfaces (
  run_id INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  ifname TEXT NOT NULL,
  mac_addr TEXT,
  state TEXT,
  mtu INTEGER,
  PRIMARY KEY (run_id, ifname)
);

CREATE TABLE IF NOT EXISTS run_interface_addrs (
  run_id INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  ifname TEXT NOT NULL,
  family TEXT NOT NULL,      -- inet / inet6
  address TEXT NOT NULL,
  prefixlen INTEGER,
  scope TEXT,
  PRIMARY KEY (run_id, ifname, family, address)
);

-- Listening sockets from `ss -punt` (best-effort parsing)
CREATE TABLE IF NOT EXISTS run_listening_sockets (
  socket_id INTEGER PRIMARY KEY,
  run_id INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  proto TEXT,
  state TEXT,
  local_addr TEXT,
  local_port INTEGER,
  peer_addr TEXT,
  peer_port INTEGER,
  process_name TEXT,
  pid INTEGER,
  raw_line TEXT,
  UNIQUE(run_id, proto, state, local_addr, local_port, peer_addr, peer_port, pid, process_name)
);

-- systemctl list-units -all --full (best-effort parsing)
CREATE TABLE IF NOT EXISTS run_services_systemctl (
  run_id INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  unit TEXT NOT NULL,
  load TEXT,
  active TEXT,
  sub TEXT,
  description TEXT,
  PRIMARY KEY (run_id, unit)
);

-- Packages from dpkg/rpm (best-effort parsing)
CREATE TABLE IF NOT EXISTS run_packages (
  package_id INTEGER PRIMARY KEY,
  run_id INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  source TEXT NOT NULL, -- dpkg | rpm
  name TEXT NOT NULL,
  version TEXT,
  arch TEXT,
  status TEXT,
  summary TEXT,
  UNIQUE(run_id, source, name, version, arch, status)
);

-- Firewall rules (store parsed rules and/or raw lines)
CREATE TABLE IF NOT EXISTS run_firewall_rules (
  run_id INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  source TEXT NOT NULL,  -- iptables_s | iptables_list | ufw_raw | firewalld_zones
  rule TEXT NOT NULL,
  PRIMARY KEY (run_id, source, rule)
);

-- Generic facts bucket for incremental parsing without schema churn.
CREATE TABLE IF NOT EXISTS run_facts (
  run_id INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  fact_group TEXT NOT NULL,
  fact_key TEXT NOT NULL,
  fact_value TEXT,
  PRIMARY KEY (run_id, fact_group, fact_key)
);

-- df -B1 disk free (size/used/avail in bytes per mount)
CREATE TABLE IF NOT EXISTS run_df_mounts (
  df_mount_id INTEGER PRIMARY KEY,
  run_id INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  filesystem TEXT NOT NULL,
  size_bytes INTEGER,
  used_bytes INTEGER,
  avail_bytes INTEGER,
  use_pct TEXT,
  mountpoint TEXT NOT NULL,
  UNIQUE(run_id, filesystem, mountpoint)
);

-- /etc/login.defs key/value (password policy, UID/GID ranges, etc.)
CREATE TABLE IF NOT EXISTS run_login_defs_kv (
  run_id INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  k TEXT NOT NULL,
  v TEXT,
  PRIMARY KEY (run_id, k)
);

-- Security findings framework
CREATE TABLE IF NOT EXISTS findings (
  finding_id INTEGER PRIMARY KEY,
  run_id INTEGER NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  severity TEXT NOT NULL,        -- critical | high | medium | low | info
  category TEXT NOT NULL,        -- audit | selinux | apparmor | network | process | persistence | identity | auth
  title TEXT NOT NULL,
  details TEXT,
  evidence_ref TEXT,             -- table.row_id format for linking to evidence
  created_at_utc TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE INDEX IF NOT EXISTS idx_findings_run_severity ON findings(run_id, severity);
CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(run_id, category);

-- =========================
-- Convenience views
-- =========================

-- `ss -punt` captures active sockets (not only LISTEN); expose a clearer name.
DROP VIEW IF EXISTS run_sockets;
CREATE VIEW run_sockets AS
SELECT * FROM run_listening_sockets;

-- Latest baseline run per asset (for "current posture" queries).
DROP VIEW IF EXISTS v_latest_runs;
CREATE VIEW v_latest_runs AS
SELECT r.*
FROM runs r
JOIN (
  SELECT asset_id, MAX(collected_at_utc) AS collected_at_utc
  FROM runs
  GROUP BY asset_id
) lr
ON lr.asset_id = r.asset_id AND lr.collected_at_utc = r.collected_at_utc;

-- One-row-per-asset convenience view for "current inventory / posture".
-- This intentionally mixes inventory identity + most recent observed facts.
DROP VIEW IF EXISTS v_asset_current;
CREATE VIEW v_asset_current AS
SELECT
  a.asset_id,
  a.hostname,
  a.domain,
  a.fqdn,
  lr.run_id AS last_run_id,
  lr.collected_at_utc AS last_collected_at_utc,
  lr.source_ip AS last_source_ip,

  hi.machine_id,
  hi.hardware_vendor,
  hi.hardware_model,
  hi.operating_system,
  hi.kernel,
  hi.architecture,

  td.time_zone,
  td.system_clock_synchronized,
  td.ntp_service,

  mem.mem_total_bytes,
  mem.swap_total_bytes,

  -- Primary IPv4: prefer the baseline's filename IP when it appears on an interface,
  -- otherwise prefer any global non-loopback address, then any non-loopback address,
  -- finally fall back to the filename IP.
  COALESCE(
    (
      SELECT ia.address
      FROM run_interface_addrs ia
      WHERE ia.run_id = lr.run_id
        AND ia.family = 'inet'
        AND ia.address = lr.source_ip
      LIMIT 1
    ),
    (
      SELECT ia.address
      FROM run_interface_addrs ia
      WHERE ia.run_id = lr.run_id
        AND ia.family = 'inet'
        AND ia.address <> '127.0.0.1'
        AND ia.scope = 'global'
      ORDER BY ia.ifname, ia.address
      LIMIT 1
    ),
    (
      SELECT ia.address
      FROM run_interface_addrs ia
      WHERE ia.run_id = lr.run_id
        AND ia.family = 'inet'
        AND ia.address <> '127.0.0.1'
      ORDER BY CASE WHEN ia.scope = 'global' THEN 0 ELSE 1 END, ia.ifname, ia.address
      LIMIT 1
    ),
    lr.source_ip
  ) AS primary_ipv4,

  -- Primary MAC: prefer the MAC of the interface that owns the filename IP;
  -- otherwise prefer the MAC of any interface with a global scope IPv4;
  -- otherwise fall back to any non-loopback MAC.
  COALESCE(
    (
      SELECT i.mac_addr
      FROM run_interfaces i
      JOIN run_interface_addrs ia
        ON ia.run_id = i.run_id AND ia.ifname = i.ifname AND ia.family = 'inet'
      WHERE i.run_id = lr.run_id
        AND ia.address = lr.source_ip
        AND i.mac_addr IS NOT NULL
        AND i.mac_addr <> ''
      ORDER BY CASE WHEN i.state = 'UP' THEN 0 ELSE 1 END, i.ifname
      LIMIT 1
    ),
    (
      SELECT i.mac_addr
      FROM run_interfaces i
      JOIN run_interface_addrs ia
        ON ia.run_id = i.run_id AND ia.ifname = i.ifname AND ia.family = 'inet'
      WHERE i.run_id = lr.run_id
        AND ia.scope = 'global'
        AND i.ifname <> 'lo'
        AND i.mac_addr IS NOT NULL
        AND i.mac_addr <> ''
      ORDER BY CASE WHEN i.state = 'UP' THEN 0 ELSE 1 END, i.ifname
      LIMIT 1
    ),
    (
      SELECT i.mac_addr
      FROM run_interfaces i
      WHERE i.run_id = lr.run_id
        AND i.ifname <> 'lo'
        AND i.mac_addr IS NOT NULL
        AND i.mac_addr <> ''
      ORDER BY CASE WHEN i.state = 'UP' THEN 0 ELSE 1 END, i.ifname
      LIMIT 1
    )
  ) AS primary_mac

FROM assets a
LEFT JOIN v_latest_runs lr ON lr.asset_id = a.asset_id
LEFT JOIN run_hostinfo hi ON hi.run_id = lr.run_id
LEFT JOIN run_timedate td ON td.run_id = lr.run_id
LEFT JOIN run_memory mem ON mem.run_id = lr.run_id;

-- Failed logins in last 30 days by host
DROP VIEW IF EXISTS v_failed_logins_recent;
CREATE VIEW v_failed_logins_recent AS
SELECT
  ac.hostname,
  fl.username,
  fl.remote_host,
  fl.tty,
  fl.attempt_time_utc,
  fl.raw_start_text,
  ac.last_collected_at_utc AS baseline_collected_at
FROM v_asset_current ac
JOIN run_failed_logins fl ON fl.run_id = ac.last_run_id
WHERE fl.attempt_time_utc IS NOT NULL
  AND fl.attempt_time_utc >= datetime(ac.last_collected_at_utc, '-30 days')
ORDER BY fl.attempt_time_utc DESC;

-- Accounts with never logged in but have authorized keys
DROP VIEW IF EXISTS v_accounts_never_logged_in_with_keys;
CREATE VIEW v_accounts_never_logged_in_with_keys AS
SELECT
  ac.hostname,
  u.username,
  ll.latest AS lastlog_status,
  COUNT(k.key_fingerprint_sha256) AS key_count
FROM v_asset_current ac
JOIN run_users u ON u.run_id = ac.last_run_id
LEFT JOIN run_lastlog ll ON ll.run_id = ac.last_run_id AND ll.username = u.username
LEFT JOIN run_ssh_authorized_keys k ON k.run_id = ac.last_run_id AND k.username = u.username
WHERE (ll.latest IS NULL OR ll.latest = 'Never logged in')
  AND u.shell LIKE '%sh'  -- Only accounts with login shells
GROUP BY ac.hostname, u.username, ll.latest
HAVING key_count > 0
ORDER BY ac.hostname, u.username;

-- "Current security posture" convenience view (one row per asset).
DROP VIEW IF EXISTS v_asset_security_summary;
CREATE VIEW v_asset_security_summary AS
SELECT
  ac.asset_id,
  ac.hostname,
  ac.last_run_id,
  ac.last_collected_at_utc,
  ac.primary_ipv4,
  ac.primary_mac,

  (SELECT COUNT(*) FROM run_users u WHERE u.run_id = ac.last_run_id) AS local_user_count,
  (SELECT COUNT(*) FROM run_users u WHERE u.run_id = ac.last_run_id AND u.shell LIKE '%sh') AS login_shell_user_count,
  (SELECT COUNT(*) FROM run_passwd_status p WHERE p.run_id = ac.last_run_id AND p.status_code = 'L') AS locked_account_count,
  (SELECT COUNT(*) FROM run_ssh_authorized_keys k WHERE k.run_id = ac.last_run_id) AS authorized_key_count,

  (SELECT COUNT(*) FROM run_packages p WHERE p.run_id = ac.last_run_id) AS package_row_count,
  (SELECT COUNT(*) FROM run_firewall_rules f WHERE f.run_id = ac.last_run_id) AS firewall_rule_row_count,

  (SELECT COUNT(DISTINCT m.member_username)
   FROM run_group_members m
   WHERE m.run_id = ac.last_run_id
     AND m.source = 'getent'
     AND m.groupname IN ('sudo','wheel','adm','admin','root')
  ) AS privileged_user_count,

  -- Audit posture
  (SELECT audit_enabled FROM run_audit_posture p WHERE p.run_id = ac.last_run_id) AS audit_enabled,
  (SELECT audit_immutable FROM run_audit_posture p WHERE p.run_id = ac.last_run_id) AS audit_immutable,
  (SELECT has_critical_auth_rules FROM run_audit_posture p WHERE p.run_id = ac.last_run_id) AS audit_has_critical_auth_rules,
  (SELECT has_critical_file_rules FROM run_audit_posture p WHERE p.run_id = ac.last_run_id) AS audit_has_critical_file_rules,
  (SELECT COUNT(*) FROM run_audit_rules r WHERE r.run_id = ac.last_run_id) AS audit_rule_count,

  -- MAC posture
  (SELECT CASE WHEN selinux_enabled = 1 THEN 'enabled' ELSE 'disabled' END FROM run_selinux_posture p WHERE p.run_id = ac.last_run_id) AS selinux_status,
  (SELECT CASE
     WHEN selinux_enforcing = 1 THEN 'enforcing'
     WHEN selinux_permissive = 1 THEN 'permissive'
     ELSE 'disabled'
   END FROM run_selinux_posture p WHERE p.run_id = ac.last_run_id) AS selinux_mode,
  (SELECT high_risk_booleans_on FROM run_selinux_posture p WHERE p.run_id = ac.last_run_id) AS selinux_high_risk_booleans_on,
  (SELECT apparmor_all_enforcing FROM run_apparmor_posture p WHERE p.run_id = ac.last_run_id) AS apparmor_all_enforcing,
  (SELECT apparmor_mixed_mode FROM run_apparmor_posture p WHERE p.run_id = ac.last_run_id) AS apparmor_mixed_mode,

  -- Logon posture
  (SELECT COUNT(*) FROM run_failed_logins fl WHERE fl.run_id = ac.last_run_id) AS failed_login_count_recent,

  -- Persistence surface size (rough)
  (SELECT COUNT(*) FROM run_file_listings l WHERE l.run_id = ac.last_run_id AND l.source = 'systemd_dirs') AS systemd_listing_rows,
  (SELECT COUNT(*) FROM run_file_listings l WHERE l.run_id = ac.last_run_id AND l.source = 'cron_dirs') AS cron_listing_rows

FROM v_asset_current ac;

-- =========================
-- Connected Data Analysis Views
-- =========================

-- Processes connected to their listening sockets
DROP VIEW IF EXISTS v_process_sockets;
CREATE VIEW v_process_sockets AS
SELECT
  ac.hostname,
  p.pid,
  p.ppid,
  p.uid,
  p.cmd,
  s.proto,
  s.local_addr,
  s.local_port,
  s.remote_addr,
  s.remote_port,
  s.state,
  s.process_name
FROM v_asset_current ac
JOIN run_processes p ON p.run_id = ac.last_run_id
LEFT JOIN run_listening_sockets s ON s.pid = p.pid AND s.run_id = p.run_id
ORDER BY ac.hostname, p.pid;

-- USB devices connected to kernel modules they use
DROP VIEW IF EXISTS v_usb_kernel_drivers;
CREATE VIEW v_usb_kernel_drivers AS
SELECT
  ac.hostname,
  u.bus_number,
  u.device_number,
  u.vendor_id,
  u.product_id,
  u.vendor_name,
  u.product_name,
  u.device_class,
  u.device_subclass,
  u.manufacturer,
  u.product,
  u.serial_number,
  -- Try to match USB devices to kernel modules by vendor/product ID patterns
  CASE
    WHEN u.vendor_id = '1d6b' THEN 'usbcore'  -- Linux Foundation (hubs)
    WHEN u.vendor_id IN ('8086', '8087') THEN 'iwlwifi'  -- Intel wireless
    WHEN u.vendor_id = '0bda' THEN 'rtl8xxxu'  -- Realtek wireless
    WHEN u.vendor_id = '0e8d' THEN 'mt76x2u'   -- MediaTek wireless
    ELSE 'unknown'
  END as likely_kernel_module
FROM v_asset_current ac
JOIN run_usb_devices u ON u.run_id = ac.last_run_id
ORDER BY ac.hostname, u.bus_number, u.device_number;

-- Network interfaces connected to processes using them
DROP VIEW IF EXISTS v_interface_processes;
CREATE VIEW v_interface_processes AS
SELECT
  ac.hostname,
  i.ifname,
  i.mac_addr,
  ia.family,
  ia.address,
  ia.scope,
  p.pid,
  p.uid,
  p.cmd,
  s.proto,
  s.local_port,
  s.state
FROM v_asset_current ac
JOIN run_interfaces i ON i.run_id = ac.last_run_id
LEFT JOIN run_interface_addrs ia ON ia.run_id = ac.last_run_id AND ia.ifname = i.ifname
LEFT JOIN run_listening_sockets s ON s.run_id = ac.last_run_id AND s.local_addr = ia.address
LEFT JOIN run_processes p ON p.run_id = ac.last_run_id AND p.pid = s.pid
ORDER BY ac.hostname, i.ifname, ia.address;

-- Kernel modules connected to hardware devices
DROP VIEW IF EXISTS v_module_hardware;
CREATE VIEW v_module_hardware AS
SELECT
  ac.hostname,
  m.module,
  m.size,
  m.used_by_count,
  m.used_by,
  -- Connect to USB devices
  GROUP_CONCAT(DISTINCT u.product_name) as usb_devices,
  -- Connect to GPU devices
  GROUP_CONCAT(DISTINCT g.description) as gpu_devices,
  -- Module security metadata
  mi.license,
  mi.signer,
  mi.description
FROM v_asset_current ac
JOIN run_lsmod m ON m.run_id = ac.last_run_id
LEFT JOIN run_modinfo_kv mi ON mi.run_id = ac.last_run_id AND mi.module = m.module AND mi.k = 'license'
LEFT JOIN run_usb_devices u ON u.run_id = ac.last_run_id
LEFT JOIN run_gpu_devices g ON g.run_id = ac.last_run_id
GROUP BY ac.hostname, m.module, m.size, m.used_by_count, m.used_by, mi.license, mi.signer, mi.description
ORDER BY ac.hostname, m.module;

-- =========================
-- Fleet-wide Anomaly Detection Views
-- =========================

-- Processes that appear on very few hosts (potential unique/custom software)
DROP VIEW IF EXISTS v_rare_processes;
CREATE VIEW v_rare_processes AS
WITH process_counts AS (
  SELECT
    p.cmd,
    COUNT(DISTINCT r.asset_id) as host_count,
    COUNT(*) as total_instances
  FROM run_processes p
  JOIN runs r ON r.run_id = p.run_id
  WHERE p.cmd NOT LIKE '/usr/bin/%'  -- Exclude common system binaries
    AND p.cmd NOT LIKE '/bin/%'
    AND p.cmd NOT LIKE '/sbin/%'
    AND p.cmd NOT LIKE '[%]%'  -- Exclude kernel threads
    AND LENGTH(p.cmd) > 10     -- Focus on longer command lines
  GROUP BY p.cmd
  HAVING host_count <= 2      -- Only appears on 2 or fewer hosts
)
SELECT
  ac.hostname,
  pc.cmd,
  pc.host_count,
  pc.total_instances,
  p.pid,
  p.uid,
  p.ppid
FROM process_counts pc
JOIN run_processes p ON p.cmd = pc.cmd
JOIN runs r ON r.run_id = p.run_id
JOIN v_asset_current ac ON ac.asset_id = r.asset_id
ORDER BY pc.host_count, pc.total_instances DESC;

-- USB devices that are rare across the fleet
DROP VIEW IF EXISTS v_rare_usb_devices;
CREATE VIEW v_rare_usb_devices AS
WITH usb_counts AS (
  SELECT
    u.vendor_id || ':' || u.product_id as device_id,
    u.vendor_name,
    u.product_name,
    COUNT(DISTINCT r.asset_id) as host_count
  FROM run_usb_devices u
  JOIN runs r ON r.run_id = u.run_id
  GROUP BY u.vendor_id, u.product_id, u.vendor_name, u.product_name
  HAVING host_count <= 2  -- Only appears on 2 or fewer hosts
)
SELECT
  ac.hostname,
  uc.device_id,
  uc.vendor_name,
  uc.product_name,
  uc.host_count,
  u.bus_number,
  u.device_number,
  u.serial_number
FROM usb_counts uc
JOIN run_usb_devices u ON u.vendor_id || ':' || u.product_id = uc.device_id
JOIN runs r ON r.run_id = u.run_id
JOIN v_asset_current ac ON ac.asset_id = r.asset_id
ORDER BY uc.host_count, uc.device_id;

-- Kernel modules that are rare across the fleet
DROP VIEW IF EXISTS v_rare_kernel_modules;
CREATE VIEW v_rare_kernel_modules AS
WITH module_counts AS (
  SELECT
    m.module,
    COUNT(DISTINCT r.asset_id) as host_count,
    COUNT(*) as total_instances
  FROM run_lsmod m
  JOIN runs r ON r.run_id = m.run_id
  GROUP BY m.module
  HAVING host_count <= 2  -- Only appears on 2 or fewer hosts
)
SELECT
  ac.hostname,
  mc.module,
  mc.host_count,
  mc.total_instances,
  m.size,
  m.used_by_count,
  m.used_by,
  mi.description,
  mi.license
FROM module_counts mc
JOIN run_lsmod m ON m.module = mc.module
JOIN runs r ON r.run_id = m.run_id
JOIN v_asset_current ac ON ac.asset_id = r.asset_id
LEFT JOIN run_modinfo_kv mi ON mi.run_id = r.run_id AND mi.module = m.module AND mi.k = 'description'
ORDER BY mc.host_count, mc.total_instances DESC;

-- Mount points that are unique to specific hosts (from lsblk mountpoints)
DROP VIEW IF EXISTS v_unique_mounts;
CREATE VIEW v_unique_mounts AS
WITH mount_counts AS (
  SELECT
    d.mountpoints,
    COUNT(DISTINCT r.asset_id) as host_count
  FROM run_block_devices d
  JOIN runs r ON r.run_id = d.run_id
  WHERE d.mountpoints IS NOT NULL
    AND d.mountpoints != ''
    AND d.mountpoints NOT LIKE '/proc%'
    AND d.mountpoints NOT LIKE '/sys%'
    AND d.mountpoints NOT LIKE '/dev%'
    AND d.mountpoints NOT LIKE '/run%'
    AND d.mountpoints NOT LIKE '/tmp%'
  GROUP BY d.mountpoints
  HAVING host_count = 1  -- Only appears on exactly 1 host
)
SELECT
  ac.hostname,
  mc.mountpoints,
  d.name,
  d.type
FROM mount_counts mc
JOIN run_block_devices d ON d.mountpoints = mc.mountpoints
JOIN runs r ON r.run_id = d.run_id
JOIN v_asset_current ac ON ac.asset_id = r.asset_id
ORDER BY ac.hostname, mc.mountpoints;

-- =========================
-- Baseline Comparison & Drift Detection Views
-- =========================

-- Import baseline expectations from CSV (requires manual loading of host_inventory.csv)
-- This would be loaded separately via a script that reads the CSV and populates baseline tables

-- Compare current memory vs expected baseline
DROP VIEW IF EXISTS v_memory_drift;
CREATE VIEW v_memory_drift AS
SELECT
  ac.hostname,
  printf('%.1f', CAST(mem.mem_total_bytes AS REAL) / (1024*1024*1024)) as current_gb,
  hi.memory_capacity_gb as expected_gb,
  CASE
    WHEN hi.memory_capacity_gb IS NULL THEN 'unknown'
    WHEN ABS(CAST(mem.mem_total_bytes AS REAL) / (1024*1024*1024) - hi.memory_capacity_gb) < 0.5 THEN 'normal'
    WHEN CAST(mem.mem_total_bytes AS REAL) / (1024*1024*1024) > hi.memory_capacity_gb THEN 'increased'
    ELSE 'decreased'
  END as status,
  CASE
    WHEN hi.memory_capacity_gb IS NOT NULL THEN
      ABS(CAST(mem.mem_total_bytes AS REAL) / (1024*1024*1024) - hi.memory_capacity_gb)
    ELSE NULL
  END as drift_gb
FROM v_asset_current ac
LEFT JOIN run_memory mem ON mem.run_id = ac.last_run_id
LEFT JOIN host_inventory hi ON hi.hostname = ac.hostname
ORDER BY
  CASE WHEN drift_gb IS NULL THEN 0 ELSE 1 END,
  drift_gb DESC;

-- Compare current CPU cores vs expected baseline
DROP VIEW IF EXISTS v_cpu_drift;
CREATE VIEW v_cpu_drift AS
SELECT
  ac.hostname,
  hi.proc_no_cores as expected_cores,
  hi.proc_count as expected_sockets,
  ac.operating_system,
  CASE
    WHEN hi.proc_no_cores IS NULL THEN 'unknown'
    ELSE 'baseline_loaded'
  END as baseline_status
FROM v_asset_current ac
LEFT JOIN host_inventory hi ON hi.hostname = ac.hostname
ORDER BY ac.hostname;

-- Compare storage configuration vs expected baseline
DROP VIEW IF EXISTS v_storage_drift;
CREATE VIEW v_storage_drift AS
WITH expected_storage AS (
  SELECT
    hostname,
    (storage_hdd_capacity_gb + storage_nvme_capabity_gb + storage_ssd_capabity_gb) as total_expected_gb,
    storage_hdd_no_drives,
    storage_nvme_no_drives,
    storage_ssd_no_drives
  FROM host_inventory
  WHERE storage_hdd_capacity_gb IS NOT NULL OR storage_nvme_capabity_gb IS NOT NULL OR storage_ssd_capabity_gb IS NOT NULL
),
current_storage AS (
  SELECT
    ac.hostname,
    SUM(CAST(d.size_bytes AS REAL) / (1024*1024*1024*1024)) as total_tb  -- Convert to TB
  FROM v_asset_current ac
  JOIN run_block_devices d ON d.run_id = ac.last_run_id
  WHERE d.type = 'disk' AND d.name LIKE '/dev/sd%' OR d.name LIKE '/dev/nvme%'
  GROUP BY ac.hostname
)
SELECT
  ac.hostname,
  printf('%.2f', cs.total_tb) as current_tb,
  es.total_expected_gb / 1000.0 as expected_tb,
  CASE
    WHEN es.total_expected_gb IS NULL THEN 'no_baseline'
    WHEN ABS(cs.total_tb - (es.total_expected_gb / 1000.0)) < 0.1 THEN 'normal'
    ELSE 'drift_detected'
  END as status
FROM v_asset_current ac
LEFT JOIN current_storage cs ON cs.hostname = ac.hostname
LEFT JOIN expected_storage es ON es.hostname = ac.hostname
ORDER BY
  CASE status
    WHEN 'drift_detected' THEN 1
    WHEN 'no_baseline' THEN 2
    ELSE 3
  END,
  ac.hostname;

-- Compare OS version vs expected baseline
DROP VIEW IF EXISTS v_os_drift;
CREATE VIEW v_os_drift AS
SELECT
  ac.hostname,
  ac.operating_system as current_os,
  hi.os_name as expected_os_name,
  hi.os_version as expected_os_version,
  CASE
    WHEN hi.os_name IS NULL THEN 'no_baseline'
    WHEN ac.operating_system LIKE '%' || hi.os_name || '%' THEN 'matches'
    ELSE 'os_changed'
  END as status
FROM v_asset_current ac
LEFT JOIN host_inventory hi ON hi.hostname = ac.hostname
ORDER BY
  CASE status
    WHEN 'os_changed' THEN 1
    WHEN 'no_baseline' THEN 2
    ELSE 3
  END,
  ac.hostname;

-- Detect unexpected privileged users (not in baseline expectations)
DROP VIEW IF EXISTS v_unexpected_privileged_users;
CREATE VIEW v_unexpected_privileged_users AS
SELECT
  ac.hostname,
  gm.groupname,
  gm.member_username,
  CASE
    WHEN hi.primary_ip IS NOT NULL THEN 'baseline_system'
    ELSE 'check_baseline'
  END as baseline_status
FROM v_asset_current ac
JOIN run_group_members gm ON gm.run_id = ac.last_run_id
LEFT JOIN host_inventory hi ON hi.hostname = ac.hostname
WHERE gm.source = 'getent'
  AND gm.groupname IN ('sudo', 'wheel', 'adm', 'admin', 'root')
  AND gm.member_username NOT IN ('root')  -- Root is expected
ORDER BY ac.hostname, gm.groupname, gm.member_username;

-- =========================
-- Performance indexes (created after all tables)
-- =========================

CREATE INDEX IF NOT EXISTS idx_runs_asset_time ON runs(asset_id, collected_at_utc);
CREATE INDEX IF NOT EXISTS idx_runs_source_ip_time ON runs(source_ip, collected_at_utc);

-- Performance indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_asset_identifiers_type_value ON asset_identifiers(id_type, id_value);
CREATE INDEX IF NOT EXISTS idx_run_failed_logins_run_user ON run_failed_logins(run_id, username);
CREATE INDEX IF NOT EXISTS idx_run_failed_logins_run_host ON run_failed_logins(run_id, remote_host);
CREATE INDEX IF NOT EXISTS idx_run_failed_logins_time ON run_failed_logins(attempt_time_utc);
CREATE INDEX IF NOT EXISTS idx_run_modinfo_kv_run_module ON run_modinfo_kv(run_id, module);
CREATE INDEX IF NOT EXISTS idx_run_users_run_username ON run_users(run_id, username);
CREATE INDEX IF NOT EXISTS idx_run_lastlog_run_username ON run_lastlog(run_id, username);
CREATE INDEX IF NOT EXISTS idx_run_processes_run_uid ON run_processes(run_id, uid);
CREATE INDEX IF NOT EXISTS idx_run_file_listings_run_source ON run_file_listings(run_id, source);
CREATE INDEX IF NOT EXISTS idx_findings_run_severity ON findings(run_id, severity);
CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(run_id, category);

