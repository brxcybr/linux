## Query playbook (starter)

This is a small set of “high signal” SQL queries you can reuse while hardening hosts.

### Current inventory per host (latest run)

```sql
SELECT
  asset_id,
  hostname,
  primary_ipv4,
  primary_mac,
  operating_system,
  kernel,
  architecture,
  mem_total_bytes,
  last_collected_at_utc
FROM v_asset_current
ORDER BY asset_id;
```

### Current security posture summary per host (latest run)

```sql
SELECT
  hostname,
  privileged_user_count,
  local_user_count,
  locked_account_count,
  authorized_key_count,
  package_row_count,
  firewall_rule_row_count,
  last_collected_at_utc
FROM v_asset_security_summary
ORDER BY hostname;
```

### Hosts missing any baseline runs

```sql
SELECT a.asset_id, a.hostname
FROM assets a
LEFT JOIN runs r ON r.asset_id = a.asset_id
WHERE r.run_id IS NULL
ORDER BY a.asset_id;
```

### Privileged users (latest run)

```sql
SELECT
  ac.hostname,
  m.groupname,
  m.member_username
FROM v_asset_current ac
JOIN run_group_members m
  ON m.run_id = ac.last_run_id
WHERE m.source = 'getent'
  AND m.groupname IN ('sudo','wheel','adm','admin','root')
ORDER BY ac.hostname, m.groupname, m.member_username;
```

### Accounts with interactive shells (latest run)

```sql
SELECT
  ac.hostname,
  u.username,
  u.uid,
  u.shell
FROM v_asset_current ac
JOIN run_users u
  ON u.run_id = ac.last_run_id
WHERE u.shell LIKE '%sh'
ORDER BY ac.hostname, u.uid;
```

### Accounts that appear unlocked vs locked (latest run)

```sql
SELECT
  ac.hostname,
  p.username,
  p.status_code,
  p.last_change
FROM v_asset_current ac
JOIN run_passwd_status p
  ON p.run_id = ac.last_run_id
ORDER BY ac.hostname, p.username;
```

### Generate Security Posture Report

Use the dedicated report generator for comprehensive leadership-ready reports:

```bash
python3 generate_security_report.py --db baseline.sqlite3 --output security_report.txt
# Output: security_report_20240122_143052.txt (timestamp automatically appended)
```

The report includes:
- Executive summary with finding counts
- Per-host detailed assessments covering:
  - Open ports and unusual services
  - Security findings with severity levels
  - User permission analysis
  - Unique/host-specific items
  - Configuration differences
- Policy recommendations for Ansible automation

### Diff packages between two hosts (latest run)

Replace `:host_a` / `:host_b` with hostnames (e.g., `lambda1`, `lambda2`).

```sql
WITH
  a AS (
    SELECT p.name, p.version
    FROM v_asset_current ac
    JOIN run_packages p ON p.run_id = ac.last_run_id
    WHERE ac.hostname = :host_a AND p.source = 'dpkg'
  ),
  b AS (
    SELECT p.name, p.version
    FROM v_asset_current ac
    JOIN run_packages p ON p.run_id = ac.last_run_id
    WHERE ac.hostname = :host_b AND p.source = 'dpkg'
  )
SELECT 'only_in_a' AS diff_type, a.name, a.version
FROM a LEFT JOIN b ON b.name = a.name
WHERE b.name IS NULL
UNION ALL
SELECT 'only_in_b' AS diff_type, b.name, b.version
FROM b LEFT JOIN a ON a.name = b.name
WHERE a.name IS NULL
ORDER BY diff_type, name;
```

### Security findings summary (latest run per host)

```sql
SELECT
  ac.hostname,
  f.severity,
  f.category,
  f.title,
  f.details
FROM v_asset_current ac
JOIN findings f ON f.run_id = ac.last_run_id
ORDER BY
  CASE f.severity
    WHEN 'critical' THEN 1
    WHEN 'high' THEN 2
    WHEN 'medium' THEN 3
    WHEN 'low' THEN 4
    WHEN 'info' THEN 5
  END,
  ac.hostname, f.category;
```

### Failed login analysis (latest 30 days)

```sql
SELECT
  ac.hostname,
  COUNT(*) as failed_login_count,
  COUNT(DISTINCT fl.username) as unique_users_targeted,
  COUNT(DISTINCT fl.remote_host) as unique_source_ips
FROM v_asset_current ac
JOIN run_failed_logins fl ON fl.run_id = ac.last_run_id
WHERE fl.attempt_time_utc >= datetime('now', '-30 days')
GROUP BY ac.hostname
HAVING failed_login_count > 5
ORDER BY failed_login_count DESC;
```

### Accounts with suspicious SSH key patterns (latest run)

```sql
SELECT
  ac.hostname,
  u.username,
  COUNT(k.key_fingerprint_sha256) as key_count,
  GROUP_CONCAT(DISTINCT k.key_type) as key_types
FROM v_asset_current ac
JOIN run_users u ON u.run_id = ac.last_run_id
LEFT JOIN run_ssh_authorized_keys k ON k.run_id = ac.last_run_id AND k.username = u.username
WHERE u.shell LIKE '%sh'  -- Interactive shell users
GROUP BY ac.hostname, u.username
HAVING key_count > 5  -- Unusual number of keys
ORDER BY key_count DESC;
```

### Kernel module anomalies (latest run)

```sql
SELECT
  ac.hostname,
  json_extract(kmi.unusual_modules, '$[0]') as unusual_module,
  json_extract(kmi.suspicious_licenses, '$[0]') as suspicious_license,
  json_extract(kmi.modules_with_unknown_signer, '$[0]') as unknown_signer
FROM v_asset_current ac
JOIN run_kernel_module_insights kmi ON kmi.run_id = ac.last_run_id
WHERE json_array_length(kmi.unusual_modules) > 0
   OR json_array_length(kmi.suspicious_licenses) > 0
   OR json_array_length(kmi.modules_with_unknown_signer) > 0;
```

### Network posture issues (latest run)

```sql
SELECT
  ac.hostname,
  CASE WHEN np.multiple_default_routes THEN 'Multiple default routes' END as route_issue,
  json_extract(np.unexpected_nameservers, '$[0]') as unexpected_nameserver,
  json_extract(np.suspicious_routes, '$[0]') as suspicious_route
FROM v_asset_current ac
JOIN run_network_posture np ON np.run_id = ac.last_run_id
WHERE np.multiple_default_routes = 1
   OR json_array_length(np.unexpected_nameservers) > 0
   OR json_array_length(np.suspicious_routes) > 0;
```

### Persistence mechanism inventory (latest run)

```sql
SELECT
  ac.hostname,
  'Cron jobs' as persistence_type,
  COUNT(*) as item_count
FROM v_asset_current ac
JOIN run_file_listings fl ON fl.run_id = ac.last_run_id AND fl.source = 'cron_dirs'
GROUP BY ac.hostname
UNION ALL
SELECT
  ac.hostname,
  'Systemd units' as persistence_type,
  COUNT(*) as item_count
FROM v_asset_current ac
JOIN run_file_listings fl ON fl.run_id = ac.last_run_id AND fl.source = 'systemd_dirs'
WHERE fl.name LIKE '%.service'
GROUP BY ac.hostname
ORDER BY ac.hostname, persistence_type;
```

