# Linux Baseline & Security Posture Analysis

A comprehensive toolkit for collecting Linux host baseline data, ingesting it into a SQLite database, and generating security posture reports. This project enables security administrators to track changes over time, identify anomalies, and assess the security posture of Linux hosts across a network.

## Overview

This project consists of two main components:

1. **Baseline Collection Scripts** (`baseline/`): Bash scripts for collecting comprehensive Linux host data
2. **Database & Analysis Tools** (`baseline_db/`): Python tools for ingesting baseline data into SQLite and generating security reports

### What is a Baseline?

A _**baseline**_ is a snapshot of a device's current running state and configurations. Regularly capturing baselines allows you to:
- Track changes over time
- Investigate unexpected deviations
- Assess security posture
- Identify indicators of compromise
- Support compliance and audit requirements

## Quick Start Workflow

### 1. Collect Baseline Data

**Local collection** (on a single host):
```bash
cd baseline
chmod +x baseline.sh
sudo ./baseline.sh
```

**Remote collection** (across multiple hosts):
```bash
# Create a hosts file (hosts.txt)
echo "10.0.0.5" >> hosts.txt
echo "server-a.example.com" >> hosts.txt

# Run baselines remotely
./baseline.sh --remote --hosts-file hosts.txt --user admin --identity ~/.ssh/id_ed25519 --results-dir ../results
```

### 2. Ingest Data into Database

```bash
cd baseline_db
python3 ingest-baselines.py --results-dir ../results
```

This creates `baseline_db/baseline.sqlite3` with all collected data.

### 3. Generate Security Report

```bash
python3 generate_security_report.py --db baseline.sqlite3 --output security_report
```

This creates a timestamped report file (e.g., `security_report_20240122_143052.txt`).

## Detailed Documentation

### Baseline Collection (`baseline/`)

#### `baseline.sh` - Main Collection Script

The core baseline script collects data across major Linux distributions. It can run in two modes:

**Local Mode** (default):
- Must be executed with root privileges (directly or via sudo)
- Collects data from the current host
- Outputs to: `./<ip>_YYYYMMDD_HHMMSSZ.txt`

**Remote Mode** (`--remote`):
- Orchestrates baseline collection across multiple hosts via SSH
- Deploys the script, executes it, retrieves results, and cleans up
- Supports hostnames, FQDNs, or IP addresses

#### Usage Examples

**Local collection with custom options:**
```bash
sudo ./baseline.sh --ip-mode auto --outdir /tmp/baselines
```

**Remote collection with password authentication:**
```bash
./baseline.sh --remote \
  --hosts-file hosts.txt \
  --user admin \
  --identity ~/.ssh/id_ed25519 \
  --results-dir ./results \
  --ask-sudo-pass
```

**Remote collection with pre-configured SSH keys:**
```bash
./baseline.sh --remote \
  --hosts-file hosts.txt \
  --user admin \
  --results-dir ./results
```

#### Command-Line Options

**Local Mode:**
- `--ip-mode auto|prompt|first|ip:<addr>|iface:<ifname>`: Controls which IP is used in the output filename
- `--outdir <dir>`: Write results to a specific directory

**Remote Mode:**
- `--remote` or `-r`: Enable remote orchestration mode
- `--hosts-file FILE`: File containing hostnames/IPs (one per line)
- `--user USER`: SSH username (default: current user)
- `--identity KEYFILE`: SSH private key path
- `--results-dir DIR`: Local directory to store retrieved results
- `--ip-mode MODE`: IP selection mode for output filenames
- `--ask-ssh-pass`: Prompt for SSH password (requires `sshpass`)
- `--ask-sudo-pass`: Prompt for remote sudo password
- `--ssh-pass PASS`: SSH password (not recommended; visible in process list)
- `--sudo-pass PASS`: Sudo password (not recommended; visible in process list)

#### Remote Authentication Notes

- **Key-based auth** (ssh-agent, `ssh-copy-id`, certificates) is preferred
- SSH password auth is supported **only if `sshpass` is installed** on the control machine
- Remote `sudo` prompting can be reduced using password options, but some environments require an interactive TTY

#### What Gets Collected

The baseline script collects:
- **Host Identity**: hostname, OS, kernel, hardware info, machine ID
- **Hardening Info**: boot parameters, sysctl settings, Secure Boot status
- **Accounts & Environment**: users, groups, password policies, environment variables
- **SSH & Sudo Posture**: SSH config, host keys, authorized keys, sudoers rules
- **Security Policy**: audit rules, SELinux/AppArmor status, PAM configs
- **Network & Firewall**: interfaces, routes, DNS, listening sockets, firewall rules
- **Services & Scheduled Tasks**: systemd units, timers, cron jobs
- **Processes & Software**: running processes, installed packages, kernel modules
- **Persistence & Filesystem**: startup scripts, SUID/SGID files, file capabilities
- **Logon History & Auth Logs**: recent logins, failed attempts, SSH activity

See `baseline_db/baseline_command_catalog.md` for a complete catalog of commands and their database mappings.

#### Output Format

Each command block begins with a line like `$ <command>` and continues until the next command. Section headers are delimited with asterisks (e.g., `************HOST INFO**************`).

#### Other Scripts

- **`parse-baseline.sh`**: Parsing/comparison script that splits baseline files by command and can compare two files

### Database & Analysis (`baseline_db/`)

#### `ingest-baselines.py` - Data Ingestion

The ingestion script loads baseline data into a SQLite database for analysis.

**Basic usage:**
```bash
python3 ingest-baselines.py --results-dir ../results
```

**With host inventory CSV:**
```bash
python3 ingest-baselines.py --results-dir ../results --host-csv host_inventory.csv
```

**Baseline-only mode (no CSV):**
```bash
python3 ingest-baselines.py --results-dir ../results --skip-host-csv
```

**Re-ingest existing files:**
```bash
python3 ingest-baselines.py --results-dir ../results --reingest
```

**Fresh database (rebuild from scratch):**
```bash
python3 ingest-baselines.py --results-dir ../results --fresh-db
```

**Custom database name:**
```bash
python3 ingest-baselines.py --db-name my_network --results-dir ../results
```

#### Command-Line Options

- `--db DB`: Full path to SQLite database file
- `--db-name DB_NAME`: Database name (creates `<script_dir>/<db-name>.sqlite3`)
- `--schema SCHEMA`: Path to schema SQL file (default: `schema.sql`)
- `--host-csv HOST_CSV`: Path to host inventory CSV (default: `host_inventory.csv`)
- `--skip-host-csv`: Skip CSV import (baseline-only mode)
- `--results-dir RESULTS_DIR`: Directory with baseline `*.txt` files (default: `results`)
- `--reingest`: Re-ingest files already in database (delete and replace)
- `--fresh-db`: Delete and rebuild database before ingesting
- `--show-identity-conflicts`: Show diagnostic report of identifier conflicts

#### Data Model

The database schema includes:

- **`assets`**: One row per host (keyed by `asset_id`)
- **`asset_inventory`**: Hardware/inventory fields from CSV
- **`runs`**: One row per baseline execution per host (timestamped)
- **`run_commands`**: Lossless storage of every command output
- **`run_*` tables**: Normalized extractions (users, groups, packages, sockets, services, firewall, etc.)
- **`run_facts`**: Generic key-value facts for incremental parsing
- **`findings`**: Security findings with severity and category

#### Convenience Views

- **`v_latest_runs`**: Latest run per asset
- **`v_asset_current`**: One-row-per-host "current inventory" (latest run)
- **`v_asset_security_summary`**: One-row-per-host "current posture" counts
- **`run_sockets`**: Alias view for listening sockets

#### Asset Identity Resolution

The ingestion script uses a multi-stage resolution process to uniquely identify hosts:
1. DMI UUID (if available)
2. Primary MAC address
3. Machine ID
4. Hostname slug
5. Exact hostname

This ensures each host gets a unique asset ID even when hostnames change or machine IDs are duplicated (e.g., cloned VMs).

#### `generate_security_report.py` - Report Generator

Generates comprehensive security posture reports suitable for leadership briefings and policy development.

**Usage:**
```bash
python3 generate_security_report.py --db baseline.sqlite3 --output security_report
```

**Parameters:**
- `--db`: Path to SQLite database file (required)
- `--output`: Base path for output file (timestamp automatically appended, required)

**Report Contents:**

1. **Executive Summary**
   - Total findings by severity level
   - Number of hosts assessed
   - Key security metrics
   - Report generation timestamp

2. **Fleet Overview**
   - Total hosts, memory, users, packages
   - Data collection timestamps (oldest/newest)

3. **Per-Host Detailed Assessments**
   - Open ports and services (with anomaly flags)
   - Security findings (Critical, High, Medium, Low)
   - User and permission analysis
   - Node-specific items (unique processes, USB devices, mounts)
   - Configuration analysis (password auth, audit, firewall)

4. **Policy Recommendations**
   - User access management improvements
   - System hardening requirements
   - Monitoring and compliance enhancements
   - Operational security procedures

**Output Format:**
The report is a text file with clear section headers, suitable for:
- Leadership briefings
- Security policy development
- Compliance documentation
- Ansible playbook development

See `baseline_db/README_REPORT_GENERATOR.md` for detailed report structure documentation.

#### `query_playbook.md` - SQL Query Examples

Contains example SQL queries for common security analysis tasks:
- Finding hosts with specific configurations
- Identifying anomalies across the fleet
- Tracking changes over time
- User and permission analysis
- Network and firewall posture

## Project Structure

```
linux/
├── baseline/                    # Baseline collection scripts
│   ├── baseline.sh             # Main collection script (local + remote)
│   └── parse-baseline.sh       # File splitting/comparison utility
├── baseline_db/                # Database and analysis tools
│   ├── ingest-baselines.py     # Data ingestion script
│   ├── generate_security_report.py  # Report generator
│   ├── schema.sql              # Database schema
│   ├── baseline_command_catalog.md  # Command catalog and DB mappings
│   ├── query_playbook.md       # SQL query examples
│   ├── README.md               # Database-specific documentation
│   └── README_REPORT_GENERATOR.md  # Report generator documentation
├── results/                    # Default directory for baseline output files
│   └── .gitkeep                # Keeps directory in git
├── .gitignore                  # Git ignore rules (excludes .db files, results, etc.)
├── hosts.txt                   # Example hosts file for remote collection
├── host_inventory.csv          # Example host inventory CSV template
├── requirements.txt            # Python requirements (standard library only)
├── LICENSE                     # License file
└── README.md                   # This file
```

## Complete Workflow Example

### Step 1: Collect Baselines

```bash
# Create hosts file
cat > hosts.txt << EOF
10.0.0.5
server-a.example.com
192.168.1.100
EOF

# Run remote collection
cd baseline
./baseline.sh --remote \
  --hosts-file hosts.txt \
  --user admin \
  --identity ~/.ssh/id_ed25519 \
  --results-dir ../results
```

### Step 2: Ingest into Database

```bash
cd baseline_db
python3 ingest-baselines.py --results-dir ../results --skip-host-csv
```

### Step 3: Generate Report

```bash
python3 generate_security_report.py \
  --db baseline.sqlite3 \
  --output ../reports/security_posture
```

### Step 4: Analyze with SQL

```bash
sqlite3 baseline.sqlite3 << EOF
-- Find hosts with password authentication enabled
SELECT DISTINCT a.hostname, rf.fact_value
FROM assets a
JOIN v_latest_runs lr ON a.asset_id = lr.asset_id
JOIN run_facts rf ON lr.run_id = rf.run_id
WHERE rf.fact_group = 'sshd' AND rf.fact_key = 'passwordauthentication' AND rf.fact_value = 'yes';

-- Find hosts with no remote log destinations
SELECT a.hostname
FROM assets a
JOIN v_latest_runs lr ON a.asset_id = lr.asset_id
JOIN run_facts rf ON lr.run_id = rf.run_id
WHERE rf.fact_group = 'rsyslog' 
  AND rf.fact_key = 'remote_destinations'
  AND rf.fact_value = '[]';
EOF
```

## Version History

### Version 2.0 (Current)

**Major Features:**
- **Integrated remote collection**: Remote orchestration functionality merged into `baseline.sh` with `--remote` flag (eliminated separate `get-baseline.sh` script)
- **Database integration**: Complete SQLite database schema and Python ingestion pipeline for baseline data
- **Security report generation**: Automated security posture report generator with executive summaries and per-host assessments
- **Enhanced data collection**: Expanded command set covering SSH/sudo posture, audit rules, SELinux/AppArmor, network configuration, and more

**Baseline Script Improvements:**
- No longer required to edit interface name manually
- Redirects both STDOUT and STDERR to file
- Outputs location of results file when complete
- Removed redundant and deprecated commands (e.g., arp)
- Collects uptime, system environment variables
- Adds `--ip-mode` and `--outdir` options for non-interactive execution
- Adds `--remote` mode to orchestrate baselines over SSH and retrieve results
- Hardens `find`-based checks using `-xdev`, prune rules, optional `timeout`, and safer `-exec ... +`
- Adds SUID/SGID inventory collection
- Adds `df -B1` for disk space tracking
- Command reordering for better reliability (fast/foundational first, expensive/noisy last)

**Database & Analysis:**
- Comprehensive SQLite schema with normalized tables for all baseline data
- Asset identity resolution (DMI UUID, MAC address, machine ID, hostname)
- Parsing for rsyslog/journald remote log destinations
- Parsing for `/etc/login.defs` password policy values
- Parsing for SSH configuration, sudoers rules, firewall rules, and more
- Convenience views for current asset state and security summaries
- Security findings framework with severity levels

**Documentation:**
- Consolidated README with complete workflow documentation
- Command catalog with detailed descriptions
- SQL query playbook with examples
- Report generator documentation

### Version 1.0

- Initial baseline collection script
- Basic command output collection
- Manual parsing and analysis required

## Troubleshooting

### Baseline Collection Issues

**"Permission denied" errors:**
- Ensure you're running with root privileges: `sudo ./baseline.sh`
- Some commands require root access to read system files and configurations
- For remote collection, ensure the SSH user has sudo access

**Script hangs on `find` commands:**
- The script now includes hardened `find` commands with `-xdev` and timeout protection
- If you still experience hangs, check for:
  - Large NFS mounts or network filesystems
  - Container overlay mounts (`/var/lib/docker`, `/var/lib/containers`)
  - Very large directory trees
- You can comment out specific `find` commands in the script if needed

**"Command not found" errors:**
- Some commands may not exist on all Linux distributions
- The script is designed to work across major distros, but some commands are distribution-specific
- Check the command catalog for alternatives or comment out problematic commands
- Common missing commands: `ntpstat`, `lshw`, `lsscsi`, `mokutil` (Secure Boot)

**Remote collection fails:**
- Verify SSH connectivity: `ssh user@host`
- Check that SSH key authentication is set up (preferred) or `sshpass` is installed for password auth
- Ensure the remote user has sudo access
- Some environments require interactive TTY for sudo; use `--ask-sudo-pass` or configure passwordless sudo
- Check firewall rules allow SSH connections

**IP selection issues:**
- Use `--ip-mode` to control which IP is used in output filename:
  - `auto`: Default route interface, then first global IPv4
  - `prompt`: Interactive selection
  - `first`: First global IPv4 found
  - `ip:10.0.0.5`: Specific IP address
  - `iface:eth0`: Specific interface

### Database Ingestion Issues

**"No such table" errors:**
- Ensure the schema has been applied: the script automatically creates tables on first run
- If using `--fresh-db`, the schema will be recreated
- Check that `schema.sql` exists in `baseline_db/` directory

**Asset identity conflicts:**
- Use `--show-identity-conflicts` to diagnose issues
- Cloned VMs may share machine IDs; the system now handles this by prioritizing DMI UUID and MAC addresses
- Each host should get a unique asset ID based on hardware identifiers

**CSV import fails:**
- Ensure CSV column names match the schema (see `host_inventory.csv` example)
- Check for encoding issues (should be UTF-8)
- Use `--skip-host-csv` to run in baseline-only mode

**"File already ingested" warnings:**
- Use `--reingest` to re-process files already in the database
- Files are identified by their content hash, so identical files won't be duplicated
- Check `runs` table to see what's already ingested

### Report Generation Issues

**"Database file not found":**
- Ensure you've run `ingest-baselines.py` first to create the database
- Check the database path: `--db baseline_db/baseline.sqlite3`

**Empty or incomplete reports:**
- Verify baseline data has been ingested: `sqlite3 baseline.sqlite3 "SELECT COUNT(*) FROM runs;"`
- Check that baseline files were successfully parsed
- Review `run_commands` table to see what data was collected

**Python import errors:**
- Ensure Python 3.6+ is installed: `python3 --version`
- Required modules: `sqlite3` (built-in), `argparse` (built-in), `pathlib` (built-in)
- No external dependencies required

### General Issues

**File permissions:**
- Ensure scripts are executable: `chmod +x baseline.sh`
- Check write permissions for output directories
- Database files inherit permissions from the directory

**Path issues:**
- Use absolute paths or ensure you're in the correct directory
- Default paths are relative to the script location
- Check `--results-dir` and `--db` paths are correct

**Performance:**
- Large networks: Consider running baselines in batches
- Database size: SQLite handles large databases well, but consider archiving old runs
- Report generation: May take time for large fleets; reports are written incrementally

## Requirements

- **Baseline Scripts**: Bash 4+, standard Linux utilities (most commands work across major distros)
- **Database Tools**: Python 3.6+ (3.7+ recommended for dataclasses support), SQLite3 (included with Python)
- **Remote Collection**: SSH access to target hosts, `sshpass` (optional, for password auth)
- **Dependencies**: None! This project uses only Python standard library modules. See `requirements.txt` for details.

## Security Considerations

- Baseline scripts collect sensitive information (SSH keys, passwords hashes, etc.)
- Store baseline output files securely
- Database files may contain sensitive data; protect accordingly
- Use key-based SSH authentication when possible
- Avoid passing passwords via command-line flags (use prompts or environment variables)

## Contributing

When contributing:
- Follow existing code style
- Update `baseline_command_catalog.md` when adding new commands
- Test with multiple Linux distributions when possible
- Document new features in this README

## License

See `LICENSE` file for details.

## Additional Resources

- **Command Catalog**: `baseline_db/baseline_command_catalog.md` - Detailed catalog of all baseline commands
- **Query Playbook**: `baseline_db/query_playbook.md` - SQL query examples for common tasks
- **Report Generator Docs**: `baseline_db/README_REPORT_GENERATOR.md` - Detailed report structure
