# Security Posture Report Generator

This script generates comprehensive security posture reports from Linux baseline data that can be shared with leadership and used to inform security policy development.

## Features

The generated report includes:

### Executive Summary
- Total findings by severity level
- Number of hosts assessed
- Key security metrics
- Report generation timestamp

### Data Collection Timestamps
- Oldest data collection date across all hosts
- Newest data collection date across all hosts
- Total time span of collected data

### Node Overview
- Total hosts, memory, users, and packages across the nodes

### Per-Host Detailed Assessments
For each host, the report covers:

#### Open Ports and Services
- All listening ports with associated processes
- Flags unusual ports that may require firewall review
- Identifies non-standard services

#### Security Findings
- Automated findings from security analysis
- Categorized by severity (Critical, High, Medium, Low)
- Includes detailed descriptions and recommendations

#### User and Permission Analysis
- Service accounts with inappropriate interactive shells
- Privileged users and their group memberships
- Accounts with SSH keys but no login history
- Recommendations for access control improvements

#### Node-Specific Items
- Processes running only on this host
- Unique USB devices connected
- Unusual mount points
- Items that stand out from the node baseline

#### Configuration Analysis
- Password authentication settings
- Account lockout status
- Audit subsystem configuration
- Firewall rule counts

### Policy Recommendations
- User access management improvements
- System hardening requirements
- Monitoring and compliance enhancements
- Operational security procedures

## Usage

```bash
python3 generate_security_report.py --db <database_file> --output <report_file>
```

### Parameters
- `--db`: Path to the SQLite database file (required)
- `--output`: Base path for the output report file (timestamp will be automatically appended, required)

### Example
```bash
python3 generate_security_report.py --db baseline.sqlite3 --output security_posture_report.txt
# Output: security_posture_report_20240122_143052.txt (timestamp automatically appended)
```

## Output Format

The report is generated as a text file with clear section headers and formatting that's suitable for:

- Leadership briefings
- Security policy development
- Compliance documentation
- Ansible playbook development

## Security Insights Covered

### Automated Detection
- Unusual network services and open ports
- Privileged account misuse
- Missing security controls (SELinux, audit, etc.)
- Configuration drift from baselines
- Suspicious system modifications

### Node-wide Analysis
- Items unique to specific hosts
- Anomalies compared across similar systems
- Baseline compliance checking
- Security control effectiveness

### Policy Development Support
- Identifies security gaps requiring policy changes
- Provides specific recommendations for automation
- Highlights high-impact security improvements
- Supports risk-based prioritization

## Asset Identity Resolution Changes

**Important**: The asset identity resolution logic has been updated to ensure each host gets a unique asset ID:

- **Machine ID excluded from asset matching**: Previously, hosts with identical machine IDs (common with cloned VMs) would be merged into a single asset. Now each host gets its own asset ID regardless of machine ID.
- **Machine ID still tracked**: Machine IDs are preserved as asset properties for auditing and troubleshooting.
- **Hardware identifiers prioritized**: Asset resolution now uses DMI UUID and primary MAC address for uniqueness.

This change resolves issues where cloned virtual machines or systems with identical machine IDs were incorrectly merged.

## Integration with Ansible

The report findings can be directly translated into Ansible playbooks for automated remediation:

- User account modifications
- Security control enablement
- Firewall rule standardization
- Audit policy implementation
- Service configuration changes

## Dependencies

- Python 3.6+
- SQLite3
- Access to baseline database with enhanced schema

## Report Structure

```
================================================================================
 EXECUTIVE SUMMARY
================================================================================

================================================================================
 FLEET OVERVIEW
================================================================================

Detailed Assessment for: HOSTNAME
===================================
[Host information and assessments...]

POLICY RECOMMENDATIONS:
==================================================
[Actionable security policy recommendations...]
```