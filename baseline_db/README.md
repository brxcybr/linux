## Linux baseline database

This folder contains a **SQLite** database schema plus an ingest script that loads:

- an optional host inventory CSV (your inventory seed)
- raw baseline outputs from `results/*_YYYYMMDD_HH:MM:SSZ.txt` (or custom path)

### Quick start

From the repository/workspace root:

```bash
python3 baseline_db/ingest-baselines.py
```

Defaults:

- **DB path**: `baseline_db/baseline.sqlite3` (same folder as the script)
- **Schema**: `baseline_db/schema.sql`
- **Host CSV**: `host_inventory.csv` (optional; can be skipped)
- **Baseline results dir**: `survey/results`

To re-import already ingested baseline files:

```bash
python3 baseline_db/ingest-baselines.py --reingest
```

To set the DB filename (without a path):

```bash
python3 baseline_db/ingest-baselines.py --db-name "my_lab_network"
```

To run **baseline-only mode** (no CSV import):

```bash
python3 baseline_db/ingest-baselines.py --skip-host-csv
```

If you ever get bad merges while experimenting with identifiers, you can rebuild from scratch:

```bash
python3 baseline_db/ingest-baselines.py --fresh-db
```

### Data model (high level)

- **`assets`**: one row per host (keyed by `asset_id`)
- **`asset_inventory`**: hardware/inventory fields from host inventory CSV
- **`runs`**: one row per baseline execution per host (timestamped)
- **`run_commands`**: lossless storage of every baseline command output (for backfills / new parsers)
- **`run_*` tables**: best-effort normalized extractions (users, groups, packages, sockets, services, firewall, etc.)

### Convenience views

- **`v_latest_runs`**: latest run per asset
- **`v_asset_current`**: one-row-per-host “current inventory” (latest run; includes primary IP + MAC)
- **`v_asset_security_summary`**: one-row-per-host “current posture” counts (users, privileged users, SSH keys, packages, firewall rules)
- **`run_sockets`**: alias view for `ss -punt` output (`run_listening_sockets`)

