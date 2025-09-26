# EventHound (Win EVTX Analyzer)

Fast Windows EVTX parser and analyzer focused on high-signal security events for cybersecurity, compromise assessment, and incident response. CLI + optional web UI. Exports JSONL/CSV/Parquet. Profiles for Security/Sysmon/PowerShell/WMI/Defender, VSS support on Windows, event maps with sync, minimal DSL, and detections with safelists and Sigma.

## Installation

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## CLI usage (core)

```bash
python main.py --input /path/to/file.evtx \
  --output outputs/analysis \
  --formats jsonl,csv,parquet \
  --profile ir-default
```

Key flags:
- `--only-event-id`, `--event-ids`, `--channels`, `--since/--until`, `--dedup`, `--dsl`
- Maps: `--maps-dir`, `--maps-sync`
- VSS (Windows): `--vss`, `--vss-drives C:,D:`
- Detections: `--rules-dir ./rules --sigma-dir ./sigma --safelists-dir ./safelists --findings-output outputs/analysis`
- Web: `--serve --host 127.0.0.1 --port 8000`

### Sigma (basic)
- Load Sigma rules from a directory via `--sigma-dir`. Current support converts simple `detection.condition` structures (single selection, or `sel1 and sel2` / `sel1 or sel2`) into internal rules. Complex Sigma features may require manual tuning.

Example:
```bash
python main.py --input logs --output outputs/run \
  --sigma-dir ./sigma --rules-dir ./rules \
  --safelists-dir ./safelists --findings-output outputs/run
```

## Web UI

- Events tab: search/filters, sortable columns, pagination, detail view, charts (trend/top IDs/channels).
- Findings tab: filters by `rule_id`, `severity`, `channel`, `event_id`, search in description/tags; pagination.

## Profiles
- `ir-default`, `ir-minimal`, `forensics-all` (see source `evtx_analyzer/profiles.py`).

## Output
- JSONL/CSV/Parquet for events, JSONL/CSV for findings.

## Packaging (standalone binary)
- Build with PyInstaller (`scripts/build_*`).

## References
- EvtxECmd & maps/VSS: [Introduction to EvtxEcmd](https://isc.sans.edu/diary/25858), [SANS EvtxECmd](https://www.sans.org/tools/evtxecmd)
- Microsoft Log Parser approach: [SANS Blog](https://www.sans.org/blog/computer-forensics-how-to-microsoft-log-parser)
- DeepBlueCLI detections/safelists inspiration: [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI)
