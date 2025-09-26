# EventHound (Win EVTX Analyzer)

Fast Windows EVTX parser and analyzer focused on high-signal security events for cybersecurity, compromise assessment, and incident response. CLI + optional web UI. Exports JSONL/CSV/Parquet. Profiles for Security/Sysmon/PowerShell/WMI/Defender, VSS support on Windows, event maps with sync, minimal DSL, and detections with safelists.

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
- Detections: `--rules-dir ./rules --safelists-dir ./safelists --findings-output outputs/analysis`
- Web: `--serve --host 127.0.0.1 --port 8000`

## Rules, Safelists, Findings

- Load rules from YAML in a directory (see `rules/basic.yaml`). Each rule supports `any`/`all` lists of conditions with operators `eq, ne, contains, not_contains, regex, not_regex, length_gt, length_lt` evaluated over top-level fields and `EventData`.
- Load safelists from YAML/TXT (see `safelists/example.yaml`) with regex patterns for usernames/SIDs/computers/processes/commandlines/event_ids/rule_ids. Safelists suppress event evaluation or individual findings.
- Findings export: when `--findings-output prefix` is used, the tool writes `prefix.findings.jsonl` and `prefix.findings.csv`. When `--serve` is used, findings are also persisted to SQLite.

Examples:
```bash
python main.py --input logs --output outputs/run \
  --rules-dir rules --safelists-dir safelists \
  --findings-output outputs/run
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
- SANS ISC on EvtxECmd (maps, VSS, dedup): [Introduction to EvtxEcmd](https://isc.sans.edu/diary/25858)
- EvtxECmd tool page: [SANS EvtxECmd](https://www.sans.org/tools/evtxecmd)
- Microsoft Log Parser style queries: [SANS Blog](https://www.sans.org/blog/computer-forensics-how-to-microsoft-log-parser)
- DeepBlueCLI detections/safelists inspiration: [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI)
