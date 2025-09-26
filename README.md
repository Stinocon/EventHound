# EventHound (Win EVTX Analyzer)

EventHound is a fast Windows EVTX parser and analyzer for cybersecurity, compromise assessment, and incident response.
- CLI + optional web UI
- Exports JSONL/CSV/Parquet
- Profiles (Security/Sysmon/PowerShell/WMI/Defender)
- Windows VSS support
- Event maps (YAML) with remote sync
- Minimal DSL filter
- Detections: YAML rules, Sigma (basic), safelists, findings export/UI

## Install
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## Quickstarts
- Basic parse to JSONL+CSV:
```bash
python main.py --input ./logs --output outputs/run --formats jsonl,csv --profile ir-default
```
- Only key IDs (e.g., SANS highlighted):
```bash
python main.py --input ./logs --output outputs/key --only-event-id 4624
python main.py --input ./logs --output outputs/key --only-event-id 1@Microsoft-Windows-Sysmon/Operational
```
- Time-bounded triage:
```bash
python main.py --input ./logs --output outputs/triage --since 2025-01-01T00:00:00Z --until 2025-01-31T23:59:59Z
```
- Minimal noise profile:
```bash
python main.py --input ./logs --output outputs/min --profile ir-minimal
```
- Forensic sweep (broad):
```bash
python main.py --input ./logs --output outputs/all --profile forensics-all
```

## VSS (Windows)
Add shadow copies (historic logs):
```bash
python main.py --input C:\\case\\evtx --output outputs/vss --vss --vss-drives C:
```

## Event Maps
Maps enrich and normalize event data.
- Local dir: `--maps-dir ./maps`
- Remote sync: `--maps-sync https://example.com/evtx-maps.yaml`

## DSL Filtering
```bash
python main.py --input ./logs --output outputs/filtered \
  --dsl "channel==Security AND TargetUserName~=^admin"
```
Operators: `== != contains !contains ~= !~ length_gt length_lt`.

## Detections & Findings
- YAML rules: `--rules-dir ./rules`
- Sigma (basic): `--sigma-dir ./sigma`
- Safelists: `--safelists-dir ./safelists`
- Findings export: `--findings-output outputs/run`

Example end-to-end:
```bash
python main.py --input ./logs --output outputs/run \
  --rules-dir ./rules --sigma-dir ./sigma \
  --safelists-dir ./safelists --findings-output outputs/run \
  --formats jsonl,csv,parquet --profile ir-default
```
Outputs:
- Events: `outputs/run.jsonl`, `outputs/run.csv`, `outputs/run.parquet`
- Findings: `outputs/run.findings.jsonl`, `outputs/run.findings.csv`

## Web UI
Start with `--serve` (SQLite is auto-populated):
```bash
python main.py --input ./logs --output outputs/web --serve
```
- Events tab: search/filters (`q`, `channel`, `event_id`), sortable columns, pagination, event detail, charts (trend/top IDs/channels)
- Findings tab: filters (`rule_id`, `severity`, `channel`, `event_id`), search (`q` in description/tags), pagination
- Dark mode toggle and saved theme

## Profiles
- `ir-default`: balanced IR set
- `ir-minimal`: high-signal subset
- `forensics-all`: broad superset across many channels
Set default via env: `WIN_EVTX_PROFILE=forensics-all` (overridden by `--profile`).

## Sample Content
- Rules: `rules/basic.yaml` (long cmdline, base64 in cmd, suspicious PowerShell, failed logon)
- Safelists: `safelists/example.yaml` (usernames, commandlines, disable noisy rule)
- Sigma samples: `sigma/windows_powershell_suspicious.yml`, `sigma/windows_failed_logons.yml`

## Packaging (standalone)
Build single-file binaries with PyInstaller (macOS/Linux/Windows):
```bash
bash scripts/build_macos.sh   # or build_linux.sh / scripts/build_windows.ps1
```

## References
- EvtxECmd & maps/VSS: [SANS ISC](https://isc.sans.edu/diary/25858), [SANS EvtxECmd](https://www.sans.org/tools/evtxecmd)
- Microsoft Log Parser approach: [SANS Blog](https://www.sans.org/blog/computer-forensics-how-to-microsoft-log-parser)
- DeepBlueCLI detections & safelists: [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI)
