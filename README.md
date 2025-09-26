# Win EVTX Analyzer

Fast Windows EVTX parser and analyzer focused on high-signal security events for cybersecurity, compromise assessment, and incident response. Supports export to JSONL and CSV. The web server is optional and only starts with the `--serve` flag.

## Installation

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## Usage (CLI only)

```bash
python main.py --input /path/to/file.evtx \
  --output outputs/analysis \
  --formats jsonl,csv \
  --profile ir-default \
  --workers 4
```

## Usage (with optional web server)

Add `--serve` to load events into SQLite and start a local web UI:

```bash
python main.py --input /path/to/file.evtx \
  --output outputs/analysis \
  --formats jsonl,csv \
  --profile ir-default \
  --serve --host 127.0.0.1 --port 8000
```

- **--input**: single EVTX file or a directory containing `.evtx` files
- **--output**: output prefix/dir; `*.jsonl` and/or `*.csv` will be created
- **--formats**: one or more of `jsonl,csv`
- **--profile**: event profile (e.g., `ir-default`, `ir-minimal`, `forensics-all`)
- **--event-ids**: custom list of Event IDs (e.g., `4624,4688,1@Sysmon`)
- **--only-event-id**: filter a single Event ID; optionally specify channel with `@` (e.g., `1@Microsoft-Windows-Sysmon/Operational`)
- **--channels**: filter by channels (e.g., `Security,Microsoft-Windows-Sysmon/Operational`)
- **--since/--until**: ISO8601 (UTC) time bounds (e.g., `2024-01-01T00:00:00Z`)
- **--dedup**: basic de-duplication of matched events
- **--dsl**: minimal query language across fields and EventData (e.g., `channel==Security AND TargetUserName~=^admin`)
- **--maps-dir**: load YAML maps (field renames/derivations/tags) from a folder (see `maps/` seeds)
- **--maps-sync**: fetch maps from a remote URL (JSON or YAML) and cache locally
- **--vss**: also scan Volume Shadow Copies (Windows only)
- **--vss-drives**: drives to scan with `--vss` (e.g., `C:,D:`)
- **--serve**: optional; starts the web server and populates `outputs/events.db`
- **--help-all**: show extended help (profiles, examples, environment variables)

### VSS (Windows)
- When `--vss` is set, the tool attempts to enumerate `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy*\Windows\System32\winevt\Logs` and harvest EVTX logs. This enables historical/hard-deleted log analysis similar to EvtxECmd’s VSS mode.
- References: [isc.sans.edu/diary/25858](https://isc.sans.edu/diary/25858), [sans.org/tools/evtxecmd](https://www.sans.org/tools/evtxecmd)

### Maps
- Seeded maps in `maps/` provide basic field normalization/tags for common Security/Sysmon events (e.g., 4624/4625/4688/4697/7045; Sysmon 1/3/10/11).
- Extend locally via YAML or provide a remote URL with `--maps-sync` to pull updates.

### Environment Variables
- `WIN_EVTX_PROFILE`: set the default profile without passing `--profile` (e.g., `WIN_EVTX_PROFILE=forensics-all`). CLI `--profile` overrides it.

## Web UI (when `--serve`)

- **Search & filters**: free text (`q`), `channel`, `event_id`, `user_sid`, `provider`, `since`/`until`. Sortable columns (asc/desc), pagination (Prev/Next).
- **Event details**: click a row to view `EventData` and metadata. "Download JSON" button for single-event export.
- **Saved queries**: save/load/delete queries via LocalStorage (dedicated dropdown).
- **Charts**: event trend by hour/day, Top Event IDs, Top Channels (Chart.js).
- **Theme**: Dark/Light mode with persisted preference.

## Profiles

- **ir-default**: broad, practical IR set across `Security`, `Sysmon`, `PowerShell`, `WMI Activity`, `Defender`, `TaskScheduler`, RDP/WinRM, `AppLocker`, and `System`.
- **ir-minimal**: low-noise, high-signal subset (e.g., 1102, 4719, 4672, 4648, 4625, 4697, 4698, 4702, 7045, Sysmon 1/3/7/10/11/13/22, ...).
- **forensics-all**: very wide superset covering many channels (Security, Sysmon, PowerShell, TaskScheduler, WMI Activity, Defender, RDP/WinRM, AppLocker, System, DNS Client, PrintService, ...). Use when you need maximum coverage and can handle more noise.

Examples:
```bash
python main.py --input /path/to/file.evtx --output outputs/analysis --profile ir-minimal
python main.py --input /path/to/file.evtx --output outputs/analysis --profile forensics-all
WIN_EVTX_PROFILE=forensics-all python main.py --input logs --output outputs/run
python main.py --help-all
```

## Interesting Event IDs (ir-default)

- Security (extended): 4624, 4625, 4634, 4647, 4648, 4672, 4688, 4689, 4697, 4698, 4699, 4700, 4701, 4702, 4719, 4720, 4726, 4732, 4733, 4756, 4767, 4768, 4769, 4771, 4776, 4779, 4798, 4799, 4820, 4821, 4822, 4823, 4824, 4964, 5140, 5145, 7045, 1102
  - 1102: Audit log cleared
  - 4624/4625: Successful/failed logon
  - 4648: Logon with explicit credentials
  - 4672: Special privileges assigned
  - 4719: Audit policy changed
  - 7045: Service installed
- Sysmon (Microsoft-Windows-Sysmon/Operational): 1, 2, 3, 7, 8, 10, 11, 12, 13, 22, 23, 24, 25
- PowerShell: 4103, 4104, 600
- WMI Activity: 5857, 5858, 5859, 5860, 5861
- Windows Defender: 1116, 1117, 5007
- Task Scheduler (Operational): 106, 140, 141
- RDP/Sessions: 21, 23, 24, 25 (LocalSessionManager/Operational), 131, 140 (RdpCoreTS/Operational)
- WinRM: 91 (WinRM/Operational)
- AppLocker: 8002, 8003, 8004 (EXE and DLL), 8006, 8007 (MSI and Script)
- System: 7036, 7040, 7045

## Output

- JSONL: one event per line, normalized fields (`timestamp`, `channel`, `event_id`, `computer`, `provider`, `record_id`, `user_sid`, `data`)
- CSV: same columns with `data` serialized to JSON
- Web UI (if `--serve`): table with search, advanced filters, sorting, pagination, detail view, single-event download, charts.

## Packaging (standalone binary)

Distribute the tool without requiring Python by building a standalone binary with PyInstaller.

- macOS:
```bash
bash scripts/build_macos.sh
./dist_macos/win-evtx-analyzer --help
```
- Linux:
```bash
bash scripts/build_linux.sh
./dist_linux/win-evtx-analyzer --help
```
- Windows (PowerShell):
```powershell
scripts\build_windows.ps1
.\dist_windows\win-evtx-analyzer.exe --help
```

Binaries support all CLI options, including the web mode `--serve`.

## Notes
- Event Viewer-style textual rendering is not available offline; normalized fields and full `EventData` are included.
- Efficient parsing with per-file processing and optional local web UI.
- Inspired by and complementary to workflows discussed here: [isc.sans.edu/diary/25858](https://isc.sans.edu/diary/25858), [sans.org/tools/evtxecmd](https://www.sans.org/tools/evtxecmd), [sans.org/blog/computer-forensics-how-to-microsoft-log-parser](https://www.sans.org/blog/computer-forensics-how-to-microsoft-log-parser)
