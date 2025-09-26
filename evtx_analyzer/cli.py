import os
import sys
import json
import click
from rich.console import Console
from rich.progress import Progress
from .parser import parse_evtx_file
from .filters import EventFilter
from .exporters import JsonlExporter, CsvExporter
from .profiles import get_profile
from .utils import iter_evtx_paths, parse_iso8601_utc, iter_vss_evtx_paths
from .storage import init_db as storage_init_db, insert_events, insert_findings
from .maps import EventMapper
from .rules import RuleSet
from .safelists import Safelist

console = Console()

EXTENDED_HELP = """
Profiles:
  - ir-default: balanced for IR
  - ir-minimal: high-signal, low-noise
  - forensics-all: broad coverage, more noise

Examples:
  python main.py --input logs/ --output outputs/run --profile ir-default
  python main.py --input logs/ --output outputs/run --only-event-id 4624
  python main.py --input logs/ --output outputs/run --only-event-id 1@Microsoft-Windows-Sysmon/Operational
  python main.py --input logs/ --output outputs/run --serve --host 127.0.0.1 --port 8000

Env vars:
  WIN_EVTX_PROFILE: set default profile (e.g., WIN_EVTX_PROFILE=forensics-all)
"""

@click.command()
@click.option('--input', 'input_path', required=True, type=click.Path(exists=True), help='EVTX file or directory')
@click.option('--output', 'output_prefix', required=True, type=str, help='Output prefix/dir')
@click.option('--formats', default='jsonl,csv', type=str, help='Output formats: jsonl,csv,parquet')
@click.option('--profile', default=None, type=str, help='Event profile (overrides env if set)')
@click.option('--event-ids', default='', type=str, help='Custom Event IDs, e.g., 4624,4688,1@Sysmon')
@click.option('--only-event-id', default='', type=str, help='Filter a single Event ID, optionally with channel via @')
@click.option('--channels', default='', type=str, help='Comma-separated channels filter')
@click.option('--since', default='', type=str, help='ISO8601 UTC start time filter')
@click.option('--until', default='', type=str, help='ISO8601 UTC end time filter')
@click.option('--workers', default=4, type=int, help='Workers per-file (reserved)')
@click.option('--dedup', is_flag=True, help='Enable basic deduplication')
@click.option('--dsl', default='', type=str, help='Minimal DSL filter, e.g., "channel==Security AND TargetUserName~=^admin"')
@click.option('--maps-dir', default='', type=str, help='Load YAML maps from this directory')
@click.option('--maps-sync', default='', type=str, help='Remote URL to sync/download maps (JSON or YAML)')
@click.option('--rules-dir', default='', type=str, help='Load detection rules (YAML) from this directory')
@click.option('--safelists-dir', default='', type=str, help='Load safelists (YAML/TXT) from this directory')
@click.option('--findings-output', default='', type=str, help='Output prefix for findings (writes .findings.jsonl/.csv)')
@click.option('--vss', is_flag=True, help='Also scan Volume Shadow Copies (Windows only)')
@click.option('--vss-drives', default='C:', type=str, help='Comma-separated drive roots to scan with --vss (e.g., C:,D:)')
@click.option('--serve', is_flag=True, help='Start local web server to visualize results')
@click.option('--host', default='127.0.0.1', type=str, help='Web server host')
@click.option('--port', default=8000, type=int, help='Web server port')
@click.option('--help-all', is_flag=True, help='Show extended help with profiles, examples, env vars')
def main(input_path: str, output_prefix: str, formats: str, profile: str, event_ids: str, only_event_id: str,
         channels: str, since: str, until: str, workers: int, dedup: bool, dsl: str, maps_dir: str, maps_sync: str,
         rules_dir: str, safelists_dir: str, findings_output: str, vss: bool, vss_drives: str,
         serve: bool, host: str, port: int, help_all: bool) -> None:
    if help_all:
        console.print(EXTENDED_HELP)
        sys.exit(0)

    os.makedirs(os.path.dirname(output_prefix) or '.', exist_ok=True)

    selected_formats = {f.strip().lower() for f in formats.split(',') if f.strip()}
    exporters = []
    if 'jsonl' in selected_formats:
        exporters.append(JsonlExporter(output_prefix + '.jsonl'))
    if 'csv' in selected_formats:
        exporters.append(CsvExporter(output_prefix + '.csv'))
    if 'parquet' in selected_formats:
        from .exporters import ParquetExporter
        exporters.append(ParquetExporter(output_prefix + '.parquet'))

    # Findings exporters (optional)
    findings_jsonl = None
    findings_csv = None
    if findings_output:
        from .exporters import FindingsJsonlExporter, FindingsCsvExporter
        findings_jsonl = FindingsJsonlExporter(findings_output + '.findings.jsonl')
        findings_csv = FindingsCsvExporter(findings_output + '.findings.csv')

    effective_profile = profile or os.environ.get('WIN_EVTX_PROFILE') or 'ir-default'
    profile_filter = get_profile(effective_profile)

    custom_ids = [s.strip() for s in event_ids.split(',') if s.strip()]
    channel_filter = {s.strip() for s in channels.split(',') if s.strip()}

    if only_event_id:
        custom_ids = []
        channel_filter = set()
        if '@' in only_event_id:
            eid, ch = only_event_id.split('@', 1)
            custom_ids = [eid.strip()]
            channel_filter = {ch.strip()}
        else:
            custom_ids = [only_event_id.strip()]

    start_ts = parse_iso8601_utc(since) if since else None
    end_ts = parse_iso8601_utc(until) if until else None

    event_filter = EventFilter(profile_filter.ids_by_channel, custom_ids, channel_filter, start_ts, end_ts, dsl or None)

    mapper = EventMapper(maps_dir or None)
    mapper.load_local()
    if maps_sync:
        mapper.sync_remote(maps_sync)

    # Load rules and safelists
    rule_set = RuleSet()
    if rules_dir:
        rule_set.load_dir(rules_dir)
    safelist = Safelist()
    if safelists_dir:
        safelist.load_dir(safelists_dir)

    evtx_paths = list(iter_evtx_paths(input_path))
    if vss:
        drives = [d.strip() for d in vss_drives.split(',') if d.strip()]
        vss_paths = list(iter_vss_evtx_paths(drives))
        evtx_paths.extend(vss_paths)
    if not evtx_paths:
        console.print('[yellow]No .evtx files found[/yellow]')
        sys.exit(1)

    total_matched = 0
    total_findings = 0
    buffered_for_db = []
    buffered_findings: list = []

    if serve:
        storage_init_db()

    with Progress() as progress:
        task = progress.add_task('Parsing EVTX...', total=len(evtx_paths))
        for path in evtx_paths:
            for evt in parse_evtx_file(path, event_filter, mapper=mapper, dedup=dedup):
                total_matched += 1
                # Evaluate rules if any
                if rule_set.rules and not safelist.is_event_safelisted(evt):
                    hits = rule_set.evaluate(evt)
                    for h in hits:
                        if safelist.is_finding_safelisted(h):
                            continue
                        finding_row = {
                            'event_timestamp': evt.get('timestamp'),
                            'channel': evt.get('channel'),
                            'event_id': evt.get('event_id'),
                            'rule_id': h.get('rule_id'),
                            'severity': h.get('severity'),
                            'description': h.get('description'),
                            'tags': h.get('tags') or [],
                            'event_ref': None,
                        }
                        total_findings += 1
                        buffered_findings.append(finding_row)
                        if findings_jsonl:
                            findings_jsonl.write(finding_row)
                        if findings_csv:
                            findings_csv.write(finding_row)

                if serve:
                    buffered_for_db.append(evt)
                    if len(buffered_for_db) >= 1000:
                        insert_events(buffered_for_db)
                        buffered_for_db.clear()
                    if len(buffered_findings) >= 500:
                        insert_findings(buffered_findings)
                        buffered_findings.clear()
                for ex in exporters:
                    ex.write(evt)
            progress.advance(task)

    if buffered_for_db:
        insert_events(buffered_for_db)
        buffered_for_db.clear()
    if buffered_findings:
        insert_findings(buffered_findings)
        buffered_findings.clear()

    for ex in exporters:
        ex.close()
    if findings_jsonl:
        findings_jsonl.close()
    if findings_csv:
        findings_csv.close()

    console.print(f'[green]Done.[/green] Extracted events: {total_matched}. Findings: {total_findings}. Profile: {effective_profile}')

    if serve:
        try:
            from .server import app, init_db as server_init
            server_init()
            import uvicorn
            console.print(f'[blue]Starting web server at http://{host}:{port}[/blue]')
            uvicorn.run(app, host=host, port=port)
        except Exception as e:
            console.print(f'[red]Server start error: {e}[/red]')
            sys.exit(1)
