import os
from datetime import datetime, timezone
from typing import Dict, Iterable, Iterator, List
import sys


def iter_evtx_paths(path: str) -> Iterable[str]:
    if os.path.isdir(path):
        for root, _dirs, files in os.walk(path):
            for f in files:
                if f.lower().endswith('.evtx'):
                    yield os.path.join(root, f)
    else:
        if path.lower().endswith('.evtx'):
            yield path


def iter_vss_evtx_paths(drives: List[str]) -> Iterable[str]:
    # Windows only: attempt to access Volume Shadow Copies via GLOBALROOT paths
    if not sys.platform.startswith('win'):
        return []
    for drive in drives:
        d = drive.rstrip('\\/')
        # Probe a reasonable range of shadow copy numbers
        for idx in range(1, 65):
            base = f"\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy{idx}"
            logs_path = os.path.join(base, 'Windows', 'System32', 'winevt', 'Logs')
            if not os.path.exists(logs_path):
                continue
            try:
                for root, _dirs, files in os.walk(logs_path):
                    for f in files:
                        if f.lower().endswith('.evtx'):
                            yield os.path.join(root, f)
            except Exception:
                continue


def parse_iso8601_utc(s: str) -> datetime:
    # Accepts 'YYYY-MM-DDTHH:MM:SSZ' or with offset, normalizes to UTC
    dt = datetime.fromisoformat(s.replace('Z', '+00:00'))
    return dt.astimezone(timezone.utc)


def _get(d: Dict, path: str, default=None):
    cur = d
    for part in path.split('.'):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return default
    return cur


def normalize_event(obj: Dict, record) -> Dict:
    sys_ts = _get(obj, 'Event.System.TimeCreated.@SystemTime')
    provider = _get(obj, 'Event.System.Provider.@Name')
    channel = _get(obj, 'Event.System.Channel')
    computer = _get(obj, 'Event.System.Computer')
    event_id = _get(obj, 'Event.System.EventID')
    record_id = _get(obj, 'Event.System.EventRecordID')
    user_sid = _get(obj, 'Event.System.Security.@UserID')

    if isinstance(event_id, dict):
        event_id = event_id.get('#text') or event_id.get('@Qualifiers')

    timestamp = None
    timestamp_dt = None
    if sys_ts:
        try:
            timestamp_dt = parse_iso8601_utc(sys_ts)
            timestamp = timestamp_dt.isoformat().replace('+00:00', 'Z')
        except Exception:
            timestamp = sys_ts

    eventdata = _get(obj, 'Event.EventData') or {}

    return {
        'timestamp': timestamp,
        'timestamp_dt': timestamp_dt,
        'channel': channel,
        'event_id': str(event_id) if event_id is not None else None,
        'computer': computer,
        'provider': provider,
        'record_id': record_id,
        'user_sid': user_sid,
        'data': eventdata,
        'raw': obj,
    }
