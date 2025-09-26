import os
import json
import time
import yaml
import requests
from typing import Dict, Any, Optional

DEFAULT_MAPS_DIR = os.path.join(os.getcwd(), 'maps')


class EventMapper:
    def __init__(self, maps_dir: Optional[str] = None) -> None:
        self.maps_dir = maps_dir or DEFAULT_MAPS_DIR
        self.maps: Dict[str, Dict[str, Any]] = {}

    def load_local(self) -> int:
        os.makedirs(self.maps_dir, exist_ok=True)
        count = 0
        for root, _dirs, files in os.walk(self.maps_dir):
            for f in files:
                if not f.lower().endswith(('.yml', '.yaml')):
                    continue
                path = os.path.join(root, f)
                try:
                    with open(path, 'r', encoding='utf-8') as fh:
                        data = yaml.safe_load(fh) or {}
                        if isinstance(data, dict):
                            for key, value in data.items():
                                # key format: "Channel:EventID" or just "EventID"
                                self.maps[str(key)] = value or {}
                            count += 1
                except Exception:
                    continue
        return count

    def sync_remote(self, url: str, timeout_sec: int = 20) -> bool:
        try:
            r = requests.get(url, timeout=timeout_sec)
            r.raise_for_status()
            payload = r.json() if 'application/json' in r.headers.get('Content-Type','') else yaml.safe_load(r.text)
            if not isinstance(payload, dict):
                return False
            # Write into maps dir as synced.yaml
            os.makedirs(self.maps_dir, exist_ok=True)
            dest = os.path.join(self.maps_dir, 'synced.yaml')
            with open(dest, 'w', encoding='utf-8') as fh:
                yaml.safe_dump(payload, fh, sort_keys=False, allow_unicode=True)
            self.load_local()
            return True
        except Exception:
            return False

    def enrich(self, evt: Dict[str, Any]) -> Dict[str, Any]:
        channel = evt.get('channel') or ''
        eid = str(evt.get('event_id')) if evt.get('event_id') is not None else ''
        key_exact = f"{channel}:{eid}"
        key_id_only = eid
        m = self.maps.get(key_exact) or self.maps.get(key_id_only)
        if not m:
            return evt
        # Simple enrichment rules: rename fields, extract from EventData, derive fields
        data = evt.get('data') or {}
        renamed = {}
        for src, dst in (m.get('rename') or {}).items():
            if src in data:
                renamed[dst] = data.get(src)
        derived = {}
        for name, expr in (m.get('derive') or {}).items():
            # very basic interp: {field} in EventData
            val = expr
            for k, v in data.items():
                val = str(val).replace('{'+str(k)+'}', str(v))
            derived[name] = val
        tags = list(set(list(evt.get('tags', [])) + list(m.get('tags', []))))
        out = dict(evt)
        out['data'] = dict(data)
        out['data'].update(renamed)
        if derived:
            out['derived'] = derived
        if tags:
            out['tags'] = tags
        return out
