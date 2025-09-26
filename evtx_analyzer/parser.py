from typing import Dict, Iterator
from Evtx.Evtx import Evtx
import xmltodict
from .utils import normalize_event
from .filters import EventFilter
from .maps import EventMapper


def parse_evtx_file(path: str, event_filter: EventFilter, mapper: EventMapper = None, dedup: bool = False) -> Iterator[Dict]:
    seen = set()
    with Evtx(path) as log:
        for record in log.records():
            try:
                xml = record.xml()
                obj = xmltodict.parse(xml)
            except Exception:
                continue

            evt = normalize_event(obj, record)
            if event_filter.match(evt):
                if mapper is not None:
                    evt = mapper.enrich(evt)
                if dedup:
                    # Basic dedup key: channel|event_id|record_id|timestamp
                    key = f"{evt.get('channel')}|{evt.get('event_id')}|{evt.get('record_id')}|{evt.get('timestamp')}"
                    if key in seen:
                        continue
                    seen.add(key)
                yield evt
