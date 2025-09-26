from typing import Dict, Set, List, Optional
from datetime import datetime
import re


class EventFilter:
    def __init__(self, ids_by_channel: Dict[str, Set[str]], custom_ids: List[str],
                 channel_filter: Set[str], start_ts: Optional[datetime], end_ts: Optional[datetime],
                 dsl: Optional[str] = None) -> None:
        self.ids_by_channel = ids_by_channel
        self.custom_ids = set(custom_ids)
        self.channel_filter = channel_filter
        self.start_ts = start_ts
        self.end_ts = end_ts
        self.dsl = dsl

    def match(self, evt: Dict) -> bool:
        channel = evt.get('channel') or ''
        event_id = str(evt.get('event_id')) if evt.get('event_id') is not None else ''
        ts = evt.get('timestamp_dt')

        if self.channel_filter and channel not in self.channel_filter:
            return False

        allowed_ids = self.ids_by_channel.get(channel, set())
        if allowed_ids or self.custom_ids:
            if event_id not in allowed_ids and event_id not in self.custom_ids:
                return False

        if self.start_ts and (ts is None or ts < self.start_ts):
            return False
        if self.end_ts and (ts is None or ts > self.end_ts):
            return False

        if self.dsl and not self._match_dsl(evt, self.dsl):
            return False

        return True

    def _get_field(self, evt: Dict, field: str):
        if field in evt:
            return evt.get(field)
        data = evt.get('data') or {}
        return data.get(field)

    def _match_dsl(self, evt: Dict, dsl: str) -> bool:
        # Simple grammar: field OP value; multiple clauses with AND/OR
        # OP: ==, !=, contains, !contains, ~= (regex), !~ (neg regex)
        # Example: channel==Security AND event_id==4624 AND TargetUserName~=^admin
        tokens = re.split(r"\s+(AND|OR)\s+", dsl)
        result = None
        op = None
        for tok in tokens:
            if tok in ("AND", "OR"):
                op = tok
                continue
            ok = self._eval_clause(evt, tok.strip())
            if result is None:
                result = ok
            else:
                result = (result and ok) if op == 'AND' else (result or ok)
        return bool(result)

    def _eval_clause(self, evt: Dict, clause: str) -> bool:
        m = re.match(r"^([^!=~\s]+)\s*(==|!=|~=|!~|contains|!contains)\s*(.+)$", clause)
        if not m:
            return False
        field, op, value = m.groups()
        value = value.strip().strip('"\'')
        val = self._get_field(evt, field)
        s = '' if val is None else str(val)
        if op == '==':
            return s == value
        if op == '!=':
            return s != value
        if op == 'contains':
            return value in s
        if op == '!contains':
            return value not in s
        if op == '~=':
            try:
                return re.search(value, s, flags=re.IGNORECASE) is not None
            except re.error:
                return False
        if op == '!~':
            try:
                return re.search(value, s, flags=re.IGNORECASE) is None
            except re.error:
                return True
        return False
