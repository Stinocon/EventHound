import os
import re
import yaml
from typing import Any, Dict, List


class Safelist:
    def __init__(self) -> None:
        self.usernames: List[re.Pattern] = []
        self.sids: List[re.Pattern] = []
        self.computers: List[re.Pattern] = []
        self.processes: List[re.Pattern] = []
        self.commandlines: List[re.Pattern] = []
        self.event_ids: List[re.Pattern] = []
        self.rule_ids: List[re.Pattern] = []

    def _compile_many(self, patterns: List[str]) -> List[re.Pattern]:
        out: List[re.Pattern] = []
        for p in patterns:
            try:
                out.append(re.compile(p, re.IGNORECASE))
            except re.error:
                continue
        return out

    def _load_yaml_obj(self, obj: Dict[str, Any]) -> None:
        self.usernames += self._compile_many(list(obj.get('usernames') or []))
        self.sids += self._compile_many(list(obj.get('sids') or []))
        self.computers += self._compile_many(list(obj.get('computers') or []))
        self.processes += self._compile_many(list(obj.get('processes') or []))
        self.commandlines += self._compile_many(list(obj.get('commandlines') or []))
        self.event_ids += self._compile_many(list(obj.get('event_ids') or []))
        self.rule_ids += self._compile_many(list(obj.get('rule_ids') or []))

    def load_dir(self, dir_path: str) -> int:
        count = 0
        for root, _dirs, files in os.walk(dir_path):
            for f in files:
                path = os.path.join(root, f)
                try:
                    if f.lower().endswith(('.yml', '.yaml')):
                        with open(path, 'r', encoding='utf-8') as fh:
                            data = yaml.safe_load(fh) or {}
                            if isinstance(data, dict):
                                self._load_yaml_obj(data)
                                count += 1
                    elif f.lower().endswith('.txt'):
                        with open(path, 'r', encoding='utf-8') as fh:
                            lines = [ln.strip() for ln in fh.readlines() if ln.strip() and not ln.strip().startswith('#')]
                            # default bucket: commandlines
                            self.commandlines += self._compile_many(lines)
                            count += 1
                except Exception:
                    continue
        return count

    def _any_match(self, value: str, patterns: List[re.Pattern]) -> bool:
        if value is None:
            return False
        for p in patterns:
            if p.search(str(value)):
                return True
        return False

    def is_event_safelisted(self, evt: Dict[str, Any]) -> bool:
        data = evt.get('data') or {}
        # Common fields
        user = data.get('TargetUserName') or data.get('SubjectUserName') or evt.get('user_sid')
        sid = evt.get('user_sid')
        comp = evt.get('computer')
        proc = data.get('NewProcessName') or data.get('Image')
        cmd = data.get('CommandLine') or data.get('ScriptBlockText')
        eid = str(evt.get('event_id')) if evt.get('event_id') is not None else None
        if self._any_match(user or '', self.usernames):
            return True
        if self._any_match(sid or '', self.sids):
            return True
        if self._any_match(comp or '', self.computers):
            return True
        if self._any_match(proc or '', self.processes):
            return True
        if self._any_match(cmd or '', self.commandlines):
            return True
        if self._any_match(eid or '', self.event_ids):
            return True
        return False

    def is_finding_safelisted(self, finding: Dict[str, Any]) -> bool:
        rid = finding.get('rule_id') or ''
        return self._any_match(str(rid), self.rule_ids)
