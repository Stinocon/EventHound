import os
import re
import yaml
from typing import Any, Dict, List, Optional, Union


SUPPORTED_OPS = {
    'eq', 'ne', 'contains', 'not_contains', 'regex', 'not_regex',
    'length_gt', 'length_lt'
}


class RuleCondition:
    def __init__(self, field: str, op: str, value: Any) -> None:
        if op not in SUPPORTED_OPS:
            raise ValueError(f"Unsupported op: {op}")
        self.field = field
        self.op = op
        self.value = value

    def _get_value(self, evt: Dict[str, Any]) -> Optional[str]:
        if self.field in evt:
            v = evt.get(self.field)
        else:
            data = evt.get('data') or {}
            v = data.get(self.field)
        if v is None:
            return None
        return str(v)

    def match(self, evt: Dict[str, Any]) -> bool:
        s = self._get_value(evt)
        if self.op == 'eq':
            return s == str(self.value)
        if self.op == 'ne':
            return s != str(self.value)
        if self.op == 'contains':
            return s is not None and str(self.value) in s
        if self.op == 'not_contains':
            return s is None or str(self.value) not in s
        if self.op == 'regex':
            if s is None:
                return False
            try:
                return re.search(str(self.value), s, flags=re.IGNORECASE) is not None
            except re.error:
                return False
        if self.op == 'not_regex':
            if s is None:
                return True
            try:
                return re.search(str(self.value), s, flags=re.IGNORECASE) is None
            except re.error:
                return True
        if self.op == 'length_gt':
            return (len(s) if s is not None else 0) > int(self.value)
        if self.op == 'length_lt':
            return (len(s) if s is not None else 0) < int(self.value)
        return False


class Rule:
    def __init__(self, rule_id: str, description: str = '', severity: str = 'info',
                 any_of: Optional[List[RuleCondition]] = None,
                 all_of: Optional[List[RuleCondition]] = None,
                 tags: Optional[List[str]] = None) -> None:
        self.rule_id = rule_id
        self.description = description
        self.severity = severity
        self.any_of = any_of or []
        self.all_of = all_of or []
        self.tags = tags or []

    def match(self, evt: Dict[str, Any]) -> bool:
        if self.all_of:
            for c in self.all_of:
                if not c.match(evt):
                    return False
        if self.any_of:
            return any(c.match(evt) for c in self.any_of)
        # If only all_of was specified and all matched, it's a hit
        return bool(self.all_of)


class RuleSet:
    def __init__(self) -> None:
        self.rules: List[Rule] = []

    def load_dir(self, rules_dir: str) -> int:
        count = 0
        for root, _dirs, files in os.walk(rules_dir):
            for f in files:
                if not f.lower().endswith(('.yml', '.yaml')):
                    continue
                path = os.path.join(root, f)
                try:
                    with open(path, 'r', encoding='utf-8') as fh:
                        data = yaml.safe_load(fh)
                        count += self._load_from_obj(data)
                except Exception:
                    continue
        return count

    def _load_from_obj(self, obj: Any) -> int:
        loaded = 0
        if isinstance(obj, list):
            for item in obj:
                r = self._rule_from_item(item)
                if r:
                    self.rules.append(r)
                    loaded += 1
        elif isinstance(obj, dict):
            # Allow {id: rule_def}
            for key, item in obj.items():
                if isinstance(item, dict) and 'id' not in item:
                    item = dict(item)
                    item['id'] = key
                r = self._rule_from_item(item)
                if r:
                    self.rules.append(r)
                    loaded += 1
        return loaded

    def _rule_from_item(self, item: Any) -> Optional[Rule]:
        if not isinstance(item, dict):
            return None
        rule_id = str(item.get('id') or '')
        if not rule_id:
            return None
        description = str(item.get('description') or '')
        severity = str(item.get('severity') or 'info')
        tags = list(item.get('tags') or [])
        any_of = []
        for c in (item.get('any') or []):
            any_of.append(RuleCondition(str(c.get('field')), str(c.get('op')), c.get('value')))
        all_of = []
        for c in (item.get('all') or []):
            all_of.append(RuleCondition(str(c.get('field')), str(c.get('op')), c.get('value')))
        return Rule(rule_id=rule_id, description=description, severity=severity, any_of=any_of, all_of=all_of, tags=tags)

    def evaluate(self, evt: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for r in self.rules:
            try:
                if r.match(evt):
                    findings.append({
                        'rule_id': r.rule_id,
                        'severity': r.severity,
                        'description': r.description,
                        'tags': r.tags,
                    })
            except Exception:
                continue
        return findings
