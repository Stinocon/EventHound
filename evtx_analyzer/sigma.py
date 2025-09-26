import os
import yaml
from typing import Any, Dict, List, Optional
from .rules import RuleSet, Rule, RuleCondition


class SigmaLoader:
    def __init__(self) -> None:
        pass

    def load_dir(self, ruleset: RuleSet, sigma_dir: str) -> int:
        count = 0
        for root, _dirs, files in os.walk(sigma_dir):
            for f in files:
                if not f.lower().endswith(('.yml', '.yaml')):
                    continue
                path = os.path.join(root, f)
                try:
                    with open(path, 'r', encoding='utf-8') as fh:
                        data = yaml.safe_load(fh)
                        if not isinstance(data, dict):
                            continue
                        r = self._convert_sigma_rule(data)
                        if r:
                            ruleset.rules.append(r)
                            count += 1
                except Exception:
                    continue
        return count

    def _convert_sigma_rule(self, obj: Dict[str, Any]) -> Optional[Rule]:
        title = str(obj.get('title') or obj.get('id') or '')
        if not title:
            return None
        rule_id = str(obj.get('id') or title.replace(' ', '_').lower())
        description = str(obj.get('description') or '')
        level = str(obj.get('level') or 'info')
        detection = obj.get('detection') or {}
        condition = str(detection.get('condition') or '').strip()
        if not condition:
            return None
        selections: Dict[str, List[RuleCondition]] = {}
        for sel_name, sel_body in detection.items():
            if sel_name == 'condition':
                continue
            conds: List[RuleCondition] = []
            if isinstance(sel_body, dict):
                for field, value in sel_body.items():
                    op = 'eq'
                    fld = str(field)
                    # map simple field modifiers
                    if '|contains' in fld:
                        fld = fld.split('|contains', 1)[0]
                        if isinstance(value, list):
                            for v in value:
                                conds.append(RuleCondition(fld, 'contains', v))
                            continue
                        else:
                            conds.append(RuleCondition(fld, 'contains', value))
                            continue
                    if '|re' in fld or '|regex' in fld:
                        fld = fld.split('|', 1)[0]
                        if isinstance(value, list):
                            for v in value:
                                conds.append(RuleCondition(fld, 'regex', v))
                            continue
                        else:
                            conds.append(RuleCondition(fld, 'regex', value))
                            continue
                    # default eq semantics
                    if isinstance(value, list):
                        for v in value:
                            conds.append(RuleCondition(fld, 'eq', v))
                    else:
                        conds.append(RuleCondition(fld, 'eq', value))
            selections[sel_name] = conds
        tokens = condition.replace('(', ' ').replace(')', ' ').split()
        if len(tokens) == 1:
            name = tokens[0]
            any_of: List[RuleCondition] = []
            all_of: List[RuleCondition] = []
            for c in selections.get(name, []):
                any_of.append(c)
            return Rule(rule_id=rule_id, description=description, severity=level, any_of=any_of, all_of=all_of, tags=['sigma'])
        else:
            any_of: List[RuleCondition] = []
            all_of: List[RuleCondition] = []
            current_op = 'AND'
            for tok in tokens:
                tl = tok.lower()
                if tl in ('and', 'or'):
                    current_op = tl.upper()
                    continue
                sel_conds = selections.get(tok, [])
                if current_op == 'AND':
                    all_of.extend(sel_conds)
                else:
                    any_of.extend(sel_conds)
            return Rule(rule_id=rule_id, description=description, severity=level, any_of=any_of, all_of=all_of, tags=['sigma'])
