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
        # Minimal subset: map detections with a single condition like "selection" or "selection1 and selection2"/"or".
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
        # Build selections map: name -> list of conditions
        selections: Dict[str, List[RuleCondition]] = {}
        for sel_name, sel_body in detection.items():
            if sel_name == 'condition':
                continue
            conds: List[RuleCondition] = []
            if isinstance(sel_body, dict):
                # field -> value or list
                for field, value in sel_body.items():
                    if isinstance(value, list):
                        # OR across the list
                        # represent as contains of any or eq any; default eq string
                        # we'll attach these later under any_of
                        # store as a special marker by expanding into multiple conditions
                        for v in value:
                            conds.append(RuleCondition(str(field), 'eq', v))
                    else:
                        conds.append(RuleCondition(str(field), 'eq', value))
            selections[sel_name] = conds
        # Parse very simple conditions: tokens split by and/or
        tokens = condition.replace('(', ' ').replace(')', ' ').split()
        # We'll support patterns like: selection, sel1 and sel2, sel1 or sel2
        if len(tokens) == 1:
            name = tokens[0]
            any_of: List[RuleCondition] = []
            all_of: List[RuleCondition] = []
            # For a single selection: fields are AND, lists generated above are OR
            # To approximate, put all field singletons into all_of, and duplicates for list items into any_of
            # Here we just put all into any_of to avoid over-constraining
            for c in selections.get(name, []):
                any_of.append(c)
            return Rule(rule_id=rule_id, description=description, severity=level, any_of=any_of, all_of=all_of, tags=['sigma'])
        else:
            # Build combined using AND/OR between selections
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
