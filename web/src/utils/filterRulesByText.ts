import type { DFWRuleRow } from '@/api/types';

export function filterRulesByText(rules: DFWRuleRow[], filter: string): DFWRuleRow[] {
  if (!filter.trim()) return rules;
  const q = filter.toLowerCase();
  return rules.filter((r) =>
    [
      String(r.id || ''),
      r.name,
      r.policy,
      r.category,
      r.action,
      (r.sources || []).join(' '),
      (r.destinations || []).join(' '),
      (r.services || []).join(' '),
    ]
      .join(' ')
      .toLowerCase()
      .includes(q),
  );
}
