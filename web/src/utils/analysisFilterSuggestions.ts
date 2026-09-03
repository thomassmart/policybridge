import type { DFWRuleRow } from '@/api/types';
import type { ConnectivityEdge } from '@/topology/types';

export type AnalysisFilterSuggestionGroup =
  | 'Policy'
  | 'Rule'
  | 'Endpoint'
  | 'Service'
  | 'Connection';

export interface AnalysisFilterSuggestion {
  value: string;
  label: string;
  group: AnalysisFilterSuggestionGroup;
}

const GROUP_ORDER: AnalysisFilterSuggestionGroup[] = [
  'Policy',
  'Rule',
  'Endpoint',
  'Service',
  'Connection',
];

function addSuggestion(
  map: Map<string, AnalysisFilterSuggestion>,
  value: string,
  group: AnalysisFilterSuggestionGroup,
) {
  const trimmed = value.trim();
  if (!trimmed) return;
  const key = trimmed.toLowerCase();
  if (!map.has(key)) {
    map.set(key, { value: trimmed, label: trimmed, group });
  }
}

export function buildAnalysisFilterSuggestions(
  rules: DFWRuleRow[],
  edges: ConnectivityEdge[],
): AnalysisFilterSuggestion[] {
  const map = new Map<string, AnalysisFilterSuggestion>();

  rules.forEach((rule) => {
    addSuggestion(map, rule.policy || '', 'Policy');
    addSuggestion(map, rule.name || '', 'Rule');
    addSuggestion(map, rule.category || '', 'Rule');
    addSuggestion(map, rule.action || '', 'Rule');
    if (rule.id != null) addSuggestion(map, String(rule.id), 'Rule');
    (rule.sources || []).forEach((s) => addSuggestion(map, s, 'Endpoint'));
    (rule.destinations || []).forEach((d) => addSuggestion(map, d, 'Endpoint'));
    (rule.services || []).forEach((s) => addSuggestion(map, s, 'Service'));
  });

  edges.forEach((edge) => {
    addSuggestion(map, edge.src || '', 'Endpoint');
    addSuggestion(map, edge.dst || '', 'Endpoint');
    addSuggestion(map, edge.conn || '', 'Connection');
  });

  return [...map.values()].sort((a, b) => {
    const groupDelta = GROUP_ORDER.indexOf(a.group) - GROUP_ORDER.indexOf(b.group);
    if (groupDelta !== 0) return groupDelta;
    return a.label.localeCompare(b.label, undefined, { sensitivity: 'base' });
  });
}

export function matchAnalysisFilterSuggestions(
  suggestions: AnalysisFilterSuggestion[],
  query: string,
  limit = 12,
): AnalysisFilterSuggestion[] {
  const q = query.trim().toLowerCase();
  if (!q) return [];

  const matches = suggestions.filter((s) => s.label.toLowerCase().includes(q));
  matches.sort((a, b) => {
    const aStarts = a.label.toLowerCase().startsWith(q);
    const bStarts = b.label.toLowerCase().startsWith(q);
    if (aStarts !== bStarts) return aStarts ? -1 : 1;
    const groupDelta = GROUP_ORDER.indexOf(a.group) - GROUP_ORDER.indexOf(b.group);
    if (groupDelta !== 0) return groupDelta;
    return a.label.localeCompare(b.label, undefined, { sensitivity: 'base' });
  });

  return matches.slice(0, limit);
}
