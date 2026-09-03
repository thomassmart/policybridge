import type { ComparisonFinding } from '@/api/types';

function asFindingArray(value: unknown): ComparisonFinding[] {
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is ComparisonFinding => item != null && typeof item === 'object');
}

export function collectComparisonFindings(comparison: unknown): ComparisonFinding[] {
  if (!comparison || typeof comparison !== 'object') return [];
  const record = comparison as Record<string, unknown>;
  return [
    ...asFindingArray(record.missing),
    ...asFindingArray(record.additional),
    ...asFindingArray(record.uncomparable),
  ];
}

export function comparisonSummary(comparison: unknown) {
  if (!comparison || typeof comparison !== 'object') return {};
  const summary = (comparison as Record<string, unknown>).summary;
  if (!summary || typeof summary !== 'object') return {};
  return summary as Record<string, number | undefined>;
}

export function displayFindingValue(value: unknown): string {
  if (value == null) return '';
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
    return String(value);
  }
  return JSON.stringify(value);
}
