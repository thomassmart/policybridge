import type { AnalysisResult } from '@/api/types';
import type { ConnectivityEdge } from '@/topology/types';

export function parseConnectivity(analysis: AnalysisResult | null): ConnectivityEdge[] {
  if (!analysis) return [];
  let data = analysis.connectivityJson ?? analysis.connectivity;
  if (!data) return [];
  if (typeof data === 'string') {
    try {
      data = JSON.parse(data);
    } catch {
      return [];
    }
  }
  return Array.isArray(data) ? (data as ConnectivityEdge[]) : [];
}
