import {
  EdgeModel,
  EdgeStyle,
  Model,
  NodeModel,
  NodeShape,
} from '@patternfly/react-topology';
import type { ConnectivityEdge } from './types';

function displayLabel(name: string, max = 18): string {
  if (name.length <= max) return name;
  return `${name.slice(0, max - 1)}…`;
}

function nodeKey(name: string): string {
  return `node:${name}`;
}

const NODE_SIZE = 80;

function edgeKey(edge: ConnectivityEdge, index: number): string {
  return `edge:${index}:${edge.src}->${edge.dst}:${edge.conn || ''}`;
}

function connectedNames(edges: ConnectivityEdge[], focus?: string | null): Set<string> | null {
  if (!focus) return null;
  const set = new Set<string>([focus]);
  edges.forEach((e) => {
    if (e.src === focus) set.add(e.dst);
    if (e.dst === focus) set.add(e.src);
  });
  return set;
}

export function filterEdges(edges: ConnectivityEdge[], filter?: string): ConnectivityEdge[] {
  const f = (filter || '').trim().toLowerCase();
  if (!f) return edges;
  return edges.filter((e) => {
    const hay = `${e.src || ''} ${e.dst || ''} ${e.conn || ''}`.toLowerCase();
    return hay.includes(f);
  });
}

export function buildTopologyModel(
  edges: ConnectivityEdge[],
  focusNode?: string | null,
  selectedEdge?: { source: string; destination: string; conn?: string } | null,
): Model {
  const nodes = new Set<string>();
  edges.forEach((e) => {
    nodes.add(e.src);
    nodes.add(e.dst);
  });

  const connected = connectedNames(edges, focusNode);
  const nodeList = [...nodes].sort();

  const nodeModels: NodeModel[] = nodeList.map((name) => {
    const dimmed = connected ? !connected.has(name) : false;
    const focused = focusNode === name;
    return {
      id: nodeKey(name),
      type: 'node',
      label: displayLabel(name),
      width: NODE_SIZE,
      height: NODE_SIZE,
      shape: NodeShape.ellipse,
      style: {
        opacity: dimmed ? 0.28 : 1,
      },
      data: {
        endpoint: name,
        fullLabel: name,
        focused,
        badge: focused ? 'Focus' : undefined,
      },
    };
  });

  const edgeModels: EdgeModel[] = edges.map((edge, index) => {
    const highlighted = focusNode ? edge.src === focusNode || edge.dst === focusNode : false;
    const dimmed = focusNode ? !highlighted : false;
    const selected =
      !!selectedEdge &&
      selectedEdge.source === edge.src &&
      selectedEdge.destination === edge.dst;
    return {
      id: edgeKey(edge, index),
      type: 'edge',
      source: nodeKey(edge.src),
      target: nodeKey(edge.dst),
      edgeStyle: EdgeStyle.default,
      style: {
        opacity: dimmed ? 0.15 : selected ? 1 : highlighted ? 0.95 : 0.55,
        strokeWidth: selected ? 3 : highlighted ? 2.5 : 1.5,
      },
      data: { edge, index },
    };
  });

  return {
    nodes: nodeModels,
    edges: edgeModels,
    graph: {
      id: 'connectivity-graph',
      type: 'graph',
      layout: 'Cola',
    },
  };
}

export function parseNodeId(id: string): string | null {
  return id.startsWith('node:') ? id.slice(5) : null;
}

export function parseEdgeData(id: string, model: Model): ConnectivityEdge | null {
  const edge = model.edges?.find((e) => e.id === id);
  if (!edge?.data || typeof edge.data !== 'object') return null;
  const data = edge.data as { edge?: ConnectivityEdge };
  return data.edge || null;
}
