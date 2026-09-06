export interface ConnectivityEdge {
  src: string;
  dst: string;
  conn?: string;
}

export interface FlowDetail {
  protocol: string;
  ports: string;
  raw: string;
  policy?: string;
  rule?: string;
  service?: string;
}

export interface EndpointFlow {
  peer: string;
  conn?: string;
  flows: FlowDetail[];
  edgeIndex: number;
}

export interface ServicePort {
  name: string;
  protocol?: string;
  ports?: string;
}

export interface DFWRule {
  id?: number;
  name?: string;
  policy?: string;
  sources?: string[];
  destinations?: string[];
  services?: string[];
  servicePorts?: ServicePort[];
  action?: string;
}

export interface TopologyRenderOptions {
  edges: ConnectivityEdge[];
  dfwRules?: DFWRule[];
  filter?: string;
  focusNode?: string | null;
  selectedEdge?: { source: string; destination: string; conn?: string } | null;
  onNodeClick?: (node: string) => void;
  onEdgeClick?: (edge: ConnectivityEdge) => void;
  onBackgroundClick?: () => void;
  onSummary?: (summary: { edgeCount: number; nodeCount: number }) => void;
}
