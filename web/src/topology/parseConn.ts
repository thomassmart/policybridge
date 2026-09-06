import type { ConnectivityEdge, DFWRule, EndpointFlow, FlowDetail, ServicePort } from './types';

export function isAllConnections(conn?: string): boolean {
  const raw = String(conn || '').trim();
  return !raw || /^all\s+connections?$/i.test(raw);
}

export function formatRuleFlowLabel(policy?: string, rule?: string, service?: string): string {
  const parts = [policy, rule, service].map((p) => p?.trim()).filter(Boolean);
  return parts.join(' | ');
}

export function parseConnDetail(connStr?: string): FlowDetail[] {
  if (!connStr) return [{ protocol: 'ALL', ports: 'all', raw: '' }];
  let raw = String(connStr).trim();
  if (raw.startsWith('{')) {
    try {
      const obj = JSON.parse(raw) as { conn?: string; connections?: string };
      raw = obj.conn || obj.connections || raw;
    } catch {
      /* fall through */
    }
  }
  if (!raw || /^all\s+connections?$/i.test(raw)) {
    return [{ protocol: 'ALL', ports: 'all', raw }];
  }

  const clauses = raw.split(';').map((part) => part.trim()).filter(Boolean);
  const flows = clauses.flatMap(parseClause).filter((v): v is FlowDetail => v !== null);
  return expandFlowPorts(flows.length ? flows : [{ protocol: 'OTHER', ports: raw, raw }]);
}

function parseClause(part: string): FlowDetail[] | FlowDetail | null {
  if (!part) return null;
  if (/^all\s+connections?$/i.test(part)) {
    return { protocol: 'ALL', ports: 'all', raw: part };
  }

  const pipeParts = part.split('|').map((p) => p.trim()).filter(Boolean);
  if (pipeParts.length >= 3) {
    const [policy, rule, service] = pipeParts;
    return ruleFlowDetail(policy, rule, service, part);
  }
  if (pipeParts.length === 2) {
    const [rule, service] = pipeParts;
    return ruleFlowDetail(undefined, rule, service, part);
  }

  const slash = part.match(/^(TCP|UDP|ICMP|SCTP|ALL)\s*\/\s*(.+)$/i);
  if (slash) {
    return { protocol: slash[1].toUpperCase(), ports: slash[2].trim(), raw: part };
  }
  const spaced = part.match(/^(TCP|UDP|ICMP|SCTP)\s+(.+)$/i);
  if (spaced) {
    let ports = spaced[2].trim();
    ports = ports.replace(/^dst-ports:\s*/i, '');
    return { protocol: spaced[1].toUpperCase(), ports, raw: part };
  }
  if (/^ICMP$/i.test(part)) {
    return { protocol: 'ICMP', ports: '—', raw: part };
  }

  const ruleService = part.match(/^([^:]+):\s*(.+)$/);
  if (ruleService && !/^(TCP|UDP|ICMP|SCTP)\s/i.test(part)) {
    return ruleFlowDetail(undefined, ruleService[1].trim(), ruleService[2].trim(), part);
  }

  if (part.includes('·') || /^(?:.+)\s+(TCP|UDP|SCTP)\//i.test(part)) {
    return ruleFlowDetail(undefined, undefined, part, part);
  }

  return { protocol: 'OTHER', ports: part, raw: part };
}

function splitServiceToken(token: string): { service: string; protocol?: string; ports?: string } {
  const trimmed = token.trim();
  if (!trimmed) return { service: '' };

  const dotted = trimmed.split(/\s*·\s*/).map((p) => p.trim()).filter(Boolean);
  if (dotted.length >= 2) {
    const service = dotted[0];
    const rest = dotted.slice(1).join(' · ');
    const parsed = parseProtocolPort(rest);
    if (parsed) return { service, protocol: parsed.protocol, ports: parsed.ports };
    return { service, ports: rest };
  }

  const spaced = trimmed.match(/^(.+?)\s+((?:TCP|UDP|SCTP|ICMPV6|ICMPV4|ICMP)\s*\/\s*.+)$/i);
  if (spaced) {
    const parsed = parseProtocolPort(spaced[2]);
    if (parsed) return { service: spaced[1].trim(), protocol: parsed.protocol, ports: parsed.ports };
  }

  return { service: trimmed };
}

function parseProtocolPort(value: string): { protocol: string; ports: string } | null {
  const raw = value.trim();
  if (!raw) return null;
  const slash = raw.match(/^(TCP|UDP|SCTP|ICMPV6|ICMPV4|ICMP)\s*\/\s*(.+)$/i);
  if (slash) {
    return { protocol: normalizeProtocol(slash[1]), ports: slash[2].trim() };
  }
  const spaced = raw.match(/^(TCP|UDP|SCTP|ICMPV6|ICMPV4|ICMP)\s+(.*)$/i);
  if (spaced) {
    return { protocol: normalizeProtocol(spaced[1]), ports: spaced[2].trim() || '—' };
  }
  if (/^(TCP|UDP|SCTP|ICMPV6|ICMPV4|ICMP)$/i.test(raw)) {
    return { protocol: normalizeProtocol(raw), ports: '—' };
  }
  return null;
}

function normalizeProtocol(protocol: string): string {
  const upper = protocol.toUpperCase();
  if (upper === 'ICMPV6') return 'ICMPv6';
  if (upper === 'ICMPV4' || upper === 'ICMP') return 'ICMP';
  return upper;
}

function ruleFlowDetail(
  policy: string | undefined,
  rule: string | undefined,
  service: string,
  raw: string,
): FlowDetail {
  const parsed = splitServiceToken(service);
  const svc = parsed.service;
  if (/^any$/i.test(svc)) {
    return {
      protocol: 'ALL',
      ports: 'all',
      raw,
      policy: policy?.trim() || undefined,
      rule: rule?.trim() || undefined,
      service: 'Any',
    };
  }

  const known = WELL_KNOWN_BY_NAME[svc.toUpperCase()];
  const protocol = parsed.protocol || known?.protocol || 'SVC';
  const ports = parsed.ports || known?.ports || svc;
  return {
    protocol,
    ports,
    raw,
    policy: policy?.trim() || undefined,
    rule: rule?.trim() || undefined,
    service: svc,
  };
}

function expandFlowPorts(flows: FlowDetail[]): FlowDetail[] {
  return flows.flatMap((flow) => {
    if (flow.policy || flow.rule || flow.service) {
      return [flow];
    }
    if (flow.protocol === 'ALL' || flow.protocol === 'ICMP' || flow.protocol === 'OTHER') {
      return [flow];
    }
    const ports = flow.ports
      .split(',')
      .map((p) => p.trim())
      .filter(Boolean);
    if (ports.length <= 1) return [flow];
    return ports.map((port) => ({
      ...flow,
      ports: port,
      raw: `${flow.protocol} dst-ports: ${port}`,
    }));
  });
}

const WELL_KNOWN_SERVICES: Record<string, string> = {
  '22': 'SSH',
  '53': 'DNS',
  '80': 'HTTP',
  '123': 'NTP',
  '139': 'SMB',
  '389': 'LDAP',
  '443': 'HTTPS',
  '445': 'SMB',
  '636': 'LDAPS',
  '1433': 'SQL',
  '3306': 'MySQL',
  '3389': 'RDP',
  '5432': 'PostgreSQL',
  '6379': 'Redis',
  '8080': 'HTTP',
  '8443': 'HTTPS',
};

const WELL_KNOWN_BY_NAME: Record<string, { protocol: string; ports: string }> = {
  HTTP: { protocol: 'TCP', ports: '80' },
  HTTPS: { protocol: 'TCP', ports: '443' },
  SSH: { protocol: 'TCP', ports: '22' },
  DNS: { protocol: 'UDP', ports: '53' },
  NTP: { protocol: 'UDP', ports: '123' },
  SMB: { protocol: 'TCP', ports: '445' },
  LDAP: { protocol: 'TCP', ports: '389' },
  LDAPS: { protocol: 'TCP', ports: '636' },
  RDP: { protocol: 'TCP', ports: '3389' },
  SQL: { protocol: 'TCP', ports: '1433' },
  MYSQL: { protocol: 'TCP', ports: '3306' },
  POSTGRESQL: { protocol: 'TCP', ports: '5432' },
  REDIS: { protocol: 'TCP', ports: '6379' },
  ICMP: { protocol: 'ICMP', ports: '—' },
};

function firstPort(ports?: string): string {
  return String(ports || '')
    .replace(/^dst-ports:\s*/i, '')
    .split(/[,\s]/)[0]
    ?.trim();
}

function formatL4(protocol: string, ports?: string): string {
  const proto = normalizeProtocol(protocol);
  const p = String(ports || '')
    .replace(/^dst-ports:\s*/i, '')
    .trim();
  if (proto === 'ICMP' || proto === 'ICMPv6') {
    if (!p || p === '—' || p === 'all') return proto;
    if (/^ICMP/i.test(p)) return p;
    return `${proto} ${p}`;
  }
  if (/^(TCP|UDP|SCTP)\//i.test(p)) return p;
  if (!p || p === 'all' || p === '—') return proto;
  return `${proto}/${p}`;
}

export function formatProtocolPort(protocol?: string, ports?: string): string | null {
  const raw = (protocol || '').trim();
  if (!raw) return null;
  const proto = raw.toUpperCase();
  if (proto === 'ALL' || proto === 'OTHER' || proto === 'SVC') return null;
  const known = WELL_KNOWN_BY_NAME[proto];
  if (known && (!ports || ports.toUpperCase() === proto || ports === known.ports)) {
    return formatL4(known.protocol, known.ports);
  }
  return formatL4(raw, ports);
}

export function formatServiceToken(name?: string, protocol?: string, ports?: string): string {
  const service = (name || '').trim();
  if (service && /^any$/i.test(service)) return 'Any';

  const protoPort = formatProtocolPort(protocol, ports);
  const known = service ? WELL_KNOWN_BY_NAME[service.toUpperCase()] : undefined;
  const knownPP = known ? formatL4(known.protocol, known.ports) : null;

  if (service && protoPort) {
    if (service.toUpperCase() === (protocol || '').toUpperCase()) {
      return knownPP ? `${service} · ${knownPP}` : protoPort;
    }
    if (service.toUpperCase() === protoPort.toUpperCase()) return protoPort;
    return `${service} · ${protoPort}`;
  }
  if (service) return knownPP ? `${service} · ${knownPP}` : service;
  if (protoPort) {
    const mapped = WELL_KNOWN_SERVICES[firstPort(ports)];
    if (mapped && mapped.toUpperCase() !== protoPort.toUpperCase()) {
      return `${mapped} · ${protoPort}`;
    }
    return protoPort;
  }
  return 'Any';
}

/** On-map and drawer label: HTTPS · TCP/443, SSH · TCP/22, TCP/8081, Any. */
export function flowServiceLabel(flow: FlowDetail): string {
  if (!flow.service && flow.protocol === 'OTHER') {
    return flow.ports || flow.raw || 'Other';
  }
  return formatServiceToken(flow.service, flow.protocol, flow.ports);
}

export function edgeServiceLabel(conn?: string): string {
  const flows = parseConnDetail(conn);
  if (!flows.length) return 'Any';
  return [...new Set(flows.map(flowServiceLabel))].join(', ');
}

export function compactEdgeLabel(conn?: string, maxItems = 2, maxChars = 42): string {
  const labels = [...new Set(parseConnDetail(conn).map(flowServiceLabel))];
  if (!labels.length) return 'Any';
  let text =
    labels.length <= maxItems
      ? labels.join(', ')
      : `${labels.slice(0, maxItems).join(', ')} +${labels.length - maxItems}`;
  if (text.length > maxChars) {
    return `${text.slice(0, maxChars - 1)}…`;
  }
  return text;
}

export function formatRuleServices(rule: { services?: string[]; servicePorts?: ServicePort[] }): string {
  if (rule.servicePorts?.length) {
    return [...new Set(rule.servicePorts.map((sp) => formatServiceToken(sp.name, sp.protocol, sp.ports)))].join(', ');
  }
  return (rule.services || []).map((name) => formatServiceToken(name)).join(', ');
}

export function flowPillLabel(flow: FlowDetail): string {
  if (flow.policy || flow.rule) {
    return formatRuleFlowLabel(flow.policy, flow.rule, flowServiceLabel(flow));
  }
  if (flow.service) return flowServiceLabel(flow);

  if (flow.protocol === 'ALL') return 'ALL';
  if (flow.protocol === 'ICMP') return 'ICMP';
  if (flow.protocol === 'OTHER') {
    const ruleService = flow.raw?.match(/^([^:]+):\s*(.+)$/);
    if (ruleService) {
      return formatRuleFlowLabel(undefined, ruleService[1].trim(), ruleService[2].trim());
    }
    return flow.ports || flow.raw;
  }
  return `${flow.protocol} ${flow.ports}`;
}

export function flowLabel(conn?: string): string {
  const flows = parseConnDetail(conn);
  if (!flows.length) return 'ALL';
  return flows.map(flowPillLabel).join(', ');
}

export function expandEdges(edges: ConnectivityEdge[]): ConnectivityEdge[] {
  const expanded: ConnectivityEdge[] = [];
  edges.forEach((edge) => {
    const flows = parseConnDetail(edge.conn);
    if (flows.length === 1 && flows[0].protocol === 'ALL') {
      expanded.push(edge);
      return;
    }
    flows.forEach((flow) => {
      expanded.push({
        src: edge.src,
        dst: edge.dst,
        conn: flow.raw || `${flow.protocol} ${flow.ports}`,
      });
    });
  });
  return expanded;
}

function endpointMatches(ruleEndpoints: string[] | undefined, vmName: string): boolean {
  if (!ruleEndpoints?.length) return true;
  return ruleEndpoints.some((endpoint) => {
    const ep = endpoint.trim();
    if (!ep || /^any$/i.test(ep)) return true;
    if (ep === vmName) return true;
    const short = ep.replace(/^grp[-_]?/i, '').replace(/^group[-_]?/i, '');
    if (short === vmName) return true;
    if (vmName.endsWith(short) || short.endsWith(vmName)) return true;
    return false;
  });
}

function servicePortToFlow(sp: ServicePort, rule?: DFWRule): FlowDetail {
  const svc = (sp.name || '').trim() || 'Service';
  const ruleName = rule?.name?.trim();
  const policy = rule?.policy?.trim();

  if (!svc || /^any$/i.test(svc)) {
    return {
      protocol: 'ALL',
      ports: 'all',
      raw: formatRuleFlowLabel(policy, ruleName, 'Any'),
      policy,
      rule: ruleName,
      service: 'Any',
    };
  }

  const known = WELL_KNOWN_BY_NAME[svc.toUpperCase()];
  const protocol = sp.protocol || known?.protocol || 'SVC';
  const ports = sp.ports || known?.ports || svc;
  return {
    protocol,
    ports,
    raw: formatRuleFlowLabel(policy, ruleName, formatServiceToken(svc, protocol, ports)),
    policy,
    rule: ruleName,
    service: svc,
  };
}

export function enrichEdgesFromDFW(edges: ConnectivityEdge[], rules?: DFWRule[]): ConnectivityEdge[] {
  if (!rules?.length) return edges;

  return edges.flatMap((edge) => {
    if (!isAllConnections(edge.conn)) return [edge];

    const matchingFlows: FlowDetail[] = [];
    for (const rule of rules) {
      if (rule.action && rule.action.toUpperCase() !== 'ALLOW') continue;
      if (!endpointMatches(rule.sources, edge.src) || !endpointMatches(rule.destinations, edge.dst)) {
        continue;
      }
      const ports = rule.servicePorts?.length
        ? rule.servicePorts
        : (rule.services?.length ? rule.services : ['Any']).map((name) => ({ name }));
      for (const sp of ports) {
        matchingFlows.push(servicePortToFlow(sp, rule));
      }
    }

    if (!matchingFlows.length) return [edge];

    const unique = dedupeFlows(matchingFlows);
    return unique.map((flow) => ({
      src: edge.src,
      dst: edge.dst,
      conn: flow.raw,
    }));
  });
}

function dedupeFlows(flows: FlowDetail[]): FlowDetail[] {
  const seen = new Set<string>();
  const out: FlowDetail[] = [];
  flows.forEach((flow) => {
    const key = `${flow.policy || ''}\0${flow.rule || ''}\0${flow.service || ''}\0${flow.protocol}\0${flow.ports}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push(flow);
  });
  return out;
}

export function collapseEdgesByPair(edges: ConnectivityEdge[]): ConnectivityEdge[] {
  const groups = new Map<string, ConnectivityEdge[]>();
  for (const edge of edges) {
    const key = `${edge.src}\0${edge.dst}`;
    const existing = groups.get(key);
    if (existing) existing.push(edge);
    else groups.set(key, [edge]);
  }
  return [...groups.values()].map((group) => {
    const conns = [...new Set(group.map((e) => (e.conn || '').trim()).filter(Boolean))];
    return {
      src: group[0].src,
      dst: group[0].dst,
      conn: conns.join('; '),
    };
  });
}

export function prepareGraphEdges(edges: ConnectivityEdge[], rules?: DFWRule[]): ConnectivityEdge[] {
  return expandEdges(enrichEdgesFromDFW(edges, rules));
}

export function aggregateEndpointFlows(edges: ConnectivityEdge[], endpoint: string, rules?: DFWRule[]) {
  const prepared = prepareGraphEdges(edges, rules);
  const ingress: EndpointFlow[] = [];
  const egress: EndpointFlow[] = [];

  prepared.forEach((e, edgeIndex) => {
    const flows = parseConnDetail(e.conn);
    const flow = flows[0] || { protocol: 'ALL', ports: 'all', raw: e.conn || '' };
    if (e.dst === endpoint) {
      ingress.push({ peer: e.src, conn: e.conn, flows: [flow], edgeIndex });
    }
    if (e.src === endpoint) {
      egress.push({ peer: e.dst, conn: e.conn, flows: [flow], edgeIndex });
    }
  });

  return { ingress, egress };
}
