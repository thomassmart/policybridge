// @vitest-environment node
import { describe, expect, it } from 'vitest';
import {
  aggregateEndpointFlows,
  collapseEdgesByPair,
  compactEdgeLabel,
  edgeServiceLabel,
  enrichEdgesFromDFW,
  expandEdges,
  flowPillLabel,
  flowServiceLabel,
  formatRuleServices,
  parseConnDetail,
  prepareGraphEdges,
} from './parseConn';

describe('parseConnDetail', () => {
  it('parses TCP dst-ports without splitting ports on comma', () => {
    const flows = parseConnDetail('TCP dst-ports: 80,443');
    expect(flows).toHaveLength(2);
    expect(flows[0]).toMatchObject({ protocol: 'TCP', ports: '80' });
    expect(flows[1]).toMatchObject({ protocol: 'TCP', ports: '443' });
  });

  it('parses multiple protocol clauses separated by semicolon', () => {
    const flows = parseConnDetail('TCP dst-ports: 443; UDP dst-ports: 53');
    expect(flows).toHaveLength(2);
    expect(flows[0].protocol).toBe('TCP');
    expect(flows[1].protocol).toBe('UDP');
  });

  it('returns ALL for unrestricted connections', () => {
    const flows = parseConnDetail('All Connections');
    expect(flows).toEqual([{ protocol: 'ALL', ports: 'all', raw: 'All Connections' }]);
  });

  it('parses service · protocol/port labels', () => {
    const flows = parseConnDetail('Fleet-Management | allow-https | HTTPS · TCP/443');
    expect(flows).toMatchObject([{
      protocol: 'TCP',
      ports: '443',
      service: 'HTTPS',
      policy: 'Fleet-Management',
      rule: 'allow-https',
    }]);
  });
});

describe('expandEdges', () => {
  it('creates one edge per flow', () => {
    const expanded = expandEdges([
      { src: 'a', dst: 'b', conn: 'TCP dst-ports: 80,443' },
    ]);
    expect(expanded).toHaveLength(2);
    expect(expanded[0].conn).toContain('80');
    expect(expanded[1].conn).toContain('443');
  });
});

describe('enrichEdgesFromDFW', () => {
  it('replaces All Connections with matching DFW services', () => {
    const enriched = enrichEdgesFromDFW(
      [{ src: 'fleet-web', dst: 'fleet-db', conn: 'All Connections' }],
      [{
        policy: 'Fleet-Management',
        name: 'allow-web-to-db-ssh',
        action: 'ALLOW',
        sources: ['grp-fleet-web'],
        destinations: ['grp-fleet-db'],
        services: ['SSH'],
      }],
    );
    expect(enriched).toHaveLength(1);
    expect(enriched[0].conn).toBe('Fleet-Management | allow-web-to-db-ssh | SSH · TCP/22');
  });

  it('uses DFW servicePorts protocol and destination ports', () => {
    const enriched = enrichEdgesFromDFW(
      [{ src: 'web', dst: 'api', conn: 'All Connections' }],
      [{
        action: 'ALLOW',
        sources: ['web'],
        destinations: ['api'],
        services: ['HTTPS'],
        servicePorts: [{ name: 'HTTPS', protocol: 'TCP', ports: '443' }],
      }],
    );
    expect(enriched[0].conn).toBe('HTTPS · TCP/443');
  });
});

describe('aggregateEndpointFlows', () => {
  it('returns one row per flow for an endpoint', () => {
    const { ingress } = aggregateEndpointFlows(
      [{ src: 'a', dst: 'b', conn: 'TCP dst-ports: 80,443' }],
      'b',
    );
    expect(ingress).toHaveLength(2);
    expect(ingress[0].flows[0].protocol).toBe('TCP');
    expect(ingress[1].flows[0].ports).toBe('443');
  });
});

describe('flowServiceLabel', () => {
  it('shows protocol and port next to the DFW service name', () => {
    expect(flowServiceLabel({
      protocol: 'TCP',
      ports: '443',
      raw: 'Fleet | allow-web | HTTPS · TCP/443',
      service: 'HTTPS',
    })).toBe('HTTPS · TCP/443');
  });

  it('maps well-known names to protocol and port', () => {
    expect(flowServiceLabel({
      protocol: 'SVC',
      ports: 'HTTPS',
      raw: 'Fleet | allow-web | HTTPS',
      service: 'HTTPS',
    })).toBe('HTTPS · TCP/443');
  });

  it('maps well-known TCP ports to service names and keeps protocol/port', () => {
    expect(flowServiceLabel({ protocol: 'TCP', ports: '443', raw: '' })).toBe('HTTPS · TCP/443');
    expect(flowServiceLabel({ protocol: 'TCP', ports: '80', raw: '' })).toBe('HTTP · TCP/80');
    expect(flowServiceLabel({ protocol: 'TCP', ports: '22', raw: '' })).toBe('SSH · TCP/22');
  });

  it('falls back to protocol/port for unknown ports', () => {
    expect(flowServiceLabel({ protocol: 'TCP', ports: '8444', raw: '' })).toBe('TCP/8444');
  });
});

describe('edgeServiceLabel', () => {
  it('returns SSH with TCP/22 for a DFW service string', () => {
    expect(edgeServiceLabel('Fleet-Management | allow-web-to-db-ssh | SSH')).toBe('SSH · TCP/22');
  });

  it('returns HTTPS · TCP/443 for TCP 443', () => {
    expect(edgeServiceLabel('TCP dst-ports: 443')).toBe('HTTPS · TCP/443');
  });
});

describe('compactEdgeLabel', () => {
  it('joins two services and summarizes extras', () => {
    expect(compactEdgeLabel('HTTP · TCP/80; HTTPS · TCP/443')).toBe('HTTP · TCP/80, HTTPS · TCP/443');
    expect(compactEdgeLabel('HTTP · TCP/80; HTTPS · TCP/443; SSH · TCP/22')).toBe(
      'HTTP · TCP/80, HTTPS · TCP/443 +1',
    );
  });
});

describe('formatRuleServices', () => {
  it('formats backend servicePorts for tables', () => {
    expect(formatRuleServices({
      services: ['HTTPS'],
      servicePorts: [{ name: 'HTTPS', protocol: 'TCP', ports: '443' }],
    })).toBe('HTTPS · TCP/443');
  });
});

describe('flowPillLabel', () => {
  it('formats protocol and ports', () => {
    expect(flowPillLabel({ protocol: 'TCP', ports: '443', raw: '' })).toBe('TCP 443');
  });

  it('formats policy, rule, and service', () => {
    expect(flowPillLabel({
      protocol: 'TCP',
      ports: '80',
      raw: 'Fleet-Management | allow-users-to-web-http | HTTP · TCP/80',
      policy: 'Fleet-Management',
      rule: 'allow-users-to-web-http',
      service: 'HTTP',
    })).toBe('Fleet-Management | allow-users-to-web-http | HTTP · TCP/80');
  });

  it('parses legacy rule: service strings', () => {
    expect(flowPillLabel({
      protocol: 'OTHER',
      ports: 'allow-users-to-web-http: HTTP',
      raw: 'allow-users-to-web-http: HTTP',
    })).toBe('allow-users-to-web-http | HTTP');
  });
});

describe('collapseEdgesByPair', () => {
  it('merges multiple services between the same endpoints into one edge', () => {
    const collapsed = collapseEdgesByPair([
      { src: 'web', dst: 'db', conn: 'Fleet | allow-http | HTTP' },
      { src: 'web', dst: 'db', conn: 'Fleet | allow-https | HTTPS' },
      { src: 'web', dst: 'api', conn: 'Fleet | allow-ssh | SSH' },
    ]);
    expect(collapsed).toHaveLength(2);
    const webDb = collapsed.find((e) => e.src === 'web' && e.dst === 'db');
    expect(webDb?.conn).toContain('HTTP');
    expect(webDb?.conn).toContain('HTTPS');
    expect(collapsed.find((e) => e.dst === 'api')?.conn).toContain('SSH');
  });

  it('round-trips combined connections through parseConnDetail', () => {
    const collapsed = collapseEdgesByPair([
      { src: 'a', dst: 'b', conn: 'TCP dst-ports: 80' },
      { src: 'a', dst: 'b', conn: 'TCP dst-ports: 443' },
    ]);
    const flows = parseConnDetail(collapsed[0].conn);
    expect(flows.map((f) => f.ports).sort()).toEqual(['443', '80']);
  });
});

describe('prepareGraphEdges', () => {
  it('enriches then expands', () => {
    const edges = prepareGraphEdges(
      [{ src: 'web', dst: 'db', conn: 'All Connections' }],
      [{
        action: 'ALLOW',
        sources: ['web'],
        destinations: ['db'],
        services: ['HTTP', 'HTTPS'],
      }],
    );
    expect(edges.length).toBeGreaterThanOrEqual(2);
  });
});
