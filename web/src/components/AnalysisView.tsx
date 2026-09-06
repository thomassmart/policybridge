import { useMemo, useState } from 'react';
import {
  FormGroup,
  Tab,
  Tabs,
  TabTitleText,
  Title,
} from '@patternfly/react-core';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { ConnectivityGraph } from '@/topology/ConnectivityGraph';
import type { AnalysisResult, DFWRuleRow } from '@/api/types';
import {
  FlowDrawer,
  useDrawerFromEdge,
  type DrawerState,
} from './FlowDrawer';
import { AnalysisFilterInput } from './AnalysisFilterInput';
import { DismissibleAlert } from './DismissibleAlert';
import { preserveScrollPosition } from '@/utils/preserveScroll';
import { buildAnalysisFilterSuggestions } from '@/utils/analysisFilterSuggestions';
import { filterRulesByText } from '@/utils/filterRulesByText';
import { parseConnectivity } from '@/utils/parseConnectivity';
import { formatRuleServices } from '@/topology/parseConn';

const DFW_CATEGORIES = ['Ethernet', 'Emergency', 'Infrastructure', 'Environment', 'Application'] as const;

function normalizeCategory(category: string) {
  return String(category || '').trim().toLowerCase();
}

function filterRulesByCategory(rules: DFWRuleRow[], category: string) {
  const want = normalizeCategory(category);
  return rules.filter((r) => normalizeCategory(r.category || '') === want);
}

function countByCategory(rules: DFWRuleRow[]) {
  const counts = Object.fromEntries(DFW_CATEGORIES.map((c) => [c, 0]));
  rules.forEach((r) => {
    const cat = DFW_CATEGORIES.find((c) => normalizeCategory(c) === normalizeCategory(r.category || ''));
    if (cat) counts[cat]++;
  });
  return counts;
}

interface AnalysisViewProps {
  analysis: AnalysisResult;
}

export function AnalysisView({ analysis }: AnalysisViewProps) {
  const [filter, setFilter] = useState('');
  const [dfwCategory, setDfwCategory] = useState<string>('Application');
  const [tab, setTab] = useState<'map' | 'dfw-rules' | 'lint'>('map');
  const [focusNode, setFocusNode] = useState<string | null>(null);
  const [drawer, setDrawer] = useState<DrawerState>(null);

  const dfwRules = analysis.dfwRules || [];
  const categoryRules = useMemo(
    () => filterRulesByCategory(dfwRules, dfwCategory),
    [dfwRules, dfwCategory],
  );
  const filteredRules = useMemo(
    () => filterRulesByText(categoryRules, filter),
    [categoryRules, filter],
  );
  const allEdges = useMemo(() => parseConnectivity(analysis), [analysis]);
  const drawerHelpers = useDrawerFromEdge(allEdges, categoryRules);
  const counts = useMemo(() => countByCategory(dfwRules), [dfwRules]);
  const filterSuggestions = useMemo(
    () => buildAnalysisFilterSuggestions(categoryRules, allEdges),
    [categoryRules, allEdges],
  );

  const lint = analysis.lint;
  const lintCount =
    (lint?.shadowedRules?.length || 0) + (lint?.ineffectiveRules?.length || 0);

  return (
    <>
      {analysis.insights?.warnings?.length ? (
        <DismissibleAlert variant="warning" title="Connectivity analysis note" isInline>
          <ul style={{ margin: '8px 0 0 1.2rem' }}>
            {analysis.insights.warnings.map((w) => (
              <li key={w}>{w}</li>
            ))}
          </ul>
        </DismissibleAlert>
      ) : null}

      <FormGroup label="Filter analysis" fieldId="analysis-filter">
        <AnalysisFilterInput
          value={filter}
          onChange={setFilter}
          suggestions={filterSuggestions}
        />
      </FormGroup>

      <div className="pb-dfw-categories" role="group" aria-label="DFW rule category">
        {DFW_CATEGORIES.map((cat, i) => {
          const active = cat === dfwCategory;
          return (
            <button
              key={cat}
              type="button"
              className={`pb-dfw-category${active ? ' pb-dfw-category--active' : ''}${i === 0 ? ' pb-dfw-category--first' : ''}${i === DFW_CATEGORIES.length - 1 ? ' pb-dfw-category--last' : ''}`}
              onClick={(e) => {
                preserveScrollPosition(() => {
                  setDfwCategory(cat);
                  setFocusNode(null);
                  setDrawer(null);
                }, e.currentTarget);
              }}
              aria-pressed={active}
            >
              {cat} ({counts[cat] || 0})
            </button>
          );
        })}
      </div>

      <Tabs
        activeKey={tab}
        onSelect={(e, k) => preserveScrollPosition(() => setTab(k as typeof tab), e.target)}
        aria-label="Analysis views"
      >
        <Tab eventKey="map" title={<TabTitleText>Connectivity map</TabTitleText>} />
        <Tab
          eventKey="dfw-rules"
          title={<TabTitleText>DFW rules ({categoryRules.length})</TabTitleText>}
        />
        <Tab eventKey="lint" title={<TabTitleText>Lint findings ({lintCount})</TabTitleText>} />
      </Tabs>

      {tab === 'map' && (
        <div style={{ marginTop: 16 }}>
          <p style={{ fontSize: '0.8rem', color: 'var(--pf-t--global--text--color--subtle)' }}>
            Connectivity derived from <strong>{dfwCategory}</strong> DFW rules ({categoryRules.length}
            ). Click an endpoint to focus ingress/egress; click a connection for port and rule details.
          </p>
          {!categoryRules.length ? (
            <DismissibleAlert variant="info" title="No rules in this category" isInline />
          ) : (
            <FlowDrawer drawer={drawer} onClose={() => setDrawer(null)}>
              <ConnectivityGraph
                edges={allEdges}
                dfwRules={categoryRules}
                filter={filter}
                focusNode={focusNode}
                selectedEdge={
                  drawer?.type === 'connection'
                    ? { source: drawer.source, destination: drawer.destination, conn: drawer.conn }
                    : null
                }
                onNodeClick={(node) => {
                  setFocusNode(node);
                  setDrawer(drawerHelpers.openEndpoint(node));
                }}
                onEdgeClick={(edge) => {
                  setDrawer(drawerHelpers.openConnection(edge));
                }}
                onBackgroundClick={() => {
                  setFocusNode(null);
                  setDrawer(null);
                }}
              />
            </FlowDrawer>
          )}
        </div>
      )}

      {tab === 'dfw-rules' && (
        <div style={{ marginTop: 16, overflowX: 'auto' }}>
          {!categoryRules.length ? (
            <DismissibleAlert variant="info" title={`No ${dfwCategory} DFW rules`} isInline />
          ) : !filteredRules.length ? (
            <DismissibleAlert variant="info" title="No rules match the current filter" isInline />
          ) : (
            <Table aria-label="DFW rules" variant="compact">
              <Thead>
                <Tr>
                  <Th>ID</Th>
                  <Th>Name</Th>
                  <Th>Category</Th>
                  <Th>Sources</Th>
                  <Th>Destinations</Th>
                  <Th>Services</Th>
                  <Th>Action</Th>
                </Tr>
              </Thead>
              <Tbody>
                {filteredRules.map((r) => (
                  <Tr key={`${r.id}-${r.name}`}>
                    <Td>{r.id}</Td>
                    <Td>{r.name}</Td>
                    <Td>{r.category}</Td>
                    <Td>{(r.sources || []).join(', ')}</Td>
                    <Td>{(r.destinations || []).join(', ')}</Td>
                    <Td>{formatRuleServices(r)}</Td>
                    <Td>{r.action}</Td>
                  </Tr>
                ))}
              </Tbody>
            </Table>
          )}
        </div>
      )}

      {tab === 'lint' && (
        <div style={{ marginTop: 16 }}>
          {!lint ? (
            <DismissibleAlert variant="info" title="No lint results available" isInline />
          ) : !lint.shadowedRules?.length && !lint.ineffectiveRules?.length ? (
            <p>No redundant DFW rules found.</p>
          ) : (
            <>
              {lint.shadowedRules?.length ? (
                <>
                  <Title headingLevel="h4" size="md">
                    Shadowed rules
                  </Title>
                  <Table aria-label="Shadowed rules" variant="compact">
                    <Thead>
                      <Tr>
                        <Th>Rule ID</Th>
                        <Th>Category</Th>
                        <Th>Direction</Th>
                        <Th>Shadowed by</Th>
                      </Tr>
                    </Thead>
                    <Tbody>
                      {lint.shadowedRules.map((r) => (
                        <Tr key={r.ruleId}>
                          <Td>{r.ruleId}</Td>
                          <Td>{r.category}</Td>
                          <Td>{r.direction}</Td>
                          <Td>{r.shadowingRuleIds}</Td>
                        </Tr>
                      ))}
                    </Tbody>
                  </Table>
                </>
              ) : null}
              {lint.ineffectiveRules?.length ? (
                <>
                  <Title headingLevel="h4" size="md" style={{ marginTop: 16 }}>
                    Ineffective rules
                  </Title>
                  <Table aria-label="Ineffective rules" variant="compact">
                    <Thead>
                      <Tr>
                        <Th>Rule ID</Th>
                        <Th>Description</Th>
                      </Tr>
                    </Thead>
                    <Tbody>
                      {lint.ineffectiveRules.map((r) => (
                        <Tr key={r.ruleId}>
                          <Td>{r.ruleId}</Td>
                          <Td>{r.description}</Td>
                        </Tr>
                      ))}
                    </Tbody>
                  </Table>
                </>
              ) : null}
            </>
          )}
        </div>
      )}

    </>
  );
}
