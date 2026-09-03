import type { ReactNode } from 'react';
import {
  Content,
  Drawer,
  DrawerActions,
  DrawerCloseButton,
  DrawerContent,
  DrawerContentBody,
  DrawerHead,
  DrawerPanelContent,
  Label,
  List,
  ListItem,
  Stack,
  StackItem,
  Title,
} from '@patternfly/react-core';
import { aggregateEndpointFlows, flowServiceLabel, parseConnDetail } from '@/topology/parseConn';
import type { ConnectivityEdge } from '@/topology/types';

export interface EndpointDrawerState {
  type: 'endpoint';
  endpoint: string;
  ingress: ReturnType<typeof aggregateEndpointFlows>['ingress'];
  egress: ReturnType<typeof aggregateEndpointFlows>['egress'];
}

export interface ConnectionDrawerState {
  type: 'connection';
  source: string;
  destination: string;
  conn?: string;
  flows: ReturnType<typeof parseConnDetail>;
}

export type DrawerState = EndpointDrawerState | ConnectionDrawerState | null;

function flowLabel(flow: Parameters<typeof flowServiceLabel>[0]) {
  return flowServiceLabel(flow);
}

function FlowSection({
  title,
  items,
}: {
  title: string;
  items: EndpointDrawerState['ingress'];
}) {
  if (!items?.length) {
    return (
      <StackItem>
        <Title headingLevel="h4" size="md">
          {title}
        </Title>
        <Content component="p" style={{ color: 'var(--pf-t--global--text--color--subtle)' }}>
          None
        </Content>
      </StackItem>
    );
  }

  const groups = new Map<string, ReturnType<typeof parseConnDetail>>();
  for (const item of items) {
    const flows = item.flows?.length ? item.flows : [{ protocol: 'ALL', ports: 'all', raw: 'all' }];
    const existing = groups.get(item.peer) || [];
    for (const flow of flows) {
      const key = `${flow.protocol}\0${flow.ports}`;
      if (!existing.some((f) => `${f.protocol}\0${f.ports}` === key)) {
        existing.push(flow);
      }
    }
    groups.set(item.peer, existing);
  }

  return (
    <StackItem>
      <Title headingLevel="h4" size="md">
        {title}
      </Title>
      <List isPlain>
        {Array.from(groups.entries()).map(([peer, flows]) => (
          <ListItem key={peer}>
            <strong>{peer}</strong>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 4 }}>
              {flows.map((flow) => (
                <Label key={`${peer}-${flow.protocol}-${flow.ports}`} color="blue">
                  {flowLabel(flow)}
                </Label>
              ))}
            </div>
          </ListItem>
        ))}
      </List>
    </StackItem>
  );
}

function DrawerPanel({ drawer, onClose }: { drawer: DrawerState; onClose: () => void }) {
  if (!drawer) return null;

  return (
    <>
      <DrawerHead>
        <span />
        <DrawerActions>
          <DrawerCloseButton onClick={onClose} />
        </DrawerActions>
      </DrawerHead>
      <DrawerContentBody className="pb-flow-drawer__body">
        {drawer.type === 'endpoint' && (
          <Stack hasGutter>
            <StackItem>
              <Title headingLevel="h3" size="lg">
                {drawer.endpoint}
              </Title>
              <Content component="p" style={{ fontSize: '0.85rem' }}>
                {drawer.ingress.length} ingress · {drawer.egress.length} egress flow(s)
              </Content>
            </StackItem>
            <FlowSection title="Ingress (allowed from)" items={drawer.ingress} />
            <FlowSection title="Egress (allowed to)" items={drawer.egress} />
          </Stack>
        )}
        {drawer.type === 'connection' && (
          <Stack hasGutter>
            <StackItem>
              <Title headingLevel="h3" size="lg">
                Connection
              </Title>
              <Content component="p">
                <strong>Source:</strong> {drawer.source}
              </Content>
              <Content component="p">
                <strong>Destination:</strong> {drawer.destination}
              </Content>
            </StackItem>
            <StackItem>
              <Title headingLevel="h4" size="md">
                Allowed traffic
              </Title>
              <List isPlain>
                {drawer.flows.length ? (
                  drawer.flows.map((flow) => (
                    <ListItem key={`${flow.protocol}-${flow.ports}-${flow.raw}`}>
                      <Label color="blue">{flowLabel(flow)}</Label>
                    </ListItem>
                  ))
                ) : (
                  <ListItem>All connections</ListItem>
                )}
              </List>
            </StackItem>
          </Stack>
        )}
      </DrawerContentBody>
    </>
  );
}

interface FlowDrawerProps {
  drawer: DrawerState;
  onClose: () => void;
  children: ReactNode;
}

export function FlowDrawer({ drawer, onClose, children }: FlowDrawerProps) {
  const isExpanded = !!drawer;

  const panelContent = isExpanded ? (
    <DrawerPanelContent isResizable defaultSize="400px" minSize="280px" maxSize="560px">
      <DrawerPanel drawer={drawer} onClose={onClose} />
    </DrawerPanelContent>
  ) : undefined;

  return (
    <div className="pb-flow-drawer">
      <Drawer isExpanded={isExpanded} isInline position="end">
        <DrawerContent panelContent={panelContent}>
          <DrawerContentBody className="pb-flow-drawer__main">{children}</DrawerContentBody>
        </DrawerContent>
      </Drawer>
    </div>
  );
}

export function useDrawerFromEdge(
  edges: ConnectivityEdge[],
  dfwRules: Parameters<typeof aggregateEndpointFlows>[2],
) {
  return {
    openEndpoint: (node: string): EndpointDrawerState => {
      const { ingress, egress } = aggregateEndpointFlows(edges, node, dfwRules);
      return { type: 'endpoint', endpoint: node, ingress, egress };
    },
    openConnection: (edge: ConnectivityEdge): ConnectionDrawerState => ({
      type: 'connection',
      source: edge.src,
      destination: edge.dst,
      conn: edge.conn,
      flows: parseConnDetail(edge.conn || ''),
    }),
  };
}
