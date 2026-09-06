import { memo, useEffect, useMemo, useRef } from 'react';
import {
  action,
  ColaLayout,
  ComponentFactory,
  createTopologyControlButtons,
  DagreLayout,
  DefaultGroup,
  DefaultNode,
  GRAPH_LAYOUT_END_EVENT,
  Graph,
  GraphComponent,
  Layout,
  LayoutFactory,
  LEFT_TO_RIGHT,
  ModelKind,
  Point,
  SELECTION_EVENT,
  TopologyControlBar,
  TopologyView,
  Visualization,
  VisualizationProvider,
  VisualizationSurface,
  withPanZoom,
  withSelection,
} from '@patternfly/react-topology';
import { ProjectDiagramIcon, TopologyIcon } from '@patternfly/react-icons';
import {
  buildTopologyModel,
  filterEdges,
  parseEdgeData,
  parseNodeId,
} from './buildModel';
import { collapseEdgesByPair, prepareGraphEdges } from './parseConn';
import { assignControlPoints } from './edgeRouting';
import { SeparatedEdge } from './SeparatedEdge';
import type { TopologyRenderOptions } from './types';

import '@patternfly/react-core/dist/styles/base.css';
import '@patternfly/react-topology/src/css/topology-components.css';
import '@patternfly/react-topology/src/css/topology-view.css';
import '@patternfly/react-topology/src/css/topology-controlbar.css';
import './topology.css';

const GRAPH_HEIGHT = 480;

type GraphLayoutMode = 'Cola' | 'Dagre';

const layoutFactory: LayoutFactory = (type: string, graph: Graph): Layout | undefined => {
  switch (type) {
    case 'Cola':
      return new ColaLayout(graph, {
        layoutOnDrag: false,
        nodeDistance: 180,
        linkDistance: 160,
        groupDistance: 100,
      });
    case 'Dagre':
    default:
      return new DagreLayout(graph, {
        layoutOnDrag: false,
        rankdir: LEFT_TO_RIGHT,
        nodesep: 110,
        ranksep: 180,
        edgesep: 50,
        marginx: 48,
        marginy: 48,
      });
  }
};

const componentFactory: ComponentFactory = (kind, type) => {
  if (type === 'group') {
    return DefaultGroup;
  }
  switch (kind) {
    case ModelKind.graph:
      return withPanZoom()(GraphComponent);
    case ModelKind.node:
      return withSelection()(DefaultNode);
    case ModelKind.edge:
      return withSelection()(SeparatedEdge);
    default:
      return undefined;
  }
};

function fitGraph(controller: Visualization) {
  const graph = controller.getGraph();
  graph.fit(48);
}

function separateGraphEdges(graph: Graph) {
  const edges = graph.getEdges();
  for (const edge of edges) {
    edge.setBendpoints([]);
  }
  const routed = edges.map((edge) => {
    const start = edge.getStartPoint();
    const end = edge.getEndPoint();
    return {
      id: edge.getId(),
      sourceId: edge.getSource().getId(),
      targetId: edge.getTarget().getId(),
      sx: start.x,
      sy: start.y,
      tx: end.x,
      ty: end.y,
    };
  });
  const points = assignControlPoints(routed);
  for (const edge of edges) {
    const point = points.get(edge.getId());
    if (point) {
      edge.setBendpoints([new Point(point.x, point.y)]);
    }
  }
}

function scheduleFit(controller: Visualization) {
  requestAnimationFrame(() => {
    fitGraph(controller);
    requestAnimationFrame(() => fitGraph(controller));
  });
  window.setTimeout(() => fitGraph(controller), 120);
}

type Props = TopologyRenderOptions;

export const ConnectivityGraph = memo(function ConnectivityGraph({
  edges,
  dfwRules,
  filter,
  focusNode,
  selectedEdge,
  onNodeClick,
  onEdgeClick,
  onBackgroundClick,
  onSummary,
}: Props) {
  const hostRef = useRef<HTMLDivElement>(null);
  const layoutModeRef = useRef<GraphLayoutMode>('Cola');
  const callbacksRef = useRef({ onNodeClick, onEdgeClick, onBackgroundClick, onSummary });
  callbacksRef.current = { onNodeClick, onEdgeClick, onBackgroundClick, onSummary };

  const graphEdges = useMemo(() => prepareGraphEdges(edges, dfwRules), [edges, dfwRules]);
  const filtered = useMemo(
    () => collapseEdgesByPair(filterEdges(graphEdges, filter)),
    [graphEdges, filter],
  );

  const model = useMemo(() => {
    const built = buildTopologyModel(filtered, focusNode, selectedEdge);
    if (built.graph) {
      built.graph.layout = layoutModeRef.current;
    }
    return built;
  }, [filtered, focusNode, selectedEdge]);

  const controller = useMemo(() => {
    const viz = new Visualization();
    viz.registerLayoutFactory(layoutFactory);
    viz.registerComponentFactory(componentFactory);
    return viz;
  }, []);

  useEffect(() => {
    callbacksRef.current.onSummary?.({
      edgeCount: filtered.length,
      nodeCount: model.nodes?.length || 0,
    });
  }, [filtered.length, model.nodes?.length]);

  useEffect(() => {
    const onSelect = (ids: string[]) => {
      const cb = callbacksRef.current;
      if (!ids?.length) {
        cb.onBackgroundClick?.();
        return;
      }
      const id = ids[0];
      const nodeName = parseNodeId(id);
      if (nodeName) {
        cb.onNodeClick?.(nodeName);
        return;
      }
      const edge = parseEdgeData(id, controller.toModel());
      if (edge) {
        cb.onEdgeClick?.(edge);
      }
    };

    const onLayoutEnd = () => {
      separateGraphEdges(controller.getGraph());
      scheduleFit(controller);
    };

    controller.addEventListener(SELECTION_EVENT, onSelect);
    controller.addEventListener(GRAPH_LAYOUT_END_EVENT, onLayoutEnd);
    return () => {
      controller.removeEventListener(SELECTION_EVENT, onSelect);
      controller.removeEventListener(GRAPH_LAYOUT_END_EVENT, onLayoutEnd);
    };
  }, [controller]);

  useEffect(() => {
    controller.fromModel(model, true);
    const graph = controller.getGraph();
    graph.setLayout(layoutModeRef.current);
    graph.layout();
    separateGraphEdges(graph);
    scheduleFit(controller);
  }, [controller, model]);

  useEffect(() => {
    const host = hostRef.current;
    if (!host || typeof ResizeObserver === 'undefined') return;
    const observer = new ResizeObserver(() => scheduleFit(controller));
    observer.observe(host);
    return () => observer.disconnect();
  }, [controller]);

  const controlButtons = useMemo(
    () =>
      createTopologyControlButtons({
        zoomInCallback: action(() => controller.getGraph().scaleBy(4 / 3)),
        zoomOutCallback: action(() => controller.getGraph().scaleBy(3 / 4)),
        fitToScreenCallback: action(() => fitGraph(controller)),
        resetViewCallback: action(() => {
          controller.getGraph().reset();
          controller.getGraph().layout();
        }),
        legend: false,
        customButtons: [
          {
            id: 'layout-cola',
            icon: <TopologyIcon />,
            tooltip: 'Cola force layout',
            ariaLabel: 'Cola force layout',
            callback: action(() => {
              layoutModeRef.current = 'Cola';
              const graph = controller.getGraph();
              graph.setLayout('Cola');
              graph.layout();
            }),
          },
          {
            id: 'layout-dagre',
            icon: <ProjectDiagramIcon />,
            tooltip: 'Dagre layout (left-to-right)',
            ariaLabel: 'Dagre layout',
            callback: action(() => {
              layoutModeRef.current = 'Dagre';
              const graph = controller.getGraph();
              graph.setLayout('Dagre');
              graph.layout();
            }),
          },
        ],
      } as unknown as Parameters<typeof createTopologyControlButtons>[0]),
    [controller],
  );

  if (!filtered.length) {
    return (
      <div className="pf-topology pf-topology--empty">
        <div className="pf-empty">
          <div className="pf-empty__title">No connections</div>
          <p>Run analysis or adjust the filter.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="pf-topology pf-topology--react" ref={hostRef}>
      <TopologyView
        className="pb-topology-view"
        controlBar={<TopologyControlBar controlButtons={controlButtons} />}
        style={{ height: GRAPH_HEIGHT }}
      >
        <VisualizationProvider controller={controller}>
          <VisualizationSurface />
        </VisualizationProvider>
      </TopologyView>
      <p className="pf-topology__hint">
        {focusNode ? (
          <>
            Focused on <strong>{focusNode}</strong>. Click the background or press Esc to reset.
          </>
        ) : (
          'Click an endpoint to focus traffic. Connection labels show service and protocol/port. Click a connection for the full list. Cola layout is used by default; use the control bar to switch to Dagre, zoom, or fit.'
        )}
      </p>
    </div>
  );
});
