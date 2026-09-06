import {
  DefaultConnectorTerminal,
  EdgeTerminalType,
  GraphElement,
  Layer,
  WithSelectionProps,
  isEdge,
  observer,
  useHover,
} from '@patternfly/react-topology';
import { compactEdgeLabel, edgeServiceLabel } from './parseConn';
import { quadPoint } from './edgeRouting';
import type { ConnectivityEdge } from './types';

type SeparatedEdgeProps = {
  element: GraphElement;
} & WithSelectionProps;

function curvePath(
  sx: number,
  sy: number,
  cx: number,
  cy: number,
  tx: number,
  ty: number,
): string {
  return `M ${sx} ${sy} Q ${cx} ${cy} ${tx} ${ty}`;
}

function labelPoint(
  sx: number,
  sy: number,
  tx: number,
  ty: number,
  bend?: { x: number; y: number },
) {
  if (bend) {
    const mid = quadPoint(sx, sy, bend.x, bend.y, tx, ty, 0.5);
    const cx = (sx + tx) / 2;
    const cy = (sy + ty) / 2;
    const dx = mid.x - cx;
    const dy = mid.y - cy;
    const len = Math.hypot(dx, dy);
    if (len < 1) {
      return { x: mid.x, y: mid.y - 10 };
    }
    const extra = 12;
    return { x: mid.x + (dx / len) * extra, y: mid.y + (dy / len) * extra };
  }
  return { x: (sx + tx) / 2, y: (sy + ty) / 2 - 10 };
}

export const SeparatedEdge = observer(function SeparatedEdge({
  element,
  selected,
  onSelect,
}: SeparatedEdgeProps) {
  const [hover, hoverRef] = useHover<SVGGElement>();
  if (!isEdge(element)) {
    return null;
  }

  const start = element.getStartPoint();
  const end = element.getEndPoint();
  const bend = element.getBendpoints()[0];
  const path = bend
    ? curvePath(start.x, start.y, bend.x, bend.y, end.x, end.y)
    : `M ${start.x} ${start.y} L ${end.x} ${end.y}`;
  const data = element.getData() as { edge?: ConnectivityEdge } | undefined;
  const fullLabel = edgeServiceLabel(data?.edge?.conn);
  const label = compactEdgeLabel(data?.edge?.conn);
  const textAt = labelPoint(start.x, start.y, end.x, end.y, bend);

  const className = [
    'pf-topology__edge',
    hover ? 'pf-m-hover' : '',
    selected ? 'pf-m-selected' : '',
  ]
    .filter(Boolean)
    .join(' ');

  return (
    <Layer id={hover || selected ? 'top' : undefined}>
      <g ref={hoverRef} className={className} data-test-id="edge-handler" onClick={onSelect}>
        {fullLabel ? <title>{fullLabel}</title> : null}
        <path className="pf-topology__edge__background" d={path} />
        <path className="pf-topology__edge__link" d={path} />
        {label ? (
          <text
            className="pb-topology__edge-label"
            x={textAt.x}
            y={textAt.y}
            textAnchor="middle"
            dominantBaseline="middle"
          >
            {label}
          </text>
        ) : null}
        <DefaultConnectorTerminal
          edge={element}
          isTarget
          terminalType={EdgeTerminalType.directional}
          highlight={hover || !!selected}
        />
      </g>
    </Layer>
  );
});
