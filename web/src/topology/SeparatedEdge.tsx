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
        <path className="pf-topology__edge__background" d={path} />
        <path className="pf-topology__edge__link" d={path} />
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
