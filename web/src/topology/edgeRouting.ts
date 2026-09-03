export interface RoutedEdge {
  id: string;
  sourceId: string;
  targetId: string;
  sx: number;
  sy: number;
  tx: number;
  ty: number;
}

export interface ControlPoint {
  x: number;
  y: number;
}

const BASE_OFFSET = 36;
const FAN_STEP = 18;

function hypot(dx: number, dy: number): number {
  return Math.sqrt(dx * dx + dy * dy) || 1;
}

function pairKey(a: string, b: string): string {
  return a < b ? `${a}::${b}` : `${b}::${a}`;
}

function unitPerp(sx: number, sy: number, tx: number, ty: number): { nx: number; ny: number; len: number } {
  const dx = tx - sx;
  const dy = ty - sy;
  const len = hypot(dx, dy);
  return { nx: -dy / len, ny: dx / len, len };
}

function outwardSign(
  sx: number,
  sy: number,
  tx: number,
  ty: number,
  cx: number,
  cy: number,
): number {
  const { nx, ny } = unitPerp(sx, sy, tx, ty);
  const mx = (sx + tx) / 2;
  const my = (sy + ty) / 2;
  return nx * (mx - cx) + ny * (my - cy) >= 0 ? 1 : -1;
}

export function controlPointFromOffset(
  sx: number,
  sy: number,
  tx: number,
  ty: number,
  offset: number,
): ControlPoint {
  const { nx, ny } = unitPerp(sx, sy, tx, ty);
  return {
    x: (sx + tx) / 2 + nx * offset,
    y: (sy + ty) / 2 + ny * offset,
  };
}

export function quadPoint(
  sx: number,
  sy: number,
  cx: number,
  cy: number,
  tx: number,
  ty: number,
  t: number,
): ControlPoint {
  const u = 1 - t;
  return {
    x: u * u * sx + 2 * u * t * cx + t * t * tx,
    y: u * u * sy + 2 * u * t * cy + t * t * ty,
  };
}

function clampOffset(offset: number, len: number): number {
  const max = Math.min(56, Math.max(16, len * 0.3));
  if (offset > max) return max;
  if (offset < -max) return -max;
  return offset;
}

/**
 * Assign a unique bowed control point to each directed edge so paths do not
 * share the same line. Bidirectional pairs curve to opposite sides; remaining
 * edges bow away from the graph center and fan around shared endpoints.
 */
export function assignControlPoints(edges: RoutedEdge[]): Map<string, ControlPoint> {
  const result = new Map<string, ControlPoint>();
  if (!edges.length) return result;

  const nodePos = new Map<string, { x: number; y: number; n: number }>();
  const addNode = (id: string, x: number, y: number) => {
    const existing = nodePos.get(id);
    if (existing) {
      existing.x += x;
      existing.y += y;
      existing.n += 1;
      return;
    }
    nodePos.set(id, { x, y, n: 1 });
  };
  for (const e of edges) {
    addNode(e.sourceId, e.sx, e.sy);
    addNode(e.targetId, e.tx, e.ty);
  }

  let cx = 0;
  let cy = 0;
  for (const p of nodePos.values()) {
    cx += p.x / p.n;
    cy += p.y / p.n;
  }
  cx /= nodePos.size;
  cy /= nodePos.size;

  const points = new Map<string, ControlPoint>();
  const byPair = new Map<string, RoutedEdge[]>();
  for (const e of edges) {
    const key = pairKey(e.sourceId, e.targetId);
    const group = byPair.get(key);
    if (group) group.push(e);
    else byPair.set(key, [e]);
  }

  const offsetOf = new Map<string, number>();

  for (const group of byPair.values()) {
    const sorted = [...group].sort((a, b) =>
      `${a.sourceId}:${a.targetId}`.localeCompare(`${b.sourceId}:${b.targetId}`),
    );
    const sample = sorted[0];
    const { len } = unitPerp(sample.sx, sample.sy, sample.tx, sample.ty);
    if (sorted.length === 2) {
      const mag = clampOffset(BASE_OFFSET, len);
      offsetOf.set(sorted[0].id, mag);
      offsetOf.set(sorted[1].id, -mag);
      points.set(sorted[0].id, controlPointFromOffset(sample.sx, sample.sy, sample.tx, sample.ty, mag));
      points.set(sorted[1].id, controlPointFromOffset(sample.sx, sample.sy, sample.tx, sample.ty, -mag));
      continue;
    }
    sorted.forEach((e, i) => {
      const mx = (e.sx + e.tx) / 2;
      const my = (e.sy + e.ty) / 2;
      const nearCenter = Math.max(0, 80 - hypot(mx - cx, my - cy));
      const mag = clampOffset(BASE_OFFSET + nearCenter * 0.35 + i * 4, len);
      offsetOf.set(e.id, outwardSign(e.sx, e.sy, e.tx, e.ty, cx, cy) * mag);
    });
  }

  const byNode = new Map<string, { edge: RoutedEdge; angle: number }[]>();
  const addIncident = (nodeId: string, edge: RoutedEdge, ox: number, oy: number, x: number, y: number) => {
    const list = byNode.get(nodeId) || [];
    list.push({ edge, angle: Math.atan2(oy - y, ox - x) });
    byNode.set(nodeId, list);
  };
  for (const e of edges) {
    addIncident(e.sourceId, e, e.tx, e.ty, e.sx, e.sy);
    addIncident(e.targetId, e, e.sx, e.sy, e.tx, e.ty);
  }

  for (const list of byNode.values()) {
    if (list.length < 3) continue;
    const unique = new Map<string, { edge: RoutedEdge; angle: number }>();
    for (const item of list) unique.set(item.edge.id, item);
    const ranked = [...unique.values()].sort((a, b) => a.angle - b.angle);
    ranked.forEach((item, i) => {
      if (points.has(item.edge.id)) return;
      const fan = (i - (ranked.length - 1) / 2) * FAN_STEP;
      offsetOf.set(item.edge.id, (offsetOf.get(item.edge.id) || 0) + fan);
    });
  }

  for (const e of edges) {
    if (points.has(e.id)) continue;
    const { len } = unitPerp(e.sx, e.sy, e.tx, e.ty);
    const offset = clampOffset(offsetOf.get(e.id) || BASE_OFFSET, len);
    points.set(e.id, controlPointFromOffset(e.sx, e.sy, e.tx, e.ty, offset));
  }
  return points;
}
