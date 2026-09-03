// @vitest-environment node
import { describe, expect, it } from 'vitest';
import { assignControlPoints, controlPointFromOffset, quadPoint } from './edgeRouting';

describe('assignControlPoints', () => {
  it('puts bidirectional edges on opposite sides of the same pair', () => {
    const points = assignControlPoints([
      { id: 'ab', sourceId: 'a', targetId: 'b', sx: 0, sy: 0, tx: 100, ty: 0 },
      { id: 'ba', sourceId: 'b', targetId: 'a', sx: 100, sy: 0, tx: 0, ty: 0 },
    ]);
    const ab = points.get('ab');
    const ba = points.get('ba');
    expect(ab).toBeDefined();
    expect(ba).toBeDefined();
    expect(ab!.y).toBeCloseTo(-ba!.y, 5);
    expect(Math.abs(ab!.y - ba!.y)).toBeGreaterThan(20);
  });

  it('bows crossing chords away from the graph center', () => {
    const points = assignControlPoints([
      { id: 'ac', sourceId: 'a', targetId: 'c', sx: 0, sy: 0, tx: 100, ty: 100 },
      { id: 'bd', sourceId: 'b', targetId: 'd', sx: 100, sy: 0, tx: 0, ty: 100 },
    ]);
    const ac = points.get('ac');
    const bd = points.get('bd');
    expect(ac).toBeDefined();
    expect(bd).toBeDefined();
    const midAc = { x: 50, y: 50 };
    const midBd = { x: 50, y: 50 };
    const distAc = Math.hypot(ac!.x - midAc.x, ac!.y - midAc.y);
    const distBd = Math.hypot(bd!.x - midBd.x, bd!.y - midBd.y);
    expect(distAc).toBeGreaterThan(10);
    expect(distBd).toBeGreaterThan(10);
    expect(Math.hypot(ac!.x - bd!.x, ac!.y - bd!.y)).toBeGreaterThan(20);
  });
});

describe('controlPointFromOffset', () => {
  it('offsets the midpoint along the perpendicular', () => {
    const p = controlPointFromOffset(0, 0, 10, 0, 4);
    expect(p.x).toBeCloseTo(5);
    expect(p.y).toBeCloseTo(4);
  });
});

describe('quadPoint', () => {
  it('starts and ends at the terminals', () => {
    expect(quadPoint(0, 0, 5, 10, 10, 0, 0)).toEqual({ x: 0, y: 0 });
    expect(quadPoint(0, 0, 5, 10, 10, 0, 1)).toEqual({ x: 10, y: 0 });
  });
});
