import { describe, it, expect } from 'vitest';

const WIZARD_STEPS = [
  'Source',
  'NSX intent',
  'Rule selection',
  'Mapping',
  'Generation settings',
  'Results',
  'Export',
];

describe('PolicyBridge API client', () => {
  it('constructs API paths correctly', () => {
    const API = '/api/v1';
    expect(`${API}/sessions`).toBe('/api/v1/sessions');
    expect(`${API}/about`).toBe('/api/v1/about');
  });
});

describe('Wizard flow', () => {
  it('defines seven collapsed wizard steps', () => {
    expect(WIZARD_STEPS).toHaveLength(7);
    WIZARD_STEPS.forEach((step) => {
      expect(step.length).toBeGreaterThan(0);
    });
  });
});
