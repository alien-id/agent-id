import { describe, expect, test } from 'bun:test';
import { topoSort } from '../lib/topo';

describe('topoSort', () => {
  test('returns single node for trivial graph', () => {
    expect(topoSort(new Map([['a', []]]))).toEqual(['a']);
  });

  test('orders a linear chain dependency-first', () => {
    // c depends on b, b depends on a → [a, b, c]
    const graph = new Map([
      ['a', []],
      ['b', ['a']],
      ['c', ['b']],
    ]);
    expect(topoSort(graph)).toEqual(['a', 'b', 'c']);
  });

  test('places isolated nodes in deterministic order', () => {
    const graph = new Map([
      ['a', []],
      ['b', []],
      ['c', []],
    ]);
    // Deterministic by insertion order
    expect(topoSort(graph)).toEqual(['a', 'b', 'c']);
  });

  test('respects diamond dependency ordering', () => {
    // a is leaf; b and c depend on a; d depends on b and c
    const graph = new Map([
      ['a', []],
      ['b', ['a']],
      ['c', ['a']],
      ['d', ['b', 'c']],
    ]);
    const result = topoSort(graph);
    expect(result.indexOf('a')).toBeLessThan(result.indexOf('b'));
    expect(result.indexOf('a')).toBeLessThan(result.indexOf('c'));
    expect(result.indexOf('b')).toBeLessThan(result.indexOf('d'));
    expect(result.indexOf('c')).toBeLessThan(result.indexOf('d'));
    expect(result).toHaveLength(4);
  });

  test('matches the actual SDK graph order', () => {
    // contract, auth-client: no deps
    // bridge: depends on contract
    // react: depends on bridge + contract
    // solana-provider: depends on bridge + contract
    const graph = new Map([
      ['contract', []],
      ['auth-client', []],
      ['bridge', ['contract']],
      ['react', ['bridge', 'contract']],
      ['solana-provider', ['bridge', 'contract']],
    ]);
    const result = topoSort(graph);
    expect(result.indexOf('contract')).toBeLessThan(result.indexOf('bridge'));
    expect(result.indexOf('bridge')).toBeLessThan(result.indexOf('react'));
    expect(result.indexOf('bridge')).toBeLessThan(
      result.indexOf('solana-provider'),
    );
    expect(result.indexOf('contract')).toBeLessThan(result.indexOf('react'));
    expect(result.indexOf('contract')).toBeLessThan(
      result.indexOf('solana-provider'),
    );
    expect(result).toHaveLength(5);
  });

  test('throws on cycle', () => {
    const graph = new Map([
      ['a', ['b']],
      ['b', ['a']],
    ]);
    expect(() => topoSort(graph)).toThrow(/cycle/i);
  });

  test('ignores dependencies on nodes outside the graph', () => {
    // External deps (e.g. emittery, zod) must not block ordering
    const graph = new Map([
      ['a', ['external-lib']],
      ['b', ['a', 'another-external']],
    ]);
    expect(topoSort(graph)).toEqual(['a', 'b']);
  });
});
