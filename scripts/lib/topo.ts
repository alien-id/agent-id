// Kahn's algorithm. Deps outside the graph (e.g. external npm packages) are
// silently ignored so callers can pass raw `package.json` dependency lists.
export function topoSort(graph: Map<string, string[]>): string[] {
  const nodes = Array.from(graph.keys());
  const nodeSet = new Set(nodes);

  const inDegree = new Map<string, number>(nodes.map((n) => [n, 0]));
  const dependents = new Map<string, string[]>(nodes.map((n) => [n, []]));

  for (const [node, deps] of graph) {
    for (const dep of deps) {
      if (!nodeSet.has(dep)) continue;
      inDegree.set(node, (inDegree.get(node) ?? 0) + 1);
      const list = dependents.get(dep);
      if (list) list.push(node);
    }
  }

  const queue = nodes.filter((n) => inDegree.get(n) === 0);
  const result: string[] = [];

  while (queue.length > 0) {
    const node = queue.shift();
    if (node === undefined) break;
    result.push(node);
    for (const dependent of dependents.get(node) ?? []) {
      const next = (inDegree.get(dependent) ?? 0) - 1;
      inDegree.set(dependent, next);
      if (next === 0) queue.push(dependent);
    }
  }

  if (result.length !== nodes.length) {
    const stuck = nodes.filter((n) => !result.includes(n));
    throw new Error(
      `Topological cycle detected involving: ${stuck.join(', ')}`,
    );
  }

  return result;
}
