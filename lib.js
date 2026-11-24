// CyberGraph pure helpers — no DOM, no Relate import, so node --test can cover them.
// The browser app (app.js) imports these too.

export const NODE_COUNTS = { nodes: 34, relationships: 39 };

// Escape a value for safe embedding in a Cypher single-quoted string literal.
export function escapeCypherString(value) {
  return String(value).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
}

// Split a multi-statement Cypher script into individual statements.
// Strips //-comments and blank lines; keeps quoted strings intact.
export function splitCypherScript(script) {
  const statements = [];
  let current = '';
  let inString = false;
  for (let i = 0; i < script.length; i++) {
    const ch = script[i];
    if (ch === "'" && script[i - 1] !== '\\') inString = !inString;
    if (!inString && ch === '/' && script[i + 1] === '/') {
      while (i < script.length && script[i] !== '\n') i++;
      continue;
    }
    if (!inString && ch === ';') {
      const stmt = current.trim();
      if (stmt) statements.push(stmt);
      current = '';
      continue;
    }
    current += ch;
  }
  const tail = current.trim();
  if (tail) statements.push(tail);
  return statements;
}

// Parse one Relate wire envelope (JSON string from RelateDb.execute).
// Returns { ok, columns, rows, stats, error } — never throws.
export function parseEnvelope(wireJson) {
  try {
    const env = JSON.parse(wireJson);
    return {
      ok: !env.error,
      columns: Array.isArray(env.columns) ? env.columns : [],
      rows: Array.isArray(env.rows) ? env.rows : [],
      stats: env.stats || {},
      error: env.error || null,
    };
  } catch (e) {
    return { ok: false, columns: [], rows: [], stats: {}, error: 'Bad envelope JSON: ' + e.message };
  }
}

// A Relate node value looks like { kind: 'node', labels: [...], properties: {...} }.
export function isNodeValue(v) {
  return v && typeof v === 'object' && v.kind === 'node' && v.properties && typeof v.properties === 'object';
}

export function isRelValue(v) {
  return v && typeof v === 'object' && v.kind === 'relationship' && typeof v.type === 'string';
}

// Pull { nodes, edges } out of rows returned by `MATCH (n) RETURN n` /
// `MATCH (a)-[r]->(b) RETURN a, r, b`. Nodes are keyed by elementId (or id).
// Two wire shapes exist: the Node native binding returns elementId /
// startElementId / endElementId, while the WASM build returns numeric
// `id` plus `start_node` / `end_node`. Both are handled; keys are prefixed
// ('n:' / 'r:') so node and relationship ids can never collide.
export function extractGraph(rows) {
  const nodes = new Map();
  const edges = [];
  const seenEdge = new Set();
  const nodeKey = (v) => (v.elementId ? String(v.elementId) : 'n:' + String(v.id));
  const addNode = (v) => {
    const key = nodeKey(v);
    if (!nodes.has(key)) {
      nodes.set(key, {
        key,
        id: v.properties.id || key,
        labels: v.labels || [],
        properties: v.properties,
      });
    }
  };
  const addRel = (v) => {
    const key = v.elementId ? String(v.elementId) : 'r:' + String(v.id);
    if (seenEdge.has(key)) return;
    seenEdge.add(key);
    const from = v.startElementId ? String(v.startElementId)
      : (v.start_node !== undefined ? 'n:' + String(v.start_node) : String(v.startId));
    const to = v.endElementId ? String(v.endElementId)
      : (v.end_node !== undefined ? 'n:' + String(v.end_node) : String(v.endId));
    edges.push({ key, type: v.type, from, to, properties: v.properties || {} });
  };
  for (const row of rows) {
    for (const value of Object.values(row)) {
      if (isNodeValue(value)) addNode(value);
      else if (isRelValue(value)) addRel(value);
      else if (Array.isArray(value)) {
        // A path value: alternating node / relationship values.
        for (const item of value) {
          if (isNodeValue(item)) addNode(item);
          else if (isRelValue(item)) addRel(item);
        }
      }
    }
  }
  return { nodes: [...nodes.values()], edges };
}

// Neighbours of one node id, from an edge list (undirected for display).
export function neighboursOf(nodeId, nodes, edges) {
  const byKey = new Map(nodes.map((n) => [n.key, n]));
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const self = byId.get(nodeId);
  if (!self) return [];
  const out = [];
  for (const e of edges) {
    let other = null;
    let rel = e.type;
    if (e.from === self.key) { other = byKey.get(e.to); }
    else if (e.to === self.key) { other = byKey.get(e.from); rel = e.type + ' (incoming)'; }
    if (other) out.push({ node: other, relationship: rel });
  }
  return out;
}
