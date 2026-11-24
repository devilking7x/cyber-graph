// CyberGraph tests — run with: npm test   (node --test tests/)
// Covers the pure helpers (lib.js) and the real Relate engine (@relate/relate,
// same engine as the browser WASM build) loaded with the project's seed.cypher.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

import {
  splitCypherScript,
  escapeCypherString,
  parseEnvelope,
  extractGraph,
  neighboursOf,
  NODE_COUNTS,
} from '../lib.js';

const require = createRequire(import.meta.url);
const { Database } = require('@relate/relate');

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const SEED = readFileSync(join(ROOT, 'seed.cypher'), 'utf-8');

function freshDb() {
  const db = Database.open(':memory:');
  const conn = db.connect();
  for (const stmt of splitCypherScript(SEED)) conn.query(stmt);
  return conn;
}

// ---------- lib.js helpers ----------

test('splitCypherScript: seed splits into 73 statements (34 nodes + 39 edges)', () => {
  const stmts = splitCypherScript(SEED);
  assert.equal(stmts.length, 73);
  assert.equal(stmts.filter((s) => s.startsWith('CREATE (:')).length, 34);
  assert.equal(stmts.filter((s) => s.includes('CREATE (')).length, 73);
});

test('splitCypherScript: strips //-comments and blank lines, keeps quotes', () => {
  const out = splitCypherScript("// hello\nCREATE (:A {id: 'x;y'});\n\n// bye\nMATCH (a) RETURN a;");
  assert.deepEqual(out, ["CREATE (:A {id: 'x;y'})", 'MATCH (a) RETURN a']);
});

test('escapeCypherString: escapes backslash and single quote', () => {
  assert.equal(escapeCypherString("o'clock \\ test"), "o\\'clock \\\\ test");
});

test('parseEnvelope: ok envelope, error envelope, garbage', () => {
  const ok = parseEnvelope('{"columns":["n"],"rows":[{"n":1}],"stats":{},"error":null}');
  assert.equal(ok.ok, true);
  assert.deepEqual(ok.rows, [{ n: 1 }]);
  const bad = parseEnvelope('{"columns":[],"rows":[],"error":"parse error at 1:2"}');
  assert.equal(bad.ok, false);
  assert.match(bad.error, /parse error/);
  assert.equal(parseEnvelope('not json{{').ok, false);
});

test('extractGraph: WASM wire shape (numeric id, start_node/end_node, no elementId)', () => {
  const rows = [
    { a: { kind: 'node', id: 0, labels: ['Vulnerability'], properties: { id: 'CVE-1' } },
      r: { kind: 'relationship', id: 0, type: 'HAS_WEAKNESS', start_node: 0, end_node: 1, properties: {} },
      b: { kind: 'node', id: 1, labels: ['Weakness'], properties: { id: 'CWE-1' } } },
    { a: { kind: 'node', id: 0, labels: ['Vulnerability'], properties: { id: 'CVE-1' } },
      r: { kind: 'relationship', id: 1, type: 'AFFECTS', start_node: 0, end_node: 2, properties: {} },
      b: { kind: 'node', id: 2, labels: ['Product'], properties: { id: 'Prod-1' } } },
  ];
  const g = extractGraph(rows);
  assert.equal(g.nodes.length, 3);
  assert.equal(g.edges.length, 2); // both types kept — must NOT dedupe to one per type
  assert.deepEqual(g.edges.map((e) => e.type).sort(), ['AFFECTS', 'HAS_WEAKNESS']);
  assert.equal(neighboursOf('CVE-1', g.nodes, g.edges).length, 2);
});

test('extractGraph + neighboursOf: nodes, edges, path values', () => {
  const rows = [
    { n: { kind: 'node', elementId: '4:rl-id:n0', id: 0, labels: ['Vulnerability'], properties: { id: 'CVE-1' } } },
    { a: { kind: 'node', elementId: '4:rl-id:n0', id: 0, labels: ['Vulnerability'], properties: { id: 'CVE-1' } },
      r: { kind: 'relationship', elementId: '5:rl-id:r0', id: 0, type: 'HAS_WEAKNESS', startId: 0, endId: 1, startElementId: '4:rl-id:n0', endElementId: '4:rl-id:n1', properties: {} },
      b: { kind: 'node', elementId: '4:rl-id:n1', id: 1, labels: ['Weakness'], properties: { id: 'CWE-1' } } },
    { p: [
      { kind: 'node', elementId: '4:rl-id:n0', id: 0, labels: ['Vulnerability'], properties: { id: 'CVE-1' } },
      { kind: 'relationship', elementId: '5:rl-id:r0', id: 0, type: 'HAS_WEAKNESS', startId: 0, endId: 1, startElementId: '4:rl-id:n0', endElementId: '4:rl-id:n1', properties: {} },
      { kind: 'node', elementId: '4:rl-id:n1', id: 1, labels: ['Weakness'], properties: { id: 'CWE-1' } },
    ] },
  ];
  const g = extractGraph(rows);
  assert.equal(g.nodes.length, 2);
  assert.equal(g.edges.length, 1);
  const neigh = neighboursOf('CVE-1', g.nodes, g.edges);
  assert.equal(neigh.length, 1);
  assert.equal(neigh[0].node.id, 'CWE-1');
  assert.equal(neigh[0].relationship, 'HAS_WEAKNESS');
});

// ---------- real Relate engine, seeded ----------

test('engine: seed loads 34 nodes and 39 relationships', () => {
  const c = freshDb();
  assert.equal(c.query('MATCH (n) RETURN count(n) AS c').rows[0].c, NODE_COUNTS.nodes);
  assert.equal(c.query('MATCH ()-[r]->() RETURN count(r) AS c').rows[0].c, NODE_COUNTS.relationships);
});

test('engine: label counts are 8/8/6/6/6', () => {
  const c = freshDb();
  const rows = c.query('MATCH (n) RETURN labels(n) AS labels, count(n) AS c').rows;
  const got = Object.fromEntries(rows.map((r) => [r.labels[0], r.c]));
  assert.deepEqual(got, { Vulnerability: 8, Weakness: 8, AttackPattern: 6, Technique: 6, Product: 6 });
});

test('engine: CVE-2024-3094 neighbours are CWE-506, xz Utils, T1027, T1059', () => {
  const c = freshDb();
  const rows = c.query("MATCH (n {id: 'CVE-2024-3094'})-[r]-(m) RETURN m.id AS id").rows;
  assert.deepEqual(rows.map((r) => r.id).sort(), ['CWE-506', 'T1027', 'T1059', 'xz Utils']);
});

test('engine: shortestPath CVE-2024-3094 -> CVE-2021-44228 goes via T1059', () => {
  const c = freshDb();
  const rows = c.query(
    "MATCH p = shortestPath((a:Vulnerability {id: 'CVE-2024-3094'})-[*]-(b:Vulnerability {id: 'CVE-2021-44228'})) RETURN p",
  ).rows;
  assert.equal(rows.length, 1);
  const nodeIds = rows[0].p.filter((v) => v.kind === 'node').map((v) => v.properties.id);
  assert.deepEqual(nodeIds, ['CVE-2024-3094', 'T1059', 'CVE-2021-44228']);
});

test('engine: example queries from the app all run', () => {
  const c = freshDb();
  const qs = [
    'MATCH (v:Vulnerability) RETURN v.id AS cve, v.name AS name, v.cvss AS cvss ORDER BY v.cvss DESC',
    'MATCH (v:Vulnerability)-[:HAS_WEAKNESS]->(w:Weakness) RETURN v.id AS cve, w.id AS cwe, w.name AS weakness',
    'MATCH (t:Technique)-[:USES]->(c:AttackPattern)-[:EXPLOITS]->(w:Weakness) RETURN t.id AS technique, c.id AS capec, w.id AS cwe',
    'MATCH (v:Vulnerability)-[:AFFECTS]->(p:Product) RETURN v.id AS cve, p.id AS product',
    'MATCH (n) RETURN labels(n) AS labels, count(n) AS count',
  ];
  const counts = qs.map((q) => c.query(q).rows.length);
  assert.deepEqual(counts, [8, 9, 10, 8, 5]);
});

test('engine: invalid Cypher is rejected', () => {
  const c = freshDb();
  assert.throws(() => c.query('MATCH (n RETURN n'), /./);
});

test('engine: missing node returns zero rows (no fake data)', () => {
  const c = freshDb();
  assert.equal(c.query("MATCH (n {id: 'CVE-2099-99999'}) RETURN n").rows.length, 0);
});

test('engine: app add-node CREATE works and count becomes 35', () => {
  const c = freshDb();
  const q = `CREATE (:Vulnerability {id: '${escapeCypherString('CVE-2024-99999')}', name: '${escapeCypherString("Test 'quoted' flaw")}'})`;
  c.query(q);
  assert.equal(c.query('MATCH (n) RETURN count(n) AS c').rows[0].c, 35);
});
