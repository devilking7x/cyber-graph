// CyberGraph — browser app. All queries run as real Cypher against the Relate
// embedded engine (v1.2.0) compiled to WebAssembly. No server, no hosted Neo4j.
import init, { RelateDb } from './vendor/relate-wasm/relate.js';
import { parseEnvelope, extractGraph, escapeCypherString } from './lib.js';

const LABEL_COLORS = {
  Vulnerability: '#e5484d',
  Weakness: '#f0b429',
  AttackPattern: '#58a6ff',
  Technique: '#7ee2a8',
  Product: '#b083f0',
};
const LABEL_ORDER = ['Vulnerability', 'Weakness', 'AttackPattern', 'Technique', 'Product'];

const EXAMPLES = [
  { name: 'All CVEs by severity', q: 'MATCH (v:Vulnerability) RETURN v.id AS cve, v.name AS name, v.cvss AS cvss ORDER BY v.cvss DESC' },
  { name: 'CVE → CWE root causes', q: 'MATCH (v:Vulnerability)-[:HAS_WEAKNESS]->(w:Weakness) RETURN v.id AS cve, w.id AS cwe, w.name AS weakness' },
  { name: 'Technique → CAPEC → CWE chains', q: 'MATCH (t:Technique)-[:USES]->(c:AttackPattern)-[:EXPLOITS]->(w:Weakness) RETURN t.id AS technique, c.id AS capec, w.id AS cwe' },
  { name: 'What does each CVE affect?', q: 'MATCH (v:Vulnerability)-[:AFFECTS]->(p:Product) RETURN v.id AS cve, p.id AS product' },
  { name: 'Nodes per type', q: 'MATCH (n) RETURN labels(n) AS labels, count(n) AS count' },
];

const $ = (id) => document.getElementById(id);
const statusEl = $('status');
let db = null;
let graph = { nodes: [], edges: [] };
let positions = new Map(); // node key -> {x, y}
let selectedKey = null;
let pathKeys = new Set();

function setStatus(text, kind = '') {
  statusEl.textContent = text;
  statusEl.className = 'status ' + kind;
}

// One statement through the real Relate engine. Errors arrive in the envelope.
function runCypher(query, params = null) {
  const wire = db.execute(query, params ? JSON.stringify(params) : null);
  return parseEnvelope(wire);
}

function valueCell(v) {
  if (v === null || v === undefined) return '';
  if (typeof v === 'object') return JSON.stringify(v);
  return String(v);
}

function renderTable(container, env) {
  if (!env.ok) {
    container.innerHTML = `<p class="error">Relate error: ${escapeHtml(env.error || 'unknown error')}</p>`;
    return;
  }
  if (env.rows.length === 0) {
    container.innerHTML = `<p>Query ran OK — 0 rows. ${env.stats ? '(' + escapeHtml(JSON.stringify(env.stats)) + ')' : ''}</p>`;
    return;
  }
  const head = env.columns.map((c) => `<th>${escapeHtml(c)}</th>`).join('');
  const body = env.rows.map((r) => `<tr>${env.columns.map((c) => `<td>${escapeHtml(valueCell(r[c]))}</td>`).join('')}</tr>`).join('');
  container.innerHTML = `<p>${env.rows.length} row(s)</p><table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>`;
}

function escapeHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function layoutGraph() {
  const cols = {};
  LABEL_ORDER.forEach((label, i) => { cols[label] = { x: 90 + i * 195, items: [] }; });
  for (const n of graph.nodes) {
    const label = n.labels[0] || 'Product';
    (cols[label] || cols.Product).items.push(n);
  }
  for (const label of LABEL_ORDER) {
    const list = cols[label].items;
    list.forEach((n, i) => {
      if (!positions.has(n.key)) {
        positions.set(n.key, { x: cols[label].x, y: 60 + (i + 0.5) * (520 / Math.max(list.length, 1)) });
      }
    });
  }
}

function renderGraph() {
  const svg = $('graph');
  const pos = (key) => positions.get(key) || { x: 480, y: 300 };
  const byKey = new Map(graph.nodes.map((n) => [n.key, n]));
  let html = '';
  for (const e of graph.edges) {
    const a = pos(e.from), b = pos(e.to);
    if (!a || !b || !byKey.has(e.from) || !byKey.has(e.to)) continue;
    const hot = pathKeys.has(e.key) ? ' hot' : '';
    const mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2;
    html += `<line class="edge${hot}" x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}"/>`;
    html += `<text class="edge-label" x="${mx}" y="${my - 4}">${escapeHtml(e.type)}</text>`;
  }
  for (const n of graph.nodes) {
    const p = pos(n.key);
    const color = LABEL_COLORS[n.labels[0]] || '#8b949e';
    const cls = [
      'node',
      n.key === selectedKey ? 'selected' : '',
      pathKeys.has(n.key) ? 'on-path' : '',
      pathKeys.size && !pathKeys.has(n.key) ? 'dimmed' : '',
    ].join(' ');
    html += `<g class="${cls}" data-key="${escapeHtml(n.key)}" transform="translate(${p.x},${p.y})">`
      + `<circle r="15" fill="${color}"/>`
      + `<text y="29">${escapeHtml(shortLabel(n.id))}</text>`
      + `<title>${escapeHtml(n.id)} — ${escapeHtml(n.properties.name || '')}</title></g>`;
  }
  svg.innerHTML = html;
  svg.querySelectorAll('.node').forEach((g) => {
    g.addEventListener('pointerdown', (ev) => startDrag(ev, g.dataset.key));
    g.addEventListener('click', () => selectNode(g.dataset.key));
  });
}

function shortLabel(id) {
  return id.replace('CVE-', '').replace('CWE-', '').replace('CAPEC-', '').replace('Microsoft ', '').slice(0, 12);
}

let dragKey = null;
function startDrag(ev, key) {
  dragKey = key;
  const svg = $('graph');
  const move = (e) => {
    if (!dragKey) return;
    const pt = svg.createSVGPoint();
    pt.x = e.clientX; pt.y = e.clientY;
    const loc = pt.matrixTransform(svg.getScreenCTM().inverse());
    positions.set(dragKey, { x: Math.max(20, Math.min(940, loc.x)), y: Math.max(20, Math.min(600, loc.y)) });
    renderGraph();
  };
  const up = () => { dragKey = null; window.removeEventListener('pointermove', move); window.removeEventListener('pointerup', up); };
  window.addEventListener('pointermove', move);
  window.addEventListener('pointerup', up);
  ev.preventDefault();
}

function selectNode(key) {
  selectedKey = key;
  const node = graph.nodes.find((n) => n.key === key);
  if (!node) return;
  const env = runCypher(
    'MATCH (n {id: $id})-[r]-(m) RETURN type(r) AS rel, labels(m) AS labels, m.id AS id, m.name AS name',
    { id: node.id },
  );
  const rows = env.ok ? env.rows : [];
  const props = Object.entries(node.properties)
    .map(([k, v]) => `<li><strong>${escapeHtml(k)}:</strong> ${escapeHtml(valueCell(v))}</li>`).join('');
  const neigh = rows.map((r) => `<li><code>${escapeHtml(r.rel)}</code> → ${escapeHtml(r.id)} (${escapeHtml((r.labels || []).join(','))}) — ${escapeHtml(r.name || '')}</li>`).join('');
  $('details').innerHTML = `<strong>${escapeHtml(node.id)}</strong> (${escapeHtml(node.labels.join(', '))})`
    + `<ul>${props}</ul><p>Neighbours (${rows.length}):</p><ul>${neigh || '<li>None</li>'}</ul>`;
  renderGraph();
}

function loadGraph() {
  const nodesEnv = runCypher('MATCH (n) RETURN n');
  const edgesEnv = runCypher('MATCH (a)-[r]->(b) RETURN a, r, b');
  if (!nodesEnv.ok) throw new Error(nodesEnv.error || 'node query failed');
  if (!edgesEnv.ok) throw new Error(edgesEnv.error || 'edge query failed');
  graph = extractGraph([...nodesEnv.rows, ...edgesEnv.rows]);
  layoutGraph();
  renderGraph();
}

function renderStats() {
  const counts = {};
  for (const n of graph.nodes) counts[n.labels[0]] = (counts[n.labels[0]] || 0) + 1;
  $('stats').innerHTML = `<span><strong>${graph.nodes.length}</strong> nodes</span>`
    + `<span><strong>${graph.edges.length}</strong> relationships</span>`
    + LABEL_ORDER.filter((l) => counts[l]).map((l) => `<span>${escapeHtml(l)}: <strong>${counts[l]}</strong></span>`).join('');
  $('legend').innerHTML = LABEL_ORDER.map((l) => `<span><i style="background:${LABEL_COLORS[l]}"></i>${escapeHtml(l)}</span>`).join('');
}

function fillSelects() {
  const opts = (sel) => {
    const el = $(sel);
    el.innerHTML = '';
    const byLabel = {};
    for (const n of graph.nodes) (byLabel[n.labels[0]] ||= []).push(n);
    for (const label of LABEL_ORDER) {
      for (const n of byLabel[label] || []) {
        const o = document.createElement('option');
        o.value = n.id; o.dataset.label = label;
        o.textContent = `${n.id} — ${n.properties.name || ''}`.slice(0, 60);
        el.appendChild(o);
      }
    }
  };
  opts('path-from'); opts('path-to');
  $('path-from').value = 'CVE-2024-3094';
  $('path-to').value = 'CVE-2021-44228';
}

function findPath() {
  const from = $('path-from');
  const to = $('path-to');
  const fromLabel = from.options[from.selectedIndex].dataset.label;
  const toLabel = to.options[to.selectedIndex].dataset.label;
  const env = runCypher(
    `MATCH p = shortestPath((a:${fromLabel} {id: $from})-[*]-(b:${toLabel} {id: $to})) RETURN p`,
    { from: from.value, to: to.value },
  );
  const box = $('path-result');
  if (!env.ok) { box.innerHTML = `<p class="error">Relate error: ${escapeHtml(env.error)}</p>`; return; }
  if (env.rows.length === 0) {
    pathKeys = new Set(); renderGraph();
    box.innerHTML = `<p>No path exists between <strong>${escapeHtml(from.value)}</strong> and <strong>${escapeHtml(to.value)}</strong> in this graph.</p>`;
    return;
  }
  const sub = extractGraph(env.rows);
  pathKeys = new Set([...sub.nodes.map((n) => n.key), ...sub.edges.map((e) => e.key)]);
  renderGraph();
  const seq = env.rows[0].p.filter((v) => v.kind === 'node').map((v) => v.properties.id);
  const rels = env.rows[0].p.filter((v) => v.kind === 'relationship').map((v) => v.type);
  let chain = seq[0];
  rels.forEach((r, i) => { chain += ` —[${r}]→ ${seq[i + 1]}`; });
  box.innerHTML = `<p><strong>Shortest path (${seq.length - 1} hop${seq.length > 2 ? 's' : ''}):</strong></p><p>${escapeHtml(chain)}</p>`;
}

function runQueryBox() {
  const q = $('cypher').value.trim();
  if (!q) { $('cypher-result').innerHTML = '<p class="error">Type a Cypher query first.</p>'; return; }
  const env = runCypher(q);
  renderTable($('cypher-result'), env);
  if (env.ok && /CREATE|MERGE|DELETE|SET/i.test(q)) {
    loadGraph(); renderStats(); fillSelects();
  }
}

function addNode() {
  const label = $('add-label').value;
  const id = $('add-id').value.trim();
  const name = $('add-name').value.trim();
  if (!id || !name) { $('add-result').textContent = 'ID and name are both required.'; return; }
  const env = runCypher(`CREATE (:${label} {id: '${escapeCypherString(id)}', name: '${escapeCypherString(name)}'})`);
  if (!env.ok) { $('add-result').textContent = 'Relate error: ' + env.error; return; }
  $('add-result').textContent = `Added ${label} ${id} to this session's in-memory store.`;
  $('add-id').value = ''; $('add-name').value = '';
  loadGraph(); renderStats(); fillSelects();
}

async function main() {
  try {
    await init();
    db = new RelateDb();
    setStatus('Relate engine loaded. Seeding graph…');
    const seed = await (await fetch('seed.cypher')).text();
    const envelopes = db.executeScript(seed, null);
    for (const wire of envelopes) {
      const env = parseEnvelope(wire);
      if (!env.ok) throw new Error('Seed failed: ' + env.error);
    }
    const count = runCypher('MATCH (n) RETURN count(n) AS n');
    const rels = runCypher('MATCH ()-[r]->() RETURN count(r) AS r');
    const n = count.ok ? count.rows[0].n : '?';
    const r = rels.ok ? rels.rows[0].r : '?';
    setStatus(`Relate 1.2.0 (WASM) ready — ${n} nodes, ${r} relationships loaded from seed.cypher. All queries below run as Cypher in this engine.`, 'ok');
    loadGraph();
    renderStats();
    fillSelects();
    const chips = $('examples');
    for (const ex of EXAMPLES) {
      const b = document.createElement('button');
      b.type = 'button'; b.textContent = ex.name;
      b.addEventListener('click', () => { $('cypher').value = ex.q; runQueryBox(); });
      chips.appendChild(b);
    }
    $('cypher-run').addEventListener('click', runQueryBox);
    $('cypher-clear').addEventListener('click', () => { $('cypher').value = ''; $('cypher-result').innerHTML = ''; });
    $('path-run').addEventListener('click', findPath);
    $('add-run').addEventListener('click', addNode);
    runQueryBox();
  } catch (e) {
    setStatus('Failed to start Relate: ' + e.message, 'err');
  }
}

main();
