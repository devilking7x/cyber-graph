# CyberGraph

A cybersecurity knowledge graph — CVE → CWE → CAPEC → MITRE ATT&CK — that runs on
Relate, Neo4j's embedded graph database, entirely in the browser. No server, no account.

**Live demo:** https://devilking7x.github.io/cyber-graph/

## Use case

When a new vulnerability lands, the first question is never just "what is it?" — it is
"what is it connected to?": which weakness caused it, which attack patterns exploit that
weakness, which attacker techniques use those patterns, and which products are affected.
That is a graph question, and flat lists or keyword search answer it badly.

CyberGraph models those connections as a real property graph so a student, analyst or
curious reader can:

- **See** the whole graph (34 nodes, 39 relationships) as an interactive visualisation.
- **Ask** anything in Cypher — a query box runs real Cypher against the live Relate engine.
- **Trace** a path between any two nodes with Cypher `shortestPath`
  (e.g. xz backdoor CVE-2024-3094 → Log4Shell CVE-2021-44228 runs through T1059).
- **Add** a node with a real `CREATE` statement (session only — see limits below).

What connects to what: `Vulnerability —HAS_WEAKNESS→ Weakness`,
`AttackPattern —EXPLOITS→ Weakness`, `Technique —USES→ AttackPattern`,
`Technique —TARGETS→ Vulnerability`, `Vulnerability —AFFECTS→ Product`.

## How it uses Relate

- **Mode: single file + in-memory (WASM).** Two faces of the same seed:
  1. **Persistent store (single file):** `store/cybergraph.rl` — built by
     `scripts/seed_store.py` with the Python `relate-db` package from `seed.cypher`.
     This is the durable store judges can inspect and open with the Relate CLI.
  2. **Browser (in-memory):** the web app loads the vendored `@relate/relate-wasm`
     1.2.0 build (`vendor/relate-wasm/`, the published npm package, Apache-2.0),
     creates an in-memory `RelateDb`, and seeds it with the same `seed.cypher`
     via `executeScript`. Every query box, path search, node detail and add-node
     action executes Cypher through that engine — there is no fake graph layer.
- **Why these modes:** the hackathon requires a persistent store judges can inspect
  (the `.rl` file) and working code with Relate actually running. The single-file
  store is the inspectable artefact; the in-memory WASM store is what makes the
  demo work on free static hosting with no server, no signup and no cost — which
  is the whole point of an embedded database. Both are built from the same seed,
  so the demo and the store can never drift apart.
- **Why not hosted Neo4j / Aura:** Relate is embedded by design — no server to
  deploy. Nothing in this project talks to a hosted database, and it never claims to.

## Setup and run

No build step, no runtime dependencies. Any static file server works:

```sh
python3 -m http.server 8000
# open http://localhost:8000/
```

Or open the live demo above.

### Rebuild the persistent store (optional)

```sh
pip install relate-db
python scripts/seed_store.py
# verifies: 34 nodes, 39 relationships
```

### Inspect the store with the Relate CLI

```sh
curl -sSfL https://relatedb.ai/install.sh | bash
relate --database ./store/cybergraph.rl --read-only "MATCH (n) RETURN count(n) AS n"
relate --database ./store/cybergraph.rl --read-only "MATCH p = shortestPath((a:Vulnerability {id: 'CVE-2024-3094'})-[*]-(b:Vulnerability {id: 'CVE-2021-44228'})) RETURN p"
```

## Where the data lives

- `seed.cypher` — the whole graph as Cypher: 34 nodes, 39 relationships,
  hand-written for this project from public knowledge (8 CVEs, 8 CWEs, 6 CAPEC
  attack patterns, 6 MITRE ATT&CK techniques, 6 products). Summaries are
  simplified and educational — verify facts against NVD / CWE / CAPEC /
  MITRE ATT&CK before relying on them.
- `store/cybergraph.rl` — the persistent single-file Relate store (36,864 bytes).
- The browser store is in-memory and seeded on every page load; nodes added in
  the web form exist only for that browser session.

## Tests

```sh
npm install   # dev only: @relate/relate (native) + playwright-core
npm test      # 14 node --test tests: helpers + real Relate engine on the seed
npm run smoke # 10 Playwright checks against the page in Chromium
```

## Honest limits

- The browser graph is **in-memory**: reload the page and session-added nodes are gone.
  Persistence lives in `store/cybergraph.rl`, not in the browser (OPFS persistence
  is a documented Relate WASM option we did not wire up — it needs a dedicated worker).
- The seed is a small hand-written teaching graph, not a live feed: it will not track
  new CVEs. The pipeline to grow it is `seed.cypher` → `seed_store.py` → `.rl` file.
- Demo video: not in this repo — it is recorded separately for the Devpost submission.
