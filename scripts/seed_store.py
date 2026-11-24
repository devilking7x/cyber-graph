#!/usr/bin/env python3
"""Build the persistent single-file Relate store for CyberGraph.

Reads seed.cypher, loads it into a real Relate database (relate-db 1.2.0)
and saves it as store/cybergraph.rl — a single-file store judges can open
with the relate CLI or the Python package. No server, no account.

Usage:
    pip install relate-db
    python scripts/seed_store.py [--store store/cybergraph.rl] [--seed seed.cypher]

Re-running deletes the old store first (seed is idempotent by construction:
a fresh store is built every time).
"""
import argparse
import os
import shutil
import sys

SEED_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "seed.cypher")


def split_statements(script):
    """Split a ;-terminated Cypher script, skipping //-comments."""
    statements, current, in_string = [], "", False
    i = 0
    while i < len(script):
        ch = script[i]
        if ch == "'" and (i == 0 or script[i - 1] != "\\"):
            in_string = not in_string
        if not in_string and ch == "/" and i + 1 < len(script) and script[i + 1] == "/":
            while i < len(script) and script[i] != "\n":
                i += 1
            continue
        if not in_string and ch == ";":
            if current.strip():
                statements.append(current.strip())
            current = ""
            i += 1
            continue
        current += ch
        i += 1
    if current.strip():
        statements.append(current.strip())
    return statements


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--store", default="store/cybergraph.rl")
    ap.add_argument("--seed", default=SEED_PATH)
    args = ap.parse_args()

    try:
        import relate
    except ImportError:
        print("relate-db is not installed: pip install relate-db", file=sys.stderr)
        return 1

    with open(args.seed, encoding="utf-8") as f:
        statements = split_statements(f.read())
    print(f"seed statements: {len(statements)}")

    if os.path.exists(args.store):
        os.remove(args.store)
        print(f"removed old store {args.store}")

    db = relate.connect(args.store)
    for stmt in statements:
        db.execute(stmt)
    nodes = list(db.execute("MATCH (n) RETURN count(n) AS c"))[0]["c"]
    rels = list(db.execute("MATCH ()-[r]->() RETURN count(r) AS c"))[0]["c"]
    labels = list(db.execute("MATCH (n) RETURN labels(n) AS labels, count(n) AS c"))
    print(f"nodes: {nodes}, relationships: {rels}")
    for row in labels:
        print(f"  {row['labels']}: {row['c']}")
    size = os.path.getsize(args.store)
    print(f"store: {args.store} ({size} bytes)")
    assert nodes == 34, f"expected 34 nodes, got {nodes}"
    assert rels == 39, f"expected 39 relationships, got {rels}"
    print("OK: store built and verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
