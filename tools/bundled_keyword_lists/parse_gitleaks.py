"""Extract gitleaks rule regexes and report which are usable under Python re.

gitleaks is MIT (Zachary Rice, 2019) and its regexes are Go RE2, which has no
backtracking - so upstream has never needed to care about ReDoS, and a rule
that is fine there can still be catastrophic under Python's backtracking
engine. Everything selected here has to clear this app's own ReDoS gate.
"""
import json
import os
import re
import sys

SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gitleaks.toml")
raw = open(SRC, encoding="utf-8").read()

ID_RE = re.compile(r'^\s*id\s*=\s*"([^"]+)"', re.M)
# Regexes are written as TOML multi-line literal strings in this file.
TRIPLE_RE = re.compile(r"^\s*regex\s*=\s*'''(.*?)'''", re.M | re.S)

rules = []
for block in raw.split("[[rules]]")[1:]:
    m_id = ID_RE.search(block)
    m_rx = TRIPLE_RE.search(block)
    if m_id and m_rx:
        rules.append({"id": m_id.group(1), "regex": m_rx.group(1).strip()})

print("rules parsed:", len(rules))

ok, bad = [], []
for r in rules:
    try:
        re.compile(r["regex"])
        ok.append(r)
    except re.error as e:
        bad.append((r["id"], str(e)))

print("compile under Python re:", len(ok), "/", len(rules))
print("first few that do NOT compile:")
for rid, err in bad[:10]:
    print("   ", rid, "->", err)

out = os.path.join(os.path.dirname(SRC), "gitleaks_rules.json")
json.dump(ok, open(out, "w", encoding="utf-8"), indent=1)
print("wrote", out)
