# Regenerating the bundled keyword lists

These scripts produce everything in `bundled_keyword_lists/`. The output files
are generated, not hand-edited — editing one directly will be lost on the next
rebuild, and can ship a pattern that never went through the ReDoS gate.

They live in the repo so the lists are reproducible and their provenance is
auditable: anyone can re-run these, diff the result against what is committed,
and see exactly which upstream data became which shipped pattern.

## Prerequisites

Source data is fetched, not vendored — these are large upstream files that
would bloat the repo and go stale:

```bash
cd tools/bundled_keyword_lists

# gitleaks ruleset (MIT)
curl -sSL -o gitleaks.toml \
  https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml

# DEA slang reference (public domain, US Government work).
# dea.gov blocks non-browser clients; the Internet Archive mirror does not.
curl -sSL -o dea_slang.pdf \
  "https://web.archive.org/web/2020id_/https://www.dea.gov/sites/default/files/2018-07/DIR-022-18.pdf"
pdftotext -layout dea_slang.pdf dea_slang.txt
```

OFAC addresses are fetched by `emit_bundled_lists.py` itself at run time.

## Running

```bash
python parse_gitleaks.py       # gitleaks.toml  -> gitleaks_rules.json
python build_creds_list.py     # select + adapt -> creds_selected.json
python build_dea_lists.py      # dea_slang.txt  -> dea_themes.json
python emit_bundled_lists.py   # everything     -> ../../bundled_keyword_lists/
```

Then confirm nothing regressed:

```bash
python -m pytest tests/test_bundled_keyword_lists.py -q
```

## Things that will bite you

**Run `emit_bundled_lists.py` as a script, never import it.** The ReDoS gate
uses `multiprocessing`, and on Windows that means `spawn()`, which re-imports
the parent module in every probe subprocess. The module-level work — including
the OFAC network fetches — would run again for every single check. The
`if __name__ == "__main__"` guard is what stops that, and removing it turns a
20-second run into an apparently-hung one.

**The ReDoS gate is the real gate, and it is not optional.** gitleaks' regexes
are Go RE2, which has no backtracking at all, so upstream has never had to care
whether a pattern is catastrophic under Python's engine. `emit()` refuses to
write any list whose combined alternation fails the check.

**Literal terms are emitted word-bounded.** See `word_bounded()` and the note
in `bundled_keyword_lists/README.md` — a bare `Ice` matches inside `device`,
`service` and `nice`, which buries the list's own real hits.
