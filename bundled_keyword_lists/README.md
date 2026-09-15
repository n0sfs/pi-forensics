# Bundled keyword lists

Reference keyword lists shipped with pi-forensics. An examiner imports one
from **Settings → Case & Reporting → Analysis & IOC Lists → Import Bundled
List**, which copies it into their own station's keyword lists where it can be
edited or deleted like any other. The files here are never modified by the
app, so a clean copy can always be re-imported.

Each `.json` file carries its own `source` (title, publisher, URL, licence,
retrieval date) and its own `caveats`, and the import picker shows both
**before** the import button. That is deliberate: every list here over-matches
in some way an examiner needs to know about before acting on a hit.

## What is here, and under what licence

| File(s) | Source | Licence |
|---|---|---|
| `dea_drug_slang_*.json` | DEA Intelligence Report DEA-HOU-DIR-022-18, *Slang Terms and Code Words: A Reference for Law Enforcement Personnel*, July 2018 (marked UNCLASSIFIED) | Public domain — a work of the US Government, 17 U.S.C. §105 |
| `credentials_api_keys.json` | [gitleaks](https://github.com/gitleaks/gitleaks) default ruleset, adapted | MIT (Zachary Rice, 2019) |
| `ofac_sanctioned_addresses_*.json` | [0xB10C/ofac-sanctioned-digital-currency-addresses](https://github.com/0xB10C/ofac-sanctioned-digital-currency-addresses) over US Treasury OFAC SDN data | MIT (tool); the SDN list itself is a US Government work |
| `anti_forensics_tools.json` | Compiled for this project from vendor documentation and public research | No third-party content — tool names and command lines are facts, not copyrightable expression |

## Why these are regexes rather than plain terms

The scanner matches patterns against raw bytes with no tokenisation. A plain
literal `Ice` — real DEA slang — matches inside `device`, `service`, `nice`,
and any run of bytes that happens to contain those three characters. Drug
slang is full of short words like that, and without boundaries a list buries
its own real hits.

Every literal term here is therefore emitted as `\bterm\b`. `is_regex` is
`true` on every file for that reason, and a test pins it so a future list
cannot regress to plain terms by accident.

## Why they are vendored rather than fetched

This appliance is routinely used on an air-gapped station, so a feature that
only works with an internet connection is not much of a feature. The tradeoff
is that a bundled snapshot goes stale — most sharply for the OFAC addresses,
which upstream regenerates nightly. Each file records the date it was
retrieved, and the caveats say so.

## What is deliberately NOT here

- **CSAM investigation term lists.** These are not publicly obtainable: Project
  VIC and CAID distribute hash sets (not keywords) gated to sworn officers, and
  IWF's keyword list is licensed only through commercial and partner
  agreements. Beyond the access question, a bundled offender-code-word list in
  a public repository works equally well as a guide to evading detection. An
  examiner with lawful access to such a list can paste it into the existing
  keyword-list UI; nothing needs to ship here for that to work.
- **Commercial vendor watchlists.** Third-party sites re-host Cellebrite and
  Magnet AXIOM watchlists with no licence grant. Convenient, and a real
  infringement risk in an MIT repository.
- **Copyleft rule sets.** TruffleHog (AGPL-3.0), bulk_extractor's stoplists
  (GPL-3.0) and LOLBAS (GPL-3.0) cannot be redistributed from here.

## Regenerating

These files are generated, not hand-edited — editing one directly will be lost
the next time it is rebuilt, and may ship a pattern that has not been through
the ReDoS gate. `tests/test_bundled_keyword_lists.py` checks every file for
required metadata, a stated licence, stated caveats, compilability, that its
combined alternation clears the same ReDoS gate an examiner-authored list must
clear, and that it actually matches one of its own terms.
