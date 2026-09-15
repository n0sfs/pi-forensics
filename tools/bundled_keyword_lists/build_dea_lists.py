"""Builds themed drug-slang keyword lists from the DEA's own reference.

Source: DEA Intelligence Report DEA-HOU-DIR-022-18, "Slang Terms and Code
Words: A Reference for Law Enforcement Personnel", July 2018. Marked
UNCLASSIFIED. A work of the United States Government, so not subject to
copyright under 17 U.S.C. 105 - public domain, redistributable.

Parses the report's own reverse index ("<slang term>  <drug>"), which is a
better source than the forward listing: it gives the term AND its drug in one
place, so the terms can be grouped into themed lists without a second mapping
being invented here.
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
text = open(os.path.join(HERE, "dea_slang.txt"), encoding="utf-8", errors="replace").read()

# Page furniture, and the forward "Drug: term; term; term" section which this
# script deliberately does not use.
SKIP_LINE = re.compile(r"^\s*(UNCLASSIFIED|DEA Intelligence Report|\d+)\s*$")

# "Term with spaces" then 2+ spaces then the drug name. pdftotext -layout
# preserves the column gap, which is what makes this parseable at all.
ROW = re.compile(r"^(?P<term>\S.{0,40}?\S)\s{2,}(?P<drug>[A-Z]\S.*)$")

# Drug string -> theme, matched by SUBSTRING in priority order rather than by
# exact name. The report spells the same drug many ways ("Oxycodone",
# "Oxycodone (Oxycontin, Roxicodone, Oxaydo)", "Uncut Heroin", "Heroin mixed
# with Fentanyl"), and an exact-name table silently dropped every variant it
# did not anticipate. A row naming two drugs ("Cocaine mixed with Heroin")
# lands in BOTH themes, which is correct - the term really is used for both.
THEME_RULES = [
    ("Cannabis & Synthetic Cannabinoids",
     ["marijuana", "cannabis", "cannabinoid", "hash oil", "hashish", "hash "]),
    ("Opioids & Heroin",
     ["heroin", "fentanyl", "opium", "opioid", "oxycodone", "oxycontin",
      "hydrocodone", "hydromorphone", "morphine", "codeine", "methadone",
      "buprenorphine", "suboxone", "carfentanil", "u-47700", "tramadol",
      "percocet", "vicodin", "norco", "dilaudid"]),
    ("Stimulants",
     ["cocaine", "crack", "methamphetamine", "amphetamine", "adderall",
      "methylphenidate", "ritalin", "concerta", "khat", "cathinone",
      "mdpv", "crystal meth"]),
    ("Hallucinogens & Dissociatives",
     ["lsd", "pcp", "phencyclidine", "ketamine", "ecstasy", "mdma", "molly",
      "psilocybin", "mescaline", "peyote", "dmt", "salvia", "ayahuasca",
      "2c-b", "nbome", "mushroom"]),
    ("Depressants & Benzodiazepines",
     ["alprazolam", "xanax", "clonazepam", "klonopin", "diazepam", "valium",
      "lorazepam", "ativan", "flunitrazepam", "rohypnol", "ghb",
      "gamma-hydroxybutyric", "barbiturate", "zolpidem", "ambien",
      "carisoprodol", "soma", "methaqualone", "promethazine"]),
    ("Anabolic Steroids & Inhalants",
     ["steroid", "dextromethorphan", "dxm", "inhalant", "kratom",
      "nitrous oxide", "xylazine"]),
]

# Lines whose "drug" column is really page furniture that slipped through.
NOT_A_DRUG = ("unclassified", "dea intelligence report", "words: a reference")


def themes_for(drug):
    """Every theme this drug string belongs to. Empty if none match."""
    low = drug.lower()
    if any(j in low for j in NOT_A_DRUG):
        return []
    return [theme for theme, needles in THEME_RULES if any(n in low for n in needles)]


def normalise_drug(s):
    # The PDF's registered-trademark glyph does not survive extraction.
    s = s.replace("�", "").replace("®", "")
    s = re.sub(r"\s+", " ", s).strip().rstrip(";,.")
    return s


by_theme = {theme: set() for theme, _ in THEME_RULES}
unmapped = {}
rows = 0

for line in text.splitlines():
    if SKIP_LINE.match(line):
        continue
    m = ROW.match(line.rstrip())
    if not m:
        continue
    term = re.sub(r"\s+", " ", m.group("term")).strip()
    if not term or len(term) < 3:
        continue          # a 1-2 char "term" is noise, and useless as a keyword
    # A term can map to several drugs ("Zoom  Cocaine; Marijuana; ...").
    drugs = [normalise_drug(d) for d in m.group("drug").split(";")]
    matched = False
    for d in drugs:
        hits = themes_for(d)
        for theme in hits:
            by_theme[theme].add(term)
            matched = True
        if not hits and d and not any(j in d.lower() for j in NOT_A_DRUG):
            unmapped[d] = unmapped.get(d, 0) + 1
    if matched:
        rows += 1

print(f"index rows matched: {rows}")
for theme, terms in by_theme.items():
    print(f"  {theme}: {len(terms)}")
if unmapped:
    print("\nUNMAPPED drug names (terms for these were skipped):")
    for d, n in sorted(unmapped.items(), key=lambda kv: -kv[1])[:40]:
        print(f"  {n:5d}  {d}")

json.dump({t: sorted(v) for t, v in by_theme.items()},
          open(os.path.join(HERE, "dea_themes.json"), "w", encoding="utf-8"), indent=1)
print("\nwrote dea_themes.json")
