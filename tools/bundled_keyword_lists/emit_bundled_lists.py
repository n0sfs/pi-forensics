"""Emits the repo's bundled keyword lists from the prepared source data.

Run from the scratchpad after build_dea_lists.py and build_creds_list.py.
Writes into <repo>/bundled_keyword_lists/.

Every emitted list is checked against the SAME gate an examiner-authored list
goes through (compile + combined-pattern ReDoS), so nothing ships that the app
would refuse to run.
"""
import json
import os
import re
import sys
import urllib.request

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, REPO)
from core.case_index_db import check_regex_pattern_for_redos

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(REPO, "bundled_keyword_lists")
os.makedirs(OUT, exist_ok=True)

RETRIEVED = "2026-09-15"


def word_bounded(term):
    """A literal term as a regex that only matches the WHOLE word.

    The scanner runs patterns against raw bytes with no tokenisation, so a
    plain literal "Ice" matches inside "device", "nice", "service" and any
    binary run that happens to contain those three bytes. Drug slang is full
    of short words like that, and without boundaries the list buries its own
    real hits. \\b is applied only where the term actually starts/ends with a
    word character - "710" and "A-1" do, "$" would not.
    """
    escaped = re.escape(term)
    lead = r"\b" if re.match(r"\w", term) else ""
    trail = r"\b" if re.search(r"\w$", term) else ""
    return f"{lead}{escaped}{trail}"


def emit(filename, name, description, terms, is_regex, source, caveats):
    terms = list(dict.fromkeys(terms))          # de-dupe, keep order
    if is_regex:
        combined = "|".join(f"(?:{t})" for t in terms)
        compiled = re.compile(combined.encode("utf-8"), re.IGNORECASE)
        verdict = check_regex_pattern_for_redos(compiled)
        if verdict:
            raise SystemExit(f"{filename}: REFUSING - fails the app's ReDoS gate: {verdict}")
    payload = {
        "schema": 1,
        "name": name,
        "description": description,
        "is_regex": is_regex,
        "source": source,
        "caveats": caveats,
        "terms": terms,
    }
    path = os.path.join(OUT, filename)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(payload, f, indent=1, ensure_ascii=False)
        f.write("\n")
    print(f"  {filename}: {len(terms)} term(s){' [regex]' if is_regex else ''}")


def main():
    # --- 1. DEA drug slang, one file per theme --------------------------------
    DEA_SOURCE = {
        "title": "DEA Intelligence Report DEA-HOU-DIR-022-18, "
                 "'Slang Terms and Code Words: A Reference for Law Enforcement Personnel'",
        "publisher": "US Drug Enforcement Administration",
        "published": "2018-07",
        "url": "https://www.dea.gov/documents/2018/2018-07/2018-07-01/drug-slang-code-words",
        "licence": "Public domain - a work of the United States Government, 17 U.S.C. 105. "
                   "Marked UNCLASSIFIED in the original.",
        "retrieved": RETRIEVED,
    }
    DEA_CAVEATS = [
        "This is a July 2018 snapshot. Drug slang moves quickly, and terms for "
        "substances that became common after 2018 will not be here.",
        "Many entries are ordinary English words used as slang (Ice, Boy, Pot, Work, "
        "Bars). Each term is matched as a whole word, but no pattern can tell the "
        "slang sense from the innocent one - expect false positives and prune the "
        "list to your case.",
        "A hit is a lead, not a finding. The DEA compiled these from law-enforcement "
        "and open sources; presence of a word is not evidence of an offence.",
    ]
    FILE_FOR_THEME = {
        "Cannabis & Synthetic Cannabinoids": "dea_drug_slang_cannabis.json",
        "Opioids & Heroin": "dea_drug_slang_opioids.json",
        "Stimulants": "dea_drug_slang_stimulants.json",
        "Hallucinogens & Dissociatives": "dea_drug_slang_hallucinogens.json",
        "Depressants & Benzodiazepines": "dea_drug_slang_depressants.json",
        "Anabolic Steroids & Inhalants": "dea_drug_slang_steroids_inhalants.json",
    }

    print("DEA drug slang:")
    themes = json.load(open(os.path.join(HERE, "dea_themes.json"), encoding="utf-8"))
    for theme, filename in FILE_FOR_THEME.items():
        terms = sorted(themes.get(theme, []))
        if not terms:
            continue
        emit(filename,
             f"DEA Drug Slang - {theme}",
             f"Slang terms and code words the DEA associates with {theme.lower()}, "
             f"from its own 2018 reference for law enforcement. Matched as whole words.",
             [word_bounded(t) for t in terms],
             True, DEA_SOURCE, DEA_CAVEATS)

    # --- 2. Credentials & API keys, from gitleaks ------------------------------
    # Added here, not taken from gitleaks: gitleaks' own private-key rule
    # requires at least 64 characters of key BODY between the BEGIN and END
    # markers, because its job is "is this a live secret in source control".
    # A forensic examiner has a different question - a bare header with no body
    # still says a private key file was present, which is exactly what a carved
    # fragment, a truncated file or a wiped-but-partially-recovered key looks
    # like. Both patterns ship; the gitleaks one for whole keys, this one for
    # the trace of a key.
    EXTRA_CRED_PATTERNS = [
        r"-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----",
        r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
        # KeePass/1Password/Bitwarden database and export filenames, which are
        # credential stores rather than credentials.
        r"\b\w[\w .-]{0,60}\.kdbx\b",
        r"\b\w[\w .-]{0,60}\.opvault\b",
        r"\bwallet\.dat\b",
    ]

    print("Credentials:")
    creds = json.load(open(os.path.join(HERE, "creds_selected.json"), encoding="utf-8"))
    emit("credentials_api_keys.json",
         "Credentials & API Keys",
         "Cloud, source-hosting, payment and messaging credentials left in files on "
         "a device - AWS and GCP keys, GitHub and GitLab tokens, Slack and Stripe "
         "tokens, private keys, JWTs and more. Adapted from the gitleaks ruleset.",
         [r["regex"] for r in creds] + EXTRA_CRED_PATTERNS,
         True,
         {
             "title": "gitleaks default ruleset (config/gitleaks.toml)",
             "publisher": "gitleaks, Zachary Rice and contributors",
             "url": "https://github.com/gitleaks/gitleaks",
             "licence": "MIT",
             "retrieved": RETRIEVED,
             "adaptation": "gitleaks regexes are Go RE2. Inline (?i) flags are removed "
                           "(this app compiles every keyword list case-insensitively "
                           "already) and \\z is rewritten to \\Z. A curated high-value "
                           "subset of the upstream rules is included, not all of them. A few "
                           "patterns of forensic rather than secret-scanning value are "
                           "added here and are not from gitleaks - see the comment in "
                           "the generator for why (a bare private-key header, credential-"
                           "store filenames).",
         },
         [
             "A match means a credential-SHAPED string is present, not that it is "
             "valid, current, or that it belongs to the device's owner.",
             "Sample and documentation keys (AWS's own AKIAIOSFODNN7EXAMPLE, for "
             "instance) match too - check before treating a hit as a real secret.",
             "RE2 has no backtracking, so upstream never had to guard against "
             "catastrophic patterns. Every pattern here was re-checked against this "
             "app's own ReDoS gate before being bundled.",
         ])

    # --- 3. OFAC sanctioned cryptocurrency addresses ---------------------------
    print("OFAC sanctioned addresses:")
    OFAC_BASE = ("https://raw.githubusercontent.com/0xB10C/"
                 "ofac-sanctioned-digital-currency-addresses/lists/sanctioned_addresses_")
    OFAC_ASSETS = {
        "XBT": ("Bitcoin", "ofac_sanctioned_addresses_bitcoin.json"),
        "ETH": ("Ethereum", "ofac_sanctioned_addresses_ethereum.json"),
        "LTC": ("Litecoin", "ofac_sanctioned_addresses_other.json"),
        "XMR": ("Monero", None),
        "ZEC": ("Zcash", None),
        "DASH": ("Dash", None),
        "BCH": ("Bitcoin Cash", None),
        "XVG": ("Verge", None),
        "ARB": ("Arbitrum", None),
        "BSC": ("BNB Smart Chain", None),
        "TRX": ("Tron", None),
        "USDT": ("Tether", None),
    }
    OFAC_SOURCE = {
        "title": "OFAC sanctioned digital currency addresses",
        "publisher": "US Treasury OFAC (data), 0xB10C (extraction tool)",
        "url": "https://github.com/0xB10C/ofac-sanctioned-digital-currency-addresses",
        "licence": "MIT (extraction tool). The underlying SDN list is published by the "
                   "US Department of the Treasury and is a US Government work.",
        "retrieved": RETRIEVED,
    }
    OFAC_CAVEATS = [
        "This is a dated snapshot. OFAC updates its SDN list continuously and the "
        "upstream extraction regenerates nightly - re-import before relying on it.",
        "An address appearing here means it is on a US sanctions list. It does not "
        "by itself establish who controlled it, or that the device's owner did.",
        "Addresses are matched as whole words, so a hit is an exact address match, "
        "not a shape match like the built-in Bitcoin/Ethereum categories.",
    ]

    fetched = {}
    for code in OFAC_ASSETS:
        try:
            with urllib.request.urlopen(OFAC_BASE + code + ".txt", timeout=30) as r:
                addrs = [ln.strip() for ln in r.read().decode("utf-8").splitlines() if ln.strip()]
            if addrs:
                fetched[code] = addrs
        except Exception as e:
            print(f"    ({code}: not fetched - {e})")

    btc = fetched.pop("XBT", []) + fetched.pop("BTC", [])
    eth = fetched.pop("ETH", [])
    other = []
    other_assets = []
    for code, addrs in sorted(fetched.items()):
        other.extend(addrs)
        other_assets.append(f"{OFAC_ASSETS.get(code, (code,))[0]} ({len(addrs)})")

    if btc:
        emit("ofac_sanctioned_addresses_bitcoin.json",
             "OFAC Sanctioned Addresses - Bitcoin",
             "Bitcoin addresses on the US Treasury's OFAC sanctions list.",
             [word_bounded(a) for a in sorted(set(btc))], True, OFAC_SOURCE, OFAC_CAVEATS)
    if eth:
        emit("ofac_sanctioned_addresses_ethereum.json",
             "OFAC Sanctioned Addresses - Ethereum",
             "Ethereum addresses on the US Treasury's OFAC sanctions list.",
             [word_bounded(a) for a in sorted(set(eth))], True, OFAC_SOURCE, OFAC_CAVEATS)
    if other:
        emit("ofac_sanctioned_addresses_other.json",
             "OFAC Sanctioned Addresses - Other Assets",
             "Sanctioned addresses for assets other than Bitcoin and Ethereum: "
             + ", ".join(other_assets) + ".",
             [word_bounded(a) for a in sorted(set(other))], True, OFAC_SOURCE, OFAC_CAVEATS)

    # --- 4. Anti-forensics / evidence destruction (authored here) --------------
    print("Anti-forensics:")
    AF_TOOLS = [
        # Disk and free-space wipers
        "BleachBit", "CCleaner", "Eraser", "DBAN", "Darik's Boot and Nuke",
        "SDelete", "sdelete64", "KillDisk", "Active@ KillDisk", "BCWipe",
        "CyberScrub", "PrivaZer", "File Shredder", "Freeraser", "WipeFile",
        "Blancco", "ShredIt", "SuperShredder", "Hardwipe", "Disk Wipe",
        "secure-delete", "srm", "shred -u", "shred -z", "wipe -rf",
        "diskpart clean all", "cipher /w", "dd if=/dev/zero", "dd if=/dev/urandom",
        "blkdiscard", "hdparm --security-erase", "nvme format",
        # Trace and artefact cleaners
        "Privacy Eraser", "HistoryKill", "Evidence Eliminator", "Window Washer",
        "Tracks Eraser", "RegSeeker", "Wise Disk Cleaner", "Glary Utilities",
        # Timestamp manipulation
        "timestomp", "SetMace", "nTimestomp", "touch -t", "touch -r", "SetFileTime",
        # Encryption and containers (presence is not wrongdoing - see caveats)
        "VeraCrypt", "TrueCrypt", "CipherShed", "DiskCryptor", "AxCrypt",
        "Cryptomator", "Boxcryptor",
        # Log and event-record destruction
        "wevtutil cl", "Clear-EventLog", "Remove-EventLog", "auditpol /clear",
        "logrotate -f", "journalctl --vacuum-time", "history -c", "unset HISTFILE",
        "HISTFILE=/dev/null", "shred /var/log",
        # Steganography and container hiding
        "OpenStego", "Steghide", "SilentEye", "OutGuess", "StegoSuite",
        "Hidden Volume", "plausible deniability",
        # Anonymity / attribution avoidance
        "Tor Browser", "torrc", "Tails OS", "Whonix", "I2P", "Freenet",
        "MAC address spoof", "macchanger", "ProxyChains",
        # Virtualisation / ephemeral environments used to leave no host trace
        "Sandboxie", "Qubes OS", "live USB persistence",
    ]
    emit("anti_forensics_tools.json",
         "Anti-Forensics & Evidence Destruction Tools",
         "Names and command lines of tools used to wipe disks and free space, erase "
         "browsing and application traces, alter timestamps, clear event logs, hide "
         "data in containers or images, and avoid attribution. Matched as whole words.",
         [word_bounded(t) for t in AF_TOOLS],
         True,
         {
             "title": "Compiled for this project from public sources",
             "publisher": "pi-forensics",
             "url": "",
             "licence": "No third-party content - tool names and command lines are "
                        "facts, not copyrightable expression. Compiled from vendor "
                        "documentation, published research on disk-wiping tools, and "
                        "openly catalogued anti-forensics tooling.",
             "retrieved": RETRIEVED,
         },
         [
             "Several of these are ordinary, legitimate software. VeraCrypt, "
             "Cryptomator and Tor Browser have entirely lawful everyday uses, and "
             "CCleaner ships preinstalled on some systems. Presence proves capability, "
             "never intent.",
             "What matters forensically is usually WHEN a tool ran relative to the "
             "events in the case - check the Evidence Timeline around any hit rather "
             "than treating the hit alone as significant.",
             "The list is not exhaustive. A renamed binary, a portable executable, or "
             "a tool released since this list was written will not appear.",
         ])

    print("\nAll bundled lists written to", OUT)


if __name__ == "__main__":
    main()
