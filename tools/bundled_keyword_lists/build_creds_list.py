"""Builds the bundled "Credentials & API Keys" keyword list from gitleaks.

gitleaks is MIT (Zachary Rice, 2019). Its regexes are Go RE2, which has no
backtracking, so upstream has never needed to care about catastrophic
behaviour - a rule that is instant there can hang Python's engine. Every
pattern kept here therefore has to clear this app's own ReDoS gate, exactly as
an examiner-authored list would.

Two mechanical adaptations RE2 -> Python re:
  - Inline (?i) anywhere but position 0 is a hard error in Python. It is also
    redundant here: build_scan_patterns() compiles every keyword list with
    re.IGNORECASE already. Stripped.
  - \\z (Go end-of-text) is \\Z in Python.
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from core.case_index_db import check_regex_pattern_for_redos

HERE = os.path.dirname(os.path.abspath(__file__))
rules = json.load(open(os.path.join(HERE, "gitleaks_rules.json"), encoding="utf-8"))
by_id = {r["id"]: r["regex"] for r in rules}

# Re-parse the full file so rules that only failed on (?i)/\z are recoverable.
raw = open(os.path.join(HERE, "gitleaks.toml"), encoding="utf-8").read()
ID_RE = re.compile(r'^\s*id\s*=\s*"([^"]+)"', re.M)
TRIPLE_RE = re.compile(r"^\s*regex\s*=\s*'''(.*?)'''", re.M | re.S)
for block in raw.split("[[rules]]")[1:]:
    m_id, m_rx = ID_RE.search(block), TRIPLE_RE.search(block)
    if m_id and m_rx:
        by_id.setdefault(m_id.group(1), m_rx.group(1).strip())

# The high-value set: credentials whose presence on a suspect device is worth
# an examiner's attention, and whose patterns are specific enough not to drown
# them. Deliberately not all 221 - most of the rest are niche SaaS tokens that
# would add noise without adding reach.
WANTED = [
    # Cloud providers
    "aws-access-token", "gcp-api-key", "gcp-service-account",
    "azure-ad-client-secret", "alibaba-access-key-id",
    # Source hosting / CI
    "github-pat", "github-fine-grained-pat", "github-oauth", "github-app-token",
    "github-refresh-token", "gitlab-pat", "gitlab-ptt", "gitlab-rrt",
    "bitbucket-client-id", "bitbucket-client-secret",
    # Messaging / collaboration
    "slack-bot-token", "slack-user-token", "slack-app-token",
    "slack-config-access-token", "slack-legacy-token", "slack-webhook-url",
    "discord-api-token", "discord-client-secret", "telegram-bot-api-token",
    # Payments / commerce
    "stripe-access-token", "square-access-token", "squarespace-access-token",
    "paypal-braintree-access-token", "shopify-access-token",
    "shopify-custom-access-token", "shopify-private-app-access-token",
    "shopify-shared-secret",
    # Comms / email
    "sendgrid-api-token", "mailchimp-api-key", "mailgun-private-api-token",
    "mailgun-pub-key", "twilio-api-key",
    # Keys and tokens of general interest
    "private-key", "jwt", "openai-api-key", "anthropic-api-key",
    "npm-access-token", "pypi-upload-token", "rubygems-api-token",
    "hashicorp-tf-api-token", "digitalocean-pat", "digitalocean-access-token",
    "heroku-api-key", "cloudflare-api-key", "cloudflare-global-api-key",
    "datadog-access-token", "dropbox-api-token", "dropbox-long-lived-api-token",
    "atlassian-api-token", "asana-client-secret", "algolia-api-key",
    "linear-api-key", "sentry-access-token", "grafana-api-key",
    "planetscale-password", "planetscale-api-token", "postman-api-token",
    "readme-api-token", "sumologic-access-token", "typeform-api-token",
    "yandex-api-key", "zendesk-secret-key", "age-secret-key",
    "okta-access-token", "new-relic-user-api-key", "netlify-access-token",
    "flutterwave-secret-key", "frameio-api-token", "clojars-api-token",
    "codecov-access-token", "coinbase-access-token", "confluent-secret-key",
]

INLINE_FLAG_RE = re.compile(r"\(\?i\)")


def adapt(pattern):
    """RE2 -> Python re. Returns None if it still will not compile."""
    p = INLINE_FLAG_RE.sub("", pattern)
    p = p.replace(r"\z", r"\Z")
    try:
        re.compile(p)
    except re.error:
        return None
    return p


kept, dropped = [], []
for rule_id in WANTED:
    src = by_id.get(rule_id)
    if src is None:
        dropped.append((rule_id, "not present in this gitleaks version"))
        continue
    adapted = adapt(src)
    if adapted is None:
        dropped.append((rule_id, "does not compile under Python re even after adaptation"))
        continue
    kept.append({"id": rule_id, "regex": adapted})

print(f"selected {len(kept)} of {len(WANTED)} wanted rules")
for rid, why in dropped:
    print("  dropped:", rid, "-", why)

# The real gate: the COMBINED alternation is what build_scan_patterns()
# compiles and runs, so check exactly that, not each term in isolation.
combined = "|".join(f"(?:{r['regex']})" for r in kept)
compiled = re.compile(combined.encode("utf-8"), re.IGNORECASE)
verdict = check_regex_pattern_for_redos(compiled)
print("combined ReDoS verdict:", verdict or "CLEAN")

if verdict:
    print("REFUSING to emit a list that fails the app's own ReDoS gate.")
    sys.exit(1)

json.dump(kept, open(os.path.join(HERE, "creds_selected.json"), "w", encoding="utf-8"), indent=1)
print("wrote creds_selected.json")
