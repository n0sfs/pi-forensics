"""Redaction for exported reports (2026-11-21).

A Redactor replaces examiner-listed terms and, optionally, every email
address, phone number and payment-card number with "[REDACTED]". The
report export applies it twice: to the case data before the report is
built (so a value is replaced before any cell is shortened to fit, which
could otherwise leave a partial match behind), and to every string the PDF
canvas or the HTML document finally carries, which catches text the
builders read from the case folder themselves.

Hashes stay readable: every pattern must start and end on a token
boundary, so a run of digits inside a hex hash, serial or path component
never matches. Embedded images are not redacted - the export pane says so.
"""
import html
import re

REDACTION_MARK = "[REDACTED]"
REDACTION_MAX_TERMS = 200
REDACTION_TERM_MAX_LEN = 200
REDACTION_CATEGORIES = ("emails", "phones", "cards")

_EMAIL_RE = re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}(?![\w-])")
# Optional +country code, then a 2-4 digit area/prefix in brackets or followed
# by a separator, then two 3-4 digit groups. Requiring separators between the
# groups keeps plain counters, sizes and timestamps out.
_PHONE_RE = re.compile(r"(?<![\w+.:/-])(?:\+\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)\s?|\d{2,4}[\s.-])\d{3,4}[\s.-]\d{3,4}(?![\w.:/-])")
_CARD_RE = re.compile(r"(?<![\w-])\d(?:[ -]?\d){12,18}(?![\w-])")


def _luhn_ok(digits):
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


class RedactionError(ValueError):
    pass


class Redactor:
    """Callable str -> str. `count` is the number of replacements made."""

    def __init__(self, terms=(), emails=False, phones=False, cards=False):
        clean = []
        for t in terms or ():
            t = str(t).strip()
            if not t:
                continue
            if len(t) < 2:
                raise RedactionError(f"Redaction term '{t}' is too short - use at least 2 characters.")
            if len(t) > REDACTION_TERM_MAX_LEN:
                raise RedactionError(f"A redaction term is longer than {REDACTION_TERM_MAX_LEN} characters.")
            clean.append(t)
        if len(clean) > REDACTION_MAX_TERMS:
            raise RedactionError(f"Too many redaction terms - max {REDACTION_MAX_TERMS}.")
        # Longest first, so "John Smith" wins over "John".
        clean = sorted(set(clean), key=len, reverse=True)
        self.terms = clean
        self.categories = [c for c, on in (("emails", emails), ("phones", phones), ("cards", cards)) if on]
        self._term_re = re.compile("|".join(re.escape(t) for t in clean), re.IGNORECASE) if clean else None
        # The same terms as they appear inside HTML text (& < > " ' escaped).
        escaped = sorted({html.escape(t) for t in clean} - set(clean), key=len, reverse=True)
        self._term_html_re = re.compile("|".join(re.escape(t) for t in escaped), re.IGNORECASE) if escaped else None
        self.count = 0

    @classmethod
    def from_request(cls, spec):
        """None when the request asks for no redaction."""
        if not spec or not isinstance(spec, dict):
            return None
        terms = spec.get('terms') or []
        if isinstance(terms, str):
            terms = terms.splitlines()
        if not isinstance(terms, list):
            raise RedactionError("Redaction terms must be a list.")
        r = cls(terms, emails=bool(spec.get('emails')), phones=bool(spec.get('phones')), cards=bool(spec.get('cards')))
        return r if (r.terms or r.categories) else None

    def _sub(self, pattern, text, check=None):
        def repl(m):
            if check and not check(m.group(0)):
                return m.group(0)
            self.count += 1
            return REDACTION_MARK
        return pattern.sub(repl, text)

    def __call__(self, text):
        if not isinstance(text, str) or not text:
            return text
        # Whole patterns first: a term inside an email address would otherwise
        # leave the rest of the address (john@[REDACTED].co.uk) unmatched.
        if "emails" in self.categories:
            text = self._sub(_EMAIL_RE, text)
        if "cards" in self.categories:
            text = self._sub(_CARD_RE, text, check=lambda s: _luhn_ok(re.sub(r"\D", "", s)))
        if "phones" in self.categories:
            text = self._sub(_PHONE_RE, text)
        if self._term_re:
            text = self._sub(self._term_re, text)
        if self._term_html_re:
            text = self._sub(self._term_html_re, text)
        return text

    def deep(self, obj):
        """A copy of obj (dict/list/str nest) with every string redacted. Dict
        keys are left alone - they are field names, not case data."""
        if isinstance(obj, str):
            return self(obj)
        if isinstance(obj, dict):
            return {k: self.deep(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return type(obj)(self.deep(v) for v in obj)
        return obj

    _TEXT_RE = re.compile(r">([^<]+)<")
    _ATTR_RE = re.compile(r'(\s(?:title|alt|aria-label)=")([^"]*)(")')

    def html_document(self, doc):
        """Redacts the text between tags (including script/style bodies) and
        title/alt/aria-label attribute values of a generated HTML document."""
        doc = self._TEXT_RE.sub(lambda m: ">" + self(m.group(1)) + "<", doc)
        return self._ATTR_RE.sub(lambda m: m.group(1) + self(m.group(2)) + m.group(3), doc)

    def summary(self):
        return {"terms": len(self.terms), "categories": self.categories, "replacements": self.count}
