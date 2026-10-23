#!/usr/bin/env python3
"""
coverage.py — Grimnir coverage-ledger reconciler.

Derives, from artifacts that ALREADY exist in an engagement dir, a terminal status
for (a) every in-scope scope entry and (b) every high-value intel item — so untouched
high-value surface becomes visible before an engagement is shelved.

It is the recon-side analog of the evidence gate: a coverage guard rail, not a testing tool.
Reads scope.md, intel.jsonl, */findings/FINDING-*.json, decisions.jsonl, reachability.json,
state.json, and (optionally) ~/.grimnir/tests/test-journal.jsonl.

Usage:
  python3 scripts/coverage.py --project-dir ~/workspace/acme-corp
  python3 scripts/coverage.py --project-dir ~/workspace/acme-corp --json
  python3 scripts/coverage.py --project-dir ~/workspace/acme-corp --gate
  python3 scripts/coverage.py --project-dir ~/workspace/acme-corp --scope-only
  python3 scripts/coverage.py --selftest
"""
from __future__ import annotations

import argparse
import json
import math
import os
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# ── constants ──────────────────────────────────────────────────────────────────

_STOPWORDS: set[str] = {
    "a", "an", "the", "and", "or", "but", "in", "on", "at", "to", "for",
    "of", "with", "by", "from", "is", "are", "was", "were", "be", "been",
    "being", "have", "has", "had", "do", "does", "did", "will", "would",
    "shall", "should", "may", "might", "must", "can", "could", "not", "no",
    "this", "that", "these", "those", "it", "its", "via", "api", "the",
    "http", "https", "com", "org", "net", "app", "all", "any", "each",
    "every", "both", "few", "some", "such", "only", "own", "same", "so",
    "than", "too", "very", "just", "then", "now", "also", "here", "there",
    "when", "where", "which", "over", "under", "into", "during", "before",
    "after", "above", "below", "between", "through", "one", "two", "three",
    "more", "most", "less", "least", "other", "new", "old", "first", "last",
}

# ── normalization ──────────────────────────────────────────────────────────────

def normalize_host(s: str) -> str:
    """Normalize a URL/host string to a bare hostname.

    >>> normalize_host('https://app.example.com:443/x')
    'app.example.com'
    >>> normalize_host('*.example.com/')
    'example.com'
    >>> normalize_host('mobile.example.com:443')
    'mobile.example.com'
    """
    s = s.lower().strip()
    s = re.sub(r'^https?://', '', s)
    s = re.sub(r'^\*\.', '', s)
    s = re.sub(r'^www\.', '', s)
    s = s.split('/')[0]
    s = re.sub(r':\d+$', '', s)
    s = s.rstrip('.')
    return s


# File extensions that should never be treated as TLDs
_FAKE_TLDS: set[str] = {
    'json', 'yaml', 'yml', 'xml', 'html', 'htm', 'css', 'js', 'ts',
    'md', 'txt', 'csv', 'py', 'rb', 'go', 'rs', 'java', 'kt', 'swift',
    'png', 'jpg', 'jpeg', 'gif', 'svg', 'ico', 'pdf', 'zip', 'tar', 'gz',
    'sh', 'bash', 'zsh', 'fish', 'conf', 'ini', 'cfg', 'toml', 'lock',
    'gradle', 'properties', 'strings', 'plist',
    'jsonl', 'ndjson', 'log', 'har', 'pcap', 'env', 'bak', 'tmp',
}


def _looks_like_host(s: str) -> bool:
    """Heuristic: does a string contain a real hostname pattern?
    Excludes common file extensions (foo.json, bar.yaml) that match the dotted-word pattern."""
    s_lower = s.lower()
    for m in re.finditer(r'\b([a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)*([a-z]{2,}))\b', s_lower):
        tld = m.group(2)
        if tld not in _FAKE_TLDS:
            return True
    return False


def _looks_like_app_id(s: str) -> bool:
    """Heuristic: does a string look like a mobile app / bundle id?"""
    s = s.strip()
    if s.isdigit():
        return True
    if s.count('.') >= 1:
        parts = s.split('.')
        if len(parts) >= 2 and all(p and re.match(r'^[a-z][a-z0-9_]*$', p, re.IGNORECASE) for p in parts):
            return True
    return False


# ── keyword extraction ─────────────────────────────────────────────────────────

def _token_variants(tok: str) -> list[str]:
    """Yield a token plus, for hyphen/underscore compounds, its parts.

    Dotted (hostname-shaped) tokens are never split — 'mcp.acme.com' stays whole.
    Splitting lets 'json-rpc' match a corpus that only ever writes 'rpc'.

    >>> _token_variants('json-rpc')
    ['json-rpc', 'json', 'rpc']
    >>> _token_variants('mcp.acme.com')
    ['mcp.acme.com']
    """
    variants = [tok]
    if '.' not in tok and ('-' in tok or '_' in tok):
        for part in re.split(r'[-_]+', tok):
            if part and part not in variants:
                variants.append(part)
    return variants


def _extract_tokens(text: str) -> list[str]:
    """Split text into significant lowercase tokens (len>=3 or dotted hostnames).
    Drops stopwords. Host-like tokens (containing a dot) are kept regardless of length.

    The length floor is 3, not 4, because this domain's most distinctive identifiers are
    three-letter acronyms (mcp, sso, jwt, xss, rce, s3 is handled by the digit rule).

    >>> _extract_tokens('MCP Server (JSON-RPC 2.0)')
    ['mcp', 'server', 'json-rpc', 'json', 'rpc', '2.0']
    >>> _extract_tokens('mcp.target.example.com')
    ['mcp.target.example.com']
    """
    tokens: list[str] = []
    # Split on non-alphanumeric, keeping dots for hostnames.
    # NOTE: the group MUST stay non-capturing — re.findall returns group 1 when a
    # capturing group is present, which silently truncates the first character of
    # every token ('mcp' -> 'cp'). That was a live bug; the doctests above pin it.
    raw = re.findall(r'[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?', text.lower())
    for t in raw:
        t = t.strip('.-_')
        if not t:
            continue
        for cand in _token_variants(t):
            if cand in _STOPWORDS:
                continue
            if '.' in cand:
                # Always keep dotted hostname-looking tokens
                tokens.append(cand)
            elif len(cand) >= 3:
                tokens.append(cand)
    return tokens


def extract_keywords(text: str, limit: int | None = 4) -> list[str]:
    """Extract 2-4 significant keywords from text for matching.
    Host-like tokens are prioritized; plain tokens must be len>=4 and non-stopword."""
    tokens = _extract_tokens(text)
    # De-dupe preserving order
    seen: set[str] = set()
    result: list[str] = []
    for t in tokens:
        if t not in seen:
            seen.add(t)
            result.append(t)
    if limit is not None and len(result) > limit:
        result = result[:limit]
    return result


def _extract_hosts_from_text(text: str) -> list[str]:
    """Extract hostname-like patterns from a text blob, normalized."""
    # Match patterns that look like hostnames: word.word.tld or word.word.word...
    pattern = re.compile(
        r'(?:https?://)?'
        r'(?:\*\.)?'
        r'(?:www\.)?'
        r'([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+(?:\.[a-z]{2,}))'
        r'(?:[/:\x00-\x20\x7f-\xff]|$)',
        re.IGNORECASE,
    )
    hosts: list[str] = []
    for m in pattern.finditer(text):
        host = m.group(1).lower().rstrip('.')
        # Reject reverse-DNS bundle/library ids (net.openid.appauth, com.example.android.app): a real
        # hostname never leads with a web TLD as its first label, but a package id always does.
        if host.split('.', 1)[0] in _WEB_TLDS:
            continue
        if host and host not in hosts:
            hosts.append(host)
    return hosts


# ── parsing: scope.md ──────────────────────────────────────────────────────────

# A heading whose text matches this starts an out-of-scope section: every asset
# under it (until a heading of the same or higher level) is excluded.
_OOS_HEADING_RE = re.compile(
    r"out[\s\-_]?of[\s\-_]?scope|not\s+in\s+scope|exclud|exclusion|never\s+submit"
    r"|ineligible|won'?t\s+pay|do\s+not\s+test|no\s+bounty",
    re.IGNORECASE,
)

# A single row/bullet marked out-of-scope inline, inside an otherwise in-scope section
# (a tier-1 asset table that lists blog/shop subdomains with a ❌ bounty column).
_OOS_ROW_RE = re.compile(
    r"out[\s\-_]?of[\s\-_]?scope|no\s+bounty|not\s+eligible|ineligible|exclud|\bOOS\b|❌",
    re.IGNORECASE,
)

# "NOT excluded" / "not out of scope" is an IN-scope assertion — don't let the row-level
# OOS check fire on it (programs routinely annotate a contested asset exactly this way).
_OOS_NEGATED_RE = re.compile(
    r"\bnot\s+(?:(?:listed|marked|flagged|named|shown)\s+(?:as\s+)?)?"
    r"(?:excluded|out[\s\-_]?of[\s\-_]?scope|ineligible|OOS\b)"
    r"|\b(?:absent|missing)\s+from\s+(?:the\s+)?(?:\w+\s+)?(?:exclusion|out[\s\-_]?of[\s\-_]?scope|OOS)",
    re.IGNORECASE,
)

# Loopback / RFC1918 literals: these show up in proxy + RoE bullets (`http://127.0.0.1:8080`),
# never as a bounty-scoped asset.
_LOCAL_HOST_RE = re.compile(
    r'^(?:127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|0\.0\.0\.0$|localhost$)',
    re.IGNORECASE,
)

# Type-column / row-context keywords that mark a token as a mobile app id rather than a host.
_APP_CONTEXT_KWS = (
    'app', 'store', 'play', 'bundle', 'package', 'apk', 'ipa',
    'android', 'ios', 'apple', 'mobile',
)
_DOMAIN_CONTEXT_KWS = ('wildcard', 'domain', 'url', 'host', 'site', 'web', 'api', 'endpoint')

# Deliberately small and unambiguous. These never appear as the LAST segment of a
# reverse-DNS bundle id, so a name ending in one is a hostname regardless of what its
# first label looks like. Kept narrow on purpose: adding `app` or `dev` here would
# reclassify real bundle ids (com.acme.app) as domains.
_WEB_TLDS = frozenset({'com', 'net', 'org', 'edu', 'gov', 'int', 'mil'})

# Backticked token, optionally wrapped in bold/emphasis: `x`, **`x`**, *`x`*
_BACKTICK_RE = re.compile(r'`([^`]+)`')

# File/code/doc extensions that are ALSO valid TLDs (.md = Moldova, .sh = St Helena) or just read
# host-ish. A token ending in one is a filename from a note (`reachability.md`, `app.js`,
# `creds.json`), never a scoped asset — the coverage denominator must not count it (item 22). Kept
# to unambiguous file extensions; real TLDs in active bug-bounty use (io, co, ai, app, dev) are
# deliberately absent so a genuine `acme.io` host still parses.
_FILE_EXT_RE = re.compile(
    r'\.(?:md|markdown|sh|bash|zsh|py|rb|pl|go|rs|java|c|cpp|js|mjs|cjs|ts|tsx|jsx|json|jsonl|'
    r'ya?ml|toml|ini|cfg|conf|env|txt|log|csv|tsv|xml|html?|css|scss|less|png|jpe?g|gif|svg|'
    r'webp|ico|pdf|zip|tar|gz|lock|bak)$',
    re.IGNORECASE,
)


def _is_doc_filename(token: str) -> bool:
    """True for a filename masquerading as a host/asset token (reachability.md, app.js)."""
    return bool(_FILE_EXT_RE.search(token.strip()))


# An intel identifier that is commentary, not testable surface: `task 8: ...`, a TODO, a step note.
# These never name an asset, so they are dropped rather than counted as an un-swept gap (item 22).
_NOTE_RE = re.compile(r'^\s*(?:task|todo|to-do|note|notes|fixme|tbd|wip|done|step|next|see)\b',
                      re.IGNORECASE)


def _scope_lines(text: str) -> list[tuple[str, bool]]:
    """Split scope.md into (line, in_scope) pairs, tracking out-of-scope headings.

    A heading matching _OOS_HEADING_RE opens an out-of-scope region that ends at the
    next heading of the same or higher level (i.e. nested subsections inherit it).
    """
    out: list[tuple[str, bool]] = []
    oos_level: int | None = None
    for line in text.splitlines():
        hm = re.match(r'^(#+)\s*(.*)$', line)
        if hm:
            level = len(hm.group(1))
            title = hm.group(2)
            if oos_level is not None and level <= oos_level:
                oos_level = None  # closed by a sibling/parent heading
            if _OOS_HEADING_RE.search(title):
                oos_level = level
            out.append((line, oos_level is None))
            continue
        out.append((line, oos_level is None))
    return out


def _classify_scope_token(token: str, context: str) -> tuple[str, str] | None:
    """Map a backticked scope token + its row context to (scope_kind, normalized), or None.

    Context (the whole table row / bullet) decides app-vs-domain when the token shape
    is ambiguous — a bare numeric token is only an app id if the row says iOS/App Store.
    """
    token = token.strip()
    if not token or '@' in token or ' ' in token:
        return None  # emails / prose, never an asset token
    if _is_doc_filename(token):
        return None  # a filename from a note (reachability.md, app.js), not a scoped asset

    # A path-ish token is only an asset if it is a real URL or a `host/` , `host/*` form;
    # otherwise it is a filesystem path from a note (`apk/com.acme.app/`).
    bare = re.sub(r'/\*?$', '', token)
    if '/' in bare and not token.lower().startswith('http'):
        return None
    ctx = context.lower()
    app_ctx = any(kw in ctx for kw in _APP_CONTEXT_KWS)
    domain_ctx = any(kw in ctx for kw in _DOMAIN_CONTEXT_KWS)

    # Bare numeric: an Apple App Store id, and only meaningful with app context.
    if token.isdigit():
        return ('app-id', token) if app_ctx and len(token) >= 6 else None

    if _looks_like_host(token) or token.startswith('http'):
        # A host wins over app context unless the row is explicitly an app-id column
        # (reverse-DNS bundle ids like com.acme.app also satisfy _looks_like_host).
        if app_ctx and not domain_ctx and not token.startswith('http') and _looks_like_app_id(token):
            # Distinguish com.acme.app (bundle) from api.acme.com (host) by TLD position:
            # bundle ids start with the TLD-ish segment (com./io./org.).
            parts = token.lower().split('.')
            first, last = parts[0], parts[-1]
            # ...but the first segment alone is not enough. `app.example.com` is a host
            # whose own first label is in that list, and whose own text supplies the
            # "app" context keyword, so a bare scope bullet with no describing prose
            # classified one of the most common hostnames there is as a bundle id. A
            # name ENDING in an unambiguous web TLD is a host; a reverse-DNS bundle
            # does not (com.acme.app ends in `app`, com.example.android in `android`).
            if first in ('com', 'io', 'org', 'net', 'co', 'app', 'me', 'de', 'fr') \
                    and last not in _WEB_TLDS:
                return ('app-id', token.lower())
        normalized = normalize_host(token)
        if not normalized or _LOCAL_HOST_RE.match(normalized):
            return None
        return ('domain', normalized)

    if _looks_like_app_id(token) and app_ctx:
        return ('app-id', token.lower())

    return None


def parse_scope_md(path: Path) -> list[dict]:
    """Parse scope.md for in-scope assets. Returns list of dicts with keys:
    item, kind, scope_kind (domain|app-id), match_value, keywords.

    Handles the layouts that engagements actually use: markdown tables with the asset
    token in ANY column (not just the second), and `- \\`asset\\` — description` bullet
    lists. Assets under an out-of-scope heading, or on a row marked out-of-scope
    inline, are excluded — reporting an OOS asset as an untested gap is worse than
    missing it.
    """
    items: list[dict] = []
    if not path.is_file():
        return items

    try:
        text = path.read_text()
    except OSError:
        return items

    seen: set[str] = set()

    for line, in_scope in _scope_lines(text):
        if not in_scope:
            continue
        stripped = line.strip()
        is_table_row = stripped.startswith('|')
        is_bullet = bool(re.match(r'^[-*+]\s+', stripped))
        if not (is_table_row or is_bullet):
            continue
        if is_table_row and re.match(r'^\|[\s:|-]+\|?$', stripped):
            continue  # table separator
        if _OOS_ROW_RE.search(stripped) and not _OOS_NEGATED_RE.search(stripped):
            continue

        candidates = [m.group(1) for m in _BACKTICK_RE.finditer(stripped)]
        if not candidates and is_bullet:
            # Bare bullet list (`- *.acme.com (all subdomains)`) — no backticks at all.
            # Only the leading token can be the asset; prose bullets fail classification.
            lead = re.sub(r'^[-*+]\s+', '', stripped)
            lead = re.sub(r'^\*\*(.+?)\*\*', r'\1', lead)
            lead = re.split(r'[\s,;(—–]', lead, maxsplit=1)[0]
            if lead:
                candidates = [lead]
        elif not candidates and is_table_row:
            # Bare table row (`| **api.prod.acme.com** | URL | notes… |`). Only the first
            # two cells are asset columns — the notes column routinely names other hosts.
            cells = [c.strip() for c in stripped.strip('|').split('|')]
            for cell in cells[:2]:
                cell = re.sub(r'^\*\*(.+?)\*\*$', r'\1', cell).strip()
                if cell and ' ' not in cell:
                    candidates.append(cell)

        for token in candidates:
            classified = _classify_scope_token(token, stripped)
            if not classified:
                continue
            scope_kind, normalized = classified
            if normalized in seen:
                continue
            seen.add(normalized)
            items.append({
                'item': normalized,
                'kind': 'scope',
                'scope_kind': scope_kind,
                'match_value': normalized,
                'keywords': _extract_tokens(normalized),
            })

    return items


# ── parsing: intel.jsonl ───────────────────────────────────────────────────────

def parse_intel_jsonl(path: Path) -> list[dict]:
    """Parse intel.jsonl for high-value items only (confidence==high or 'high-value' tag).
    Returns list of dicts with keys: item, kind, intel_id, processed, match_type, match_value, keywords."""
    items: list[dict] = []
    if not path.is_file():
        return items

    try:
        lines = path.read_text().splitlines()
    except OSError:
        return items

    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        # Filter: high-value only
        confidence = str(entry.get('confidence', '')).lower()
        tags: list[str] = entry.get('tags', []) or []
        if confidence != 'high' and 'high-value' not in tags:
            continue

        intel_id = str(entry.get('id', ''))
        processed = bool(entry.get('processed', False))
        # `data` is canonically a dict of structured fields, but some rows carry it as a free-text
        # string (a note blob). Treat a string as a summary field so its embedded hosts are still
        # extracted below, rather than crashing the whole report on `str.get`.
        raw_data = entry.get('data', {})
        if isinstance(raw_data, str):
            data: dict = {'summary': raw_data}
        elif isinstance(raw_data, dict):
            data = raw_data
        else:
            data = {}

        # An intel row is coverage-worthy only if it names real surface — a host/endpoint, or an
        # asset-like label. A row that resolves only to the intel id, 'unknown', or a free-text
        # note is commentary, not a testable asset, and must NOT pad the denominator (item 22): a
        # padded denominator understates real coverage and, at wind-down, reads as "you missed N
        # things" when several were never assets.

        # 1) Every host we can find — the structured host fields AND hosts embedded in text, so a
        #    "insight.x.com / sso.x.com" blob becomes two host items, not one keyword blob.
        host_src = ' '.join(
            str(data.get(k, '')) for k in
            ('url', 'host', 'endpoint', 'affected_endpoint', 'target',
             'summary', 'hint', 'discovered_via', 'context', 'content', 'service', 'location', 'name'))
        hosts: list[str] = []
        for h in _extract_hosts_from_text(host_src):
            if _is_doc_filename(h):
                continue  # reachability.md etc. — a filename, not a host
            nh = normalize_host(h)
            if nh and not _LOCAL_HOST_RE.match(nh) and nh not in hosts:
                hosts.append(nh)

        if hosts:
            for nh in hosts:
                items.append({
                    'item': nh, 'kind': 'intel', 'intel_id': intel_id, 'processed': processed,
                    'match_type': 'host', 'match_value': nh, 'keywords': _extract_tokens(nh),
                })
            continue

        # 2) No host: a keyword item only from an asset-NAMING field (name/service/location/type),
        #    taken whole — these label a real thing (a technology, a service) even without a host.
        identifier = None
        for key in ('name', 'service', 'location', 'type'):
            if data.get(key):
                identifier = str(data[key]).strip().replace('\n', ' ')[:80]
                break
        # A short, non-note descriptive field can still name a lane; a long sentence or a
        # "task N: ..." note is commentary — dropped, not counted as un-swept surface.
        if not identifier:
            for key in ('summary', 'hint', 'discovered_via'):
                v = str(data.get(key, '')).strip().replace('\n', ' ')
                if v and len(v.split()) <= 6 and not _NOTE_RE.match(v):
                    identifier = v[:80]
                    break
        if not identifier or _NOTE_RE.match(identifier) or identifier.lower() == 'unknown':
            continue  # no real asset — drop (was: fall back to the intel id, a phantom UNTOUCHED)

        # match_value is the DISPLAY string (first few tokens); matching uses the full token set.
        keywords = extract_keywords(identifier, limit=None)
        if not keywords:
            continue
        items.append({
            'item': identifier, 'kind': 'intel', 'intel_id': intel_id, 'processed': processed,
            'match_type': 'keyword', 'match_value': ' '.join(keywords[:4]), 'keywords': keywords,
        })

    return items


# ── corpus builders ────────────────────────────────────────────────────────────

def _read_json_file(path: Path) -> dict | None:
    """Read a single JSON file, returning None on any error."""
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def build_tested_corpus(project_dir: Path, project_name: str) -> str:
    """Build the TESTED corpus blob from findings, non-skip decisions, state checkpoints,
    and (optionally) the negatives journal. One big lowercased string."""
    parts: list[str] = []

    # 1. Findings: any JSON under a findings/ dir, at the root or under an agent dir.
    # The filename convention is NOT stable across engagements — FINDING-001.json,
    # specter-FINDING-003-oauth.json, NOMAD-F-002.json have all been used — so match on
    # the directory, not the prefix. A stricter glob silently empties the tested corpus.
    for pattern in ('findings/*.json', '*/findings/*.json', '*/*/findings/*.json'):
        for fpath in sorted(project_dir.glob(pattern)):
            finding = _read_json_file(fpath)
            if finding is None:
                continue
            # Join affected_targets + title + description + reproduction_steps
            for key in ('affected_targets',):
                val = finding.get(key)
                if isinstance(val, list):
                    parts.extend(str(v) for v in val)
            for key in ('title', 'description'):
                val = finding.get(key)
                if isinstance(val, str):
                    parts.append(val)
            steps = finding.get('reproduction_steps')
            if isinstance(steps, list):
                parts.extend(str(s) for s in steps)

    # 2. decisions.jsonl: non-skip types → TESTED corpus
    decisions_path = project_dir / 'decisions.jsonl'
    skip_types = {'skip', 'defer', 'gate-block', 'close'}
    if decisions_path.is_file():
        try:
            for line in decisions_path.read_text().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                dtype = str(entry.get('decision_type', '')).lower()
                reason = str(entry.get('reason', ''))
                if dtype not in skip_types and reason:
                    parts.append(reason)
        except OSError:
            pass

    # 3. state.json: completed_tests + last_completed_action (NOT pending_tests)
    state = _read_json_file(project_dir / 'state.json')
    if state:
        checkpoints = state.get('checkpoints') or {}
        for agent_name, cp in checkpoints.items():
            if not isinstance(cp, dict):
                continue
            completed = cp.get('completed_tests') or []
            if isinstance(completed, list):
                parts.extend(str(t) for t in completed)
            last_action = cp.get('last_completed_action')
            if isinstance(last_action, str) and last_action:
                parts.append(last_action)

    # 4. Negatives journal (host-global, optional): $GRIMNIR_HOME/tests/test-journal.jsonl.
    # test-journal.sh WRITES via $GRIMNIR_HOME, so reading a literal ~/.grimnir here made
    # the gate silently miss every recorded negative on a relocated store.
    journal_path = Path(
        os.path.expanduser(os.environ.get('GRIMNIR_HOME') or '~/.grimnir')
    ) / 'tests' / 'test-journal.jsonl'
    if journal_path.is_file():
        try:
            for line in journal_path.read_text().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if str(entry.get('program', '')).lower() == project_name.lower():
                    for key in ('lane', 'surface', 'reason'):
                        val = entry.get(key)
                        if isinstance(val, str) and val:
                            parts.append(val)
        except OSError:
            pass

    return '\n'.join(parts).lower()


def build_skip_corpus(project_dir: Path) -> str:
    """Build the SKIP corpus from decision types in {skip, defer, gate-block, close}."""
    decisions_path = project_dir / 'decisions.jsonl'
    skip_types = {'skip', 'defer', 'gate-block', 'close'}
    parts: list[str] = []
    if not decisions_path.is_file():
        return ''
    try:
        for line in decisions_path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            dtype = str(entry.get('decision_type', '')).lower()
            if dtype in skip_types:
                reason = str(entry.get('reason', ''))
                entry_id = str(entry.get('id', ''))
                if reason:
                    parts.append(f"{entry_id}: {reason}")
    except OSError:
        return ''
    return '\n'.join(parts).lower()


def parse_reachability(path: Path) -> list[dict]:
    """Parse reachability.json, returning the list of blocking lanes (verdict != REACHABLE).
    Each lane dict has keys: lane, gates, verdict, note, keywords."""
    data = _read_json_file(path)
    if data is None:
        return []
    lanes = data.get('lanes') or []
    blocking: list[dict] = []
    for lane in lanes:
        if not isinstance(lane, dict):
            continue
        verdict = str(lane.get('verdict', '')).strip()
        if verdict == 'REACHABLE' or verdict == 'DONE':
            continue
        lane_text = ' '.join([
            str(lane.get('lane', '')),
            str(lane.get('note', '')),
        ])
        blocking.append({
            'lane': str(lane.get('lane', '')),
            'gates': [str(g) for g in (lane.get('gates') or [])],
            'verdict': verdict,
            'note': str(lane.get('note', '')),
            'keywords': set(_extract_tokens(lane_text)),
        })
    return blocking


# ── presence tests ─────────────────────────────────────────────────────────────

_HOSTNAME_CHARS = frozenset('abcdefghijklmnopqrstuvwxyz0123456789-')


def _boundary_match(needle: str, haystack: str) -> bool:
    """Substring test that respects hostname/app-id boundaries.

    A bare substring test conflates a host with any longer host that merely ENDS in
    it: 'eu1.acme.com' is a substring of 'ccardseu1.acme.com', so one host's skip
    record silently marks a different host covered. The match must therefore start
    and end on a label boundary.

    >>> _boundary_match('acme.com', 'tested app.acme.com today')
    True
    >>> _boundary_match('eu1.acme.com', 'skipped ccardseu1.acme.com')
    False
    >>> _boundary_match('acme.com', 'acme.company.org')
    False
    """
    if not needle:
        return False
    for m in re.finditer(re.escape(needle), haystack):
        before_ok = m.start() == 0 or haystack[m.start() - 1] not in _HOSTNAME_CHARS
        end = m.end()
        after_ok = end == len(haystack) or haystack[end] not in _HOSTNAME_CHARS
        if before_ok and after_ok:
            return True
    return False


def _item_present_in_text(item: dict, text: str) -> bool:
    """Check whether an item (scope or intel) is 'present' in a lowercased text blob."""
    if not text or not item.get('match_value'):
        return False

    match_type = item.get('match_type', 'domain')
    match_value = str(item['match_value']).lower()
    text_lower = text.lower()

    if match_type in ('domain', 'app-id'):
        # scope domain or app-id: boundary-anchored substring test.
        # 'acme.com' matches 'app.acme.com' (label boundary) but NOT 'acmeworks.com'
        # and NOT the tail of 'ccardsacme.com'.
        if _boundary_match(match_value, text_lower):
            return True

    elif match_type == 'host':
        # intel host identifier: normalized host appears at a label boundary OR any
        # corpus host is equal-or-subdomain of this item's host.
        if _boundary_match(match_value, text_lower):
            return True
        # Check if any corpus host is a subdomain of this item's host
        corpus_hosts = _extract_hosts_from_text(text_lower)
        for ch in corpus_hosts:
            if ch == match_value or ch.endswith(f'.{match_value}'):
                return True
            # Also: corpus host might BE the item's parent (item host is subdomain of corpus host)
            if match_value.endswith(f'.{ch}'):
                return True
        return False

    elif match_type == 'keyword':
        # intel keyword: enough of the token set appears. The bar scales with label
        # length so a long prose label cannot be cleared by two incidental hits,
        # while a terse label still needs both of its tokens.
        keywords = item.get('keywords') or []
        if not keywords:
            return False
        matches = sum(1 for kw in keywords if kw in text_lower)
        if len(keywords) < 2:
            return matches >= len(keywords)
        threshold = max(2, math.ceil(0.4 * len(keywords)))
        return matches >= threshold

    return False


def _item_in_skip(item: dict, skip_corpus: str) -> str | None:
    """Check if item is named in the SKIP corpus. Returns evidence string or None."""
    if not skip_corpus:
        return None
    # Re-use the same presence logic against the skip corpus
    if _item_present_in_text(item, skip_corpus):
        # Try to find the specific skip decision line that mentions it
        for line in skip_corpus.splitlines():
            if _item_present_in_text(item, line):
                # Return short evidence: decision id + truncated reason
                evidence = line.strip()[:70]
                return evidence
        return 'skip-record'
    return None


def _item_gated(item: dict, blocking_lanes: list[dict]) -> str | None:
    """Check if item overlaps a blocking reachability lane. Returns gate evidence or None."""
    if not blocking_lanes:
        return None

    item_kws = set(item.get('keywords') or [])
    # Also add the match_value itself and its dot-separated components
    match_value = str(item.get('match_value', '')).lower()
    if match_value:
        item_kws.add(match_value)
        for part in match_value.replace('-', '.').replace('_', '.').split('.'):
            part = part.strip()
            if part and len(part) >= 2:
                item_kws.add(part)

    for lane in blocking_lanes:
        lane_kws = lane.get('keywords', set())
        if item_kws & lane_kws:
            gates = lane.get('gates', [])
            if gates:
                return f"gate: {', '.join(gates)}"
            return f"gate: {lane.get('verdict', 'GATED').lower()}"
    return None


# ── terminal-state resolution ──────────────────────────────────────────────────

def resolve_status(item: dict, tested_corpus: str, skip_corpus: str,
                   blocking_lanes: list[dict]) -> tuple[str, str]:
    """Resolve an item to one of: TESTED, SKIPPED, GATED, UNTOUCHED.
    Returns (status, evidence). Precedence: TESTED > SKIPPED > GATED > UNTOUCHED."""
    # 1. TESTED
    if _item_present_in_text(item, tested_corpus):
        return ('TESTED', 'found in findings/decisions/state corpus')

    # 2. SKIPPED
    skip_evidence = _item_in_skip(item, skip_corpus)
    if skip_evidence:
        return ('SKIPPED', skip_evidence)

    # 3. GATED
    gate_evidence = _item_gated(item, blocking_lanes)
    if gate_evidence:
        return ('GATED', gate_evidence)

    # 4. UNTOUCHED
    return ('UNTOUCHED', '—')


# ── core runner ────────────────────────────────────────────────────────────────

def run(project_dir: Path, *, scope_only: bool = False) -> dict:
    """Run the full coverage reconciliation. Returns a results dict suitable for
    formatting (text or json)."""
    project_dir = project_dir.resolve()
    project_name = project_dir.name

    # Try to get project_name from state.json
    state = _read_json_file(project_dir / 'state.json')
    if state and isinstance(state.get('project_name'), str):
        project_name = state['project_name']

    # Parse inputs
    scope_path = project_dir / 'scope.md'
    scope_items = parse_scope_md(scope_path)
    intel_items: list[dict] = []
    if not scope_only:
        intel_items = parse_intel_jsonl(project_dir / 'intel.jsonl')

    # Scope-intake guard: zero parsed scope entries is NOT a clean sheet. Without it an
    # engagement that never did scope intake reconciles 0 items and reports vacuous 100%
    # coverage — a green light for a surface nobody ever enumerated.
    if scope_items:
        intake_status = 'ok'
    elif not scope_path.is_file():
        intake_status = 'missing'
    else:
        intake_status = 'unparseable'
    scope_intake = {
        'status': intake_status,
        'entries': len(scope_items),
        'path': str(scope_path),
    }

    # Build corpora
    tested_corpus = build_tested_corpus(project_dir, project_name)
    skip_corpus = build_skip_corpus(project_dir)
    blocking_lanes = parse_reachability(project_dir / 'reachability.json')

    # Resolve status for each item
    results: list[dict] = []
    for item in scope_items + intel_items:
        status, evidence = resolve_status(item, tested_corpus, skip_corpus, blocking_lanes)
        results.append({
            'item': item['item'],
            'kind': item['kind'],
            'intel_id': item.get('intel_id', ''),
            'status': status,
            'evidence': evidence,
            'reachable_gap': status == 'UNTOUCHED',
        })

    # Sort: UNTOUCHED first, then GATED, SKIPPED, TESTED
    sort_order = {'UNTOUCHED': 0, 'GATED': 1, 'SKIPPED': 2, 'TESTED': 3}
    results.sort(key=lambda r: (sort_order.get(r['status'], 9), r['item']))

    # Summary
    counts = {'TESTED': 0, 'SKIPPED': 0, 'GATED': 0, 'UNTOUCHED': 0}
    for r in results:
        counts[r['status']] = counts.get(r['status'], 0) + 1

    total = len(results)
    untouched = counts['UNTOUCHED']
    tested = counts['TESTED']
    # Undefined, not 100%: nothing was reconciled, so nothing was covered.
    coverage_pct = round(100.0 * (total - untouched) / total, 1) if total > 0 else None

    # Hard list: reachable + untouched (not gated)
    hard_list = [r for r in results if r['reachable_gap']]
    # Scope items before intel items in hard list
    hard_list.sort(key=lambda r: (0 if r['kind'] == 'scope' else 1, r['item']))

    return {
        'project': project_name,
        'project_dir': str(project_dir),
        'generated_at': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'summary': {
            'total': total,
            'tested': tested,
            'skipped': counts['SKIPPED'],
            'gated': counts['GATED'],
            'untouched': untouched,
            'coverage_pct': coverage_pct,
        },
        'scope_intake': scope_intake,
        'items': results,
        'hard_list': [r['item'] for r in hard_list],
    }


_INTAKE_MSG = {
    'missing': 'no scope.md in the engagement dir — scope intake never ran',
    'unparseable': 'scope.md has no parseable in-scope assets — check its format',
}


def intake_failure(data: dict) -> str | None:
    """Return the gate-failure reason if scope intake is not usable, else None."""
    status = (data.get('scope_intake') or {}).get('status', 'ok')
    return _INTAKE_MSG.get(status)


# ── output formatters ──────────────────────────────────────────────────────────

def format_text(data: dict) -> str:
    """Render results as a human-readable text table."""
    lines: list[str] = []
    proj = data['project']
    ts = data['generated_at']
    lines.append(f"Project: {proj}  (generated {ts})")
    lines.append("")

    intake_problem = intake_failure(data)
    if intake_problem:
        lines.append(f"⚠ SCOPE INTAKE: {intake_problem}")
        lines.append("  Coverage below is NOT a clean sheet — in-scope assets were never enumerated.")
        lines.append("")

    items = data['items']
    if not items:
        lines.append("(no items to reconcile)")
        return '\n'.join(lines)

    # Column widths
    item_w = min(max(len(_format_item_label(r)) for r in items), 62)
    kind_w = 5
    status_w = 10
    evid_w = 70

    # Header
    header = (f"{'ITEM':<{item_w}}  {'KIND':<{kind_w}}  {'STATUS':<{status_w}}  EVIDENCE")
    lines.append(header)
    lines.append('-' * len(header))

    for r in items:
        item_label = _format_item_label(r)
        evidence = r['evidence'][:evid_w]
        lines.append(
            f"{item_label:<{item_w}}  {r['kind']:<{kind_w}}  {r['status']:<{status_w}}  {evidence}"
        )

    lines.append("")
    s = data['summary']
    pct = 'n/a' if s['coverage_pct'] is None else f"{s['coverage_pct']}%"
    lines.append(f"Total: {s['total']}  |  TESTED: {s['tested']}  SKIPPED: {s['skipped']}  "
                 f"GATED: {s['gated']}  UNTOUCHED: {s['untouched']}  |  "
                 f"Coverage: {pct}")

    lines.append("")
    hard_list = [r for r in items if r['reachable_gap']]
    if hard_list:
        lines.append("⚠ REACHABLE + UNTOUCHED (account for before wind-down):")
        for r in hard_list:
            label = _format_item_label(r)
            lines.append(f"  - {label}")
    elif intake_problem:
        lines.append("⚠ no untouched items, but scope intake is unusable — see above.")
    else:
        lines.append("✓ none — every must-cover item reached a terminal state.")

    return '\n'.join(lines)


def _format_item_label(r: dict) -> str:
    """Format an item for display in the table. Intel items get their id prefix."""
    if r['kind'] == 'intel' and r.get('intel_id'):
        return f"{r['intel_id']} {r['item']}"
    return r['item']


def format_json(data: dict) -> str:
    """Render results as JSON."""
    # Build a JSON-safe output (drop internal match fields from items)
    clean_items = []
    for r in data['items']:
        clean_items.append({
            'item': r['item'],
            'kind': r['kind'],
            'intel_id': r.get('intel_id', ''),
            'status': r['status'],
            'evidence': r['evidence'],
            'reachable_gap': r['reachable_gap'],
        })
    return json.dumps({
        'project': data['project'],
        'generated_at': data['generated_at'],
        'summary': data['summary'],
        'scope_intake': data.get('scope_intake', {}),
        'items': clean_items,
        'hard_list': data['hard_list'],
    }, indent=2)


# ── selftest ───────────────────────────────────────────────────────────────────

def _selftest_tokenizer() -> list[str]:
    """Regression cases for the token extractor. Each pins a bug that shipped once."""
    errors: list[str] = []

    # A capturing group in the findall pattern makes re.findall return group 1, which
    # silently drops the first character of every token ('mcp' -> 'cp').
    toks = _extract_tokens('MCP Server')
    if 'mcp' not in toks:
        errors.append(f"tokenizer truncation regression: 'MCP Server' -> {toks} (expected 'mcp')")
    if _extract_tokens('mcp.target.example.com') != ['mcp.target.example.com']:
        errors.append(f"host token mangled: {_extract_tokens('mcp.target.example.com')}")

    # Three-letter acronyms are this domain's most distinctive identifiers.
    for acronym, phrase in (('mcp', 'MCP endpoint'), ('sso', 'SSO login'), ('jwt', 'JWT claims')):
        if acronym not in _extract_tokens(phrase):
            errors.append(f"acronym {acronym!r} dropped from {phrase!r}")

    # Hyphen compounds must also yield their parts.
    if 'rpc' not in _extract_tokens('JSON-RPC 2.0'):
        errors.append("compound split regression: 'JSON-RPC' did not yield 'rpc'")

    # Keyword selection must not be positional: a distinctive trailing token has to
    # survive a label whose leading tokens are prose filler.
    kws = extract_keywords('Fender app JS yielded 1,535+ API paths via /ajax/*', limit=None)
    if 'ajax' not in kws:
        errors.append(f"distinctive trailing token lost: {kws}")

    return errors


def cmd_selftest(_args) -> int:
    """Run a built-in synthetic fixture and assert the four states resolve correctly."""
    tokenizer_errors = _selftest_tokenizer()

    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)

        # scope.md with two wildcards + one app id
        (tdp / 'scope.md').write_text("""# Scope

## In-Scope Assets

| WILDCARD | `*.alpha.example/` | [Y] |
| WILDCARD | `*.beta.example/` | [Y] |
| GOOGLE_PLAY_APP_ID | `com.acme.app` | [Y] |

- lane matrix in `reachability.md`; notes in `test-plan.md`
""")

        # intel.jsonl with two high-value items
        (tdp / 'intel.jsonl').write_text(
            json.dumps({
                'id': 'INTEL-000001', 'timestamp': '2026-01-01T00:00:00Z',
                'source_agent': 'huginn', 'discovery_type': 'endpoint',
                'data': {'url': 'api.alpha.example'},
                'confidence': 'high', 'tags': ['needs-specter'], 'processed': False,
            }) + '\n' +
            json.dumps({
                'id': 'INTEL-000002', 'timestamp': '2026-01-01T00:00:00Z',
                'source_agent': 'huginn', 'discovery_type': 'endpoint',
                'data': {'url': 'secret.gamma.example'},
                'confidence': 'high', 'tags': ['high-value'], 'processed': False,
            }) + '\n' +
            # Technology-shaped item: no host to anchor on, generic vendor-neutral label.
            # The corpus below exercises it, so it must reconcile to TESTED.
            json.dumps({
                'id': 'INTEL-000003', 'timestamp': '2026-01-01T00:00:00Z',
                'source_agent': 'huginn', 'discovery_type': 'technology',
                'data': {'name': 'MCP Server (JSON-RPC 2.0)', 'category': 'ai'},
                'confidence': 'confirmed', 'tags': ['high-value'], 'processed': False,
            }) + '\n' +
            # Same shape, never exercised — proves the keyword path still fails loud.
            json.dumps({
                'id': 'INTEL-000004', 'timestamp': '2026-01-01T00:00:00Z',
                'source_agent': 'huginn', 'discovery_type': 'technology',
                'data': {'name': 'Kerberos KDC ticket service', 'category': 'auth'},
                'confidence': 'confirmed', 'tags': ['high-value'], 'processed': False,
            }) + '\n' +
            # item 22 — a task NOTE, not an asset: must be DROPPED (was a phantom UNTOUCHED).
            json.dumps({
                'id': 'INTEL-000005', 'timestamp': '2026-01-01T00:00:00Z',
                'source_agent': 'huginn', 'discovery_type': 'note',
                'data': {'summary': 'task 8: DSAR gateway entry point'},
                'confidence': 'high', 'tags': ['high-value'], 'processed': False,
            }) + '\n' +
            # item 22 — a multi-host prose blob: must SPLIT into one item per host.
            json.dumps({
                'id': 'INTEL-000006', 'timestamp': '2026-01-01T00:00:00Z',
                'source_agent': 'huginn', 'discovery_type': 'endpoint',
                'data': {'summary': 'seen on insight.gamma.example / sso.gamma.example'},
                'confidence': 'high', 'tags': ['high-value'], 'processed': False,
            }) + '\n' +
            # item 22 — empty data (would have fallen back to the intel id): must be DROPPED.
            json.dumps({
                'id': 'INTEL-000007', 'timestamp': '2026-01-01T00:00:00Z',
                'source_agent': 'huginn', 'discovery_type': 'note',
                'data': {}, 'confidence': 'high', 'tags': ['high-value'], 'processed': False,
            }) + '\n'
        )

        # One finding that tests alpha.example
        (tdp / 'specter').mkdir(parents=True, exist_ok=True)
        (tdp / 'specter' / 'findings').mkdir(parents=True, exist_ok=True)
        (tdp / 'specter' / 'findings' / 'FINDING-001.json').write_text(json.dumps({
            'id': 'FINDING-001',
            'title': 'Info disclosure on api.alpha.example',
            'severity': 'low',
            'description': 'Found exposed endpoint on alpha.example returning debug info.',
            'agent': 'specter',
            'affected_targets': ['api.alpha.example'],
            'reproduction_steps': ['GET /debug on api.alpha.example'],
            'validation': {'state': 'confirmed'},
        }))

        # decisions.jsonl with one skip (beta.example) and one engage (alpha context)
        (tdp / 'decisions.jsonl').write_text(
            json.dumps({
                'id': 'DECISION-000001', 'timestamp': '2026-01-01T00:00:00Z',
                'actor': 'grimnir', 'source': 'reasoning',
                'decision_type': 'engage',
                'reason': 'Engaged project — alpha.example surface prioritized. '
                      'Enumerated the MCP server over JSON-RPC: 12 tools, 2 prompts.',
            }) + '\n' +
            json.dumps({
                'id': 'DECISION-000002', 'timestamp': '2026-01-01T00:00:00Z',
                'actor': 'grimnir', 'source': 'reasoning',
                'decision_type': 'skip',
                'reason': 'beta.example deprioritized — low value',
            }) + '\n'
        )

        # reachability.json with a blocking lane for the mobile app
        (tdp / 'reachability.json').write_text(json.dumps({
            'gates_held': {'device': False},
            'lanes': [
                {
                    'lane': 'mobile app com.acme.app',
                    'class': 'MOBILE',
                    'gates': ['device'],
                    'verdict': 'GATED',
                    'note': 'emulator needed for com.acme.app',
                },
            ],
        }))

        # state.json with minimal checkpoints
        (tdp / 'state.json').write_text(json.dumps({
            'project_name': 'selftest',
            'checkpoints': {
                'specter': {
                    'completed_tests': ['INFO-disclosure-alpha'],
                    'last_completed_action': 'Tested api.alpha.example',
                    'pending_tests': [],
                },
            },
        }))

        data = run(tdp)

        # Assertions
        by_item = {}
        for r in data['items']:
            key = r['item']
            # For intel items, use intel_id as key
            if r['kind'] == 'intel':
                key = r.get('intel_id', r['item'])
            by_item[key] = r

        errors: list[str] = list(tokenizer_errors)

        # alpha.example → TESTED
        r = by_item.get('alpha.example')
        if r is None:
            errors.append("alpha.example not found in results")
        elif r['status'] != 'TESTED':
            errors.append(f"alpha.example expected TESTED, got {r['status']}")

        # beta.example → SKIPPED
        r = by_item.get('beta.example')
        if r is None:
            errors.append("beta.example not found in results")
        elif r['status'] != 'SKIPPED':
            errors.append(f"beta.example expected SKIPPED, got {r['status']}")

        # com.acme.app → GATED
        r = by_item.get('com.acme.app')
        if r is None:
            errors.append("com.acme.app not found in results")
        elif r['status'] != 'GATED':
            errors.append(f"com.acme.app expected GATED, got {r['status']}")

        # INTEL-000001 (api.alpha.example) → TESTED
        r = by_item.get('INTEL-000001')
        if r is None:
            errors.append("INTEL-000001 not found in results")
        elif r['status'] != 'TESTED':
            errors.append(f"INTEL-000001 expected TESTED, got {r['status']}")

        # INTEL-000002 (secret.gamma.example) → UNTOUCHED
        r = by_item.get('INTEL-000002')
        if r is None:
            errors.append("INTEL-000002 not found in results")
        elif r['status'] != 'UNTOUCHED':
            errors.append(f"INTEL-000002 expected UNTOUCHED, got {r['status']}")

        # INTEL-000003 (technology label, no host, exercised in corpus) → TESTED
        r = by_item.get('INTEL-000003')
        if r is None:
            errors.append("INTEL-000003 not found in results")
        elif r['status'] != 'TESTED':
            errors.append(f"INTEL-000003 (technology label) expected TESTED, got {r['status']}")

        # INTEL-000004 (technology label, never exercised) → UNTOUCHED
        r = by_item.get('INTEL-000004')
        if r is None:
            errors.append("INTEL-000004 not found in results")
        elif r['status'] != 'UNTOUCHED':
            errors.append(f"INTEL-000004 (unexercised label) expected UNTOUCHED, got {r['status']}")

        # item 22 — the coverage denominator must not be padded with parse artifacts.
        item_values = {r['item'] for r in data['items']}
        for phantom in ('reachability.md', 'test-plan.md'):
            if phantom in item_values:
                errors.append(f"doc filename {phantom!r} leaked into coverage items (scope parse artifact)")
        intel_ids_present = {r.get('intel_id') for r in data['items'] if r['kind'] == 'intel'}
        for dropped in ('INTEL-000005', 'INTEL-000007'):
            if dropped in intel_ids_present:
                errors.append(f"label-only intel {dropped} became a phantom UNTOUCHED item")
        for h in ('insight.gamma.example', 'sso.gamma.example'):
            if h not in item_values:
                errors.append(f"multi-host intel blob did not split into host item {h!r}")

        # --gate logic: should be non-zero because INTEL-000002 is UNTOUCHED
        has_untouched_reachable = any(r['reachable_gap'] for r in data['items'])
        if not has_untouched_reachable:
            errors.append("--gate should detect reachable+untouched item (INTEL-000002)")

        # Scope intake parsed cleanly on the fixture.
        if data['scope_intake']['status'] != 'ok':
            errors.append(f"fixture scope intake expected ok, got {data['scope_intake']['status']}")
        if intake_failure(data) is not None:
            errors.append("fixture should not trip the scope-intake guard")

        # Scope-intake guard: a dir with no scope.md must NOT read as clean coverage.
        with tempfile.TemporaryDirectory() as bare_dir:
            bare = run(Path(bare_dir))
            if bare['scope_intake']['status'] != 'missing':
                errors.append(f"missing scope.md expected status 'missing', got {bare['scope_intake']['status']}")
            if bare['summary']['coverage_pct'] is not None:
                errors.append("empty engagement must report coverage n/a, not a percentage")
            if intake_failure(bare) is None:
                errors.append("missing scope.md must trip the scope-intake guard")

        # An unparseable scope.md is distinguished from a missing one.
        with tempfile.TemporaryDirectory() as blank_dir:
            (Path(blank_dir) / 'scope.md').write_text("# Scope\n\nTBD — pending program brief.\n")
            blank = run(Path(blank_dir))
            if blank['scope_intake']['status'] != 'unparseable':
                errors.append(f"contentless scope.md expected 'unparseable', got {blank['scope_intake']['status']}")
            if intake_failure(blank) is None:
                errors.append("unparseable scope.md must trip the scope-intake guard")

        if errors:
            print(f"SELFTEST: FAIL: {'; '.join(errors)}")
            return 1

    print("SELFTEST: PASS")
    return 0


# ── commands ───────────────────────────────────────────────────────────────────

def cmd_run(args) -> int:
    """Run coverage reconciliation against a project directory."""
    project_dir = Path(args.project_dir)
    if not project_dir.is_absolute():
        sys.stderr.write("--project-dir must be an absolute path\n")
        return 2
    if not project_dir.is_dir():
        sys.stderr.write(f"no such directory: {project_dir}\n")
        return 2

    data = run(project_dir, scope_only=args.scope_only)

    if args.format == 'json':
        print(format_json(data))
    else:
        print(format_text(data))

    # --gate: exit 1 if scope intake is unusable, or any item is UNTOUCHED-and-reachable
    if args.gate:
        failed = False
        intake_problem = intake_failure(data)
        if intake_problem:
            sys.stderr.write(f"coverage gate: {intake_problem}\n")
            failed = True
        if data['hard_list']:
            sys.stderr.write(f"coverage gate: {len(data['hard_list'])} reachable + untouched item(s)\n")
            failed = True
        return 1 if failed else 0

    return 0


def main() -> int:
    p = argparse.ArgumentParser(
        prog='coverage.py',
        description='Grimnir coverage-ledger reconciler — surface untouched high-value target surface.',
    )
    p.add_argument(
        '--project-dir', required=False,
        help='Absolute path to the engagement directory.',
    )
    p.add_argument(
        '--format', choices=['text', 'json'], default='text',
        help='Output format (default: text).',
    )
    p.add_argument(
        '--gate', action='store_true',
        help='Exit 1 if scope intake is missing/unparseable, or any must-cover item '
             'is REACHABLE + UNTOUCHED.',
    )
    p.add_argument(
        '--scope-only', action='store_true',
        help='Only evaluate scope entries; skip intel items.',
    )
    p.add_argument(
        '--selftest', action='store_true',
        help='Run the built-in synthetic fixture (no --project-dir needed).',
    )
    args = p.parse_args()

    if args.selftest:
        return cmd_selftest(args)

    if not args.project_dir:
        p.error('--project-dir is required (or use --selftest)')

    return cmd_run(args)


if __name__ == '__main__':
    sys.exit(main())
