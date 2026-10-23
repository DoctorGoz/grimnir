#!/usr/bin/env python3
"""js-endpoints.py — memory-safe endpoint/secret extractor for JS bundles.

Why this exists: `grep`/`ugrep` OOMs on minified JS (a whole bundle is often one
multi-hundred-KB line, and line-buffering tools try to hold the entire line). This
reads each file INDIVIDUALLY with Python (a few MB is nothing for Python) and uses
regex over the string, so it cannot OOM on a single long line the way a streaming
line-grep does. Use this instead of grep for any JS/bundle mining.

Usage:
    python3 scripts/js-endpoints.py <dir> [--host REGEX] [--paths] [--secrets] [--all]

    <dir>          directory to walk (recurses; default: cwd)
    --host REGEX   also collect absolute URLs whose host matches REGEX
                   (e.g. --host 'bridge\\.xyz'); defaults to any http(s) URL
    --paths        print API-ish paths (default on if no selector given)
    --secrets      print secret-ish matches (keys/tokens)
    --all          paths + secrets + absolute URLs

Output groups matches, and tags anything that looks like a token/session/mint/
hosted flow (generate/sign/mint/session/token/otp/verify/kyc/ephemeral/reveal/
hosted/link/agreement/consent...) — the classes most worth testing uncredentialed.
"""
import re, os, sys, argparse

EXTS = ('.js', '.mjs', '.cjs', '.json', '.map', '.txt', '.html')

PATH_RE   = re.compile(r'/(?:v\d+|api|dashboard|hosted|internal|admin|graphql)/[A-Za-z0-9_{}:.?=&/-]{1,100}')
GENPATH_RE= re.compile(r'["\'`](/[A-Za-z0-9_][A-Za-z0-9_{}:./-]{2,90})["\'`]')
SECRET_RE = re.compile(r'(?:api[_-]?key|apikey|secret|token|password|bearer|client[_-]?secret|access[_-]?key)'
                       r'["\'`\s:=]{1,4}["\'`]([A-Za-z0-9_\-./+=]{12,})["\'`]', re.I)
MINT_RE   = re.compile(r'generate|sign|mint|session|token|otp|verify|approv|attest|kyc|verification|'
                       r'ephemeral|provision|reveal|_pin|agreement|consent|hosted|magic|redeem|claim|'
                       r'card_details|whoami', re.I)

def walk(d):
    for root, _, files in os.walk(d):
        for f in files:
            if f.lower().endswith(EXTS):
                yield os.path.join(root, f)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('dir', nargs='?', default='.')
    ap.add_argument('--host')
    ap.add_argument('--paths', action='store_true')
    ap.add_argument('--secrets', action='store_true')
    ap.add_argument('--all', action='store_true')
    a = ap.parse_args()
    if not (a.paths or a.secrets or a.all):
        a.paths = True

    host_re = re.compile(r'https?://[a-z0-9.-]*' + a.host + r'[A-Za-z0-9_{}:.?=&/-]{0,100}', re.I) if a.host \
        else re.compile(r'https?://[A-Za-z0-9_.:-]+/[A-Za-z0-9_{}:.?=&/-]{0,100}')

    paths, secrets, urls = set(), set(), set()
    per_file = {}
    for fp in sorted(walk(a.dir)):
        try:
            with open(fp, 'r', errors='ignore') as fh:
                data = fh.read()          # per-file read: bounded, cannot OOM on one long line
        except Exception:
            continue
        p = set(PATH_RE.findall(data)) | {m for m in GENPATH_RE.findall(data)}
        s = set(SECRET_RE.findall(data))
        u = set(host_re.findall(data)) if (a.all or a.host) else set()
        if p or s or u:
            per_file[fp] = (len(p), len(s), len(u))
        paths |= p; secrets |= s; urls |= u

    def dump(title, items, tag_mint=False):
        print(f"\n### {title} ({len(items)})")
        for x in sorted({i.rstrip('?&=.') for i in items}):
            tag = '   <<< token/session/mint/hosted flow' if (tag_mint and MINT_RE.search(x)) else ''
            print(f"  {x}{tag}")

    if a.paths or a.all:
        dump("API-ish paths", paths, tag_mint=True)
    if a.secrets or a.all:
        dump("secret-ish matches", secrets)
    if a.all or a.host:
        dump("absolute URLs", urls, tag_mint=True)

    print(f"\n### files with matches (paths, secrets, urls)")
    for fp, c in sorted(per_file.items(), key=lambda kv: -sum(kv[1])):
        print(f"  {c[0]:3} {c[1]:3} {c[2]:3}  {fp}")
    print(f"\nTOTAL paths={len(paths)} secrets={len(secrets)} urls={len(urls)}")

if __name__ == '__main__':
    main()
