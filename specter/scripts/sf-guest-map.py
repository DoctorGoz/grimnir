#!/usr/bin/env python3
"""sf-guest-map.py — map what a Salesforce Experience Cloud GUEST session exposes (read-only).

Follows the reproduction skeleton in specter/docs/salesforce-experience-cloud.md:

  1. GET <site>/s/ and extract fwuid + appId (the aura.context a guest POST needs).
  2. Find the live aura endpoint (/s/sfsites/aura, /aura, /sfsites/aura) with a catalog call.
  3. getConfigData  -> object catalog (apiNamesToKeyPrefixes), custom objects flagged (__c).
  4. getItems       -> per-object row count (pageSize 1: counts, not data), preceded by a garbage-object
                       NEGATIVE CONTROL, since getItems is not an existence oracle.
  5. getObjectInfo  -> field map per custom object; secret-looking field names flagged.
  6. Apex name harvest from everything already saved (apex://, compound://c). Names only.

Read-only by construction: it never reads individual records, never invokes Apex, never downloads
files and never writes. Paced (--delay), bounded (--max-requests), one retry after a cooldown on a
5xx, one re-bootstrap on clientOutOfSync. Every response is saved verbatim under
<out>/evidence/. Egress: every request rides the program's egress proxy (scripts/egress.py) or the
run refuses with exit 4.

  sf-guest-map.py https://site.example.com [--project-dir DIR] [--out DIR] [--delay 1.0]
                  [--max-requests 120] [--objects A,B] [--max-info 25] [--cooldown 10] [--json]

Reading the result: a count of 0 on a standard object is guest sharing working as designed. A
non-zero count on a business object, or a flagged field on a custom object, is a lead to confirm
by hand with the minimum data that proves it, not a finding by itself.
"""
import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if os.path.join(_REPO, "scripts") not in sys.path:
    sys.path.insert(0, os.path.join(_REPO, "scripts"))
import egress as _egress  # noqa: E402

ENDPOINTS = ["/s/sfsites/aura", "/aura", "/sfsites/aura"]
CTRL = "serviceComponent://ui.force.components.controllers."
D_CONFIG = CTRL + "hostConfig.HostConfigController/ACTION$getConfigData"
D_ITEMS = (CTRL + "lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems")
D_INFO = "aura://RecordUiController/ACTION$getObjectInfo"
APP = "siteforce:communityApp"
APP_KEY = "APPLICATION@markup://" + APP
GARBAGE_OBJECT = "Zzq_Nonexistent_Control__c"
SECRET_FIELD = re.compile(
    r"(password|passwd|pwd|secret|token|api[_]?key|apikey|credential|totp|otp|ssn|hash|private[_]?key|"
    r"salt|session)", re.I)
_RE_APEX = re.compile(r"apex(?:://|%3a%2f%2f)([A-Za-z0-9_.]+)(?:/ACTION\$|%2FACTION%24)?([A-Za-z0-9_]*)", re.I)
_RE_COMPOUND = re.compile(r"compound://c\.([A-Za-z0-9_]+)")


class Budget(Exception):
    pass


# ── pure parsing ───────────────────────────────────────────────────────────────
def extract_context(html: str):
    """(fwuid, appId) from the /s/ bootstrap, tolerant of plain and URL-encoded forms."""
    text = html
    for _ in range(2):
        text = urllib.parse.unquote(text).replace("\\/", "/").replace('\\"', '"')
    fw = re.search(r'"fwuid"\s*:\s*"([^"]+)"', text)
    app = re.search(re.escape(APP_KEY) + r'"\s*:\s*"([^"]+)"', text)
    return (fw.group(1) if fw else None, app.group(1) if app else None)


def parse_aura(text: str):
    """Aura bodies are JSON, sometimes behind a `*/` or `while(1);` guard. None if not parseable."""
    i = text.find("{")
    if i < 0:
        return None
    try:
        return json.loads(text[i:])
    except ValueError:
        return None


def first_action(parsed):
    """(state, returnValue, error_text) of the first action in a parsed aura response."""
    if not isinstance(parsed, dict):
        return "NO_JSON", None, ""
    acts = parsed.get("actions") or []
    if not acts:
        ev = json.dumps(parsed.get("event") or parsed)[:200]
        return ("OUT_OF_SYNC" if "clientOutOfSync" in ev else "NO_ACTIONS"), None, ev
    a = acts[0]
    err = json.dumps(a.get("error") or "")[:300] if a.get("error") else ""
    return a.get("state", "UNKNOWN"), a.get("returnValue"), err


def row_count(rv) -> int:
    if not isinstance(rv, dict):
        return 0
    for k in ("totalCount", "count", "total"):
        if isinstance(rv.get(k), int):
            return rv[k]
    res = rv.get("result")
    return len(res) if isinstance(res, list) else 0


def harvest_apex(texts) -> dict:
    classes, comps = set(), set()
    for t in texts:
        for m in _RE_APEX.finditer(t):
            classes.add(m.group(1) + ("." + m.group(2) if m.group(2) else ""))
        comps.update(_RE_COMPOUND.findall(t))
    return {"apex_refs": sorted(classes), "custom_components": sorted(comps)}


# ── session ────────────────────────────────────────────────────────────────────
class Mapper:
    def __init__(self, base, out, send, delay=1.0, max_requests=120, cooldown=10.0, sleep=time.sleep):
        self.base, self.out, self.send = base.rstrip("/"), out, send
        self.delay, self.max_requests, self.cooldown, self.sleep = delay, max_requests, cooldown, sleep
        self.n = 0
        self.fwuid = self.app_id = self.endpoint = None
        self.index = []
        self.texts = []
        os.makedirs(os.path.join(out, "evidence"), exist_ok=True)

    def _save(self, label, method, url, body, status, text):
        self.n_saved = getattr(self, "n_saved", 0) + 1
        name = f"{self.n_saved:03d}-{re.sub(r'[^A-Za-z0-9_.-]', '_', label)[:60]}"
        with open(os.path.join(self.out, "evidence", name + ".txt"), "w") as fh:
            fh.write(f"{method} {url}\n\n{body or ''}\n\n--- HTTP {status} ---\n{text}")
        self.texts.append(text)
        self.index.append({"label": label, "file": f"evidence/{name}.txt", "status": status, "bytes": len(text)})

    def _request(self, label, method, url, body=None):
        if self.n >= self.max_requests:
            raise Budget()
        if self.n:
            self.sleep(self.delay)
        self.n += 1
        status, text = self.send(method, url, body)
        if status >= 500 and status != 0:            # rate-limit/backoff, not a block: cool down, retry once
            self._save(label + "-5xx", method, url, body, status, text)
            self.sleep(self.cooldown)
            if self.n >= self.max_requests:
                raise Budget()
            self.n += 1
            status, text = self.send(method, url, body)
        self._save(label, method, url, body, status, text)
        return status, text

    def bootstrap(self):
        st, html = self._request("bootstrap", "GET", self.base + "/s/")
        self.fwuid, self.app_id = extract_context(html)
        return st, bool(self.fwuid and self.app_id)

    def _form(self, descriptor, params):
        ctx = {"mode": "PROD", "fwuid": self.fwuid, "app": APP, "loaded": {APP_KEY: self.app_id},
               "dn": [], "globals": {}, "uad": False}
        msg = {"actions": [{"id": "1", "descriptor": descriptor, "callingDescriptor": "UNKNOWN",
                            "params": params}]}
        return urllib.parse.urlencode({"message": json.dumps(msg), "aura.context": json.dumps(ctx),
                                       "aura.pageURI": "/s/", "aura.token": "undefined"})

    def action(self, label, descriptor, params, _retry=True):
        url = self.base + (self.endpoint or ENDPOINTS[0])
        st, text = self._request(label, "POST", url, self._form(descriptor, params))
        state, rv, err = first_action(parse_aura(text))
        if state == "OUT_OF_SYNC" and _retry:         # framework rebuilt: re-extract once
            self.bootstrap()
            return self.action(label + "-resync", descriptor, params, _retry=False)
        return st, state, rv, err

    def find_endpoint(self):
        for ep in ENDPOINTS:
            self.endpoint = ep
            st, state, rv, _ = self.action("endpoint" + ep.replace("/", "_"), D_CONFIG, {})
            if state == "SUCCESS" and isinstance(rv, dict):
                return rv
        self.endpoint = None
        return None

    def run(self, only=None, max_info=25):
        rec = {"base": self.base, "started": datetime.now(timezone.utc).isoformat(), "notes": [],
               "fwuid": None, "app_id": None, "endpoint": None, "objects": {}, "control": {}}
        try:
            st, ok = self.bootstrap()
            rec["fwuid"], rec["app_id"] = self.fwuid, self.app_id
            if not ok:
                rec["notes"].append(f"no fwuid/appId in /s/ (HTTP {st}): not an Experience Cloud site, "
                                    "or the bootstrap moved; fingerprint by hand")
                return self._finish(rec)
            cfg = self.find_endpoint()
            rec["endpoint"] = self.endpoint
            if cfg is None:
                rec["notes"].append("no aura endpoint answered getConfigData with SUCCESS: API access may be "
                                    "off for the guest profile, or the context is stale")
                return self._finish(rec)
            catalog = cfg.get("apiNamesToKeyPrefixes") or {}
            rec["notes"].append(f"catalog: {len(catalog)} guest-visible objects")
            # negative control: a garbage object must read as empty, or counts below mean nothing
            _, cstate, crv, _ = self.action("control-getItems", D_ITEMS, self._items(GARBAGE_OBJECT))
            rec["control"] = {"object": GARBAGE_OBJECT, "state": cstate, "rows": row_count(crv)}
            if rec["control"]["rows"]:
                rec["notes"].append("negative control returned rows: counts are NOT trustworthy")
            names = sorted(catalog) if not only else list(only)
            for obj in names:
                _, state, rv, err = self.action("items-" + obj, D_ITEMS, self._items(obj))
                rec["objects"][obj] = {"prefix": catalog.get(obj), "custom": obj.endswith("__c"),
                                       "state": state, "rows": row_count(rv) if state == "SUCCESS" else None,
                                       "error": err or None, "fields": None, "flagged_fields": []}
            custom = [o for o in names if o.endswith("__c")]
            nonempty = [o for o in names if (rec["objects"][o]["rows"] or 0) > 0 and o not in custom]
            for obj in (custom + nonempty)[:max_info]:
                _, state, rv, _ = self.action("info-" + obj, D_INFO, {"objectApiName": obj})
                fields = sorted((rv or {}).get("fields", {})) if state == "SUCCESS" and isinstance(rv, dict) else []
                rec["objects"][obj]["fields"] = len(fields)
                rec["objects"][obj]["flagged_fields"] = [f for f in fields if SECRET_FIELD.search(f)]
        except Budget:
            rec["notes"].append(f"stopped at --max-requests {self.max_requests}; results are partial")
        return self._finish(rec)

    @staticmethod
    def _items(obj):
        return {"entityNameOrId": obj, "layoutType": "FULL", "pageSize": 1, "currentPage": 0, "getCount": True}

    def _finish(self, rec):
        rec["apex"] = harvest_apex(self.texts)
        rec["requests"] = self.n
        rec["leads"] = [o for o, v in rec["objects"].items()
                        if (v["rows"] or 0) > 0 or v["flagged_fields"]]
        rec["evidence_index"] = self.index
        with open(os.path.join(self.out, "summary.json"), "w") as fh:
            json.dump(rec, fh, indent=2)
        return rec


# ── transport ──────────────────────────────────────────────────────────────────
def make_send(timeout=20):
    """Raises EgressError up front if the configured proxy is unusable: refuse, never go direct."""
    opener = _egress.opener(proxy=_egress.proxy())

    def send(method, url, body):
        req = urllib.request.Request(url, data=body.encode() if body else None, method=method)
        req.add_header("User-Agent", "Mozilla/5.0 (compatible; security-assessment)")
        if body:
            req.add_header("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
        try:
            with opener.open(req, timeout=timeout) as r:
                return r.status, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace")
        except Exception as e:
            return 0, f"transport error: {e}"
    return send


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="sf-guest-map.py", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("site", help="site base URL, e.g. https://site.example.com or https://x.example.com/prefix")
    ap.add_argument("--project-dir", help="engagement dir (egress proxy from roe.json; default evidence root)")
    ap.add_argument("--out", help="output dir (default <project-dir>/specter/recon/sf-guest-<ts>)")
    ap.add_argument("--delay", type=float, default=1.0, help="seconds between requests (RoE pacing)")
    ap.add_argument("--max-requests", type=int, default=120)
    ap.add_argument("--cooldown", type=float, default=10.0, help="seconds to wait before the one retry after a 5xx")
    ap.add_argument("--objects", help="comma-separated object API names to probe instead of the full catalog")
    ap.add_argument("--max-info", type=int, default=25, help="max objects to fetch getObjectInfo for")
    ap.add_argument("--json", action="store_true", help="print summary JSON to stdout")
    a = ap.parse_args(argv)

    if a.project_dir:
        _egress.init(a.project_dir)
    try:
        send = make_send()
    except _egress.EgressError as e:
        print(f"sf-guest-map.py: refusing to run: {e}", file=sys.stderr)
        return 4
    root = a.project_dir or os.getcwd()
    out = a.out or os.path.join(root, "specter", "recon", "sf-guest-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
    m = Mapper(a.site, out, send, delay=a.delay, max_requests=a.max_requests, cooldown=a.cooldown)
    rec = m.run(only=a.objects.split(",") if a.objects else None, max_info=a.max_info)

    if a.json:
        print(json.dumps(rec, indent=2))
    else:
        print(f"===== sf-guest-map: {a.site} =====")
        print(f"  endpoint: {rec['endpoint']}  fwuid: {rec['fwuid']}  requests: {rec['requests']}")
        print(f"  negative control: {rec['control']}")
        for o, v in rec["objects"].items():
            if (v["rows"] or 0) > 0 or v["flagged_fields"]:
                print(f"  LEAD {o}: rows={v['rows']} flagged_fields={v['flagged_fields']}")
        print(f"  apex refs: {len(rec['apex']['apex_refs'])}  custom components: {len(rec['apex']['custom_components'])}")
        for n in rec["notes"]:
            print(f"  note: {n}")
        print(f"  evidence + summary.json: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
