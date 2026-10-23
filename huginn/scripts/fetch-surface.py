#!/usr/bin/env python3
"""
fetch-surface.py — tag server-side-fetch surfaces in an asset map (HUGINN Phase 0).

Why this exists. The SSRF playbook family is split by WHERE the fetch lives — a
fetch-by-URL feature, a processing pipeline, a rendering bot, an outbound callback — and
`playbook.py match` selects lanes from signal tokens. Nothing was emitting those tokens, so
the surface-specific lanes either never matched or (worse) had to key off the bare word
`ssrf` appearing anywhere in the engagement text, which fired all of them on every target
at a critical ceiling. This pass produces the real signals.

What it is NOT. A hit here is a *lane to consider*, never a finding. The evidence is a URL
shape, which is a hint about what the server probably does; Specter still has to confirm the
server dereferences anything. Keep the precision honest: a query parameter literally named
`url` is strong, a path containing `preview` is weak, and the output records which.

Usage:
  fetch-surface.py --project-dir DIR [--write] [--json]
  fetch-surface.py --asset-map PATH  [--write] [--json]

Without --write it reports and changes nothing. With --write it adds `.fetch_surfaces` and
merges tags into matching `.endpoints[]`, idempotently.
"""
import argparse
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit, parse_qs

# ── Signal rules ──────────────────────────────────────────────────────────────
# (signal, confidence, kind, pattern). `kind` says what the pattern is matched against:
#   param  -> a query-parameter NAME (exact, case-insensitive)
#   path   -> a substring of the URL path (case-insensitive)
# Confidence is recorded in the output so a weak hint is never mistaken for a strong one.
PARAM_RULES = [
    # A parameter whose name IS a URL is the strongest signal in this whole file.
    ("url_fetch", "strong", {"url", "uri", "src", "source", "href", "link", "target",
                             "dest", "destination", "endpoint", "fetch", "load", "u"}),
    ("import_from_url", "strong", {"import_url", "importurl", "remote_url", "remoteurl",
                                   "remote_attachment_url", "attachment_url", "upload_url",
                                   "download_url", "file_url", "fileurl", "document_url"}),
    ("avatar_url", "strong", {"avatar", "avatar_url", "logo", "logo_url", "icon", "icon_uri",
                              "iconurl", "banner", "image", "image_url", "imageurl", "photo"}),
    ("callback_url", "strong", {"callback", "callback_url", "callbackurl", "webhook",
                                "webhook_url", "hook", "notify_url", "postback"}),
    ("feed_url", "moderate", {"feed", "feed_url", "rss", "rss_url", "atom", "sitemap"}),
    ("proxy_param", "moderate", {"proxy", "proxy_url", "via", "through"}),
]

# Path rules match whole path SEGMENTS, not substrings. Real asset maps proved why: a
# `/opengraph` substring matched the asset `opengraphimage.png`, and `/meta` matched
# `/files/{id}/metadata/enterprise/...`. Both are the context-free keyword failure this
# repo already has a name for. A needle is a tuple of consecutive segments to match exactly.
PATH_RULES = [
    ("image_proxy", "strong", [("imageproxy",), ("image-proxy",), ("img-proxy",),
                               ("_next", "image"), ("cdn-cgi", "image"), ("proxy", "image"),
                               ("i", "proxy"), ("resize",)]),
    ("link_preview", "strong", [("unfurl",), ("link-preview",), ("linkpreview",), ("oembed",),
                                ("opengraph",), ("og-scrape",), ("metascraper",),
                                ("url-preview",)]),
    ("screenshot", "strong", [("screenshot",), ("screenshots",), ("snapshot",), ("capture",),
                              ("page-image",), ("render-page",), ("webshot",)]),
    ("pdf_export", "strong", [("pdf",), ("to-pdf",), ("topdf",), ("print-pdf",),
                              ("export", "pdf"), ("render", "pdf"), ("generate-pdf",)]),
    ("transcode", "strong", [("transcode",), ("encode",), ("ffmpeg",), ("convert", "video"),
                             ("media", "convert")]),
    ("thumbnail", "strong", [("thumbnail",), ("thumbnails",), ("thumb",), ("poster",),
                             ("preview-image",)]),
    ("document_convert", "strong", [("convert",), ("docconvert",), ("libreoffice",),
                                    ("office", "preview"), ("doc-preview",)]),
    ("delivery_log", "strong", [("deliveries",), ("webhook-log",), ("webhook-logs",),
                                ("hook-logs",), ("delivery-history",)]),
    ("webhook", "strong", [("webhook",), ("webhooks",), ("hooks",),
                           ("integrations", "hook"), ("subscriptions", "callback")]),
    ("file_upload", "moderate", [("upload",), ("uploads",), ("attachment",), ("attachments",),
                                 ("media", "upload")]),
    ("import_from_url", "moderate", [("import",), ("imports",), ("fetch-remote",),
                                     ("from-url",)]),
    ("page_preview", "weak", [("preview",), ("embed",)]),
    ("og_scraper", "weak", [("scrape",), ("scraper",)]),
]

# Paths ending in one of these are static assets, not endpoints that fetch anything.
ASSET_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".svg", ".ico", ".bmp",
             ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp4", ".webm", ".mp3",
             ".wav", ".zip", ".gz", ".map", ".txt", ".xml"}

# Technology names that mean a headless engine is in the stack, i.e. the rendering-bot lane.
TECH_RULES = [
    ("headless_browser", ["puppeteer", "playwright", "chromium", "headless", "phantomjs",
                          "selenium", "splash"]),
    ("media_processing", ["ffmpeg", "imagemagick", "graphicsmagick", "libvips", "gd"]),
    ("document_convert", ["libreoffice", "openoffice", "ghostscript", "pandoc", "unoconv"]),
    ("pdf_render", ["wkhtmltopdf", "weasyprint", "prince", "puppeteer", "pdfkit", "tcpdf"]),
]

# JS symbols that name a client-side caller of a server-side fetch feature.
JS_SYMBOL_RULES = [
    ("url_fetch", ["fetchremote", "loadexternal", "proxyrequest", "fetchurl", "fetchbyurl",
                   "downloadfrom", "importfromurl", "getremote"]),
    ("link_preview", ["getpreview", "unfurl", "fetchoembed", "linkpreview", "fetchmetadata"]),
    ("screenshot", ["takescreenshot", "capturepage", "renderscreenshot"]),
]


def _segs_match(segs: list[str], needles) -> bool:
    """True if any needle (a tuple of consecutive path segments) appears in `segs`."""
    for needle in needles:
        n = len(needle)
        for i in range(len(segs) - n + 1):
            if tuple(segs[i:i + n]) == needle:
                return True
    return False


URLISH = re.compile(r"^(?:https?://|/)[^\s\"\'<>]{1,2048}$")


def _iter_urls(am):
    """Every URL-ish string reachable in the asset map, with the endpoint index that owns
    it when there is one.

    Shape tolerance is not optional here. Audited across a real corpus of 44 asset maps,
    only 34 used the canonical {endpoints: [{url: ...}]} shape; ten used ten different
    ad-hoc shapes and one was a top-level array. Two of them crashed an earlier version of
    this function outright -- `js_analysis.api_endpoints_found` holding a COUNT instead of a
    list, and a list at the root. `playbook.py` already carries a schema-tolerant fallback
    for the same reason; this is the same defence, and a crash here would silently drop the
    whole SSRF surface signal for a quarter of engagements.
    """
    seen: set[str] = set()

    def emit(idx, v):
        if not isinstance(v, str):
            return None
        s = v.strip()
        if not s or len(s) > 2048 or not URLISH.match(s):
            return None
        key = f"{idx}\x00{s}"
        if key in seen:
            return None
        seen.add(key)
        return (idx, s)

    # Fast path: the canonical shape, which is the only one whose hits are taggable.
    if isinstance(am, dict) and isinstance(am.get("endpoints"), list):
        for i, ep in enumerate(am["endpoints"]):
            if isinstance(ep, dict):
                for key in ("url", "path", "endpoint", "uri"):
                    r = emit(i, ep.get(key))
                    if r:
                        yield r
            else:
                r = emit(i, ep)
                if r:
                    yield r

    # Tolerant walk over everything else. Untaggable (idx None) but still a signal.
    stack = [am]
    budget = 200_000
    while stack and budget > 0:
        node = stack.pop()
        budget -= 1
        if isinstance(node, dict):
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
        elif isinstance(node, str):
            r = emit(None, node)
            if r:
                yield r


def scan(am, extra_text: str = "") -> dict:
    """Return {signal: {confidence, evidence[], endpoint_idx[]}} for one asset map."""
    found: dict[str, dict] = {}

    def note(signal, confidence, evidence, idx=None):
        rec = found.setdefault(signal, {"confidence": confidence, "evidence": [],
                                        "endpoint_idx": []})
        # keep the strongest confidence seen for a signal
        order = {"weak": 0, "moderate": 1, "strong": 2}
        if order[confidence] > order[rec["confidence"]]:
            rec["confidence"] = confidence
        if evidence not in rec["evidence"] and len(rec["evidence"]) < 8:
            rec["evidence"].append(evidence)
        if idx is not None and idx not in rec["endpoint_idx"]:
            rec["endpoint_idx"].append(idx)

    for idx, raw in _iter_urls(am):
        try:
            parts = urlsplit(raw if "://" in raw else f"http://x/{raw.lstrip('/')}")
        except ValueError:
            continue
        path = (parts.path or "").lower()
        qs = parse_qs(parts.query or "", keep_blank_values=True)
        names = {k.lower() for k in qs}

        # A parameter on a static asset is still a parameter, but a static PATH never
        # describes a fetch feature -- skip path rules for it, keep param rules.
        dot = path.rfind(".")
        is_asset = dot > 0 and path[dot:] in ASSET_EXT

        for signal, conf, wanted in PARAM_RULES:
            hit = names & wanted
            if hit:
                note(signal, conf, f"?{sorted(hit)[0]}= on {path or '/'}", idx)

        if is_asset:
            continue

        segs = [s for s in path.split("/") if s]
        for signal, conf, needles in PATH_RULES:
            if _segs_match(segs, needles):
                note(signal, conf, f"path {path}", idx)

    techs = []
    tech_src = am.get("technologies") if isinstance(am, dict) else None
    for t in (tech_src if isinstance(tech_src, list) else []):
        if isinstance(t, dict) and t.get("name"):
            techs.append(str(t["name"]).lower())
        elif isinstance(t, str):
            techs.append(t.lower())
    # A non-canonical asset map still names its stack somewhere; fall back to the raw text
    # rather than reporting no headless engine on a shape we did not anticipate.
    tech_blob = " ".join(techs) if techs else json.dumps(am)[:400_000].lower()
    for signal, needles in TECH_RULES:
        for n in needles:
            if n in tech_blob:
                note(signal, "strong", f"technology {n}")
                break

    blob = extra_text.lower()
    if blob:
        for signal, needles in JS_SYMBOL_RULES:
            for n in needles:
                if n in blob:
                    note(signal, "moderate", f"js symbol {n}")
                    break

    # A hit sourced only from a JS string blob has no owning endpoint, so it is a lead
    # rather than an observed surface. Cap those at moderate so the confidence column
    # keeps meaning something.
    for rec in found.values():
        if not rec["endpoint_idx"] and rec["confidence"] == "strong":
            rec["confidence"] = "moderate"
    return found


def main() -> int:
    ap = argparse.ArgumentParser(prog="fetch-surface")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--project-dir")
    g.add_argument("--asset-map")
    ap.add_argument("--write", action="store_true",
                    help="persist .fetch_surfaces and merge endpoint tags (default: report only)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    a = ap.parse_args()

    if a.asset_map:
        amp = Path(a.asset_map)
        recon = amp.parent / "recon"
    else:
        amp = Path(a.project_dir) / "asset-map.json"
        recon = Path(a.project_dir) / "recon"
    if not amp.is_file():
        sys.stderr.write(f"no asset map at {amp}\n")
        return 2
    try:
        am = json.loads(amp.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        sys.stderr.write(f"could not read {amp}: {exc}\n")
        return 2

    extra = ""
    for name in ("js-interesting.txt", "js-endpoints.txt"):
        f = recon / name
        if f.is_file():
            try:
                extra += "\n" + f.read_text(errors="replace")[:400_000]
            except OSError:
                pass

    found = scan(am, extra)

    if a.json:
        print(json.dumps({"asset_map": str(amp), "fetch_surfaces": found}, indent=2))
    else:
        if not found:
            print("no server-side-fetch surfaces detected")
        else:
            print(f"fetch surfaces in {amp}:")
            for sig in sorted(found, key=lambda s: (-len(found[s]["endpoint_idx"]), s)):
                r = found[sig]
                print(f"  {sig:<18} [{r['confidence']:<8}] "
                      f"{len(r['endpoint_idx'])} endpoint(s)  e.g. {r['evidence'][0]}")
            print("\nThese are lanes to consider, not findings. Confirm the server "
                  "dereferences anything before treating one as a primitive.")

    if a.write and found:
        if not isinstance(am, dict):
            print("\n--write skipped: asset map root is not an object, so there is nowhere "
                  "to record fetch_surfaces without rewriting its shape.", file=sys.stderr)
            return 0
        am["fetch_surfaces"] = [
            {"surface": s, "confidence": r["confidence"], "evidence": r["evidence"],
             "endpoints": len(r["endpoint_idx"])}
            for s, r in sorted(found.items())
        ]
        eps = am.get("endpoints") if isinstance(am, dict) else None
        eps = eps if isinstance(eps, list) else []
        for sig, r in found.items():
            for i in r["endpoint_idx"]:
                if 0 <= i < len(eps) and isinstance(eps[i], dict):
                    tags = eps[i].setdefault("tags", [])
                    if sig not in tags:
                        tags.append(sig)
        amp.write_text(json.dumps(am, indent=2) + "\n")
        print(f"\nwrote {len(am['fetch_surfaces'])} surface(s) + endpoint tags to {amp}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
