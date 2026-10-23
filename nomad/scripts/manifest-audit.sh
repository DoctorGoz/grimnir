#!/bin/bash
set -euo pipefail
# Nomad — AndroidManifest audit: exported components, risky flags, permissions.
# Usage: manifest-audit.sh <app.apk>

APK="${1:?Usage: manifest-audit.sh <app.apk>}"
have() { command -v "$1" >/dev/null 2>&1; }
have apktool || { echo "apktool required"; exit 1; }

WORK="$(mktemp -d)"
apktool d -f -o "$WORK" "$APK" >/dev/null 2>&1 || { echo "apktool decode failed"; exit 1; }
MAN="$WORK/AndroidManifest.xml"
[[ -f "$MAN" ]] || { echo "no manifest"; exit 1; }

echo "== Risky flags =="
grep -oE 'android:(debuggable|allowBackup|usesCleartextTraffic)="[^"]*"' "$MAN" | sort -u || echo "(none)"
grep -q 'networkSecurityConfig' "$MAN" && echo "networkSecurityConfig present (inspect res/xml/)" || echo "no networkSecurityConfig (defaults apply)"

echo "== Exported components =="
# Robust parse: catches BOTH explicit android:exported="true" AND components that are
# IMPLICITLY exported via an <intent-filter> with no explicit android:exported attr
# (pre-API-31 default = exported). The old grep-only pass missed the implicit case.
grep_fallback() {
  grep -nE '<(activity|service|receiver|provider)' "$MAN" | grep -i 'exported="true"' \
    || echo "  (none explicitly exported=true)"
}
if have python3 && python3 - "$MAN" <<'PY'
import sys, xml.etree.ElementTree as ET
A='{http://schemas.android.com/apk/res/android}'
try:
    root = ET.parse(sys.argv[1]).getroot()
except Exception as e:
    sys.stderr.write("parse failed: %s\n" % e); sys.exit(3)
app = root.find('application')
comps = []
if app is not None:
    for tag in ('activity','activity-alias','service','receiver','provider'):
        for c in app.findall(tag):
            comps.append((tag, c.get(A+'name','?'), c.get(A+'exported'),
                          c.get(A+'permission'), c.find('intent-filter') is not None))
def show(title, items):
    print(title)
    if not items:
        print("  (none)"); return
    for tag, name, exp, perm, hasif in items:
        print("  %-14s %-55s perm=%s%s" % (tag, name, perm or 'NONE',
              ' [intent-filter]' if hasif else ''))
show("[explicit android:exported=true]",
     [c for c in comps if c[2] == 'true'])
show("[IMPLICITLY exported: intent-filter present, no explicit android:exported (pre-API-31 default = exported)]",
     [c for c in comps if c[2] is None and c[4]])
show("[providers with no explicit android:exported (default = exported pre-API-17)]",
     [c for c in comps if c[0] == 'provider' and c[2] is None])
PY
then :
else
  echo "  (python3 unavailable or manifest parse failed — grep fallback, explicit-only:)"
  grep_fallback
fi

echo "== Deeplink / custom schemes =="
grep -oE 'android:scheme="[^"]*"' "$MAN" | sort -u || echo "(none)"
grep -oE 'android:host="[^"]*"' "$MAN" | sort -u || true

echo "== Custom / dangerous permissions =="
grep -oE 'uses-permission android:name="[^"]*"' "$MAN" | sort -u | tail -40 || true

echo "[nomad] For each exported component, test invocation from adb / an unprivileged app and confirm impact (see deeplink-ipc)."
rm -rf "$WORK"
