#!/bin/bash
set -euo pipefail
# Nomad — MITM rig bring-up helper/checklist for mobile dynamic analysis.
# The rooted-emulator rig is operator-local; this verifies prerequisites and
# prints the bring-up steps. Non-destructive.

have() { command -v "$1" >/dev/null 2>&1; }
echo "== Nomad MITM prerequisites =="
for t in adb frida objection; do
  have "$t" && echo "  [ok] $t" || echo "  [missing] $t"
done
echo
echo "== Connected devices =="
have adb && adb devices -l || echo "  adb not installed"
echo
cat <<'STEPS'
== Bring-up steps (rooted emulator / device) ==
1. Start the rig (see ~/Android/RUNBOOK.md): emulator + Xvfb/Mesa as needed.
2. Set the app proxy to your Caido listener (host:port).
3. Install the Caido CA as a SYSTEM trust anchor:
   - Android 7+: apps ignore user CAs by default. Use Magisk AlwaysTrustUserCerts
     or push the CA to the system store (rooted), or patch network-security-config.
4. Start Frida server on the device (matching your frida client version).
5. Launch the app; drive flows; review traffic in Caido (caido-mode skill).
6. No traffic? -> certificate pinning. Use the cert-pinning-bypass skill, then retry.

Notes:
- Confirm the package id is in scope before deep analysis.
- Prefer the caido-mode skill for traffic capture/replay so it stays in the engagement record.
STEPS
