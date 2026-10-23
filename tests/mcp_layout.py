"""Where the MCP kit lives in this tree, and how its commands are spelled here.

test_mcp_kit.py is shared with the standalone MCP tester that is generated from this repo, so
everything that differs between the two layouts is in this one file. The generated tree ships its
own copy (a single `mcptester` entrypoint); this one maps each subcommand to the script that
implements it in the development repo.
"""
import importlib.util
import json
import os
import subprocess
import sys
import threading

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_A = os.path.join(ROOT, "artemis", "scripts")
CMDS = {
    "enum": ["bash", os.path.join(_A, "mcp-enum.sh")],
    "probe": ["bash", os.path.join(_A, "mcp-probe.sh")],
    "call": ["bash", os.path.join(_A, "mcp-call.sh")],
    "shadow-scan": ["bash", os.path.join(_A, "mcp-shadow-scan.sh")],
    "safe": ["bash", os.path.join(_A, "mcp-readonly-broker.sh")],
    "fuzz": [sys.executable, os.path.join(_A, "mcp-fuzz.py")],
    "poison-scan": [sys.executable, os.path.join(_A, "mcp-poison-scan.py")],
    "confirm": [sys.executable, os.path.join(ROOT, "scripts", "confirm", "mcp-confirm.py")],
}
_SCRUB = ("http_proxy", "https_proxy", "all_proxy", "grimnir_proxy", "grimnir_mcp_auth",
          "grimnir_mcp_project_dir")
ENV = {k: v for k, v in os.environ.items() if k.lower() not in _SCRUB}
ENV["NO_PROXY"] = "127.0.0.1,localhost"


def run(sub, *args, cwd=None, env=None, timeout=120):
    return subprocess.run(CMDS[sub] + list(args), capture_output=True, text=True, cwd=cwd,
                          env={**ENV, **(env or {})}, timeout=timeout)


def confirm_out(tmp_path, name):
    """Extra confirm flags, and the file the verdict lands in. Here the evidence gate's layout."""
    d = tmp_path / ("engagement-" + name)
    d.mkdir(exist_ok=True)
    kind = "authz.json" if "authz" in name else "verdict.json"
    return ["--finding-id", "TST-001", "--project-dir", str(d)], d / "evidence" / "TST-001" / kind


def oob_env(log):
    return {"GRIMNIR_OOB_LOG": str(log)}


def max_calls_env(n):
    return {"GRIMNIR_MCP_MAX_CALLS": str(n)}


def fuzz_flags(tmp_path):
    """An engagement dir with a roe.json that lets the fuzz run at test speed."""
    d = tmp_path / "fuzz-engagement"
    d.mkdir(exist_ok=True)
    (d / "roe.json").write_text(json.dumps({"max_rps_per_host": 1000, "daily_request_budget": 100000}))
    return ["--project-dir", str(d)]


def start_oob(log):
    """The repo's OOB listener, bound to loopback on a free port, recording to `log`."""
    os.environ["GRIMNIR_OOB_LOG"] = str(log)
    spec = importlib.util.spec_from_file_location("oob_listener", os.path.join(ROOT, "scripts", "confirm", "oob-listener.py"))
    lst = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(lst)
    lst.LOG = str(log)
    srv = lst.Server(("127.0.0.1", 0), lst.H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv
