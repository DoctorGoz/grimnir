"""_pace.py — the RoE pacing hook every confirm primitive calls around a live request.

    _pace.init(project_dir)      once, after argument parsing
    _pace.before(url)            immediately before each request: holds the per-host rate from
                                 $PROJECT_DIR/roe.json and counts the request against the budget
    _pace.after(url, status)     after it: records 429/503 for the batch back-off

Best-effort by design: if roe.py cannot be imported or the state file cannot be written, the
request still goes out unpaced, the same as before pacing existed. The pre-fire budget and
auto-fire checks live in the calling harness, which refuses before a primitive ever runs.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
try:
    import roe as _roe
except Exception:  # noqa: BLE001
    _roe = None

_PROJECT_DIR = None
_ROE = None


def init(project_dir):
    global _PROJECT_DIR, _ROE
    if _roe is None or not project_dir or not os.path.isdir(project_dir):
        return
    _PROJECT_DIR = project_dir
    try:
        _ROE = _roe.load(project_dir)
    except Exception:  # noqa: BLE001
        _ROE = None


def before(url):
    if _PROJECT_DIR and _ROE:
        try:
            _roe.pace(_PROJECT_DIR, url, _ROE)
        except Exception:  # noqa: BLE001
            pass


def after(url, status):
    if _PROJECT_DIR and _ROE:
        try:
            _roe.note_status(_PROJECT_DIR, url, status)
        except Exception:  # noqa: BLE001
            pass
