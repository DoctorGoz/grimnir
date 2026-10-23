"""_rung.py — the response-channel rung, shared by every confirmation primitive.

Hunting Rule 32: a server-side request is scored by what came back, not by the fact
that it fired. The ladder is blind -> partial -> full -> credential -> execution and
validate-finding.sh enforces it (critical needs credential/execution, high needs full
or better).

This module exists because the rung was first wired into ONE of the four primitives that
write verdict.json. The other three wrote no rung at all, so `resolve_rung` fell through
to `blind` and every finding they confirmed was silently capped at medium -- including
every https-only SSRF, which is the common case. A capped finding looks like severity
discipline rather than a broken tool, so nothing surfaced it. One definition, imported by
all of them, is what stops that recurring.

Scripts here are run as `python3 scripts/confirm/<name>.py`, so their own directory is
sys.path[0] and a plain `from _rung import ...` resolves. The leading underscore keeps the
name importable despite the hyphenated filenames around it.
"""

RUNGS = ("blind", "partial", "full", "credential", "execution")

#: What each rung will carry through the gate in validate-finding.sh.
CEILING = {
    "blind": "medium",
    "partial": "medium",
    "full": "high",
    "credential": "critical",
    "execution": "critical",
}

HELP = ("response-channel rung (hunting Rule 32): " + "|".join(RUNGS) +
        ". Records WHAT CAME BACK, not that the request fired. Omitted resolves to "
        "'blind', which caps the finding at medium in the evidence gate.")


def normalize(value):
    """Return a canonical rung, or None when nothing was supplied.

    Raises ValueError on a value that is not a rung. Refusing an unknown string matters
    more than it looks: silently coercing a typo to the floor would cap a real critical,
    and coercing it to a default would waive the gate. Neither is safe, so it is an error.
    """
    if value is None:
        return None
    v = str(value).strip().lower()
    if not v:
        return None
    if v not in RUNGS:
        raise ValueError(
            "channel_rung %r is not a rung. Use: %s" % (value, " ".join(RUNGS)))
    return v


def add_argument(parser, flag="--channel-rung"):
    """Attach the flag with the one help string, so every primitive documents it alike."""
    parser.add_argument(flag, default=None, choices=RUNGS, metavar="RUNG", help=HELP)
    return parser
