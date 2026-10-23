# Contributing to Grimnir

Thanks for your interest. Grimnir is a methodology toolkit for authorized security testing, and
contributions are welcome under a few rules that keep the public tree clean and the team
consistent.

## The one hard rule: tracked files stay generic

This repository is public. Anything committed is visible to the world, so operator-specific
data must never land in a tracked file. That means **no real target or program names, no
company or host names, no credentials or tokens, no personal identifiers, and no engagement
war stories that name the program.** Use the generic placeholders the repo already uses:
`$PROGRAM`, `acme-corp`, `target.example.com`, `report #NNNNNNN`. Generic vendor names used as
fingerprinting categories (on par with "WordPress" or "Apache") are fine.

The full policy is the "Public Repository Hygiene" section of `CLAUDE.md`. Read it before your
first pull request. `scripts/check-repo-hygiene.sh` mechanizes part of the check; run it over
anything you add.

Your own measured numbers (conversion rates, bounty figures, named-program lessons) belong in
your operator overlay (`~/.grimnir/rules/hunting-local.md`), never in the tracked rules.

## Before you open a pull request

```bash
python3 -m pip install -r requirements-dev.txt
python3 -m pytest -q                 # the test gate must pass
shellcheck scripts/*.sh              # shell scripts must be clean
bash scripts/check-repo-hygiene.sh   # no operator data in the diff
```

## Conventions worth knowing

- **Executables live in `scripts/` (shared) or `<agent>/scripts/` (specialist) and nowhere
  else.** The agent allow-lists grant `bash <agent>/scripts/*` per agent, so a script placed
  outside that path cannot run unattended. If you add an executable elsewhere, add the matching
  allow-list rule in the same change.
- **New capability?** Decide its two axes first (shared vs specialist, executable vs knowledge).
  `ARCHITECTURE.md` explains the model.
- **New hunting lesson?** Add it to `rules/hunting.md` (methodology, generic) so every agent
  benefits. Keep measured numbers out of the tracked rules.
- **New finding type or schema change?** Update the matching file in `schemas/` and add a test.
- **Tests pair with behavior.** A script that computes something gets a test that checks the
  answer, not just the exit code.

## Reporting a security issue in Grimnir itself

See `SECURITY.md`.
