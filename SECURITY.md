# Security Model

Read this before running GRIMNIR. It describes what the repository grants to the
agent when you clone and launch it, what that does and does not protect against,
and where the real isolation boundary has to live.

## What cloning this repo grants

`.claude/settings.json` is tracked, so every clone inherits its permission
allow-list. That list exists because GRIMNIR dispatches specialist agents to run
unattended: an agent that stops for an interactive approval every few commands
cannot complete a recon sweep or a confirmation run.

The consequence is that a freshly cloned GRIMNIR can, without prompting you:

- **Execute arbitrary code.** `Bash(python3*)` and `Bash(curl*)` are prefix
  rules. `python3 -c '<anything>'` matches, as does `curl -o <any path>`. No
  compound command or clever quoting is needed; a single ordinary invocation is
  enough.
- **Write files and then run them.** `Write` and `Edit` are granted without path
  restriction, and `Bash(bash scripts/*)` never inspects a script's contents.
  Authoring a script and executing it is two separately pre-approved steps that
  compose into arbitrary execution.
- **Reach the network.** `curl`, `httpx`, `nuclei`, `ffuf`, `katana`,
  `subfinder`, `nmap`, and the rest of the offensive toolchain are allowed by
  design. That is the product.

The `deny` entries are string patterns, not controls. `Bash(sudo rm*)` does not
match `sudo  rm` with two spaces, and `Bash(rm -rf /)*` does not match
`rm -fr /`. Treat them as reminders to a cooperating agent, not as a boundary
against a determined one.

## Why this is the shape it is

These grants are not an oversight, and narrowing them inside the repository
would not buy what it appears to. Anyone in a position to run GRIMNIR already
has a shell and a Python interpreter on that machine. A permission rule that
prevents the agent from calling `python3` does not prevent code execution on the
host; it only prevents the agent from doing its job.

Claude Code's permission system is a control on *what the agent does by
default*, not a sandbox. It is well suited to catching a surprising action. It
is not designed to contain a process that is deliberately trying to escape, and
it should not be relied on for that.

## The threat that actually matters here

GRIMNIR is a penetration testing orchestrator, which means it ingests hostile
input as a matter of routine: HTTP response bodies, JavaScript bundles, APK
strings, MCP tool descriptions, and the output of the LLMs it is testing. All of
that is attacker-controlled by definition, and all of it flows into an agent
that can write and execute files.

This is the reason the security model deserves stating plainly, and it is a
sharper concern than "the operator might do something careless." A prompt
injection embedded in a target's response is untrusted input arriving at a
component with write and execute capability. The permission allow-list is not a
meaningful barrier against it.

## Where the boundary belongs

**Run GRIMNIR on a machine you are willing to lose.** A dedicated VM, a
container, or a disposable VPS. Not your daily workstation, and not a host
holding credentials unrelated to the engagement.

Concretely:

- Give it its own user account, not your primary one.
- Keep engagement credentials scoped to the engagement. Do not sign the agent's
  host into unrelated accounts, cloud consoles, or password managers.
- Assume anything readable on that host is readable by the agent, and therefore
  potentially by a target that successfully injects it.
- Snapshot or rebuild the host between engagements if the target was hostile.

The isolation boundary is the operating system. That is true of any agentic tool
with shell access, and doubly so for one whose purpose is to interact with
systems that may attack it back.

## If your threat model differs

You can narrow the allow-list in `.claude/settings.json` to suit a stricter
environment. Expect to trade autonomy for it: removing `Bash(python3*)` will
stop the confirmation harness, and removing the offensive toolchain entries will
stop the specialists. If you want a middle ground, narrowing `Write`/`Edit` to
the engagement directory rather than granting them repo-wide is the change with
the best ratio of safety gained to capability lost.

Local overrides belong in `.claude/settings.local.json`, which is gitignored and
never published.

## Reporting a vulnerability

If you find a security issue in GRIMNIR itself, open an issue describing the
impact and reproduction steps. Do not include credentials, engagement data, or
the name of any program you were testing.
