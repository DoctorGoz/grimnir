# GRIMNIR — Fedora VPS Install Reference

**Audience:** Claude Code on a fresh, fully-updated Fedora VPS.  
**Goal:** Install every tool GRIMNIR needs, using methods that actually work on Fedora 43+.

Read this file top to bottom and execute each phase in order. Do not rely on `setup-fedora.sh` — the DNF package loops are broken and many packages are not in Fedora repos at all.

---

## System Context

- Shell: bash, normal user with passwordless sudo (or confirm sudo works)
- Go binary: `/usr/bin/go` (installed via dnf `golang`)
- Python venv: `~/venv` — ALL pip installs go here, never system pip
- Go tools land in: `~/go/bin/` — must be in PATH
- Git-cloned tools land in: `~/tools/`
- Wrapper scripts (for git-cloned Python tools): `/usr/local/bin/`

### PATH setup (add to `~/.bashrc` if not already there)

```bash
export PATH="$HOME/go/bin:$HOME/bin:/usr/local/bin:$PATH"
```

---

## Fedora-Specific Gotchas

1. **Fedora 43+ uses `dnf5`** — `dnf info <pkg>` output format changed. Use `dnf5 search` or just attempt install and check exit code.
2. **`zlib-devel` does not exist** — replaced by `zlib-ng-compat-devel` (usually already installed).
3. **Most security tools are NOT in Fedora repos** — nikto, sqlmap, feroxbuster, enum4linux, wfuzz, commix, wapiti, recon-ng, fierce, sslyze, mitmproxy are all pip or git installs.
4. **`kiterunner (kr)`** — `go install` fails; must build from source.
5. **`wfuzz` on PyPI is broken** (pycurl wheel fails even with libcurl-devel installed) — install from git clone instead.
6. **`feroxbuster`** — not in repos; download pre-built binary from GitHub releases.
7. **`theHarvester`** — install via `pip install -e` from its git clone; PyPI stub is version 0.0.1.
8. **`graphqlmap`** — has a `setup.py`; install via `pip install -e .`, not a wrapper to a .py file.
9. **`paramspider`** — not on PyPI; install via `pip install -e ~/tools/ParamSpider`.

---

## Phase 0 — Directory Structure

```bash
# $GRIMNIR_WORKSPACE holds engagement data (default ~/workspace); the rest is tooling.
mkdir -p "${GRIMNIR_WORKSPACE:-$HOME/workspace}" ~/tools ~/go/bin ~/bin ~/.gf ~/.config/grimnir
```

---

## Phase 1 — DNF Packages (what actually works)

These packages ARE available in Fedora repos:

```bash
sudo dnf install -y \
    gcc gcc-c++ make cmake automake autoconf libtool \
    git git-lfs \
    python3 python3-devel python3-pip python3-virtualenv \
    golang nodejs npm \
    ruby ruby-devel rubygems \
    libffi-devel openssl-devel libxml2-devel libxslt-devel \
    libcurl-devel readline-devel sqlite-devel pcre-devel libpcap-devel \
    nmap nmap-ncat masscan hping3 fping \
    net-tools whois bind-utils tcpdump wireshark-cli \
    traceroute ngrep socat netcat arpwatch \
    smbclient openssl stunnel proxychains-ng \
    curl wget jq httpie \
    hydra medusa john hashcat \
    subfinder ffuf gobuster \
    sslscan whatweb wafw00f \
    dnsenum lynis ShellCheck
```

**Do NOT try to install via dnf:** nikto, sqlmap, mitmproxy, bandit, feroxbuster, enum4linux, fierce, theharvester, sslyze, wfuzz, commix, wapiti, dirb, recon-ng, nbtscan — they are not in repos. Install them via pip or git (see below).

---

## Phase 2 — Python Virtual Environment

```bash
python3 -m venv ~/venv
source ~/venv/bin/activate
pip install --upgrade pip setuptools wheel
```

### Pip installs (all inside venv)

```bash
pip install \
    uro semgrep waymore jshunter porch-pirate \
    holehe sherlock-project apkleaks \
    litellm playwright \
    garak langchain langgraph openai ollama \
    mitmproxy sslyze bandit fierce wapiti3 \
    theHarvester
```

**Special case — wfuzz (PyPI is broken, install from git):**
```bash
git clone --depth 1 https://github.com/xmendez/wfuzz.git ~/tools/wfuzz
pip install -e ~/tools/wfuzz
```

**Install Playwright browser:**
```bash
python -m playwright install chromium
```

```bash
deactivate
```

---

## Phase 3 — Go Tools

```bash
export GOPATH="$HOME/go"
export PATH="$GOPATH/bin:$PATH"

go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
go install github.com/projectdiscovery/alterx/cmd/alterx@latest
go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest
go install github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest
go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest
go install github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest
go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest
go install github.com/hahwul/dalfox/v2@latest
go install github.com/tomnomnom/gf@latest
go install github.com/tomnomnom/anew@latest
go install github.com/tomnomnom/gron@latest
go install github.com/tomnomnom/qsreplace@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/tomnomnom/httprobe@latest
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest
```

### kiterunner (kr) — must build from source, `go install` does NOT work

```bash
git clone --depth 1 https://github.com/assetnote/kiterunner.git ~/tools/kiterunner
cd ~/tools/kiterunner
make build
sudo cp dist/kr /usr/local/bin/
sudo chmod +x /usr/local/bin/kr
cd -
```

---

## Phase 4 — Git-Cloned Tools

Clone to `~/tools/`, install requirements, create wrapper scripts.

```bash
TOOLS_DIR="$HOME/tools"

# Clone all tools
git clone --depth 1 https://github.com/s0md3v/XSStrike.git         $TOOLS_DIR/XSStrike
git clone --depth 1 https://github.com/swisskyrepo/GraphQLmap.git   $TOOLS_DIR/GraphQLmap
git clone --depth 1 https://github.com/GerbenJavado/LinkFinder.git  $TOOLS_DIR/LinkFinder
git clone --depth 1 https://github.com/m4ll0k/SecretFinder.git      $TOOLS_DIR/SecretFinder
git clone --depth 1 https://github.com/devanshbatham/ParamSpider.git $TOOLS_DIR/ParamSpider
git clone --depth 1 https://github.com/anouarbensaad/vulnx.git       $TOOLS_DIR/vulnx
git clone --depth 1 https://github.com/xnl-h4ck3r/waymore.git        $TOOLS_DIR/waymore
git clone --depth 1 https://github.com/MandConsultingGroup/porch-pirate.git $TOOLS_DIR/porch-pirate
git clone --depth 1 https://github.com/1ndianl33t/Gf-Patterns.git    $TOOLS_DIR/Gf-Patterns
git clone --depth 1 https://github.com/dolevf/graphw00f.git           $TOOLS_DIR/graphw00f
git clone --depth 1 https://github.com/ticarpi/jwt_tool.git           $TOOLS_DIR/jwt_tool

# Not in Fedora repos — also clone these
git clone --depth 1 https://github.com/sullo/nikto.git                $TOOLS_DIR/nikto
git clone --depth 1 https://github.com/laramies/theHarvester.git      $TOOLS_DIR/theHarvester
git clone --depth 1 https://github.com/cddmp/enum4linux-ng.git        $TOOLS_DIR/enum4linux-ng
git clone --depth 1 https://github.com/lanmaster53/recon-ng.git        $TOOLS_DIR/recon-ng
git clone --depth 1 https://github.com/commixproject/commix.git        $TOOLS_DIR/commix
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git        $TOOLS_DIR/sqlmap
```

### Install requirements for each (inside venv)

```bash
source ~/venv/bin/activate

for tool in XSStrike LinkFinder SecretFinder vulnx waymore graphw00f jwt_tool \
            enum4linux-ng theHarvester recon-ng; do
    [ -f "$TOOLS_DIR/$tool/requirements.txt" ] && pip install -r "$TOOLS_DIR/$tool/requirements.txt"
done

# These have setup.py / pyproject.toml — install as editable packages
pip install -e $TOOLS_DIR/GraphQLmap
pip install -e $TOOLS_DIR/ParamSpider
pip install -e $TOOLS_DIR/porch-pirate
pip install -e $TOOLS_DIR/theHarvester

deactivate
```

### Create wrapper scripts

```bash
TOOLS_DIR="$HOME/tools"
VENV="$HOME/venv"

create_py_wrapper() {
    local name="$1" script="$2"
    [ -f "$script" ] || { echo "WARN: $script not found"; return; }
    sudo tee /usr/local/bin/"$name" > /dev/null <<WRAPPER
#!/bin/bash
source "$VENV/bin/activate" 2>/dev/null
exec python3 "$script" "\$@"
WRAPPER
    sudo chmod +x /usr/local/bin/"$name"
}

create_py_wrapper xsstrike       $TOOLS_DIR/XSStrike/xsstrike.py
create_py_wrapper linkfinder     $TOOLS_DIR/LinkFinder/linkfinder.py
create_py_wrapper secretfinder   $TOOLS_DIR/SecretFinder/SecretFinder.py
create_py_wrapper vulnx          $TOOLS_DIR/vulnx/vulnx.py
create_py_wrapper graphw00f      $TOOLS_DIR/graphw00f/main.py
create_py_wrapper jwt_tool       $TOOLS_DIR/jwt_tool/jwt_tool.py
create_py_wrapper enum4linux-ng  $TOOLS_DIR/enum4linux-ng/enum4linux-ng.py
create_py_wrapper commix         $TOOLS_DIR/commix/commix.py
create_py_wrapper sqlmap         $TOOLS_DIR/sqlmap/sqlmap.py
create_py_wrapper recon-ng       $TOOLS_DIR/recon-ng/recon-ng

# nikto is perl, not python
sudo tee /usr/local/bin/nikto > /dev/null <<'WRAPPER'
#!/bin/bash
exec perl "$HOME/tools/nikto/program/nikto.pl" "$@"
WRAPPER
sudo chmod +x /usr/local/bin/nikto

# graphqlmap and theHarvester install to venv/bin — wrap to activate venv first
sudo tee /usr/local/bin/graphqlmap > /dev/null <<WRAPPER
#!/bin/bash
source "$HOME/venv/bin/activate" 2>/dev/null
exec "$HOME/venv/bin/graphqlmap" "\$@"
WRAPPER
sudo chmod +x /usr/local/bin/graphqlmap

sudo tee /usr/local/bin/theHarvester > /dev/null <<WRAPPER
#!/bin/bash
source "$HOME/venv/bin/activate" 2>/dev/null
exec python3 -m theHarvester "\$@"
WRAPPER
sudo chmod +x /usr/local/bin/theHarvester
```

---

## Phase 5 — feroxbuster (GitHub binary release)

```bash
curl -sL https://github.com/epi052/feroxbuster/releases/latest/download/x86_64-linux-feroxbuster.zip \
    -o /tmp/feroxbuster.zip
unzip -o /tmp/feroxbuster.zip -d /tmp/feroxbuster_bin
sudo cp /tmp/feroxbuster_bin/feroxbuster /usr/local/bin/
sudo chmod +x /usr/local/bin/feroxbuster
feroxbuster --version
```

---

## Phase 6 — Gf Patterns & SecLists

```bash
# Gf patterns
cp -n ~/tools/Gf-Patterns/*.json ~/.gf/ 2>/dev/null
echo "$(ls ~/.gf/*.json | wc -l) gf patterns installed"

# SecLists (not in Fedora repos — git clone)
sudo git clone --depth 1 https://github.com/danielmiessler/SecLists.git /opt/seclists
sudo ln -sf /opt/seclists /usr/share/seclists
```

---

## Phase 7 — Claude Code + Statusline

```bash
if ! command -v claude &>/dev/null; then
    curl -fsSL https://claude.ai/install.sh | bash
fi
```

### Statusline

Create `~/.claude/statusline-command.sh`:

```bash
cat > ~/.claude/statusline-command.sh << 'EOF'
#!/usr/bin/env bash
# Claude Code statusLine — styled after the Kali twoline PS1
# Full ROYGBIV: user㉿host | cwd(branch*) | model | ctx | 5h | 7d | load
# Line 2: └─

input=$(cat)

user=$(whoami)
host=$(hostname -s)
cwd=$(echo "$input" | jq -r '.workspace.current_dir // .cwd // ""')
[ -z "$cwd" ] && cwd=$(pwd)

home_dir="$HOME"
cwd_display="${cwd/#$home_dir/\~}"

# Git branch + dirty indicator for Orange field
git_branch=$(git -C "$cwd" rev-parse --abbrev-ref HEAD 2>/dev/null)
if [ -n "$git_branch" ]; then
    git_dirty=$(git -C "$cwd" status --porcelain 2>/dev/null)
    [ -n "$git_dirty" ] && git_suffix="*" || git_suffix=""
    cwd_git=" (${git_branch}${git_suffix})"
else
    cwd_git=""
fi

model=$(echo "$input" | jq -r '.model.display_name // ""')
effort=$(echo "$input" | jq -r '.effort.level // empty')

used=$(echo "$input" | jq -r '.context_window.used_percentage // empty')
five_h=$(echo "$input" | jq -r '.rate_limits.five_hour.used_percentage // empty')
five_h_reset=$(echo "$input" | jq -r '.rate_limits.five_hour.resets_at // empty')
seven_d=$(echo "$input" | jq -r '.rate_limits.seven_day.used_percentage // empty')
seven_d_reset=$(echo "$input" | jq -r '.rate_limits.seven_day.resets_at // empty')

# Load average (1m/5m/15m) from /proc/loadavg
load=$(awk '{print $1"/"$2"/"$3}' /proc/loadavg)

# ROYGBIV palette
C_RED='\033[1;31m'
C_ORANGE='\033[1;38;5;208m'
C_YELLOW='\033[1;33m'
C_GREEN='\033[1;32m'
C_BLUE='\033[1;34m'
C_INDIGO='\033[1;38;5;63m'
C_VIOLET='\033[1;38;5;135m'

S_GREEN='\033[0;32m'
DIM='\033[2m'
RESET='\033[0m'

fmt_pct() {
    printf '%.0f%%' "$1"
}

fmt_countdown() {
    local reset_epoch="$1"
    local now=$(date +%s)
    local diff=$(( reset_epoch - now ))
    if [ "$diff" -le 0 ]; then
        printf "now"
        return
    fi
    local days=$(( diff / 86400 ))
    local hours=$(( (diff % 86400) / 3600 ))
    local mins=$(( (diff % 3600) / 60 ))
    if [ "$days" -gt 0 ]; then
        printf "%dd%dh" "$days" "$hours"
    elif [ "$hours" -gt 0 ]; then
        printf "%dh%dm" "$hours" "$mins"
    else
        printf "%dm" "$mins"
    fi
}

# --- Line 1 ---
# R: user㉿host
printf "${S_GREEN}┌──(${C_RED}%s㉿%s${S_GREEN})" "$user" "$host"

# O: cwd (branch*)
printf -- "-[${C_ORANGE}%s${C_ORANGE}${DIM}%s${S_GREEN}]${RESET}" "$cwd_display" "$cwd_git"

# Y: model (effort)
if [ -n "$model" ]; then
    printf " ${S_GREEN}|${RESET} ${C_YELLOW}%s${RESET}" "$model"
    if [ -n "$effort" ]; then
        printf " ${C_YELLOW}${DIM}(%s)${RESET}" "$effort"
    fi
fi

# G: ctx
if [ -n "$used" ]; then
    printf " ${S_GREEN}|${RESET} ${C_GREEN}ctx:%s${RESET}" "$(fmt_pct "$used")"
fi

# B: 5h
if [ -n "$five_h" ]; then
    printf " ${S_GREEN}|${RESET} ${C_BLUE}5h:%s${RESET}" "$(fmt_pct "$five_h")"
    if [ -n "$five_h_reset" ]; then
        printf "${C_BLUE}${DIM}(%s)${RESET}" "$(fmt_countdown "$five_h_reset")"
    fi
fi

# I: 7d
if [ -n "$seven_d" ]; then
    printf " ${S_GREEN}|${RESET} ${C_INDIGO}7d:%s${RESET}" "$(fmt_pct "$seven_d")"
    if [ -n "$seven_d_reset" ]; then
        printf "${C_INDIGO}${DIM}(%s)${RESET}" "$(fmt_countdown "$seven_d_reset")"
    fi
fi

# V: load average
printf " ${S_GREEN}|${RESET} ${C_VIOLET}load:%s${RESET}" "$load"

# --- Line 2 ---
printf "\n${S_GREEN}└─${RESET}"
EOF
chmod +x ~/.claude/statusline-command.sh
```

Add the `statusLine` block to `~/.claude/settings.json` (merge with existing keys):

```json
{
  "statusLine": {
    "command": "~/.claude/statusline-command.sh"
  }
}
```

Requires `jq` — install if missing: `sudo dnf install -y jq`

---

## Verification Checklist

Run this to confirm everything is in place:

```bash
source ~/venv/bin/activate

echo "--- Go Tools ---"
for t in nuclei httpx naabu subfinder dnsx katana gf anew gron qsreplace gau \
          waybackurls httprobe grpcurl dalfox; do
    command -v $t &>/dev/null && echo "✓ $t" || echo "✗ $t"
done
command -v kr &>/dev/null && echo "✓ kr" || echo "✗ kr"

echo "--- Pip Packages ---"
for p in uro semgrep waymore jshunter porch-pirate holehe sherlock-project apkleaks \
          litellm playwright garak langchain langgraph openai ollama \
          mitmproxy sslyze bandit wfuzz fierce wapiti3; do
    pip show $p &>/dev/null && echo "✓ $p" || echo "✗ $p"
done

echo "--- CLI Wrappers ---"
for c in xsstrike graphqlmap linkfinder secretfinder vulnx graphw00f jwt_tool \
          nikto theHarvester enum4linux-ng recon-ng commix sqlmap feroxbuster; do
    command -v $c &>/dev/null && echo "✓ $c" || echo "✗ $c"
done

echo "--- Wordlists ---"
echo "Gf patterns: $(ls ~/.gf/*.json 2>/dev/null | wc -l)"
[ -d /opt/seclists ] && echo "✓ SecLists" || echo "✗ SecLists"

deactivate
```

---

## Phase 8 -- Caido Mode Skill (Claude Code <> Caido proxy)

The Caido Mode skill lets Claude Code query and control a running Caido proxy instance directly (search requests, replay, manage findings, scopes, filters).

**Automated by setup script:** npm dependencies are installed from the repo's `.agents/skills/caido-mode/` and the symlink at `.claude/skills/caido-mode` is created.

**Manual step — PAT authentication:**

1. Open Caido desktop: **Settings > Developer > Personal Access Tokens**
2. Generate a new token
3. Run:

```bash
npx tsx "${GRIMNIR_REPO_DIR:-$HOME/workspace/grimnir}"/.agents/skills/caido-mode/caido-client.ts setup <your-pat>
```

4. Verify:

```bash
npx tsx "${GRIMNIR_REPO_DIR:-$HOME/workspace/grimnir}"/.agents/skills/caido-mode/caido-client.ts health
```

If doing a fresh install without the repo cloned yet:

```bash
cd "${GRIMNIR_REPO_DIR:-$HOME/workspace/grimnir}"/.agents/skills/caido-mode
npm install
```

---

## Still Manual (script intentionally skips these)

| Tool | Install method |
|------|---------------|
| caido desktop | Download from https://caido.io/download |
| caido PAT | Settings > Developer > Personal Access Tokens (see Phase 8 above) |
| wpscan | `gem install wpscan` (needs `ruby-devel`) |
| exploitdb / searchsploit | `git clone https://gitlab.com/exploit-database/exploitdb.git ~/tools/exploitdb` then symlink `searchsploit` to `~/bin/` |
| zaproxy | `flatpak install flathub org.zaproxy.ZAP` |
| beef-xss | https://github.com/beefproject/beef (Ruby + bundler) |
