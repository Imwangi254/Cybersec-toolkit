# Recon Tools — Installation & Setup

> Passive/active reconnaissance toolkit for Kali Linux.
> Built and verified on Kali Linux (`kali-linux-2026.1`, kernel `7.0.12+kali`) running in VMware.
> Documented: July 2026.

This is my working install log for the core recon stack (AH200 recon module). Each tool
is listed with what it does, how it's installed, and the gotchas I hit so a rebuild is
painless.

---

## Tool overview

| Tool | Job | Installed via |
|------|-----|---------------|
| **Go** | Compiler/toolchain — needed to build the Go-based tools below | tarball → `/usr/local/go` |
| **Subfinder** | Passive subdomain enumeration (what subdomains *exist*) | `go install` |
| **Httpx** | Probes which hosts are *alive* over HTTP/HTTPS | `go install` (renamed `httpx-pd`) |
| **Anew** | Appends only *new* lines to a file — dedup/diffing glue | `go install` |
| **Dnsenum** | DNS enumeration (nameservers, MX, zone transfer, brute) | `apt` (Perl tool) |
| **Nuclei** | Template-based vulnerability scanner | `go install` |
| **SecLists** | Wordlist collection — ammunition for the tools above | `apt` (dataset) |

Go tools land in `$HOME/go/bin`. Apt tools/datasets land in `/usr/share` and `/usr/bin`.
Knowing which is which saves confusion at update time.

---

## 1. Go (the toolchain)

Go is the language most modern recon tools are *written in*. Installing it isn't the goal —
it's the prerequisite that lets `go install ...` compile the actual tools.

```bash
# Download the Linux amd64 build (NOT the Windows/macOS one)
cd $HOME && wget https://go.dev/dl/go1.26.5.linux-amd64.tar.gz

# Wipe any old install, then extract into /usr/local
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.26.5.linux-amd64.tar.gz

# Add Go + the Go-tools bin dir to PATH permanently (zsh on Kali)
echo 'export PATH=$PATH:/usr/local/go/bin' >> $HOME/.zshrc
echo 'export PATH=$PATH:$HOME/go/bin'      >> $HOME/.zshrc
source $HOME/.zshrc

# Verify
go version    # -> go version go1.26.5 linux/amd64
```

**Gotcha:** the download must match your OS. It's easy to grab the Linux tarball and try to
run it on Windows (or vice-versa) — it won't work. Install Go *inside the Kali VM*, since
that's where the tools run.

---

## 2. Subfinder — passive subdomain enumeration

Finds subdomains by querying public sources (cert logs, DNS databases) **without touching
the target directly**. That "passive" part = quiet and low-risk. First recon move.

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
subfinder -version

# Usage
subfinder -d example.com
subfinder -d example.com -silent    # names only, no banner (good for piping)
```

**Note:** subfinder is genuinely on **v2**, so its module path includes `/v2`. (Not every
ProjectDiscovery tool does — see the httpx gotcha below.)

First `go install` is slow — Go downloads every dependency. Later installs reuse the cache
and are much faster.

---

## 3. Httpx — live-host probing

subfinder tells you a name *exists*; httpx tells you if there's a *live server* behind it.
Returns status codes, page titles, and detected tech stack.

```bash
# CORRECT path — httpx is still on v1, so NO /v2
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
```

### Gotcha A — the `/v2` trap
My first attempt used `.../httpx/v2/cmd/httpx@latest` (copying subfinder's pattern). It failed:

```
module github.com/projectdiscovery/httpx@latest found (v1.10.0),
but does not contain package .../httpx/v2/cmd/httpx
```

httpx is on **v1**, not v2 — no `/v2` in the path. Lesson: the version segment matches the
tool's actual major version, don't assume.

### Gotcha B — name collision with Python's httpx
Kali ships a *different* tool also called `httpx` (a Python HTTP client) at `/usr/bin/httpx`.
It sits earlier in PATH, so typing `httpx` runs the wrong one:

```bash
which -a httpx
# /usr/bin/httpx          <- Python (wins)
# /bin/httpx
# /home/kali/go/bin/httpx <- the recon one (shadowed)
```

**Fix — rename the recon binary** (community convention: `-pd` for ProjectDiscovery):

```bash
mv $HOME/go/bin/httpx $HOME/go/bin/httpx-pd
httpx-pd -version    # ProjectDiscovery banner, v1.10.0
```

Renaming (not PATH reordering) is surgical: both tools stay usable, and the name tells you
which is which. From here, always call the recon one as **`httpx-pd`**.

```bash
# Usage — the classic subfinder -> httpx pipeline
subfinder -d example.com -silent | httpx-pd -silent
subfinder -d example.com -silent | httpx-pd -silent -sc -title -tech-detect
#   -sc = status code, -title = page title, -tech-detect = tech fingerprint
```

---

## 4. Anew — new-line dedup

Tiny but essential. Appends lines to a file **only if they're new**. In recon it's the glue:
re-run a scan later, pipe through anew, and only *newly appeared* results show up.

```bash
go install github.com/tomnomnom/anew@latest
anew -h    # prints usage to stderr, exits non-zero — that's normal, not an error
```

```bash
# Usage — only surface hosts that weren't seen before
subfinder -d example.com -silent | anew subs.txt
```

---

## 5. Dnsenum — DNS enumeration

Perl tool (not Go), so it comes from Kali's repos, not `go install`. Usually pre-installed.

```bash
which dnsenum || sudo apt install -y dnsenum
dnsenum --help | head -5
```

---

## 6. Nuclei — template vulnerability scanner

The heavy hitter. Reads YAML "templates" (recipes for detecting a specific CVE, exposed
panel, misconfig, default cred…) and fires the matching ones at a target. This is where
recon crosses from *observing* into **active testing** — scope discipline matters.

```bash
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest   # note /v3 — genuinely v3
nuclei -version
nuclei -update-templates    # first run pulls ~10k templates into ~/.local/nuclei-templates
```

```bash
# Usage
nuclei -u https://example.com
# Skip [info] noise, only actionable findings, with progress:
nuclei -u https://example.com -stats -severity low,medium,high,critical
```

**Reading output — the core skill:**
- `[info]` (green) = observations, **not** vulnerabilities (WAF present, TLS version,
  missing optional headers, tech detected). Skip these.
- `[low]/[medium]/[high]/[critical]` (colored) = **stop and look.**

Scanning a hardened target (e.g. a security company's own site) returns almost all `[info]` —
that's the normal, healthy result, not 33 problems. Train the eye to *skip the green, stop
on the color*.

**Engine vs templates:** these version independently. Templates being "latest" is what
matters for scan quality; the engine showing "outdated" is cosmetic — bump it with the same
`go install` when convenient.

---

## 7. SecLists — wordlists (dataset, not a tool)

A massive collection of wordlists (subdomain guesses, passwords, fuzzing payloads) that the
tools above *consume*. No compile — just install from apt so it lands where tools expect it.

```bash
sudo apt install -y seclists              # ~545 MB
ls /usr/share/seclists
# Discovery  Fuzzing  Miscellaneous  Passwords  Pattern-Matching  Payloads  Usernames  Web-Shells
```

The `Discovery/DNS/` folder holds the subdomain wordlists that dnsenum and fuzzers draw from.

---

## The full pipeline

Chaining the tools is the whole point — this uses three at once:

```bash
subfinder -d example.com -silent | httpx-pd -silent | nuclei -silent
```

Flow: **subfinder** finds names → **httpx-pd** filters to live hosts → **nuclei** scans those.
That funnel (*exists → alive → interesting → actionable*) is the front end of real recon.

> **Note:** `-silent` gives no progress output; a multi-host nuclei scan can take 15-25 min.
> Add `-stats` to nuclei to see live progress, and `-severity ...` to cut the info noise.

---

## Scope & authorization — the line that matters

- **Passive** (subfinder, light httpx) against a public target = fine.
- **Active** (nuclei scanning, fuzzing) against a target you don't own or aren't authorized
  to test = potentially unauthorized access, **regardless of intent or results**.
- For learning nuclei, use targets built for it or ones you own:
  - `scanme.nuclei.sh` (ProjectDiscovery's test host)
  - **Metasploitable2** on your own lab network — deliberately vulnerable, yours to fully test.
- For bug bounty: start with **VDP programs** (a written invitation to test the listed scope).
  Stay inside the declared scope, always.

---

## Environment notes / gotchas recap

- **DNS:** if `/etc/resolv.conf` keeps reverting, it's because NetworkManager regenerates it.
  Fix it *in NetworkManager*, not by editing the file:
  ```bash
  sudo nmcli connection modify "Wired connection 1" ipv4.dns "8.8.8.8 8.8.4.4" ipv4.ignore-auto-dns yes
  sudo nmcli connection up "Wired connection 1"
  ```
- **A resolver returning `No answer` for one host but resolving `google.com` fine** = that
  host isn't resolving on the internet right now, *not* a local DNS problem. Test a known-good
  name before blaming your setup.
- **Go tools** → `$HOME/go/bin` (update with `go install ...@latest`).
  **Apt tools/datasets** → `/usr/share`, `/usr/bin` (update with `apt`).
