# DepSec — CLI Security Tool: Full Project Brief

## What is DepSec?
A CLI tool that automatically scans packages in an isolated sandbox
before they touch the host system. The user installs DepSec once,
enables auto-scan, and every package install is silently screened
from that point on.

---

## Dependencies

### Docker (Required for sandbox scanning)
- On first run, check if Docker daemon is running
- If not found:
  → Show a one-time warning (not on every run)
  → "Docker not found. Sandbox scanning disabled. Download: https://docker.com/desktop"
  → Fall back to static analysis only (CVE + metadata)
  → Store "docker_missing_warned: true" in config so warning never repeats

### ClamAV (Optional — binary scanning layer)
- On first run, check if ClamAV is installed
- If not found:
  → "ClamAV not found. Binary scanning disabled."
  → "Install: brew install clamav / apt install clamav / choco install clamav"
  → Continue normally without it — other layers still run
- If found: run inside the sandbox container, never on host directly

### Graceful Degradation Table
| Docker | ClamAV | Active Layers                          |
|--------|--------|----------------------------------------|
| ✅     | ✅     | Sandbox + CVE + YARA + ClamAV + Meta  |
| ✅     | ❌     | Sandbox + CVE + YARA + Meta            |
| ❌     | ✅     | CVE + Meta (static only, no sandbox)  |
| ❌     | ❌     | CVE + Meta (static only)              |

---

## Scanning Pipeline (layered, each layer is independently skippable)

### Layer 1 — CVE Matching (no download required)
- Query OSV (osv.dev) and NVD APIs
- Match package name + version against known CVE records
- Cache results in local SQLite with 24h TTL
- Works fully offline with --offline flag using cached data

### Layer 2 — Metadata Anomaly Detection (no download required)
- Package publish date (flag if < 7 days old)
- Maintainer change detection (compare against registry history)
- Typosquatting detection: fuzzy match against top-500 packages per ecosystem
- Suspicious install scripts: flag any preinstall/postinstall that calls
  curl, wget, fetch, exec, eval, or opens a network socket

### Layer 3 — Sandbox Scan (requires Docker)
Flow:
  1. Pull package tarball from registry into memory (never write to host disk)
  2. Spin up an ephemeral Docker container (DepSec's own minimal image)
  3. Extract tarball inside container
  4. Run ClamAV scan inside container (if available)
  5. Run YARA rules against source files inside container
  6. Execute install scripts inside container and monitor:
     - Any outbound network calls → flag immediately
     - Any writes outside expected paths → flag
     - Any attempts to read env variables (HOME, PATH, secrets) → flag
  7. Destroy container completely
  8. Report results to host

The host filesystem is never touched until the user explicitly approves.

### Layer 4 — YARA Rule Matching (runs inside sandbox)
- Bundle a default ruleset covering:
  - Obfuscated code (base64 blobs, hex-encoded strings)
  - Suspicious eval/exec patterns
  - Encoded network payloads
  - Known malicious code signatures from past supply chain attacks
- User can add custom rules via --rules flag
- Rules are updatable via: depsec update-rules

---

## Auto-Scan Feature

### Enable / Disable
depsec auto enable    # enable automatic scanning on every package install
depsec auto disable   # disable, return to manual-only mode
depsec auto status    # show current auto-scan status and active layers

### How Auto-Scan Works
When enabled, DepSec injects shell hooks into the user's shell config
(.bashrc / .zshrc / .fishrc) that wrap npm, pip, cargo, gem commands.

The user types: npm install lodash
What actually runs:
  1. DepSec intercepts the call
  2. Runs full scan pipeline on lodash
  3. If clean → proceeds with original npm install
  4. If risky → prompts user (or blocks in strict mode)

Shell hook example (DepSec manages this automatically, user never writes it):
  npm() { depsec scan --pkg "$2" --ecosystem node && command npm "$@"; }

On depsec auto enable:
  → Detect user's shell automatically
  → Inject hooks
  → Print: "Auto-scan enabled. Restart your shell or run: source ~/.zshrc"

On depsec auto disable:
  → Remove injected hooks cleanly
  → Print: "Auto-scan disabled."

---

## CLI Commands

### Scanning
depsec scan [path]              # scan a local project directory
depsec scan --pkg <name>        # scan a package before installing
depsec scan --pkg <name>@<ver>  # scan a specific version
depsec scan --ecosystem <node|python|rust|go|ruby>  # force ecosystem

### Auto-Scan
depsec auto enable              # enable shell hooks for auto-scan
depsec auto disable             # remove shell hooks
depsec auto status              # show status + which layers are active

### Reports
depsec report                   # show last scan report
depsec report --history         # show all past scan results
depsec report --pkg <name>      # show report for a specific package

### Configuration
depsec config show              # show current config
depsec config set <key> <val>   # set a config value
depsec config reset             # reset to defaults

### Maintenance
depsec update-rules             # update YARA rules and CVE DB cache
depsec doctor                   # check Docker, ClamAV, shell hooks — full health check
depsec version                  # show DepSec version

---

## Risk Response Behavior

### Interactive Mode (default)
  ⚠️  RISK DETECTED: some-package@1.0.0
      Layer: Sandbox — postinstall script made outbound network call
      Destination: http://suspicious-domain.xyz
      Severity: HIGH

      [Y] Install anyway   [N] Cancel   [D] Show full details

### Strict Mode (--strict or config: mode = strict)
- Any risk above threshold → auto-cancel, no prompt
- Designed for CI/CD pipelines

### Log-Only Mode (--log-only or config: mode = log)
- Never blocks, always logs
- Silent watcher mode for teams that want visibility without interruption

### Severity Threshold
depsec config set min_severity low|medium|high|critical
Only report and act on findings at or above the configured threshold.

---

## Output Formats

Default (table):
  Package         Version   Severity   Layer     Reason
  some-package    1.0.0     HIGH       Sandbox   Outbound network in postinstall
  lodash          4.17.15   MEDIUM     CVE       CVE-2021-23337
  safe-package    2.3.1     CLEAN      —         —

JSON mode (for CI/CD):
  depsec scan --format json

Minimal mode (for scripts):
  depsec scan --format minimal

---

## Technical Stack

- Language: Go
  Reason: single binary distribution, fast startup, strong Docker/syscall
  libraries, easy cross-platform builds via GOOS/GOARCH

- Dependency resolution: parse package-lock.json, requirements.txt,
  Cargo.toml, go.mod, Gemfile — resolve full transitive dependency tree

- CVE data: OSV API (osv.dev/v1) + NVD API, cached in local SQLite

- Sandbox runtime: Docker SDK for Go (github.com/docker/docker/client)

- YARA: go-yara bindings

- ClamAV: shell out to clamd socket inside container (preferred over
  clamscan for speed), or clamscan as fallback

- Config: TOML at ~/.config/depsec/config.toml

- Shell hook management: detect shell from $SHELL, write/remove hooks
  programmatically from Go

---

## Project Structure

depsec/
├── cmd/
│   ├── scan.go
│   ├── auto.go
│   ├── report.go
│   ├── config.go
│   └── doctor.go
├── scanner/
│   ├── pipeline.go
│   ├── resolver.go
│   ├── cve.go
│   ├── metadata.go
│   ├── sandbox.go
│   ├── clamav.go
│   └── yara.go
├── hooks/
│   └── shell.go
├── cache/
├── rules/
├── output/
└── config/

---

## What NOT to Do

- Never write package contents to host filesystem at any point
- Never require root/sudo for normal operation
- Never modify the user's shell config without explicit depsec auto enable
- Never block the user silently — always explain why something was flagged
- Never re-warn about missing Docker/ClamAV after the first warning
- Do not reinstall or manage packages — only inspect

---

## First Implementation Step

Build in this order, get each step working end-to-end before moving on:

1. Project scaffold with the full structure above
2. depsec doctor — checks Docker, ClamAV, shell, prints status
3. Dependency resolver for Node.js (package-lock.json) and Python (requirements.txt)
4. CVE layer: OSV API query + SQLite cache
5. Metadata anomaly detection layer
6. Table output formatter + JSON mode
7. Docker sandbox: container lifecycle, tarball extraction, destroy
8. YARA integration inside sandbox
9. ClamAV integration inside sandbox
10. Shell hook injection for auto-scan (depsec auto enable/disable)

For testing, use the existing Fedora distrobox container via:

distrobox enter Project

Build the binary inside the container and run all test commands there. 
Do not install anything on the host system during testing.
