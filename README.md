# security-scan

Local security / software hygiene scanners for macOS, Windows and WSL/Linux, meant to be run
manually or on a schedule. Reports are plain Markdown, so they diff nicely and survive in
git-less backups.

Nothing here uploads data or changes packages silently: scanners only read state, and the one
script that does upgrade packages (`windows/winget-upgrade.ps1`) is explicit about scope and
logs everything.

## Scanners

| Scanner | Platform | What it answers |
|---|---|---|
| [`macos/software-audit.sh`](macos/software-audit.sh) | macOS | What is installed, what is outdated (Homebrew formulae/casks, App Store, macOS updates), and what changed in `/Applications` since last run. |
| [`source/vuln-audit.sh`](source/vuln-audit.sh) | macOS / Linux / WSL | Known CVEs/GHSAs in project dependency lockfiles (OSV-Scanner), grouped by git repository with severity and advisory links. |
| [`windows/vuln-scan.ps1`](windows/vuln-scan.ps1) | Windows | Outdated winget packages, pending Windows Update items, and HIGH/CRITICAL CVEs in dependency manifests (Trivy). |
| [`windows/winget-upgrade.ps1`](windows/winget-upgrade.ps1) | Windows | Unattended winget upgrades that cannot hang on a UAC prompt. |
| [`wsl/scan.sh`](wsl/scan.sh) | WSL / Linux | HIGH/CRITICAL CVEs in installed OS packages (Trivy) plus advisories in project lockfiles (OSV-Scanner). |

## Windows

### Requirements

- PowerShell 5.1+ (built in)
- `winget` (App Installer)
- Internet access on first run (Trivy vulnerability DB, ~135 MB)
- No admin required for scanning or user-scope upgrades

### Setup

```powershell
# installs Trivy into %USERPROFILE%\security-scan\bin and registers two daily tasks
.\windows\install.ps1
```

That creates:

| Task | Script | Default time |
|---|---|---|
| `Security Scan Daily` | `windows/vuln-scan.ps1` | 03:00 |
| `Winget Upgrade Daily` | `windows/winget-upgrade.ps1 -Scope user` | 04:00 |

Use `-NoTasks` to install binaries only, or `-ScanTime` / `-UpgradeTime` to change times.

### Usage

```powershell
# full scan (winget + Windows Update + Trivy on Documents)
.\windows\vuln-scan.ps1

# explicit paths and report location
.\windows\vuln-scan.ps1 -Path "$HOME\source","$HOME\Documents" -OutDir D:\reports

# skip parts you do not want
.\windows\vuln-scan.ps1 -SkipWinget -SkipWindowsUpdate

# what would be upgraded?
.\windows\winget-upgrade.ps1 -DryRun

# actual upgrade (user scope only)
.\windows\winget-upgrade.ps1

# elevated, includes machine-scope packages
.\windows\winget-upgrade.ps1 -Scope any
```

Reports land in `%USERPROFILE%\security-scan\reports\<timestamp>\summary.md` (scan) and
`%USERPROFILE%\security-scan\winget-upgrade\reports\<timestamp>\summary.md` (upgrades), each
with JSON/TXT evidence and a `run.log`.

### Why the upgrade script looks paranoid

`winget upgrade --all` will happily launch an installer that raises a UAC prompt. In a
scheduled task nobody clicks it, so the job hangs forever — this actually happened while
building this repo. The script therefore:

- defaults to `-Scope user`, which skips machine-scope packages entirely;
- runs winget under a hard timeout and kills the process tree on expiry;
- re-reads the pending list afterwards, so the report shows what actually moved.

To cover machine-scope packages, register the task with `-Scope any` from an **elevated**
shell:

```powershell
schtasks /Create /TN "Winget Upgrade Daily" /TR '"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "C:\path\to\security-scan\windows\winget-upgrade.ps1" -Scope any' /SC DAILY /ST 04:00 /RL HIGHEST /F
```

### Excluding packages

`winget` has no exclude flag, so the script switches to per-package upgrades when an exclude
list is present. Copy `windows/exclude.txt.example` to `windows/exclude.txt` and list exact IDs.

## WSL / Linux

### Setup

```bash
./wsl/install.sh          # trivy + osv-scanner into ~/.local/share/security-scan/bin
export PATH="$HOME/.local/share/security-scan/bin:$PATH"
cp wsl/paths.txt.example wsl/paths.txt   # edit: project directories to scan
```

`-Scope`/elevation is irrelevant here; `osv-scanner` is only installed when a Go toolchain is
present.

### Usage

```bash
./wsl/scan.sh                          # writes ~/security-scan/reports/<timestamp>/
OUT_DIR=/tmp/scan SEVERITY=CRITICAL ./wsl/scan.sh
PATHS_FILE=~/my-paths.txt ./wsl/scan.sh
```

Output per run:

- `os.txt` / `os.json` — OS package findings (HIGH/CRITICAL, fixed only)
- `apt-status.tsv` — installed vs apt candidate per flagged package; candidate == installed
  means it is a legacy/third-party package that apt cannot fix
- `deps-*.md` — OSV advisories (CVSS, fixed version, lockfile)
- `run.log`

### Scheduling (cron)

```cron
PATH=$HOME/.local/share/security-scan/bin:/usr/local/bin:/usr/bin:/bin

0 3 * * * /path/to/security-scan/wsl/scan.sh >> ~/security-scan/cron.log 2>&1
```

## macOS

### Requirements

- macOS
- `bash` (system bash 3.2 is fine)
- Optional: [Homebrew](https://brew.sh), [`mas`](https://github.com/mas-cli/mas) (`brew install mas`)
- Optional: `gh` for publishing reports as gists

### Usage

```bash
# full run: refresh brew metadata, then audit
./macos/software-audit.sh

# faster run without `brew update` (may report stale/zero updates)
BREW_UPDATE=0 ./macos/software-audit.sh

# custom report location / retention / timeout for softwareupdate
OUT_DIR=~/Desktop/audit KEEP=10 SU_TIMEOUT=45 ./macos/software-audit.sh
```

Reports land in `~/software-audit/reports/software-audit-<timestamp>.md`, with `/Applications`
snapshots in `~/software-audit/snapshots/`. The last 30 of each are kept (`KEEP=N` to change).

Each report contains:

1. Outdated formulae — `brew outdated --verbose`
2. Outdated casks — `brew outdated --cask --greedy --verbose` (incl. self-updating apps)
3. Installed formulae — `brew list --versions`
4. Top-level formulae — `brew leaves`
5. Installed casks — `brew list --cask --versions`
6. App Store updates — `mas outdated` (best-effort, see caveats)
7. macOS updates — `softwareupdate -l`, killed after `SU_TIMEOUT` seconds
8. Application changes vs. the previous run (added/removed apps in `/Applications`, `~/Applications`)

### Scheduling (cron)

```cron
PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin

0 9 * * * /Users/<you>/source/trmaphi/security-scan/macos/software-audit.sh >> ~/software-audit/cron.log 2>&1
```

The script repairs its own `PATH` for cron's minimal environment, so the `PATH=` line is
belt-and-braces rather than required.

## Source dependency scanning (any platform)

`source/vuln-audit.sh` uses [osv-scanner](https://google.github.io/osv-scanner/) to find
known CVEs/GHSAs in dependency lockfiles, grouped by the enclosing git repository.

### Requirements

- `osv-scanner` (`brew install osv-scanner`, or run it from WSL)
- `python3` (ships with macOS; any 3.x)
- `git` for attributing findings to a repository (falls back to directory names)

### Usage

```bash
# scan all repos under ~/source/trmaphi (default root)
./source/vuln-audit.sh

# scan specific roots (each may contain many repos)
./source/vuln-audit.sh ~/source/trmaphi/scheduler ~/work/api

SCAN_TIMEOUT=600 ./source/vuln-audit.sh   # cap scan time (default 900s)
./source/vuln-audit.sh --no-fail          # exit 0 even with findings
```

Reports land in `~/security-scan/reports/vuln-scan-<timestamp>.md`, with a severity summary,
a per-repository table (severity, package, version, advisory link, summary) and the last 30
reports retained.

Exit codes: `0` clean, `1` scan failed or timed out, `2` findings include HIGH or CRITICAL.

Only dependency manifests are scanned (npm/pnpm/yarn, Go modules, pip/poetry/uv, Cargo,
Bundler, Composer). OS packages, Homebrew formulae, macOS apps and App Store apps are **not**
covered — there is no local CVE mapping for those on macOS; use `softwareupdate`, each
vendor's advisories, and section 7 of the software audit instead.

## Caveats

- **Stale Homebrew metadata.** `brew outdated` only knows about the tap state as of the last
  `brew update`. The script runs `brew update --quiet` first by default (`BREW_UPDATE=1`);
  disable with `BREW_UPDATE=0` only if some other job refreshes the index.
- **`mas outdated` is unreliable** on recent macOS versions — it can return empty output while
  App Store updates are pending. Treat section 6 as best-effort; the App Store UI is the
  source of truth for security patches.
- **`softwareupdate -l` hits Apple's servers** and takes 10–30 s, occasionally hanging. It is
  wrapped in a timeout (`SU_TIMEOUT`, default 90 s) and the report says so when it fires.
- **Greedy casks** (1Password, Chrome, VS Code, …) update themselves. `brew upgrade --cask`
  won't move them; that is expected, not a scanner bug.
- **Windows installed apps have no public CVE feed.** The winget list means "outdated", not
  "vulnerable"; Windows Update is authoritative for OS patches. Trivy only sees dependency
  manifests, not `.exe` files.
- **Legacy Linux packages** (e.g. `libssl1.1` on Ubuntu 24.04) have no apt candidate; the
  `apt-status.tsv` column makes that visible instead of promising a fix that cannot happen.
- **Trivy database** must be downloadable (`ghcr.io` / `mirror.gcr.io`). Scanning is
  read-only; DBs are cached under `%USERPROFILE%\security-scan\cache` or
  `~/.cache/trivy` unless overridden.
- **`vuln-audit.sh` severity is advisory-specific.** Go stdlib advisories in OSV carry no
  severity score and show up as `UNKNOWN`; they are still real advisories. Findings reflect
  what the lockfiles say, not what runs — dev dependencies count even if never bundled.
- **No CVE mapping for macOS apps.** "Outdated" in the software audit is not "vulnerable",
  and an up-to-date app can still be vulnerable. Nothing local knows that today.
