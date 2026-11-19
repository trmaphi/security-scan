# security-scan

Local security / software hygiene scanners for macOS, meant to be run manually or on a
schedule. Reports are plain Markdown, so they diff nicely and survive in git-less backups.

## Scanners

| Scanner | What it answers |
|---|---|
| [`macos/software-audit.sh`](macos/software-audit.sh) | What is installed, what is outdated (Homebrew formulae/casks, App Store, macOS updates), and what changed in `/Applications` since last run. |

## Requirements

- macOS
- `bash` (system bash 3.2 is fine)
- Optional: [Homebrew](https://brew.sh), [`mas`](https://github.com/mas-cli/mas) (`brew install mas`)
- Optional: `gh` for publishing reports as gists

## Usage

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

## Scheduling (cron)

```cron
PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin

0 9 * * * /Users/<you>/source/trmaphi/security-scan/macos/software-audit.sh >> ~/software-audit/cron.log 2>&1
```

The script repairs its own `PATH` for cron's minimal environment, so the `PATH=` line is
belt-and-braces rather than required.

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
