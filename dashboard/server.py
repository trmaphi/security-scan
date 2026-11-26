#!/usr/bin/env python3
"""Security dashboard — a small read-only web app over local scan artifacts.

Reads the reports and logs produced by this repo's scanners and renders them as a
single page. No database, no dependencies, no writes: it only parses files under
~/software-audit and ~/security-scan and shells out to `brew autoupdate status`,
`crontab -l`, `launchctl list`.

Usage:
    python3 dashboard/server.py                 # http://127.0.0.1:8787
    python3 dashboard/server.py --port 9000
    python3 dashboard/server.py --host 0.0.0.0  # expose on LAN (no auth!)

Endpoints:
    /                 dashboard HTML (auto-refreshes every 60s)
    /api/summary      same data as JSON
    /report/audit     raw latest software-audit markdown
    /report/vuln      raw latest vuln-scan markdown
"""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import subprocess
from datetime import datetime
from glob import glob
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOME = os.path.expanduser("~")
AUDIT_DIR = os.path.join(HOME, "software-audit", "reports")
VULN_DIR = os.path.join(HOME, "security-scan", "reports")
LOG_DIR = os.path.join(HOME, "security-scan", "logs")

PATH_ENV = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"



# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def newest(pattern: str) -> str | None:
    files = sorted(glob(pattern), key=os.path.getmtime, reverse=True)
    return files[0] if files else None


def read(path: str | None) -> str:
    if not path or not os.path.exists(path):
        return ""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def run(cmd: list[str], timeout: int = 15) -> str:
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                             env={**os.environ, "PATH": PATH_ENV})
        return (res.stdout or "") + (res.stderr or "")
    except Exception as exc:  # noqa: BLE001
        return f"error: {exc}"


def table_rows(text: str) -> list[list[str]]:
    """Rows of the first markdown table in *text* (excluding header/separator)."""
    rows: list[list[str]] = []
    in_table = False
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("|"):
            if in_table and rows:
                break
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if all(re.fullmatch(r":?-{2,}:?", c) for c in cells):
            continue
        if not in_table:
            in_table = True  # header row
            rows = []
            continue
        rows.append(cells)
    return rows


def as_int(value: str) -> int:
    m = re.search(r"-?\d+", value.replace("*", "").replace(",", ""))
    return int(m.group(0)) if m else 0


def section(text: str, heading: str) -> str:
    """Body of a '## heading' section."""
    m = re.search(rf"^##\s+{re.escape(heading)}\s*$(.*?)(?=^##\s|\Z)", text, re.S | re.M)
    return m.group(1) if m else ""


# --------------------------------------------------------------------------
# collectors
# --------------------------------------------------------------------------


def collect_audit() -> dict:
    path = newest(os.path.join(AUDIT_DIR, "software-audit-*.md"))
    text = read(path)
    data = {
        "available": bool(text),
        "path": path,
        "generated": "",
        "os": "",
        "metadata": "",
        "metrics": {},
        "apps_changed": "",
    }
    if not text:
        return data

    m = re.search(r"^# macOS Software Audit — (.+)$", text, re.M)
    if m:
        data["generated"] = m.group(1).strip()
    m = re.search(r"\*\*OS:\*\* (.+)$", text, re.M)
    if m:
        data["os"] = m.group(1).strip()
    m = re.search(r"\*\*Homebrew metadata:\*\* (.+)$", text, re.M)
    if m:
        data["metadata"] = m.group(1).strip()

    for row in table_rows(section(text, "Summary")):
        if len(row) >= 2:
            data["metrics"][row[0].replace("*", "")] = as_int(row[1])

    m = re.search(r"\*\*Apps added / removed since last run\*\* \| (.+?) \|", text)
    if m:
        data["apps_changed"] = m.group(1).strip()
    return data


def collect_vuln() -> dict:
    path = newest(os.path.join(VULN_DIR, "vuln-scan-*.md"))
    text = read(path)
    data = {
        "available": bool(text),
        "path": path,
        "generated": "",
        "severities": {},
        "total": 0,
        "packages": 0,
        "repos": 0,
        "top": [],
    }
    if not text:
        return data

    m = re.search(r"^# Source Vulnerability Scan — (.+)$", text, re.M)
    if m:
        data["generated"] = m.group(1).strip()

    for row in table_rows(section(text, "Summary")):
        if len(row) >= 2:
            name = row[0].replace("*", "")
            if name.lower() == "total":
                data["total"] = as_int(row[1])
                data["packages"] = as_int(row[2]) if len(row) > 2 else 0
            else:
                data["severities"][name.upper()] = as_int(row[1])

    data["repos"] = len(re.findall(r"^### ", text, re.M))
    top = re.findall(r"^### (.+?) — (\d+) advisories", text, re.M)
    data["top"] = [{"repo": r, "count": int(c)} for r, c in top[:4]]
    return data


def collect_upgrades() -> dict:
    today = datetime.now().strftime("%Y-%m-%d")
    daily_path = os.path.join(LOG_DIR, f"daily-{today}.log")
    if not os.path.exists(daily_path):
        daily_path = newest(os.path.join(LOG_DIR, "daily-*.log"))
    appstore_path = os.path.join(LOG_DIR, f"appstore-{today}.log")
    if not os.path.exists(appstore_path):
        appstore_path = newest(os.path.join(LOG_DIR, "appstore-*.log"))

    daily = read(daily_path)
    appstore = read(appstore_path)

    data = {
        "daily": {"available": bool(daily), "path": daily_path, "started": "",
                  "ok": None, "mise_failed": [], "codex": ""},
        "appstore": {"available": bool(appstore), "path": appstore_path,
                     "pending": 0, "note": ""},
    }
    if daily:
        stamps = re.findall(r"^=== daily upgrades — (.+?) ===$", daily, re.M)
        data["daily"]["started"] = stamps[-1] if stamps else ""
        tail = daily[daily.rfind("=== daily upgrades"):] if stamps else daily
        data["daily"]["ok"] = "all steps succeeded" in tail
        for m in re.finditer(r"^mise ✗ (\S+).*?failed: (.+)$", tail, re.M):
            data["daily"]["mise_failed"].append({"tool": m.group(1), "error": m.group(2)[:120]})
        after = re.findall(r"^after:\s+codex-cli (\S+)", tail, re.M)
        if after:
            data["daily"]["codex"] = after[-1]

    if appstore:
        pending = re.findall(r"^\s*\d{6,}\s+\S", appstore, re.M)
        data["appstore"]["pending"] = len(pending)
        if "passwordless sudo is not available" in appstore:
            data["appstore"]["note"] = "needs root — App Store auto-update is the fallback"
        elif "all steps succeeded" in appstore:
            data["appstore"]["note"] = "upgraded"
    return data


def collect_services() -> dict:
    brew_status = run(["brew", "autoupdate", "status"])
    cron = run(["crontab", "-l"])
    launchd = run(["launchctl", "list"])

    jobs = []
    for line in launchd.splitlines():
        if "security-scan" in line or "homebrew-autoupdate" in line:
            parts = line.split("\t")
            if len(parts) >= 3:
                jobs.append({"pid": parts[0], "exit": parts[1], "label": parts[2]})

    schedule = []
    for line in cron.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("PATH="):
            continue
        fields = line.split()
        if len(fields) >= 6:
            schedule.append({"spec": " ".join(fields[:5]), "cmd": " ".join(fields[5:])})

    return {
        "brew": {
            "installed": "Autoupdate is installed and running" in brew_status,
            "schedule": (re.search(r"Schedule: (.+)", brew_status) or [None, ""])[1],
            "greedy": "Greedy cask upgrades: yes" in brew_status,
        },
        "jobs": jobs,
        "cron": schedule,
    }


def collect_reports() -> dict:
    def entries(directory: str, pattern: str, kind: str) -> list[dict]:
        out = []
        for f in sorted(glob(os.path.join(directory, pattern)),
                        key=os.path.getmtime, reverse=True)[:8]:
            st = os.stat(f)
            out.append({
                "name": os.path.basename(f),
                "size": st.st_size,
                "mtime": datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M"),
                "link": f"/report/{kind}/{os.path.basename(f)}",
            })
        return out
    return {
        "audit": entries(AUDIT_DIR, "software-audit-*.md", "audit"),
        "vuln": entries(VULN_DIR, "vuln-scan-*.md", "vuln"),
    }


def days_old(stamp: str) -> int | None:
    if not stamp:
        return None
    try:
        dt = datetime.strptime(stamp.strip(), "%Y-%m-%d %H:%M %z")
    except ValueError:
        return None
    return (datetime.now(dt.tzinfo) - dt).days


def collect_actions(data: dict) -> list[dict]:
    """Prioritised next actions derived from the reports."""
    acts: list[dict] = []
    m = data["audit"]["metrics"]
    v = data["vuln"]
    crit = v["severities"].get("CRITICAL", 0)
    high = v["severities"].get("HIGH", 0)
    age = days_old(v["generated"])

    if v["available"] and (age is None or age > 7):
        acts.append({
            "priority": "high" if crit else "medium",
            "title": f"Re-run the vulnerability scan (stale{f' {age}d' if age is not None else ''})",
            "why": f"last scan {v['generated'] or 'never'} — advisories change daily",
            "cmd": "./source/vuln-audit.sh",
        })
    if crit or high:
        acts.append({
            "priority": "high",
            "title": f"Triage {crit} critical / {high} high CVEs",
            "why": "dependency advisories in your repos; see the report below",
            "cmd": "open ~/security-scan/reports/$(ls -t ~/security-scan/reports | head -1)",
        })
    if m.get("macOS updates available", 0):
        acts.append({
            "priority": "high",
            "title": f"Install {m['macOS updates available']} macOS updates",
            "why": "Safari and OS security patches",
            "cmd": "sudo softwareupdate -i -a",
        })
    if m.get("App Store updates (mas)", 0):
        acts.append({
            "priority": "medium",
            "title": f"Update {m['App Store updates (mas)']} App Store apps",
            "why": "mas needs root, so the weekly job skips them",
            "cmd": "sudo mas upgrade",
        })
    if m.get("Outdated formulae", 0):
        acts.append({
            "priority": "medium",
            "title": f"Upgrade {m['Outdated formulae']} Homebrew formulae",
            "why": "brew autoupdate runs daily — this usually clears itself",
            "cmd": "brew upgrade",
        })
    greedy = m.get("Outdated casks (incl. greedy/self-updating)", 0)
    if greedy:
        acts.append({
            "priority": "medium",
            "title": f"Upgrade {greedy} self-updating casks",
            "why": "apps that normally update themselves; brew can force them",
            "cmd": "brew upgrade --cask --greedy",
        })
    failed = data["upgrades"]["daily"]["mise_failed"]
    if failed:
        tools = " ".join(f"--exclude {f['tool'].split('@')[0]}" for f in failed)
        acts.append({
            "priority": "low",
            "title": f"Work around {len(failed)} mise failures",
            "why": ", ".join(f["tool"] for f in failed) + " — upstream asset naming",
            "cmd": f"mise upgrade {tools}",
        })
    return acts


def collect() -> dict:
    data = {
        "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "audit": collect_audit(),
        "vuln": collect_vuln(),
        "upgrades": collect_upgrades(),
        "services": collect_services(),
    }
    data["reports"] = collect_reports()
    data["actions"] = collect_actions(data)
    return data


# --------------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------------

CSS = """
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body { margin: 0; font: 15px/1.5 -apple-system, BlinkMacSystemFont, "SF Pro Text", sans-serif;
       background: #0f1115; color: #e6e9ef; }
header { padding: 24px 32px 8px; }
h1 { margin: 0; font-size: 22px; letter-spacing: -0.02em; }
.sub { color: #8c94a3; font-size: 13px; margin-top: 4px; }
main { padding: 16px 32px 48px; max-width: 1180px; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 14px; }
.card { background: #171a21; border: 1px solid #242936; border-radius: 12px; padding: 16px; }
.card .k { color: #8c94a3; font-size: 12px; text-transform: uppercase; letter-spacing: .06em; }
.card .v { font-size: 30px; font-weight: 650; margin-top: 6px; }
.card.wide { grid-column: span 2; }
.pill { display: inline-block; padding: 3px 9px; border-radius: 999px; font-size: 12px; font-weight: 600; }
.ok { background: #14321f; color: #5fd38a; }
.warn { background: #3a2a10; color: #f0b354; }
.bad { background: #3a1618; color: #ff7b7b; }
.muted { color: #8c94a3; }
h2 { font-size: 15px; margin: 28px 0 10px; color: #cfd5e2; }
table { width: 100%; border-collapse: collapse; font-size: 13.5px; }
th, td { text-align: left; padding: 7px 10px; border-bottom: 1px solid #222734; }
th { color: #8c94a3; font-weight: 500; }
td.num { text-align: right; font-variant-numeric: tabular-nums; }
code { background: #12151b; padding: 1px 6px; border-radius: 6px; font-size: 12.5px; }
a { color: #7cb0ff; text-decoration: none; }
.row { display: flex; gap: 18px; flex-wrap: wrap; }
.row > * { flex: 1 1 320px; }
footer { color: #626a79; font-size: 12px; padding: 0 32px 32px; }
button.copy { background: #202634; color: #cfd5e2; border: 1px solid #2c3343; border-radius: 6px;
              padding: 2px 8px; font-size: 11px; cursor: pointer; margin-left: 6px; }
button.copy:hover { background: #283042; }
td.act-title strong { font-weight: 600; }

"""


def pill(ok: bool | None, text: str) -> str:
    cls = "ok" if ok else ("bad" if ok is False else "warn")
    return f'<span class="pill {cls}">{html.escape(text)}</span>'


def esc(value: object) -> str:
    return html.escape(str(value))


SCRIPT = """<script>
document.querySelectorAll("button.copy").forEach(function (b) {
  b.addEventListener("click", function () {
    var done = function () { b.textContent = "copied"; setTimeout(function () { b.textContent = "copy"; }, 1200); };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(b.dataset.cmd).then(done, done);
    } else { done(); }
  });
});
</script>"""


def render(data: dict) -> str:
    a, v, u, s = data["audit"], data["vuln"], data["upgrades"], data["services"]
    m = a["metrics"]

    outdated_f = m.get("Outdated formulae", 0)
    outdated_c = m.get("Outdated casks", 0)
    greedy = m.get("Outdated casks (incl. greedy/self-updating)", 0)
    os_updates = m.get("macOS updates available", 0)
    appstore = m.get("App Store updates (mas)", 0)

    crit = v["severities"].get("CRITICAL", 0)
    high = v["severities"].get("HIGH", 0)

    daily_ok = u["daily"]["ok"]
    daily_pill = pill(daily_ok, "last run ok" if daily_ok else ("last run failed" if daily_ok is False else "no run yet"))
    vuln_pill = pill(crit == 0, f"{crit} critical")
    brew = s["brew"]
    brew_pill = pill(brew["installed"], "autoupdate active" if brew["installed"] else "autoupdate off")

    summary_bits = [
        f"{outdated_f} outdated formulae",
        f"{greedy} casks ({outdated_c} non-greedy)",
        f"{os_updates} macOS updates",
        f"{v['total']} CVEs ({crit} critical)",
        f"App Store {appstore} pending",
        daily_pill,
    ]

    cards = f"""
    <div class="grid">
      <div class="card"><div class="k">Outdated formulae</div><div class="v">{outdated_f}</div>
        <div class="muted">Homebrew metadata: {esc(a['metadata'] or 'unknown')}</div></div>
      <div class="card"><div class="k">Outdated casks</div><div class="v">{greedy}</div>
        <div class="muted">{outdated_c} not self-updating</div></div>
      <div class="card"><div class="k">macOS updates</div><div class="v">{os_updates}</div>
        <div class="muted">system</div></div>
      <div class="card"><div class="k">App Store</div><div class="v">{appstore}</div>
        <div class="muted">pending updates</div></div>
      <div class="card"><div class="k">Known CVEs</div><div class="v">{v['total']}</div>
        <div class="muted">{crit} critical · {high} high · {v['repos']} repos</div></div>
      <div class="card"><div class="k">Daily upgrades</div><div class="v">{len(u['daily']['mise_failed'])}</div>
        <div class="muted">mise failures · {daily_pill}</div></div>
    </div>
    """

    prio_class = {"high": "bad", "medium": "warn", "low": "ok"}
    action_rows = "".join(
        f"""<tr><td><span class="pill {prio_class.get(act['priority'], 'warn')}">{esc(act['priority'])}</span></td>
        <td class="act-title"><strong>{esc(act['title'])}</strong>
          <div class="muted">{esc(act['why'])}</div></td>
        <td><code>{esc(act['cmd'])}</code><button class="copy" data-cmd="{esc(act['cmd'])}">copy</button></td></tr>"""
        for act in data["actions"]
    ) or "<tr><td colspan=3 class='muted'>nothing to do — all clear</td></tr>"

    def report_rows(rows: list[dict]) -> str:
        return "".join(
            f"<tr><td><a href=\"{r['link']}\">{esc(r['name'])}</a></td>"
            f"<td class='muted'>{esc(r['mtime'])}</td><td class='num'>{r['size'] // 1024}</td></tr>"
            for r in rows
        ) or "<tr><td colspan=3 class='muted'>no reports yet</td></tr>"

    vuln_rows = "".join(
        f"<tr><td>{esc(k)}</td><td class='num'>{n}</td></tr>"
        for k, n in v["severities"].items()
    ) or "<tr><td colspan=2 class='muted'>no vulnerability report yet — run <code>./source/vuln-audit.sh</code></td></tr>"

    top_rows = "".join(
        f"<tr><td>{esc(t['repo'])}</td><td class='num'>{t['count']}</td></tr>" for t in v["top"]
    ) or "<tr><td colspan=2 class='muted'>—</td></tr>"

    failed_rows = "".join(
        f"<tr><td><code>{esc(f['tool'])}</code></td><td class='muted'>{esc(f['error'])}</td></tr>"
        for f in u["daily"]["mise_failed"]
    ) or "<tr><td colspan=2 class='muted'>none</td></tr>"

    schedule_rows = ""
    for item in s["cron"]:
        schedule_rows += (
            f"<tr><td><code>{esc(item['spec'])}</code></td>"
            f"<td class='muted'>{esc(item['cmd'].split('/')[-1] if '/' in item['cmd'] else item['cmd'])[:90]}</td></tr>"
        )
    for job in s["jobs"]:
        state = "running" if job["pid"] != "-" else f"idle (exit {job['exit']})"
        schedule_rows += f"<tr><td><code>{esc(job['label'])}</code></td><td class='muted'>{esc(state)}</td></tr>"
    schedule_rows = schedule_rows or "<tr><td colspan=2 class='muted'>—</td></tr>"

    return f"""<!doctype html>
<html><head><meta charset="utf-8">
<meta http-equiv="refresh" content="60">
<title>Security Dashboard</title>
<style>{CSS}</style></head>
<body>
<header>
  <h1>Security Dashboard</h1>
  <div class="sub">generated {esc(data['generated'])} · audit {esc(a['generated'] or 'never')} · vuln scan {esc(v['generated'] or 'never')} · auto-refresh 60s</div>
  <div class="sub">{' · '.join(summary_bits)}</div>
</header>
<main>
  {cards}

  <h2>Actions <span class="muted">({len(data['actions'])})</span></h2>
  <div class="card"><table><tr><th>priority</th><th>action</th><th>command</th></tr>{action_rows}</table></div>

  <h2>Vulnerabilities <span class="muted">({esc(v['generated'] or 'no scan')})</span> {vuln_pill}</h2>
  <div class="row">
    <div class="card"><table>{vuln_rows}</table></div>
    <div class="card"><table><tr><th>Top repos</th><th class="num">advisories</th></tr>{top_rows}</table>
      <div class="muted" style="margin-top:8px">full report: <a href="/report/vuln">vuln-scan.md</a></div></div>
  </div>

  <h2>Upgrades {daily_pill}</h2>
  <div class="row">
    <div class="card">
      <table>
        <tr><th>Daily CLI pass</th><td>{esc(u['daily']['started'] or '—')}</td></tr>
        <tr><th>Codex CLI</th><td>{esc(u['daily']['codex'] or '—')}</td></tr>
        <tr><th>App Store</th><td>{appstore} pending · {esc(u['appstore']['note'] or '—')}</td></tr>
        <tr><th>Brew autoupdate</th><td>{brew_pill} {esc(brew['schedule'])}</td></tr>
      </table>
      <div class="muted" style="margin-top:8px">logs: <code>~/security-scan/logs/</code></div>
    </div>
    <div class="card">
      <div class="k" style="margin-bottom:8px">mise failures</div>
      <table>{failed_rows}</table>
    </div>
  </div>

  <h2>Schedules</h2>
  <div class="card"><table><tr><th>when</th><th>job</th></tr>{schedule_rows}</table></div>

  <h2>Reports</h2>
  <div class="row">
    <div class="card">
      <div class="k" style="margin-bottom:8px">software audit</div>
      <table><tr><th>file</th><th>date</th><th class="num">KB</th></tr>{report_rows(data['reports']['audit'])}</table>
    </div>
    <div class="card">
      <div class="k" style="margin-bottom:8px">vulnerability scans</div>
      <table><tr><th>file</th><th>date</th><th class="num">KB</th></tr>{report_rows(data['reports']['vuln'])}</table>
    </div>
  </div>
</main>
<footer>read-only dashboard · localhost only · data: {esc(AUDIT_DIR)} and {esc(VULN_DIR)}</footer>
</body></html>""" + SCRIPT


# --------------------------------------------------------------------------
# http
# --------------------------------------------------------------------------


class Handler(BaseHTTPRequestHandler):
    def _send(self, body: bytes, status: int = 200, ctype: str = "text/html; charset=utf-8") -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?")[0]
        try:
            if path == "/":
                self._send(render(collect()).encode())
            elif path == "/api/summary":
                self._send(json.dumps(collect(), default=str).encode(),
                           ctype="application/json; charset=utf-8")
            elif path == "/report/audit":
                self._send(read(newest(os.path.join(AUDIT_DIR, "software-audit-*.md"))).encode(),
                           ctype="text/plain; charset=utf-8")
            elif path == "/report/vuln":
                self._send(read(newest(os.path.join(VULN_DIR, "vuln-scan-*.md"))).encode(),
                           ctype="text/plain; charset=utf-8")
            elif path.startswith("/report/audit/") or path.startswith("/report/vuln/"):
                parts = path.strip("/").split("/", 2)
                kind = parts[1] if len(parts) == 3 else ""
                name = parts[2] if len(parts) == 3 else ""
                base = AUDIT_DIR if kind == "audit" else VULN_DIR
                if not re.fullmatch(r"[A-Za-z0-9._-]+\.md", name):
                    self._send(b"not found", status=404, ctype="text/plain")
                else:
                    self._send(read(os.path.join(base, name)).encode(),
                               ctype="text/plain; charset=utf-8")
            else:
                self._send(b"not found", status=404, ctype="text/plain")
        except Exception as exc:  # noqa: BLE001
            self._send(f"error: {exc}".encode(), status=500, ctype="text/plain")

    def log_message(self, fmt: str, *args: object) -> None:  # quieter logs
        return


def main() -> None:
    ap = argparse.ArgumentParser(description="Local security dashboard")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8787)
    args = ap.parse_args()
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"Security dashboard: http://{args.host}:{args.port}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
