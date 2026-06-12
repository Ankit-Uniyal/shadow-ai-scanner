#!/usr/bin/env python3
"""
Shadow AI Endpoint Scanner
==========================
Endpoint-local discovery of AI tools, assistants, agents, SDKs, browser
extensions, local model runtimes, and active AI network sessions.

Runs ON the device being assessed. For fleet coverage, deploy via MDM / RMM /
EDR so it executes in each user context. Run only on devices you are authorized
to scan.

Detection is signature-based (see signatures.json). It flags presence of AI
credentials and config but never reads or transmits secret values.

Usage:
    python3 shadowai.py                 # full scan, writes JSON + HTML to ./reports
    python3 shadowai.py --no-network    # skip live network / DNS checks
    python3 shadowai.py --output-dir /tmp/out
    python3 shadowai.py --signatures /path/to/signatures.json
    python3 shadowai.py --quiet         # suppress console summary
"""

import os
import sys
import json
import socket
import getpass
import platform
import argparse
import datetime
import subprocess
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import psutil
    HAVE_PSUTIL = True
except ImportError:
    HAVE_PSUTIL = False

VERSION = "1.1.0"

RISK_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
RISK_NAMES = {v: k for k, v in RISK_ORDER.items()}

# Governance context per finding category. Indicative only, not a control mapping.
GRC_CONTEXT = {
    "assistant": "Cloud assistant. Prompt/file content may leave the org boundary. Assess against data classification, DLP, and acceptable-use policy.",
    "code_assistant": "Code assistant. Source, secrets, and IP may be transmitted to a third party. Assess against IP protection and secure-SDLC policy.",
    "agent": "Autonomous agent. Can take actions and execute code with elevated blast radius. Treat as high-priority review.",
    "agent_framework": "Agent framework present. Indicates autonomous workflows may be built or run locally. Review use case and guardrails.",
    "sdk": "AI provider SDK. A direct integration path to a cloud model exists. Confirm whether sanctioned and where data is sent.",
    "sdk_gateway": "Multi-provider gateway. Can route data to many models including non-approved ones. Review allow-list enforcement.",
    "framework": "AI application framework. May orchestrate calls to cloud models. Review for embedded provider credentials.",
    "local_model_runtime": "Local model runtime. Lower data-egress risk but still unsanctioned compute and a potential exfil/abuse vector.",
    "image_model_runtime": "Local image-generation runtime. Review for content and licensing risk.",
    "model_library": "Model/embedding library. Often pulls weights from external hubs. Review provenance and licensing.",
    "vector_store": "Vector store / RAG component. May hold embeddings of sensitive corpora. Review what was indexed and where it lives.",
    "ai_enabled_app": "Application with embedded AI features. Confirm whether AI features are active and where content is processed.",
    "meeting_ai": "Meeting capture AI. Records and transcribes conversations to the cloud. High confidentiality exposure.",
    "browser_extension": "Browser AI extension. Can read page content (potentially internal apps) and send it to a third party.",
    "credential": "AI credential present. A configured path to a cloud model exists on this device.",
    "network": "Active session to an AI endpoint observed at scan time. Confirms in-use cloud AI consumption.",
}


# --------------------------------------------------------------------------- #
# Signature loading
# --------------------------------------------------------------------------- #
def load_signatures(path=None):
    candidate = None
    if path:
        candidate = Path(path)
    else:
        here = Path(__file__).resolve().parent
        local = here / "signatures.json"
        if local.exists():
            candidate = local
    if not candidate or not candidate.exists():
        raise FileNotFoundError(
            "signatures.json not found. Place it next to shadowai.py or pass --signatures."
        )
    with open(candidate, "r", encoding="utf-8") as fh:
        return json.load(fh)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def finding(source, name, vendor, category, hosting, base_risk, evidence, detail=""):
    return {
        "source": source,
        "name": name,
        "vendor": vendor,
        "category": category,
        "hosting": hosting,
        "base_risk": base_risk,
        "evidence": evidence,
        "detail": detail,
    }


def run_cmd(args, timeout=15):
    try:
        out = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout, check=False
        )
        return out.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return ""


# --------------------------------------------------------------------------- #
# Collector: running processes
# --------------------------------------------------------------------------- #
def _own_process_tree():
    """PIDs of the scanner and its ancestors, to avoid self-detection when a
    parent shell or launcher happens to reference an AI tool in its arguments."""
    exclude = set()
    if not HAVE_PSUTIL:
        return exclude
    try:
        p = psutil.Process()
        while p is not None:
            exclude.add(p.pid)
            try:
                p = p.parent()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                p = None
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
    return exclude


def scan_processes(sig):
    results = []
    if not HAVE_PSUTIL:
        return results, "psutil unavailable, process scan skipped"
    exclude = _own_process_tree()
    matches = {}
    for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
        try:
            info = proc.info
            pid = info.get("pid")
            if pid in exclude:
                continue
            name = (info.get("name") or "")
            exe = (info.get("exe") or "")
            exe_base = os.path.basename(exe) if exe else ""
            # Match on the executable/process name only. Command-line arguments
            # are not matched, since an AI tool name can appear as a data
            # argument or script path without the tool running.
            haystack = " ".join([name, exe_base]).lower()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        if not haystack.strip():
            continue
        for s in sig.get("processes", []):
            if any(p.lower() in haystack for p in s["patterns"]):
                m = matches.setdefault(
                    s["name"], {"sig": s, "pids": [], "pname": name or exe_base}
                )
                m["pids"].append(pid)
                break
    # One finding per tool. Desktop apps (especially Electron-based ones)
    # spawn many OS processes; that is one installed tool, not many findings.
    for tool, m in matches.items():
        s = m["sig"]
        pids = sorted(p for p in m["pids"] if p is not None)
        shown = ", ".join(str(p) for p in pids[:6])
        if len(pids) > 6:
            shown += f" +{len(pids) - 6} more"
        plural = "es" if len(pids) != 1 else ""
        results.append(
            finding(
                "process", s["name"], s["vendor"], s["category"],
                s["hosting"], s["risk"],
                f"running, {len(pids)} process{plural} ({m['pname']})",
                f"pids {shown}",
            )
        )
    return results, None


# --------------------------------------------------------------------------- #
# Collector: CLI binaries on PATH
# --------------------------------------------------------------------------- #
def which(binary):
    from shutil import which as _which
    return _which(binary)


def scan_cli(sig):
    results = []
    for s in sig.get("cli", []):
        for b in s["binaries"]:
            found = which(b)
            if found:
                results.append(
                    finding(
                        "cli", s["name"], s["vendor"], s["category"],
                        s["hosting"], s["risk"],
                        f"{b} on PATH", found,
                    )
                )
                break
    return results


# --------------------------------------------------------------------------- #
# Collector: Python packages
# --------------------------------------------------------------------------- #
def installed_pip_packages():
    names = {}
    # Current interpreter environment.
    try:
        from importlib import metadata as imd
        for dist in imd.distributions():
            try:
                nm = (dist.metadata["Name"] or "").lower()
                ver = dist.version
            except Exception:
                continue
            if nm:
                names[nm] = ver
    except Exception:
        pass
    # Whatever pip is on PATH (may be a different environment).
    for pip_bin in ("pip3", "pip"):
        if which(pip_bin):
            out = run_cmd([pip_bin, "list", "--format=json"])
            if out:
                try:
                    for pkg in json.loads(out):
                        names.setdefault(pkg["name"].lower(), pkg.get("version", "?"))
                except (json.JSONDecodeError, KeyError, TypeError):
                    pass
            break
    return names


def scan_pip(sig):
    results = []
    installed = installed_pip_packages()
    if not installed:
        return results
    for s in sig.get("pip", []):
        nm = s["name"].lower()
        if nm in installed:
            results.append(
                finding(
                    "pip", s["name"], s["vendor"], s["category"],
                    s["hosting"], s["risk"],
                    f"pip package {s['name']} {installed[nm]}", "",
                )
            )
    return results


# --------------------------------------------------------------------------- #
# Collector: global npm packages
# --------------------------------------------------------------------------- #
def scan_npm(sig):
    results = []
    if not which("npm"):
        return results
    out = run_cmd(["npm", "ls", "-g", "--depth=0", "--json"], timeout=25)
    if not out:
        return results
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return results
    deps = data.get("dependencies", {}) or {}
    for s in sig.get("npm", []):
        if s["name"] in deps:
            ver = deps[s["name"]].get("version", "?")
            results.append(
                finding(
                    "npm", s["name"], s["vendor"], s["category"],
                    s["hosting"], s["risk"],
                    f"global npm {s['name']} {ver}", "",
                )
            )
    return results


# --------------------------------------------------------------------------- #
# Collector: browser extensions
# --------------------------------------------------------------------------- #
def chromium_profile_roots():
    home = Path.home()
    system = platform.system()
    roots = []
    families = {
        "Chrome": {
            "Windows": home / "AppData/Local/Google/Chrome/User Data",
            "Darwin": home / "Library/Application Support/Google/Chrome",
            "Linux": home / ".config/google-chrome",
        },
        "Edge": {
            "Windows": home / "AppData/Local/Microsoft/Edge/User Data",
            "Darwin": home / "Library/Application Support/Microsoft Edge",
            "Linux": home / ".config/microsoft-edge",
        },
        "Brave": {
            "Windows": home / "AppData/Local/BraveSoftware/Brave-Browser/User Data",
            "Darwin": home / "Library/Application Support/BraveSoftware/Brave-Browser",
            "Linux": home / ".config/BraveSoftware/Brave-Browser",
        },
    }
    for browser, mapping in families.items():
        base = mapping.get(system)
        if base and base.exists():
            roots.append((browser, base))
    return roots


def read_extension_name(ext_dir):
    # Pick a version subfolder and read manifest name, resolving __MSG_ tokens.
    try:
        versions = [p for p in ext_dir.iterdir() if p.is_dir()]
    except OSError:
        return None
    for vdir in sorted(versions, reverse=True):
        manifest = vdir / "manifest.json"
        if not manifest.exists():
            continue
        try:
            with open(manifest, "r", encoding="utf-8", errors="ignore") as fh:
                m = json.load(fh)
        except (json.JSONDecodeError, OSError):
            continue
        name = m.get("name", "")
        if name.startswith("__MSG_"):
            token = name.strip("_").replace("MSG_", "").strip("_")
            default_locale = m.get("default_locale", "en")
            msgs = vdir / "_locales" / default_locale / "messages.json"
            if msgs.exists():
                try:
                    with open(msgs, "r", encoding="utf-8", errors="ignore") as fh:
                        md = json.load(fh)
                    for k, v in md.items():
                        if k.lower() == token.lower():
                            return v.get("message", name)
                except (json.JSONDecodeError, OSError):
                    pass
            return name
        if name:
            return name
    return None


def scan_browser_extensions(sig):
    results = []
    cfg = sig.get("browser_extensions", {})
    known = {k.lower(): v for k, v in cfg.get("known_ids", {}).items()}
    keywords = [k.lower() for k in cfg.get("name_keywords", [])]
    base_risk = cfg.get("risk", "high")
    vendor = cfg.get("vendor", "various")

    for browser, base in chromium_profile_roots():
        for ext_root in base.glob("*/Extensions"):
            profile = ext_root.parent.name
            try:
                ext_ids = [p for p in ext_root.iterdir() if p.is_dir()]
            except OSError:
                continue
            for ext_dir in ext_ids:
                ext_id = ext_dir.name.lower()
                matched_name = None
                if ext_id in known:
                    matched_name = known[ext_id]
                else:
                    nm = read_extension_name(ext_dir)
                    if nm and any(kw in nm.lower() for kw in keywords):
                        matched_name = nm
                if matched_name:
                    results.append(
                        finding(
                            "browser_extension", matched_name, vendor,
                            "browser_extension", "cloud", base_risk,
                            f"{browser} / {profile}",
                            f"id {ext_dir.name}",
                        )
                    )
    return results


# --------------------------------------------------------------------------- #
# Collector: listening ports (local model servers)
# --------------------------------------------------------------------------- #
def scan_ports(sig):
    results = []
    if not HAVE_PSUTIL:
        return results
    targets = {p["port"]: p for p in sig.get("ports", [])}
    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        return results
    seen = set()
    for c in conns:
        if c.status != psutil.CONN_LISTEN or not c.laddr:
            continue
        port = c.laddr.port
        if port in targets and port not in seen:
            seen.add(port)
            t = targets[port]
            pname = ""
            if c.pid:
                try:
                    pname = psutil.Process(c.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pname = ""
            results.append(
                finding(
                    "listening_port", t["name"], t["vendor"],
                    "local_model_runtime", t["hosting"], t["risk"],
                    f"listening on :{port}",
                    f"pid {c.pid} {pname}".strip(),
                )
            )
    return results


# --------------------------------------------------------------------------- #
# Collector: active network sessions to AI endpoints
# --------------------------------------------------------------------------- #
def resolve_domains(domains):
    ip_map = {}

    def _resolve(d):
        ips = set()
        try:
            for res in socket.getaddrinfo(d["domain"], 443, proto=socket.IPPROTO_TCP):
                ips.add(res[4][0])
        except (socket.gaierror, socket.timeout, OSError):
            pass
        return d, ips

    socket.setdefaulttimeout(3)
    with ThreadPoolExecutor(max_workers=12) as ex:
        futures = [ex.submit(_resolve, d) for d in domains]
        for fut in as_completed(futures):
            d, ips = fut.result()
            for ip in ips:
                ip_map[ip] = d
    socket.setdefaulttimeout(None)
    return ip_map


def scan_network(sig):
    results = []
    if not HAVE_PSUTIL:
        return results, "psutil unavailable, network scan skipped"
    domains = sig.get("domains", [])
    ip_map = resolve_domains(domains)
    if not ip_map:
        return results, "no AI endpoints resolved (offline or DNS blocked)"
    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        return results, "insufficient privilege for connection table"
    matches = {}
    for c in conns:
        if not c.raddr or c.status != psutil.CONN_ESTABLISHED:
            continue
        rip = c.raddr.ip
        if rip not in ip_map:
            continue
        d = ip_map[rip]
        m = matches.setdefault(
            d["domain"], {"d": d, "n": 0, "pids": set(), "pnames": set()}
        )
        m["n"] += 1
        if c.pid:
            m["pids"].add(c.pid)
            try:
                m["pnames"].add(psutil.Process(c.pid).name())
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    # One finding per AI endpoint. Several parallel connections to the same
    # API are one consumption channel, not several findings.
    for domain, m in matches.items():
        d = m["d"]
        plural = "s" if m["n"] != 1 else ""
        by = ", ".join(sorted(m["pnames"])) or "unknown process"
        pid_str = ", ".join(str(p) for p in sorted(m["pids"])[:6])
        results.append(
            finding(
                "network", f"{d['vendor']} session", d["vendor"],
                "network", "cloud", d["risk"],
                f"{m['n']} established session{plural} to {domain}",
                f"by {by} (pids {pid_str})",
            )
        )
    return results, None


# --------------------------------------------------------------------------- #
# Collector: AI credentials and config (presence only)
# --------------------------------------------------------------------------- #
def scan_credentials(sig):
    results = []
    # Environment variables (value never recorded).
    for s in sig.get("env_keys", []):
        if os.environ.get(s["key"]):
            results.append(
                finding(
                    "credential", f"{s['vendor']} API key", s["vendor"],
                    "credential", "cloud", s["risk"],
                    f"env var {s['key']} set", "value not read",
                )
            )
    # Config paths under home.
    home = Path.home()
    for s in sig.get("config_paths", []):
        target = home / s["path"]
        if target.exists():
            results.append(
                finding(
                    "config", s["name"], s["vendor"],
                    "credential", "hybrid", s["risk"],
                    f"path {target}", "presence only",
                )
            )
    return results


# --------------------------------------------------------------------------- #
# Risk scoring
# --------------------------------------------------------------------------- #
def score_findings(findings, allowlist=None):
    """Adjust base risk with context and attach computed severity + reason.
    Finding names on the allowlist are sanctioned: downgraded to info and
    excluded from posture and exit-code decisions."""
    allow = {a.lower() for a in (allowlist or [])}
    network_vendors = {f["vendor"] for f in findings if f["source"] == "network"}
    cred_vendors = {f["vendor"] for f in findings if f["category"] == "credential"}

    for f in findings:
        f["grc_context"] = GRC_CONTEXT.get(f["category"], "")

        if f["name"].lower() in allow:
            f["severity"] = "info"
            f["severity_rank"] = 0
            f["risk_reason"] = "sanctioned (on allowlist)"
            continue

        level = RISK_ORDER.get(f["base_risk"], 1)
        reasons = []

        if f["vendor"] in network_vendors and f["source"] != "network":
            level = min(level + 1, 4)
            reasons.append("active network session to same vendor")

        if f["category"] in ("sdk", "framework", "code_assistant", "assistant") \
                and f["vendor"] in cred_vendors and f["source"] != "credential":
            level = min(level + 1, 4)
            reasons.append("matching credential or config present")

        if f["category"] in ("agent", "agent_framework"):
            level = max(level, RISK_ORDER["high"])
            reasons.append("autonomous action capability")

        f["severity"] = RISK_NAMES[level]
        f["severity_rank"] = level
        f["risk_reason"] = "; ".join(reasons) if reasons else "base signature risk"
    return findings


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
def run_scan(sig, do_network=True, quiet=False):
    def log(msg):
        if not quiet:
            print(f"  {msg}", flush=True)

    findings = []
    warnings = []

    log("scanning processes")
    res, warn = scan_processes(sig)
    findings += res
    if warn:
        warnings.append(warn)

    log("scanning CLI tools on PATH")
    findings += scan_cli(sig)

    log("scanning Python packages")
    findings += scan_pip(sig)

    log("scanning global npm packages")
    findings += scan_npm(sig)

    log("scanning browser extensions")
    findings += scan_browser_extensions(sig)

    log("scanning listening ports")
    findings += scan_ports(sig)

    if do_network:
        log("scanning active AI network sessions")
        res, warn = scan_network(sig)
        findings += res
        if warn:
            warnings.append(warn)
    else:
        warnings.append("network scan skipped (--no-network)")

    log("scanning AI credentials and config")
    findings += scan_credentials(sig)

    findings = score_findings(findings, sig.get("allowlist", []))
    findings.sort(key=lambda f: (-f["severity_rank"], f["source"], f["name"]))
    return findings, warnings


def build_report(findings, warnings, sig):
    host = socket.gethostname()
    try:
        user = getpass.getuser()
    except Exception:
        user = "unknown"

    sev_counts = {k: 0 for k in ("critical", "high", "medium", "low", "info")}
    hosting_counts = {}
    category_counts = {}
    vendor_counts = {}
    for f in findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1
        hosting_counts[f["hosting"]] = hosting_counts.get(f["hosting"], 0) + 1
        category_counts[f["category"]] = category_counts.get(f["category"], 0) + 1
        vendor_counts[f["vendor"]] = vendor_counts.get(f["vendor"], 0) + 1

    posture = "clean"
    if sev_counts["critical"]:
        posture = "critical exposure"
    elif sev_counts["high"]:
        posture = "high exposure"
    elif sev_counts["medium"]:
        posture = "moderate exposure"
    elif findings:
        posture = "low exposure"

    return {
        "scanner": "shadow-ai-endpoint-scanner",
        "version": VERSION,
        "signatures_version": sig.get("updated", "?"),
        "scan_time_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "host": {
            "hostname": host,
            "user": user,
            "os": platform.system(),
            "os_release": platform.release(),
            "platform": platform.platform(),
            "python": platform.python_version(),
            "psutil_available": HAVE_PSUTIL,
        },
        "posture": posture,
        "summary": {
            "total_findings": len(findings),
            "by_severity": sev_counts,
            "by_hosting": hosting_counts,
            "by_category": category_counts,
            "by_vendor": vendor_counts,
        },
        "findings": findings,
        "warnings": warnings,
    }


# --------------------------------------------------------------------------- #
# HTML report (self-contained, grouped by severity, card per finding)
# --------------------------------------------------------------------------- #
SEV_COLOR = {
    "critical": "#7a1f1f",
    "high": "#9a4a1a",
    "medium": "#8a6d1a",
    "low": "#3a5a3a",
    "info": "#5a5f6e",
}

POSTURE_COLOR = {
    "clean": "#2e6b46",
    "low exposure": "#2e6b46",
    "moderate exposure": "#8a6d1a",
    "high exposure": "#9a4a1a",
    "critical exposure": "#7a1f1f",
}

SEV_LABEL = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Informational and sanctioned",
}

SEV_BLURB = {
    "critical": "Confirmed in use, configured, or high blast radius. Review these first.",
    "high": "Significant exposure. Confirm whether each tool is sanctioned.",
    "medium": "Present on the endpoint. Lower urgency, still part of the inventory.",
    "low": "Minor or supporting components.",
    "info": "On the sanctioned allowlist or informational. Not counted toward posture.",
}


def esc(s):
    return (
        str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    )


def _stat_rows(counts, limit=None):
    items = sorted(counts.items(), key=lambda x: -x[1])
    if limit:
        items = items[:limit]
    if not items:
        return '<tr><td class="empty" colspan="2">none</td></tr>'
    return "".join(
        f"<tr><td>{esc(k).replace('_', ' ')}</td><td class='num'>{v}</td></tr>"
        for k, v in items
    )


def render_html(report):
    h = report["host"]
    s = report["summary"]
    sev = s["by_severity"]
    posture = report["posture"]
    pcolor = POSTURE_COLOR.get(posture, "#5a5f6e")

    chips = "".join(
        f'<div class="chip"><span class="chip-dot" style="background:{SEV_COLOR[k]}"></span>'
        f'<span class="chip-n">{sev.get(k, 0)}</span><span class="chip-l">{k}</span></div>'
        for k in ("critical", "high", "medium", "low", "info")
    )

    # Findings grouped by severity, one card per finding. The governance note
    # sits under each card at full width so it is never truncated.
    groups = []
    for level in ("critical", "high", "medium", "low", "info"):
        items = [f for f in report["findings"] if f["severity"] == level]
        if not items:
            continue
        cards = []
        for f in items:
            why = ""
            reason = f.get("risk_reason", "")
            if reason and reason != "base signature risk":
                why = (
                    f'<div class="f-why" style="color:{SEV_COLOR[level]}">'
                    f"Severity driver: {esc(reason)}</div>"
                )
            detail = (
                f'<span class="f-detail">{esc(f["detail"])}</span>'
                if f.get("detail") else ""
            )
            grc = (
                f'<p class="f-grc">{esc(f["grc_context"])}</p>'
                if f.get("grc_context") else ""
            )
            cards.append(
                f'<article class="f" style="border-left-color:{SEV_COLOR[level]}">'
                f'<div class="f-head">'
                f'<span class="badge" style="background:{SEV_COLOR[level]}">{esc(level)}</span>'
                f'<span class="f-name">{esc(f["name"])}</span>'
                f'<span class="f-vendor">{esc(f["vendor"])}</span>'
                f"</div>"
                f'<div class="f-meta">{esc(f["category"].replace("_", " "))} &middot; '
                f'{esc(f["hosting"])} &middot; detected via {esc(f["source"].replace("_", " "))}</div>'
                f'<div class="f-evidence"><code>{esc(f["evidence"])}</code> {detail}</div>'
                f"{why}{grc}</article>"
            )
        groups.append(
            f'<section class="sevgroup">'
            f'<h2><span class="dot" style="background:{SEV_COLOR[level]}"></span>'
            f'{SEV_LABEL[level]} <span class="count">{len(items)}</span></h2>'
            f'<p class="sevblurb">{SEV_BLURB[level]}</p>'
            f'{"".join(cards)}</section>'
        )
    if not groups:
        groups.append(
            '<section class="sevgroup"><p class="empty">'
            "No AI tooling detected on this endpoint.</p></section>"
        )

    warn_html = ""
    if report["warnings"]:
        items = "".join(f"<li>{esc(w)}</li>" for w in report["warnings"])
        warn_html = (
            f'<div class="warns"><strong>Scan notes</strong><ul>{items}</ul></div>'
        )

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Shadow AI Report &middot; {esc(h['hostname'])}</title>
<style>
:root {{ --ink:#1c1c1e; --muted:#6b6b70; --line:#e4e4e7; --bg:#fbfbfa; --card:#ffffff; }}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--bg); color:var(--ink);
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  font-size:14px; line-height:1.55;
  -webkit-print-color-adjust:exact; print-color-adjust:exact; }}
.wrap {{ max-width:880px; margin:0 auto; padding:40px 24px 80px; }}
header {{ border-bottom:1px solid var(--line); padding-bottom:22px; margin-bottom:26px; }}
h1 {{ font-size:20px; font-weight:600; letter-spacing:-0.01em; margin:0 0 4px; }}
.sub {{ color:var(--muted); font-size:13px; }}
.posture {{ display:inline-block; margin-top:14px; padding:6px 14px; border-radius:5px;
  font-weight:600; font-size:13px; color:#fff; text-transform:capitalize; }}
.meta {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr));
  gap:12px 26px; margin:22px 0 6px; }}
.meta .k {{ display:block; color:var(--muted); font-size:11px;
  text-transform:uppercase; letter-spacing:0.04em; }}
.meta .v {{ display:block; font-size:13px; font-weight:500; word-break:break-word; }}
.chips {{ display:flex; flex-wrap:wrap; gap:10px; margin-top:20px; }}
.chip {{ display:flex; align-items:center; gap:8px; background:var(--card);
  border:1px solid var(--line); border-radius:6px; padding:9px 13px; min-width:92px; }}
.chip-dot {{ width:9px; height:9px; border-radius:50%; }}
.chip-n {{ font-size:17px; font-weight:600; }}
.chip-l {{ color:var(--muted); font-size:12px; text-transform:capitalize; }}
.twocol {{ display:grid; grid-template-columns:1fr 1fr; gap:18px; margin-bottom:8px; }}
@media (max-width:640px) {{ .twocol {{ grid-template-columns:1fr; }} }}
.card {{ background:var(--card); border:1px solid var(--line); border-radius:8px; overflow:hidden; }}
.card h3 {{ margin:0; padding:12px 16px; border-bottom:1px solid var(--line);
  font-size:13px; font-weight:600; }}
.card table {{ width:100%; border-collapse:collapse; font-size:13px; }}
.card td {{ padding:8px 16px; border-bottom:1px solid #f0f0f2; }}
.card tr:last-child td {{ border-bottom:none; }}
.num {{ text-align:right; font-variant-numeric:tabular-nums; color:var(--muted); }}
.warns {{ margin:14px 0 0; background:#fffdf5; border:1px solid #ece4c7;
  border-radius:8px; padding:12px 18px; font-size:13px; }}
.warns ul {{ margin:6px 0 2px; padding-left:18px; color:var(--muted); font-size:12px; }}
.sevgroup {{ margin-top:34px; }}
.sevgroup h2 {{ display:flex; align-items:center; gap:9px; font-size:15px;
  font-weight:600; margin:0 0 2px; }}
.dot {{ width:10px; height:10px; border-radius:50%; flex:none; }}
.count {{ background:#eeeeec; color:var(--muted); border-radius:10px;
  font-size:12px; font-weight:600; padding:1px 9px; }}
.sevblurb {{ margin:2px 0 14px; color:var(--muted); font-size:12.5px; }}
.f {{ background:var(--card); border:1px solid var(--line); border-left-width:4px;
  border-radius:8px; padding:14px 18px; margin-bottom:12px; }}
.f-head {{ display:flex; align-items:baseline; gap:10px; flex-wrap:wrap; }}
.badge {{ display:inline-block; color:#fff; padding:3px 9px; border-radius:4px;
  font-size:11px; font-weight:600; text-transform:capitalize; flex:none; }}
.f-name {{ font-weight:600; font-size:15px; }}
.f-vendor {{ color:var(--muted); font-size:13px; }}
.f-meta {{ color:var(--muted); font-size:12px; margin-top:5px; }}
.f-evidence {{ margin-top:8px; font-size:12.5px; }}
.f-evidence code {{ font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  background:#f4f4f2; border:1px solid #ebebe8; border-radius:4px; padding:2px 7px; }}
.f-detail {{ color:var(--muted); font-size:12px;
  font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }}
.f-why {{ margin-top:8px; font-size:12px; font-weight:600; }}
.f-grc {{ margin:10px 0 0; padding-top:9px; border-top:1px dashed #e8e8e4;
  font-size:13px; color:#3a3a40; line-height:1.6; }}
.empty {{ text-align:center; color:var(--muted); padding:26px; }}
footer {{ margin-top:40px; padding-top:16px; border-top:1px solid var(--line);
  color:var(--muted); font-size:12px; line-height:1.6; }}
@media print {{
  body {{ background:#fff; }}
  .f, .card {{ break-inside:avoid; }}
  .wrap {{ padding:10px 0 30px; }}
}}
</style></head>
<body><div class="wrap">
<header>
  <h1>Shadow AI Endpoint Report</h1>
  <div class="sub">Endpoint-local discovery of AI tools, agents, and integrations</div>
  <div><span class="posture" style="background:{pcolor}">{esc(posture)}</span></div>
  <div class="meta">
    <div><span class="k">Host</span><span class="v">{esc(h['hostname'])}</span></div>
    <div><span class="k">User</span><span class="v">{esc(h['user'])}</span></div>
    <div><span class="k">OS</span><span class="v">{esc(h['os'])} {esc(h['os_release'])}</span></div>
    <div><span class="k">Scan time (UTC)</span><span class="v">{esc(report['scan_time_utc'][:19])}</span></div>
    <div><span class="k">Findings</span><span class="v">{s['total_findings']}</span></div>
    <div><span class="k">Signatures</span><span class="v">{esc(report['signatures_version'])}</span></div>
  </div>
  <div class="chips">{chips}</div>
</header>
<div class="twocol">
  <div class="card"><h3>Findings by category</h3>
    <table><tbody>{_stat_rows(s['by_category'])}</tbody></table></div>
  <div class="card"><h3>Findings by vendor</h3>
    <table><tbody>{_stat_rows(s['by_vendor'], limit=8)}</tbody></table></div>
</div>
{warn_html}
{''.join(groups)}
<footer>
  Generated by shadow-ai-endpoint-scanner v{esc(report['version'])}. Signature-based, point-in-time, endpoint-local.
  Presence of credentials is flagged but secret values are never read or transmitted.
  Governance notes are indicative starting points for triage, not a control attestation.
  Severity reflects base signature risk plus contextual escalation (active use, configured credentials, autonomous capability).
</footer>
</div></body></html>"""


# --------------------------------------------------------------------------- #
# Console summary
# --------------------------------------------------------------------------- #
def print_summary(report):
    s = report["summary"]
    sev = s["by_severity"]
    print("\n" + "=" * 60)
    print(f"  SHADOW AI SCAN  |  host: {report['host']['hostname']}  |  {report['posture'].upper()}")
    print("=" * 60)
    print(f"  Total findings : {s['total_findings']}")
    print(f"  Severity       : critical {sev['critical']}  high {sev['high']}  "
          f"medium {sev['medium']}  low {sev['low']}")
    if s["by_hosting"]:
        hosting = "  ".join(f"{k} {v}" for k, v in s["by_hosting"].items())
        print(f"  Hosting        : {hosting}")
    print("-" * 60)
    top = report["findings"][:12]
    for f in top:
        print(f"  [{f['severity']:>8}] {f['name'][:32]:<32} {f['source']:<16} {f['evidence'][:44]}")
    if len(report["findings"]) > len(top):
        print(f"  ... and {len(report['findings']) - len(top)} more (see report)")
    if report["warnings"]:
        print("-" * 60)
        for w in report["warnings"]:
            print(f"  note: {w}")
    print("=" * 60 + "\n")


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(description="Shadow AI endpoint scanner")
    ap.add_argument("--output-dir", default="reports", help="where to write reports")
    ap.add_argument("--signatures", default=None, help="path to signatures.json")
    ap.add_argument("--no-network", action="store_true", help="skip network/DNS checks")
    ap.add_argument("--json-only", action="store_true", help="write JSON only, no HTML")
    ap.add_argument("--quiet", action="store_true", help="suppress console output")
    args = ap.parse_args()

    try:
        sig = load_signatures(args.signatures)
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    if not args.quiet:
        print(f"Shadow AI Endpoint Scanner v{VERSION}")
        if not HAVE_PSUTIL:
            print("  warning: psutil not installed. Process, port, and network "
                  "scans are degraded. Install with: pip install psutil")

    findings, warnings = run_scan(sig, do_network=not args.no_network, quiet=args.quiet)
    report = build_report(findings, warnings, sig)

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    host = report["host"]["hostname"].replace(" ", "_")
    json_path = out_dir / f"shadowai-{host}-{stamp}.json"
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)

    html_path = None
    if not args.json_only:
        html_path = out_dir / f"shadowai-{host}-{stamp}.html"
        with open(html_path, "w", encoding="utf-8") as fh:
            fh.write(render_html(report))

    if not args.quiet:
        print_summary(report)
        print(f"  JSON report: {json_path}")
        if html_path:
            print(f"  HTML report: {html_path}")

    # Exit code reflects posture, useful for MDM/CI gating.
    if report["summary"]["by_severity"]["critical"]:
        return 3
    if report["summary"]["by_severity"]["high"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
