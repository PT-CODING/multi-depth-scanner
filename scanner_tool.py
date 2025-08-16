# -*- coding: utf-8 -*-
# DISCLAIMER:
# This tool is for educational purposes and authorized security testing only.
# Do NOT use it on systems you do not own or without explicit permission.
# The author assumes no responsibility for misuse or damage.

import nmap
import requests
import socket
import sys
import argparse
import json
import urllib3
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
from datetime import datetime
from html import escape as html_escape
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_DIRS_FILE = "dirs.txt"
COMMON_HTTP_ALT_PORTS = {80, 81, 88, 443, 444, 591, 593, 8000, 8008, 8010, 8080, 8081, 8088, 8181, 8443, 8888}

# ---------- Utilities ----------

def is_ip(addr: str) -> bool:
    try:
        socket.inet_aton(addr)
        return True
    except OSError:
        return False

def load_wordlist(path: str):
    items = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                if s.startswith("/"):
                    s = s[1:]
                items.append(s)
    except FileNotFoundError:
        items = ["admin", "login", "uploads", "images", "css", "js", "backup", "api",
                 "test", "dev", "private", "config", "files", "downloads"]
    return list(dict.fromkeys(items))  

def build_nmap_args(mode: str) -> str:
    if mode == "q":  # Quick
        return "-T4 --top-ports 50"
    if mode == "m":  # Medium
        return "-T4 -p 1-5000 -sV -O --script http-title,ssl-cert"
    # Deep
    return "-T4 -p 1-65535 -sV -A -O --traceroute --script vuln,vulners,ssl-cert,http-title,http-headers,dns-brute"

def guess_http_schemes(service_name: str, port: int):
    s = (service_name or "").lower()
    schemes = []
    if s in {"https", "ssl/http"} or port == 443:
        schemes = ["https", "http"]
    elif s in {"http", "http-proxy", "http-alt"} or port in COMMON_HTTP_ALT_PORTS:
        schemes = ["http", "https"]
    else:
        schemes = ["https", "http"] if port == 443 else ["http", "https"]
    return schemes

# ---------- HTTP Probing ----------

def fetch_http_info(base_url: str, timeout: float, max_preview_bytes: int):
    info = {
        "url": base_url,
        "ok": False,
        "status": None,
        "headers": {},
        "title": None,
        "preview": None,
        "error": None
    }
    try:
        r = requests.get(base_url, timeout=timeout, verify=False, allow_redirects=True)
        info["ok"] = True
        info["status"] = r.status_code
        info["headers"] = dict(r.headers)
        text = r.text if isinstance(r.text, str) else r.content.decode("utf-8", errors="ignore")
        start = text.lower().find("<title>")
        end = text.lower().find("</title>") if start != -1 else -1
        if start != -1 and end != -1 and end > start:
            info["title"] = text[start+7:end].strip()[:200]
        # previews
        info["preview"] = text[:max_preview_bytes]
    except requests.RequestException as e:
        info["error"] = str(e)
    return info

def dir_bruteforce_for_base(base_url: str, dirs: list, timeout: float):
    results = []
    def probe(path):
        url = f"{base_url.rstrip('/')}/{path.strip('/')}/"
        try:
            r = requests.get(url, timeout=timeout, verify=False, allow_redirects=False)
            if (r.status_code < 400) or (r.status_code in {401, 403, 301, 302}):
                return {
                    "url": url,
                    "status": r.status_code,
                    "length": int(r.headers.get("Content-Length", "0")) if r.headers.get("Content-Length") else None,
                    "location": r.headers.get("Location")
                }
        except requests.RequestException:
            pass
        return None

    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(probe, d): d for d in dirs}
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                results.append(res)
    results.sort(key=lambda x: (x["status"], (x["length"] or 0)))
    return results

# ---------- HTML Report ----------

def html_escape(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def build_html(ip, mode, nm_raw, ports, vulns, http_pages, dir_hits, os_guess, traceroute):
    date_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    css = """
    body{font-family:Inter,Arial,sans-serif;margin:0;background:#0b1020;color:#e7ecf3}
    header{padding:24px 32px;background:linear-gradient(135deg,#0f172a,#1e293b);border-bottom:1px solid #223}
    h1{margin:0;font-size:28px}
    .meta{opacity:.8}
    .container{padding:24px 32px}
    .grid{display:grid;gap:16px;grid-template-columns:repeat(auto-fit,minmax(280px,1fr))}
    .card{background:#111930;border:1px solid #223;border-radius:16px;padding:16px;box-shadow:0 1px 0 #000}
    .card h2{margin:0 0 8px 0;font-size:18px}
    table{width:100%;border-collapse:collapse;border-radius:12px;overflow:hidden}
    th,td{padding:10px 12px;border-bottom:1px solid #223;text-align:left;font-size:14px}
    th{background:#0d152a;position:sticky;top:0}
    .badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;border:1px solid #345;background:#0a1428}
    .ok{color:#4ade80;border-color:#234}
    .warn{color:#fbbf24;border-color:#443}
    .err{color:#f87171;border-color:#522}
    .muted{opacity:.7}
    .section{margin-top:24px}
    pre{white-space:pre-wrap;background:#0a1420;border:1px solid #223;border-radius:12px;padding:12px;max-height:420px;overflow:auto}
    a{color:#93c5fd;text-decoration:none}
    a:hover{text-decoration:underline}
    .credit{padding:10px 32px;font-size:16px;font-weight:700;text-align:center;border-bottom:2px solid #ffffff;border-radius:8px;margin:8px 32px;box-shadow:0 0 8px rgba(255,255,255,.3);animation:colorChange 4s infinite}
    .credit a{color:#ffffff;text-shadow:0 1px 3px rgba(0,0,0,.4)}
    .credit a:hover{transform:scale(1.1);transition:transform .2s;color:#f0f9ff;text-decoration:none}
    @keyframes colorChange {
        0% {background:linear-gradient(135deg,#ef4444,#f97316)}
        25% {background:linear-gradient(135deg,#3b82f6,#06b6d4)}
        50% {background:linear-gradient(135deg,#10b981,#22c55e)}
        75% {background:linear-gradient(135deg,#8b5cf6,#d946ef)}
        100% {background:linear-gradient(135deg,#ef4444,#f97316)}
    }
    """
    # Credit and Header
    html = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Scan Report {ip}</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>{css}</style></head><body>
<div class="credit">
  Created by <a href="https://github.com/PT-CODING/YOSEFCOHEN" target="_blank">Yosef Cohen</a>
</div>
<header>
  <h1>Scan Report — {html_escape(ip)} <span class="badge">{mode.upper()}</span></h1>
  <div class="meta">Generated: {date_str}</div>
</header>
<div class="container">
<div class="grid">
  <div class="card">
    <h2>Host Info</h2>
    <div class="muted">IP: <code>{html_escape(ip)}</code></div>
    <div>Open Ports: <b>{len([p for p in ports if p.get('state')=='open'])}</b></div>
    <div>HTTP Targets: <b>{len(http_pages)}</b></div>
  </div>
  <div class="card">
    <h2>OS Guess</h2>
    <div>{html_escape(os_guess or 'N/A')}</div>
  </div>
  <div class="card">
    <h2>Traceroute</h2>
    <pre>{html_escape(traceroute or 'N/A')}</pre>
  </div>
</div>

<div class="section card">
  <h2>Open Ports</h2>
  <table>
    <thead><tr><th>Port</th><th>State</th><th>Service</th><th>Version</th></tr></thead>
    <tbody>"""
    for r in ports:
        state = r.get("state","")
        badge_cls = "ok" if state == "open" else "warn"
        html += f"""<tr>
          <td><span class="badge {badge_cls}">{r.get('port')}</span></td>
          <td>{html_escape(state)}</td>
          <td>{html_escape(r.get('service',''))}</td>
          <td>{html_escape(r.get('version',''))}</td>
        </tr>"""
    html += "</tbody></table></div>"

    # Vulnerabilities
    html += '<div class="section card"><h2>Vulnerabilities</h2>'
    if vulns:
        html += "<ul>"
        for v in vulns:
            html += f'<li><span class="badge err">VULN</span> {html_escape(v)}</li>'
        html += "</ul>"
    else:
        html += '<div class="muted">No vulnerabilities reported by scripts.</div>'
    html += "</div>"

    # HTTP Pages (multiple)
    html += '<div class="section card"><h2>HTTP/HTTPS Pages</h2>'
    if not http_pages:
        html += '<div class="muted">No HTTP/HTTPS services detected or accessible.</div>'
    else:
        for page in http_pages:
            html += f"""<div class="section">
                <div><b>URL:</b> <a href="{html_escape(page['url'])}" target="_blank">{html_escape(page['url'])}</a></div>
                <div>Status: <span class="badge {'ok' if page['ok'] else 'err'}">{page.get('status') if page.get('status') else 'ERROR'}</span></div>
                <div class="muted">Title: {html_escape(page.get('title') or '-')}</div>
                <details><summary>Headers</summary>
                    <pre>{html_escape(json.dumps(page.get('headers') or {}, indent=2))}</pre>
                </details>
                <details><summary>Body Preview</summary>
                    <pre>{html_escape(page.get('preview') or '')}</pre>
                </details>
            </div>"""
    html += "</div>"

    # Directory hits
    html += '<div class="section card"><h2>Directory Discovery (Wordlist)</h2>'
    if not dir_hits:
        html += '<div class="muted">No interesting directories found.</div>'
    else:
        html += '<table><thead><tr><th>URL</th><th>Status</th><th>Length</th><th>Location</th></tr></thead><tbody>'
        for hit in dir_hits:
            status = hit.get("status") or 0
            cls = "ok" if status < 400 else "warn"
            html += f"""<tr>
                <td><a href="{html_escape(hit['url'])}" target="_blank">{html_escape(hit['url'])}</a></td>
                <td><span class="badge {cls}">{status}</span></td>
                <td>{html_escape(str(hit.get('length') or '-'))}</td>
                <td>{html_escape(hit.get('location') or '-')}</td>
            </tr>"""
        html += "</tbody></table>"
    html += "</div>"

    # Raw Nmap JSON
    html += f"""<div class="section card">
        <h2>Raw Nmap JSON</h2>
        <details open><summary>Show/Hide</summary>
        <pre>{html_escape(json.dumps(nm_raw, indent=2))}</pre>
        </details>
    </div>

</div></body></html>"""
    return html
# ---------- Main Scan ----------

def run_scan(ip: str, mode: str, dirs_file: str, http_timeout: float, preview_bytes: int, save_json: bool):
    nm = nmap.PortScanner()
    args = build_nmap_args(mode)
    print(f"[+] Starting {mode.upper()} scan on {ip} with args: {args}")
    nm.scan(ip, arguments=args)

    scan_results = []
    vulnerabilities = []
    os_guess = None
    traceroute_text = None

    # Parse Nmap results
    for host in nm.all_hosts():
        # OS guess
        if nm[host].get("osmatch"):
          
            best = nm[host]["osmatch"][0]
            os_guess = f"{best.get('name','')} (accuracy {best.get('accuracy','?')}%)"
        # traceroute
        if "trace" in nm[host]:
            hops = nm[host]["trace"].get("hops", [])
            traceroute_text = "\n".join(
                f"{i+1}. {h.get('ipaddr','?')} ({h.get('rtt','?')} ms)" for i, h in enumerate(hops)
            )
        for proto in nm[host].all_protocols():
            for port in sorted(nm[host][proto].keys()):
                entry = nm[host][proto][port]
                state = entry.get("state", "")
                if state != "open":
               
                    scan_results.append({
                        "port": port, "state": state,
                        "service": entry.get("name",""),
                        "version": f"{entry.get('product','')} {entry.get('version','')}".strip()
                    })
                    continue
                service = entry.get("name", "unknown")
                version = (entry.get("product","") + " " + entry.get("version","")).strip()
                scan_results.append({
                    "port": port,
                    "state": state,
                    "service": service,
                    "version": version
                })
                # collect vuln script outputs (deep usually, sometimes medium)
                if "script" in entry:
                    for k, v in entry["script"].items():
                        if k.startswith("vuln") or k == "vulners":
                            # פיצול לפי שורות
                            for line in str(v).splitlines():
                                line = line.strip()
                                if line:
                                    vulnerabilities.append(f"[{port}/{service}] {line}")

    # HTTP pages — try all HTTP-like ports/services
    http_pages = []
    bases_for_dirs = []
    for r in scan_results:
        if r["state"] != "open":
            continue
        port = int(r["port"])
        service = r.get("service", "")
        for scheme in guess_http_schemes(service, port):
            url = f"{scheme}://{ip}:{port}"
            page_info = fetch_http_info(url, timeout=http_timeout, max_preview_bytes=preview_bytes)
            if page_info["ok"] or page_info["error"]:
                http_pages.append(page_info)
                if page_info["ok"] and page_info["status"] is not None:
                    bases_for_dirs.append(url)

            if page_info["ok"]:
                break

    wordlist = load_wordlist(dirs_file)
    dir_hits = []
    for base in bases_for_dirs:
        dir_hits.extend(dir_bruteforce_for_base(base, wordlist, timeout=min(http_timeout, 6.0)))

    # Build artifacts
    nm_raw = nm._scan_result  
    report_html = build_html(ip, mode, nm_raw, scan_results, vulnerabilities, http_pages, dir_hits, os_guess, traceroute_text)

    html_name = f"scan_report_{ip.replace('.', '_')}_{mode}.html"
    with open(html_name, "w", encoding="utf-8") as f:
        f.write(report_html)
    print(f"[+] HTML report saved -> {html_name}")

    if save_json:
        json_name = f"scan_raw_{ip.replace('.', '_')}_{mode}.json"
        with open(json_name, "w", encoding="utf-8") as f:
            json.dump(nm_raw, f, indent=2)
        print(f"[+] Raw JSON saved -> {json_name}")

def main():
    parser = argparse.ArgumentParser(description="Multi-depth scanner with rich HTML report & HTTP dir discovery.")
    parser.add_argument("target", help="Target IP or hostname")
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("-q", action="store_true", help="Quick scan")
    mode_group.add_argument("-m", action="store_true", help="Medium scan")
    mode_group.add_argument("-d", action="store_true", help="Deep scan")
    parser.add_argument("--dirs-file", default=DEFAULT_DIRS_FILE, help=f"Wordlist file for directory discovery (default: {DEFAULT_DIRS_FILE})")
    parser.add_argument("--http-timeout", type=float, default=5.0, help="HTTP timeout per request (seconds)")
    parser.add_argument("--preview-bytes", type=int, default=2000, help="Max bytes to preview from HTTP body")
    parser.add_argument("--save-json", action="store_true", help="Also save raw Nmap JSON")
    args = parser.parse_args()

    target = args.target
    if is_ip(target):
        ip = target
    else:
        # Resolve hostname
        try:
            ip = socket.gethostbyname(target)
        except socket.gaierror:
            print("[-] Failed to resolve hostname.")
            sys.exit(1)

    mode = "q" if args.q else "m" if args.m else "d"
    try:
        run_scan(ip, mode, args.dirs_file, args.http_timeout, args.preview_bytes, args.save_json)
    except nmap.PortScannerError as e:
        print(f"[-] Nmap error: {e}")
        sys.exit(2)
    except KeyboardInterrupt:
        print("\n[!] Aborted by user.")
        sys.exit(130)
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(3)

if __name__ == "__main__":
    main()
