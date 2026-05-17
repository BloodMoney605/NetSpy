#!/usr/bin/env python3
"""
Phase 5: Report Generation
- Consolidates all phase outputs into a single HTML report
- Severity color coding
- Tables for findings, hosts, technologies, ports
- Timeline metadata
"""

import argparse
import json
import os
import time
from typing import Any

try:
    from jinja2 import Template
except ImportError:
    print("[!] jinja2 not installed. run: pip3 install jinja2")
    exit(1)


REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>aegis-audit Report - {{ domain }}</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace; background: #0d1117; color: #c9d1d9; line-height: 1.6; padding: 20px; }
.container { max-width: 1200px; margin: 0 auto; }
h1 { color: #58a6ff; font-size: 1.8em; margin-bottom: 5px; }
h2 { color: #58a6ff; font-size: 1.3em; margin: 25px 0 10px; border-bottom: 1px solid #21262d; padding-bottom: 5px; }
h3 { color: #c9d1d9; font-size: 1.1em; margin: 15px 0 8px; }
.header { background: #161b22; padding: 20px; border-radius: 8px; margin-bottom: 20px; border: 1px solid #30363d; }
.header .meta { color: #8b949e; font-size: 0.9em; margin-top: 8px; }
.header .meta span { margin-right: 20px; }
.summary-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin: 15px 0; }
.card { background: #161b22; border-radius: 8px; padding: 15px; text-align: center; border: 1px solid #30363d; }
.card .number { font-size: 2em; font-weight: bold; }
.card .label { font-size: 0.8em; color: #8b949e; margin-top: 4px; }
table { width: 100%; border-collapse: collapse; margin: 10px 0 20px; background: #161b22; border-radius: 8px; overflow: hidden; border: 1px solid #30363d; }
th, td { padding: 10px 14px; text-align: left; border-bottom: 1px solid #21262d; }
th { background: #21262d; color: #8b949e; font-weight: 600; font-size: 0.85em; text-transform: uppercase; letter-spacing: 0.5px; }
tr:hover td { background: #1c2128; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 0.75em; font-weight: 600; }
.sev-critical { background: #3d1111; color: #f85149; border: 1px solid #f85149; }
.sev-high { background: #3d1a11; color: #ff7b24; border: 1px solid #ff7b24; }
.sev-medium { background: #3d2e11; color: #d29922; border: 1px solid #d29922; }
.sev-low { background: #11323d; color: #58a6ff; border: 1px solid #58a6ff; }
.sev-info { background: #161b22; color: #8b949e; border: 1px solid #30363d; }
.finding-detail { font-size: 0.9em; color: #8b949e; margin-top: 2px; }
.section { margin: 25px 0; }
.footer { text-align: center; color: #484f58; font-size: 0.8em; margin-top: 40px; padding-top: 20px; border-top: 1px solid #21262d; }
@media (max-width: 700px) { .summary-cards { grid-template-columns: repeat(2, 1fr); } }
</style>
</head>
<body>
<div class="container">

<div class="header">
<h1>aegis-audit Report</h1>
<div class="meta">
<span>Target: <strong>{{ domain }}</strong></span>
<span>Generated: <strong>{{ timestamp }}</strong></span>
</div>
</div>

<div class="summary-cards">
<div class="card"><div class="number" style="color:#f85149;">{{ summary.critical }}</div><div class="label">Critical</div></div>
<div class="card"><div class="number" style="color:#ff7b24;">{{ summary.high }}</div><div class="label">High</div></div>
<div class="card"><div class="number" style="color:#d29922;">{{ summary.medium }}</div><div class="label">Medium</div></div>
<div class="card"><div class="number" style="color:#58a6ff;">{{ summary.low }}</div><div class="label">Low</div></div>
<div class="card"><div class="number" style="color:#8b949e;">{{ summary.info }}</div><div class="label">Info</div></div>
<div class="card"><div class="number">{{ summary.total }}</div><div class="label">Total Findings</div></div>
</div>

{% if recon %}
<div class="section">
<h2>Phase 1: Reconnaissance</h2>

<h3>Subdomains ({{ recon.subdomains|length }})</h3>
<table>
<thead><tr><th>Subdomain</th></tr></thead>
<tbody>
{% for sub in recon.subdomains[:50] %}
<tr><td>{{ sub }}</td></tr>
{% endfor %}
{% if recon.subdomains|length > 50 %}
<tr><td style="color:#8b949e;">... and {{ recon.subdomains|length - 50 }} more</td></tr>
{% endif %}
</tbody></table>

<h3>IP Addresses ({{ recon.ips|length }})</h3>
<table>
<thead><tr><th>IP</th></tr></thead>
<tbody>
{% for ip in recon.ips[:20] %}
<tr><td>{{ ip }}</td></tr>
{% endfor %}
{% if recon.ips|length > 20 %}
<tr><td style="color:#8b949e;">... and {{ recon.ips|length - 20 }} more</td></tr>
{% endif %}
</tbody></table>

<h3>DNS Records</h3>
<table>
<thead><tr><th>Type</th><th>Values</th></tr></thead>
<tbody>
{% for rtype, values in recon.dns.items() %}
<tr><td>{{ rtype|upper }}</td><td>{{ values[:5]|join(', ') }}</td></tr>
{% endfor %}
</tbody></table>

{% if recon.whois %}
<h3>WHOIS</h3>
<table>
<thead><tr><th>Field</th><th>Value</th></tr></thead>
<tbody>
{% for key, val in recon.whois.items() if key != 'raw' %}
<tr><td>{{ key.replace('_', ' ').title() }}</td><td>{{ val }}</td></tr>
{% endfor %}
</tbody></table>
{% endif %}
</div>
{% endif %}

{% if scan %}
<div class="section">
<h2>Phase 2: Port Scan</h2>
<p>Open ports: <strong>{{ scan.total_open_ports }}</strong> | Hosts: <strong>{{ scan.hosts|length }}</strong></p>
{% if scan.services %}
<table>
<thead><tr><th>IP</th><th>Port</th><th>Proto</th><th>Service</th><th>Product</th><th>Version</th></tr></thead>
<tbody>
{% for s in scan.services[:100] %}
<tr><td>{{ s.ip }}</td><td>{{ s.port }}</td><td>{{ s.protocol }}</td><td>{{ s.service }}</td><td>{{ s.get('product', '') }}</td><td>{{ s.get('version', '') }}</td></tr>
{% endfor %}
</tbody></table>
{% endif %}
</div>
{% endif %}

{% if tech %}
<div class="section">
<h2>Phase 3: Fingerprinting</h2>

{% if tech.alive_hosts %}
<h3>Alive Web Hosts ({{ tech.alive_hosts|length }})</h3>
<table>
<thead><tr><th>URL</th><th>Status</th><th>Title</th><th>Server</th></tr></thead>
<tbody>
{% for h in tech.alive_hosts[:50] %}
<tr><td>{{ h.url }}</td><td>{{ h.get('status', '?') }}</td><td>{{ h.get('title', '')[:60] }}</td><td>{{ h.get('server', '') }}</td></tr>
{% endfor %}
</tbody></table>
{% endif %}

{% if tech.technologies %}
<h3>Technologies ({{ tech.technologies|length }})</h3>
<table>
<thead><tr><th>Technology</th><th>Version</th></tr></thead>
<tbody>
{% for t in tech.technologies %}
<tr><td>{{ t.name }}</td><td>{{ t.get('version', '') }}</td></tr>
{% endfor %}
</tbody></table>
{% endif %}

{% if tech.versions %}
<h3>Version Strings ({{ tech.versions|length }})</h3>
<table>
<thead><tr><th>Product</th><th>Version</th><th>Source URL</th></tr></thead>
<tbody>
{% for v in tech.versions %}
<tr><td>{{ v.product }}</td><td>{{ v.version }}</td><td>{{ v.get('source', '') }}</td><td>{{ v.get('from', '') }}</td></tr>
{% endfor %}
</tbody></table>
{% endif %}
</div>
{% endif %}

{% if findings %}
<div class="section">
<h2>Phase 4: Vulnerabilities ({{ findings|length }})</h2>
<table>
<thead><tr><th>Severity</th><th>ID</th><th>Product</th><th>Description</th></tr></thead>
<tbody>
{% for f in findings %}
{% set sev = f.severity|upper %}
{% set sev_class = 'sev-critical' if sev == 'CRITICAL' else 'sev-high' if sev == 'HIGH' else 'sev-medium' if sev == 'MEDIUM' else 'sev-low' if sev == 'LOW' else 'sev-info' %}
<tr>
<td><span class="badge {{ sev_class }}">{{ sev }}</span></td>
<td>{{ f.id or f.get('name', '?') }}</td>
<td>{{ (f.product + ' ' + f.version) if f.get('product') else '' }}</td>
<td class="finding-detail">{{ (f.summary or f.get('detail', '') or '')[:150] }}</td>
</tr>
{% endfor %}
</tbody></table>
</div>
{% endif %}

<div class="footer">
Generated by aegis-audit &mdash; Automated Vulnerability Assessment Pipeline
</div>
</div>
</body>
</html>"""


def load_json(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {}


def generate_report(input_dir: str, output_dir: str) -> str:
    recon = load_json(os.path.join(input_dir, "recon.json"))
    scan = load_json(os.path.join(input_dir, "ports.json"))
    tech = load_json(os.path.join(input_dir, "tech.json"))
    findings_data = load_json(os.path.join(input_dir, "findings.json"))

    domain = recon.get("domain", input_dir.split("/")[-1])
    findings = findings_data.get("findings", [])
    summary = findings_data.get("summary", {
        "total_findings": len(findings),
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
    })
    summary["total"] = summary.pop("total_findings", len(findings))

    template = Template(REPORT_TEMPLATE)
    html = template.render(
        domain=domain,
        timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
        summary=summary,
        recon=recon if recon.get("subdomains") else None,
        scan=scan if scan.get("services") else None,
        tech=tech if tech.get("alive_hosts") or tech.get("technologies") else None,
        findings=findings,
    )

    report_path = os.path.join(output_dir, "report.html")
    with open(report_path, "w") as f:
        f.write(html)

    print(f"  report: {report_path}")
    return report_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Phase 5: Report Generation")
    parser.add_argument("--input", required=True)
    parser.add_argument("--config", default="config/default.yaml")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)
    generate_report(args.input, args.output)


if __name__ == "__main__":
    main()
