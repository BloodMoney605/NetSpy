#!/usr/bin/env python3

import argparse
import json
import os
import time
from typing import Any

from common import load_config


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

    sep = "=" * 70
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

    lines = []
    lines.append(sep)
    lines.append("  NETSPY REPORT")
    lines.append(sep)
    lines.append("")
    lines.append(f"  Target:     {domain}")
    lines.append(f"  Generated:  {timestamp}")
    lines.append("")
    lines.append(sep)
    lines.append("  SUMMARY")
    lines.append(sep)
    lines.append("")
    lines.append(f"  Critical:  {summary.get('critical', 0)}")
    lines.append(f"  High:      {summary.get('high', 0)}")
    lines.append(f"  Medium:    {summary.get('medium', 0)}")
    lines.append(f"  Low:       {summary.get('low', 0)}")
    lines.append(f"  Info:      {summary.get('info', 0)}")
    lines.append(f"  Total:     {summary.get('total', 0)}")

    if recon and recon.get("subdomains"):
        lines.append("")
        lines.append(sep)
        lines.append("  PHASE 1: RECONNAISSANCE")
        lines.append(sep)

        subs = recon.get("subdomains", [])
        lines.append("")
        lines.append(f"  Subdomains ({len(subs)}):")
        lines.append("  " + "-" * 50)
        for sub in subs[:50]:
            lines.append(f"    {sub}")
        if len(subs) > 50:
            lines.append(f"    ... and {len(subs) - 50} more")

        ips = recon.get("ips", [])
        lines.append("")
        lines.append(f"  IP Addresses ({len(ips)}):")
        lines.append("  " + "-" * 50)
        for ip in ips[:20]:
            lines.append(f"    {ip}")
        if len(ips) > 20:
            lines.append(f"    ... and {len(ips) - 20} more")

        dns = recon.get("dns", {})
        if dns:
            lines.append("")
            lines.append("  DNS Records:")
            lines.append("  " + "-" * 50)
            for rtype, values in dns.items():
                val_str = ", ".join(values[:5])
                lines.append(f"    {rtype.upper():6s}  {val_str}")

        whois = recon.get("whois", {})
        if whois:
            lines.append("")
            lines.append("  WHOIS:")
            lines.append("  " + "-" * 50)
            for key, val in whois.items():
                if key != "raw":
                    label = key.replace("_", " ").title()
                    lines.append(f"    {label:20s}  {val}")

    if scan and scan.get("services"):
        lines.append("")
        lines.append(sep)
        lines.append("  PHASE 2: PORT SCAN")
        lines.append(sep)

        total = scan.get("total_open_ports", 0)
        hosts = len(scan.get("hosts", []))
        lines.append("")
        lines.append(f"  Open ports: {total}  |  Hosts: {hosts}")
        lines.append("")

        services = scan.get("services", [])
        lines.append(f"  {'IP':<18s} {'Port':<7s} {'Proto':<6s} {'Service':<14s} {'Product':<20s} {'Version'}")
        lines.append("  " + "-" * 95)
        for s in services[:100]:
            ip = s.get("ip", "")
            port = str(s.get("port", ""))
            proto = s.get("protocol", "")
            svc = s.get("service", "")
            prod = s.get("product", "")
            ver = s.get("version", "")
            lines.append(f"  {ip:<18s} {port:<7s} {proto:<6s} {svc:<14s} {prod:<20s} {ver}")
        if len(services) > 100:
            lines.append(f"  ... and {len(services) - 100} more")

    if tech and (tech.get("alive_hosts") or tech.get("technologies")):
        lines.append("")
        lines.append(sep)
        lines.append("  PHASE 3: FINGERPRINTING")
        lines.append(sep)

        alive = tech.get("alive_hosts", [])
        if alive:
            lines.append("")
            lines.append(f"  Alive Web Hosts ({len(alive)}):")
            lines.append("")
            lines.append(f"  {'URL':<50s} {'Status':<7s} {'Title':<40s} {'Server'}")
            lines.append("  " + "-" * 120)
            for h in alive[:50]:
                url = h.get("url", "")[:50]
                status = str(h.get("status", "?"))
                title = (h.get("title", "") or "")[:40]
                server = h.get("server", "")
                lines.append(f"  {url:<50s} {status:<7s} {title:<40s} {server}")
            if len(alive) > 50:
                lines.append(f"  ... and {len(alive) - 50} more")

        techs = tech.get("technologies", [])
        if techs:
            lines.append("")
            lines.append(f"  Technologies ({len(techs)}):")
            lines.append("  " + "-" * 50)
            for tech_entry in techs:
                name = tech_entry.get("name", "")
                ver = tech_entry.get("version", "")
                if ver:
                    lines.append(f"    {name}  {ver}")
                else:
                    lines.append(f"    {name}")

        versions = tech.get("versions", [])
        if versions:
            lines.append("")
            lines.append(f"  Version Strings ({len(versions)}):")
            lines.append("")
            lines.append(f"  {'Product':<25s} {'Version':<12s} {'Source'}")
            lines.append("  " + "-" * 80)
            for ver_entry in versions:
                prod = ver_entry.get("product", "")[:25]
                ver = ver_entry.get("version", "")
                src = ver_entry.get("source", "")
                lines.append(f"  {prod:<25s} {ver:<12s} {src}")

    if findings:
        lines.append("")
        lines.append(sep)
        lines.append(f"  PHASE 4: VULNERABILITIES ({len(findings)})")
        lines.append(sep)

        for finding_entry in findings:
            sev = finding_entry.get("severity", "UNKNOWN").upper()
            fid = finding_entry.get("id", finding_entry.get("name", "?"))
            prod = finding_entry.get("product", "")
            ver = finding_entry.get("version", "")
            detail = (finding_entry.get("summary", "") or finding_entry.get("detail", "") or "")[:120]

            label = f"{prod} {ver}".strip() if prod else ""
            lines.append("")
            if sev == "CRITICAL":
                lines.append(f"  [CRIT] {fid}")
            elif sev == "HIGH":
                lines.append(f"  [HIGH] {fid}")
            elif sev == "MEDIUM":
                lines.append(f"  [MED ] {fid}")
            elif sev == "LOW":
                lines.append(f"  [LOW ] {fid}")
            else:
                lines.append(f"  [INFO] {fid}")
            if label:
                lines.append(f"         {label}")
            if detail:
                lines.append(f"         {detail}")

    lines.append("")
    lines.append(sep)
    lines.append("  Generated by NetSpy - Network Surveillance Pipeline")
    lines.append(sep)

    report_text = "\n".join(lines) + "\n"

    report_path = os.path.join(output_dir, "report.txt")
    with open(report_path, "w") as f:
        f.write(report_text)

    print(f"  report: {report_path}")
    return report_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Phase 5: Report Generation")
    parser.add_argument("--input", required=True)
    parser.add_argument("--config", default="config/default.yaml")
    parser.add_argument("--output", required=True)
    parser.add_argument("--threads", type=int, default=None)
    args = parser.parse_args()

    config = load_config(args.config)
    os.makedirs(args.output, exist_ok=True)

    try:
        generate_report(args.input, args.output)
    except KeyboardInterrupt:
        print("\n  [!] interrupted")
        sys.exit(130)


if __name__ == "__main__":
    main()
