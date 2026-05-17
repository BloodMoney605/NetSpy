#!/usr/bin/env python3
"""
Phase 1: Reconnaissance
- Certificate transparency (crt.sh)
- DNS enumeration (A, AAAA, MX, NS, TXT)
- WHOIS lookup
- ASN discovery
- Subdomain discovery (multiple sources)
- Output: JSON with all findings
"""

import argparse
import json
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any
from urllib.request import urlopen, Request


def load_config(config_path: str) -> dict:
    """Load YAML config. Returns dict with defaults if config missing."""
    try:
        import yaml
        with open(config_path) as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


def run_cmd(cmd: list[str], timeout: int = 15) -> str | None:
    """Run a shell command and return stdout. Returns None on failure."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout.strip() if result.returncode == 0 else None
    except Exception:
        return None


def crtsh_subdomains(domain: str) -> list[str]:
    """Query crt.sh certificate transparency logs for subdomains.
    Retries up to 3 times with backoff on failure."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    req = Request(url, headers={"User-Agent": "Mozilla/5.0"})
    subdomains: set[str] = set()

    for attempt in range(3):
        try:
            with urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())
                for entry in data:
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lower()
                        if sub.endswith(f".{domain}") and "*" not in sub:
                            subdomains.add(sub)
                break
        except Exception:
            if attempt < 2:
                time.sleep(2 * (attempt + 1))
            continue

    return sorted(subdomains)


def dns_resolve(subdomain: str, record_type: str = "A") -> list[str]:
    """Resolve DNS records for a given name and type."""
    result = run_cmd(["dig", "+short", record_type, subdomain])
    if not result:
        return []
    return [line.strip() for line in result.split("\n") if line.strip()]


def dns_enum(domain: str) -> dict[str, Any]:
    """Enumerate all DNS record types for the domain."""
    records: dict[str, Any] = {}
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
        values = dns_resolve(domain, rtype)
        if values:
            records[rtype.lower()] = values
    return records


def whois_lookup(domain: str) -> dict[str, str]:
    """Run whois and extract key fields."""
    output = run_cmd(["whois", domain])
    if not output:
        return {"raw": ""}

    fields: dict[str, str] = {"raw": output[:2000]}
    patterns = [
        "Registrar", "Creation Date", "Registry Expiry Date",
        "Name Server", "Registrant Organization", "Registrant Country",
        "Admin Organization", "Tech Organization",
        "OrgName", "NetRange", "CIDR",
    ]

    for line in output.split("\n"):
        for p in patterns:
            if line.lower().startswith(p.lower()) and ":" in line:
                key = p.lower().replace(" ", "_")
                val = line.split(":", 1)[1].strip()
                if val and val != "REDACTED FOR PRIVACY":
                    fields[key] = val

    return fields


def asn_lookup(ip: str) -> dict[str, Any]:
    """Look up ASN information for an IP using whois."""
    output = run_cmd(["whois", ip])
    if not output:
        return {}

    result: dict[str, Any] = {}
    for line in output.split("\n"):
        for prefix in ["OriginAS", "ASNumber", "ASN"]:
            if line.lower().startswith(prefix.lower()) and ":" in line:
                result["asn"] = line.split(":", 1)[1].strip()
        if "OrgName" in line and ":" in line:
            result["org"] = line.split(":", 1)[1].strip()
        if "CIDR" in line and ":" in line:
            result["cidr"] = line.split(":", 1)[1].strip()
        if "Country" in line and ":" in line and "org" not in result:
            result["country"] = line.split(":", 1)[1].strip()

    return result


def resolve_all(subdomains: list[str], threads: int = 20) -> dict[str, list[str]]:
    """Resolve all subdomains to IPs in parallel."""
    resolved: dict[str, list[str]] = {}

    def resolve_one(sub: str) -> tuple[str, list[str]]:
        ips = dns_resolve(sub, "A")
        return sub, ips

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(resolve_one, s): s for s in subdomains}
        for future in as_completed(futures):
            sub, ips = future.result()
            if ips:
                resolved[sub] = ips

    return resolved


def collect_unique_ips(resolved: dict[str, list[str]]) -> list[str]:
    """Collect all unique IPs from resolved subdomains."""
    seen: set[str] = set()
    ips: list[str] = []
    for ip_list in resolved.values():
        for ip in ip_list:
            if ip not in seen:
                seen.add(ip)
                ips.append(ip)
    return ips


def run_recon(domain: str, config: dict, output: str) -> dict[str, Any]:
    """Execute full reconnaissance phase."""
    print(f"  domain:              {domain}")
    print(f"  subdomain sources:   crt.sh")
    print()

    # -- Subdomain enumeration --
    print("  enumerating subdomains via crt.sh...", end=" ", flush=True)
    subs = crtsh_subdomains(domain)
    print(f"{len(subs)} found")

    # Always include base domain
    if domain not in subs:
        subs.insert(0, domain)

    # -- DNS resolution --
    print(f"  resolving {len(subs)} subdomains...", end=" ", flush=True)
    resolved = resolve_all(subs, threads=config.get("target", {}).get("threads", 20))
    print(f"{len(resolved)} alive")

    # -- Unique IPs --
    ips = collect_unique_ips(resolved)

    # -- Base domain DNS records --
    dns_records = dns_enum(domain)

    # -- WHOIS --
    print("  whois lookup...", end=" ", flush=True)
    whois = whois_lookup(domain)
    print("done")

    # -- ASN per IP (first 5 to be reasonable) --
    asn_results: list[dict[str, Any]] = []
    for ip in ips[:5]:
        info = asn_lookup(ip)
        if info:
            info["ip"] = ip
            asn_results.append(info)

    # -- Build output --
    result: dict[str, Any] = {
        "domain": domain,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "subdomains": subs,
        "subdomains_count": len(subs),
        "resolved": resolved,
        "resolved_count": len(resolved),
        "ips": ips,
        "ips_count": len(ips),
        "dns": dns_records,
        "whois": whois,
        "asn": asn_results,
    }

    # Save to file
    recon_path = os.path.join(output, "recon.json")
    with open(recon_path, "w") as f:
        json.dump(result, f, indent=2, default=str)

    # Save IPs to separate file for next phases
    ips_path = os.path.join(output, "ips.txt")
    with open(ips_path, "w") as f:
        for ip in ips:
            f.write(ip + "\n")

    # Save resolved subdomains to file
    subs_path = os.path.join(output, "subdomains.txt")
    with open(subs_path, "w") as f:
        for sub in resolved:
            f.write(sub + "\n")

    print(f"  output files:\n"
          f"    {recon_path}\n"
          f"    {ips_path}\n"
          f"    {subs_path}")

    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Phase 1: Reconnaissance")
    parser.add_argument("--domain", required=True)
    parser.add_argument("--config", default="config/default.yaml")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    config = load_config(args.config)
    os.makedirs(args.output, exist_ok=True)

    run_recon(args.domain, config, args.output)


if __name__ == "__main__":
    main()
