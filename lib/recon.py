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
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any
from urllib.request import urlopen, Request

from common import load_config, apply_thread_override


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


import re

def dns_resolve(subdomain: str, record_type: str = "A") -> list[str]:
    """Resolve DNS records for a given name and type. Only returns valid IPv4 for A records."""
    result = run_cmd(["dig", "+short", record_type, subdomain])
    if not result:
        return []
    lines = [line.strip() for line in result.split("\n") if line.strip()]
    if record_type == "A":
        ipv4_re = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
        return [l for l in lines if ipv4_re.match(l)]
    return lines


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


COMMON_SUBS = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail",
    "dns", "ns1", "ns2", "mx", "mx1", "mx2", "cpanel",
    "whm", "autodiscover", "admin", "login", "api", "app",
    "dev", "staging", "test", "blog", "shop", "store",
    "cdn", "static", "assets", "media", "images", "files",
    "portal", "dashboard", "support", "help", "docs",
    "vpn", "remote", "cloud", "db", "database", "git",
    "jenkins", "monitor", "status", "mail2", "web",
]


def normalize_domain(domain: str) -> str:
    """Strip www. prefix and trailing dots to get the base domain."""
    domain = domain.strip().rstrip(".")
    if domain.startswith("www."):
        domain = domain[4:]
    parts = domain.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


def brute_subdomains(domain: str, threads: int = 20) -> list[str]:
    """Resolve common subdomain wordlist. Fast fallback when CT logs fail."""
    found: list[str] = []

    def check(sub: str) -> str | None:
        full = f"{sub}.{domain}"
        ips = dns_resolve(full, "A")
        return full if ips else None

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(check, s): s for s in COMMON_SUBS}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)

    return sorted(found)


def run_recon(domain: str, config: dict, output: str) -> dict[str, Any]:
    """Execute full reconnaissance phase."""
    base_domain = normalize_domain(domain)

    print(f"  domain:              {base_domain}")
    print(f"  subdomain sources:   crt.sh + wordlist fallback")
    print()

    # -- Subdomain enumeration --
    print("  enumerating subdomains via crt.sh...", end=" ", flush=True)
    subs = crtsh_subdomains(base_domain)
    print(f"{len(subs)} found")

    if not subs:
        print("  [!] crt.sh failed or returned empty, using wordlist fallback...")
        print("  wordlist brute-force...", end=" ", flush=True)
        subs = brute_subdomains(base_domain, threads=config.get("target", {}).get("threads", 20))
        print(f"{len(subs)} found")

    # Always include base domain
    if base_domain not in subs:
        subs.insert(0, base_domain)

    # -- DNS resolution --
    print(f"  resolving {len(subs)} subdomains...", end=" ", flush=True)
    resolved = resolve_all(subs, threads=config.get("target", {}).get("threads", 20))
    print(f"{len(resolved)} alive")

    # -- Unique IPs --
    ips = collect_unique_ips(resolved)

    # -- Base domain DNS records --
    dns_records = dns_enum(base_domain)

    # -- WHOIS --
    print("  whois lookup...", end=" ", flush=True)
    whois = whois_lookup(base_domain)
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
        "domain": base_domain,
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
    parser.add_argument("--threads", type=int, default=None)
    args = parser.parse_args()

    config = load_config(args.config)
    config = apply_thread_override(config, args.threads)
    os.makedirs(args.output, exist_ok=True)

    run_recon(args.domain, config, args.output)


if __name__ == "__main__":
    main()
