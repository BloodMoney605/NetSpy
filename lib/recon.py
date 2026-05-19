#!/usr/bin/env python3

import argparse
import json
import os
import re
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any
from urllib.request import urlopen, Request

from common import load_config, apply_thread_override, t, get_stealth_ua, stealth_sleep

BOLD = "\033[1m"
GREEN = "\033[0;32m"
CYAN = "\033[0;36m"
YELLOW = "\033[0;33m"
DIM = "\033[2m"
NC = "\033[0m"


COMMON_SUBS = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail",
    "dns", "ns1", "ns2", "ns3", "ns4", "mx", "mx1", "mx2", "mx3",
    "cpanel", "whm", "autodiscover", "admin", "login", "api",
    "app", "dev", "staging", "test", "beta", "qa", "uat", "prod",
    "blog", "shop", "store", "cdn", "static", "assets",
    "media", "images", "files", "portal", "dashboard",
    "support", "help", "docs", "vpn", "remote", "cloud",
    "db", "database", "git", "jenkins", "monitor", "status",
    "mail2", "web", "sso", "auth", "oauth", "saml",
    "ldap", "ad", "internal", "intranet", "extranet",
    "backup", "archive", "logs", "metrics", "grafana",
    "kibana", "elastic", "redis", "cache", "proxy",
    "lb", "loadbalancer", "firewall", "waf", "bastion",
    "docker", "k8s", "kubernetes", "registry", "harbor",
    "jira", "confluence", "wiki", "gitlab", "github",
    "bitbucket", "nexus", "artifactory", "maven", "npm",
    "pypi", "dockerhub", "sonar", "sonarqube", "sentry",
    "prometheus", "alertmanager", "consul", "vault",
    "terraform", "ansible", "puppet", "chef",
    "exchange", "owa", "lync", "skype",
    "teams", "meet", "zoom", "webinar", "conference",
    "calendar", "contacts", "directory", "phonebook",
    "crm", "erp", "hr", "finance", "accounting",
    "billing", "payments", "checkout", "cart", "orders",
    "inventory", "warehouse", "shipping", "tracking",
    "analytics", "pixel", "tag", "beacon",
    "sandbox", "demo", "preview", "example", "sample",
    "training", "learn", "education", "course", "lms",
    "forum", "community", "social", "chat", "irc",
    "discord", "slack", "mattermost", "rocket",
    "news", "press", "pr", "marketing",
    "seo", "sem", "ads", "campaign", "promo",
    "affiliate", "partner", "reseller", "vendor",
    "supplier", "customer", "client", "user",
    "member", "subscriber", "newsletter", "digest",
    "rss", "atom", "feed", "sitemap", "robots",
    "health", "healthcheck", "ping", "heartbeat",
    "uptime", "downtime", "maintenance", "deploy",
    "release", "version", "changelog", "roadmap",
    "server", "host", "node", "cluster", "master", "slave",
    "primary", "secondary", "replica", "mirror",
    "origin", "edge", "gateway", "router", "switch",
    "wifi", "wireless", "guest", "corp", "office",
    "home", "lab", "devops", "ci", "cd", "pipeline",
    "build", "artifact", "package", "release",
    "debug", "trace", "log", "audit", "compliance",
    "security", "pentest", "bugbounty", "vuln",
    "scan", "nmap", "nessus", "qualys", "openvas",
    "siem", "soc", "ids", "ips", "honeypot",
    "ticket", "helpdesk", "servicedesk", "itsm",
    "payroll", "benefits", "recruiting", "onboarding",
    "legal", "privacy", "gdpr", "compliance",
    "investor", "ir", "shareholder", "board",
    "events", "webcast", "livestream", "broadcast",
    "survey", "feedback", "review", "rating",
    "download", "upload", "transfer", "sync",
    "api2", "api-v2", "api3", "api-v3", "graphql",
    "ws", "websocket", "socket", "stream",
    "m", "mobile", "mapi", "madmin",
    "old", "legacy", "v1", "v2", "v3", "new",
    "temp", "tmp", "scratch", "playground",
    "research", "rnd", "innovation", "ideas",
    "data", "datalake", "warehouse", "etl",
    "ai", "ml", "model", "training-data",
    "backup2", "dr", "disaster-recovery", "failover",
]


def run_cmd(cmd: list[str], timeout: int = 15) -> str | None:
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
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    req = Request(url, headers={"User-Agent": get_stealth_ua()})
    subdomains: set[str] = set()
    failed = True

    for attempt in range(3):
        try:
            stealth_sleep()
            with urlopen(req, timeout=8) as resp:
                raw = resp.read().decode()
                data = json.loads(raw)
                if not isinstance(data, list):
                    raise ValueError("crt.sh returned non-list response")
                for entry in data:
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lower()
                        if sub.endswith(f".{domain}") and "*" not in sub:
                            subdomains.add(sub)
                failed = False
                break
        except Exception:
            if attempt < 2:
                time.sleep(1)
            continue

    if failed:
        pass

    return sorted(subdomains)


def certspotter_subdomains(domain: str) -> list[str]:
    url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
    req = Request(url, headers={"User-Agent": get_stealth_ua()})
    subdomains: set[str] = set()

    try:
        stealth_sleep()
        with urlopen(req, timeout=12) as resp:
            data = json.loads(resp.read().decode())
            for entry in data:
                for dns_name in entry.get("dns_names", []):
                    name = dns_name.lstrip("*.")
                    if name.endswith(f".{domain}") and name != domain:
                        subdomains.add(name.lower())
    except Exception:
        pass

    return sorted(subdomains)


def alienvault_subdomains(domain: str) -> list[str]:
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    req = Request(url, headers={"User-Agent": get_stealth_ua()})
    subdomains: set[str] = set()

    try:
        stealth_sleep()
        with urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
            for entry in data.get("passive_dns", []):
                hostname = entry.get("hostname", "")
                if hostname and hostname.endswith(f".{domain}") and "*" not in hostname:
                    subdomains.add(hostname.lower())
    except Exception:
        pass

    return sorted(subdomains)


def threatcrowd_subdomains(domain: str) -> list[str]:
    url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
    req = Request(url, headers={"User-Agent": get_stealth_ua()})
    subdomains: set[str] = set()

    try:
        stealth_sleep()
        with urlopen(req, timeout=12) as resp:
            data = json.loads(resp.read().decode())
            for sub in data.get("subdomains", []):
                if sub.endswith(f".{domain}") and "*" not in sub:
                    subdomains.add(sub.lower())
    except Exception:
        pass

    return sorted(subdomains)


def dnsdumpster_subdomains(domain: str) -> list[str]:
    url = "https://dnsdumpster.com/"
    subdomains: set[str] = set()

    try:
        import ssl
        ctx = ssl.create_default_context()
        conn = __import__("http.client").HTTPSConnection("dnsdumpster.com", timeout=12, context=ctx)
        stealth_sleep()
        conn.request("GET", "/", headers={"User-Agent": get_stealth_ua()})
        resp = conn.getresponse()
        csrf_token = ""
        for header in resp.getheaders():
            if header[0].lower() == "set-cookie":
                cookie_val = header[1]
                if "csrftoken" in cookie_val:
                    csrf_token = cookie_val.split("csrftoken=")[1].split(";")[0]
                    break

        if not csrf_token:
            return []

        conn.request("POST", "/",
                     body=f"csrfmiddlewaretoken={csrf_token}&targetip={domain}",
                     headers={
                         "Content-Type": "application/x-www-form-urlencoded",
                         "Referer": "https://dnsdumpster.com/",
                         "Cookie": f"csrftoken={csrf_token}",
                         "User-Agent": get_stealth_ua(),
                     })
        resp = conn.getresponse()
        html = resp.read().decode()

        hrefs = re.findall(r'href="https?://([^"]+)"', html)
        for href in hrefs:
            host = href.split("/")[0]
            if host.endswith(f".{domain}") and "*" not in host:
                subdomains.add(host.lower())

        conn.close()
    except Exception:
        pass

    return sorted(subdomains)


def rapiddns_subdomains(domain: str) -> list[str]:
    url = f"https://rapiddns.io/subdomain/{domain}?full=1"
    req = Request(url, headers={"User-Agent": get_stealth_ua()})
    subdomains: set[str] = set()

    try:
        stealth_sleep()
        with urlopen(req, timeout=15) as resp:
            html = resp.read().decode()
            hrefs = re.findall(r'href="https?://([^"]+)"', html)
            for href in hrefs:
                host = href.split("/")[0]
                if host.endswith(f".{domain}") and "*" not in host:
                    subdomains.add(host.lower())
    except Exception:
        pass

    return sorted(subdomains)


def wayback_subdomains(domain: str) -> list[str]:
    subdomains: set[str] = set()

    try:
        import ssl
        ctx = ssl.create_default_context()
        conn = __import__("http.client").HTTPSConnection("web.archive.org", timeout=10, context=ctx)
        conn.request("GET", f"/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey&limit=2000",
                     headers={"User-Agent": "Mozilla/5.0"})
        resp = conn.getresponse()
        line_count = 0
        while line_count < 2000:
            line = resp.readline()
            if not line:
                break
            line_count += 1
            raw = line.decode().strip()
            if not raw:
                continue
            try:
                parsed = __import__("urllib.parse").urlparse(raw)
                hostname = parsed.hostname
                if hostname and hostname.endswith(f".{domain}"):
                    subdomains.add(hostname.lower())
            except Exception:
                pass
        conn.close()
    except Exception:
        pass

    return sorted(subdomains)


def dns_resolve(subdomain: str, record_type: str = "A") -> list[str]:
    result = run_cmd(["dig", "+short", record_type, subdomain])
    if not result:
        return []
    lines = [line.strip() for line in result.split("\n") if line.strip()]
    if record_type == "A":
        ipv4_re = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
        return [line for line in lines if ipv4_re.match(line)]
    return lines


def dns_enum(domain: str) -> dict[str, Any]:
    records: dict[str, Any] = {}
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
        values = dns_resolve(domain, rtype)
        if values:
            records[rtype.lower()] = values
    return records


def whois_lookup(domain: str) -> dict[str, str]:
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
        for pattern in patterns:
            if line.lower().startswith(pattern.lower()) and ":" in line:
                key = pattern.lower().replace(" ", "_")
                val = line.split(":", 1)[1].strip()
                if val and val != "REDACTED FOR PRIVACY":
                    fields[key] = val

    return fields


def asn_lookup(ip_address: str) -> dict[str, Any]:
    output = run_cmd(["whois", ip_address])
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
    resolved: dict[str, list[str]] = {}

    def resolve_one(subdomain: str) -> tuple[str, list[str]]:
        ips = dns_resolve(subdomain, "A")
        return subdomain, ips

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(resolve_one, subdomain): subdomain for subdomain in subdomains}
        for future in as_completed(futures):
            subdomain, ips = future.result()
            if ips:
                resolved[subdomain] = ips

    return resolved


def collect_unique_ips(resolved: dict[str, list[str]]) -> list[str]:
    seen: set[str] = set()
    ips: list[str] = []
    for ip_list in resolved.values():
        for ip_address in ip_list:
            if ip_address not in seen:
                seen.add(ip_address)
                ips.append(ip_address)
    return ips


def normalize_domain(domain: str) -> str:
    domain = domain.strip().rstrip("/")
    if "://" in domain:
        domain = domain.split("://", 1)[1]
    if "/" in domain:
        domain = domain.split("/", 1)[0]
    if ":" in domain:
        domain = domain.split(":", 1)[0]
    domain = domain.rstrip(".")
    if domain.startswith("www."):
        domain = domain[4:]
    parts = domain.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


def detect_wildcard_dns(domain: str) -> list[str]:
    import uuid
    wildcard_ips: list[str] = []
    for _ in range(3):
        fake = f"{uuid.uuid4().hex[:12]}.{domain}"
        ips = dns_resolve(fake, "A")
        if ips:
            for ip_address in ips:
                if ip_address not in wildcard_ips:
                    wildcard_ips.append(ip_address)
    return wildcard_ips


def brute_subdomains(domain: str, threads: int = 20) -> list[str]:
    found: list[str] = []

    wildcard_ips = detect_wildcard_dns(domain)
    if wildcard_ips:
        print(f"  {DIM}wildcard DNS detected, filtering fake subs{NC}")

    def check(subdomain: str) -> str | None:
        full = f"{subdomain}.{domain}"
        ips = dns_resolve(full, "A")
        if not ips:
            return None
        if wildcard_ips and any(ip_address in wildcard_ips for ip_address in ips):
            return None
        return full

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(check, subdomain): subdomain for subdomain in COMMON_SUBS}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)

    return sorted(found)


def run_recon(domain: str, config: dict, output: str) -> dict[str, Any]:
    base_domain = normalize_domain(domain)

    print(f"  {t('domain')}:              {base_domain}")
    print()

    all_subs: set[str] = set()

    sources = [
        ("crt.sh", lambda: crtsh_subdomains(base_domain)),
        ("certspotter", lambda: certspotter_subdomains(base_domain)),
        ("alienvault", lambda: alienvault_subdomains(base_domain)),
        ("threatcrowd", lambda: threatcrowd_subdomains(base_domain)),
        ("dnsdumpster", lambda: dnsdumpster_subdomains(base_domain)),
        ("rapiddns", lambda: rapiddns_subdomains(base_domain)),
        ("wayback", lambda: wayback_subdomains(base_domain)),
    ]

    total_sources = len(sources)
    bar_len = 30

    def _run_progress_bar(label: str, work_fn, total_steps: int):
        current_step = 0
        done = False

        def _animate():
            step = 0
            max_steps = total_steps * 10
            while not done and step < max_steps:
                time.sleep(0.15)
                step += 1
                pct = min(int((step / max_steps) * 100), 99)
                filled = int(bar_len * pct // 100)
                bar = "#" * filled + "-" * (bar_len - filled)
                print(f"\r  [{bar}] {pct}% {label}", end="", flush=True)

        anim = threading.Thread(target=_animate, daemon=True)
        anim.start()

        for step_idx in range(total_steps):
            work_fn(step_idx)
            current_step = step_idx + 1

        done = True
        anim.join(timeout=1)
        filled = bar_len
        bar = "#" * filled
        print(f"\r  [{bar}] 100% {label}", flush=True)

    source_idx = 0
    source_results: list[tuple[str, list[str]]] = []

    def _fetch_source(idx: int):
        nonlocal source_idx
        name, fetch_fn = sources[idx]
        new_subs = fetch_fn()
        all_subs.update(new_subs)
        source_results.append((name, new_subs))
        source_idx = idx + 1

    _run_progress_bar(t('enumerating_subdomains'), _fetch_source, total_sources)

    subs = sorted(all_subs)

    if len(subs) < 10:
        print(f"  {t('wordlist_brute')}...", end=" ", flush=True)
        brute = brute_subdomains(base_domain, threads=config.get("target", {}).get("threads", 20))
        all_subs.update(brute)
        subs = sorted(all_subs)
        print(f"{len(brute)} {t('found')}")

    if base_domain not in all_subs:
        subs.insert(0, base_domain)
        all_subs.add(base_domain)

    subs = sorted(all_subs)

    print(f"\n  {BOLD}{t('subdomains')} ({len(subs)}){NC}")
    for sub in subs:
        print(f"  {GREEN}{sub}{NC}")

    resolved: dict[str, list[str]] = {}
    whois: dict[str, str] = {}

    print(f"  {t('resolving')} {len(subs)}...", end=" ", flush=True)
    resolved = resolve_all(subs, threads=config.get("target", {}).get("threads", 20))
    print(f"{len(resolved)} {t('alive')}")

    print(f"  {t('whois_lookup')}...", end=" ", flush=True)
    whois = whois_lookup(base_domain)
    print(t('done'))

    ips = collect_unique_ips(resolved)
    dns_records = dns_enum(base_domain)

    asn_results: list[dict[str, Any]] = []
    for ip_address in ips[:5]:
        info = asn_lookup(ip_address)
        if info:
            info["ip"] = ip_address
            asn_results.append(info)

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

    recon_path = os.path.join(output, "recon.json")
    with open(recon_path, "w") as recon_file:
        json.dump(result, recon_file, indent=2, default=str)

    ips_path = os.path.join(output, "ips.txt")
    with open(ips_path, "w") as ips_file:
        for ip_address in ips:
            ips_file.write(ip_address + "\n")

    subs_path = os.path.join(output, "subdomains.txt")
    with open(subs_path, "w") as subs_file:
        for subdomain in resolved:
            subs_file.write(subdomain + "\n")

    print(f"\n  {BOLD}{t('recon_summary')}{NC}")
    print(f"  {BOLD}{'─' * 40}{NC}")
    print(f"  {t('subdomains')}: {GREEN}{len(subs)}{NC}")
    print(f"  {t('resolved')}:   {GREEN}{len(resolved)}{NC}")
    print(f"  {t('unique_ips')}: {CYAN}{len(ips)}{NC}")
    if ips:
        print(f"\n  {BOLD}{t('top_ips')}{NC}")
        for ip_address in ips[:10]:
            print(f"  {GREEN}{ip_address}{NC}")
        if len(ips) > 10:
            print(f"  {DIM}{t('more').format(len(ips) - 10)}{NC}")

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

    try:
        run_recon(args.domain, config, args.output)
    except KeyboardInterrupt:
        print("\n  [!] interrupted")
        sys.exit(130)


if __name__ == "__main__":
    main()
