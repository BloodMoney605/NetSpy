#!/usr/bin/env python3
"""
Phase 4: Vulnerability Assessment
- Version-to-CVE matching via OSV.dev API (cached locally)
- Nuclei scan for template-based vulnerability detection
- SSL/TLS audit (testssl.sh)
- Severity classification
- Output: JSON with findings, CVEs, risk scores
"""

import argparse
import json
import os
import sqlite3
import subprocess
import sys
import time
from typing import Any
from urllib.parse import quote
from urllib.request import Request, urlopen


def load_config(config_path: str) -> dict:
    try:
        import yaml
        with open(config_path) as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


# ============================================================
# CVE Database (SQLite local cache)
# ============================================================

def init_cve_db(db_path: str) -> sqlite3.Connection:
    """Initialize local SQLite CVE cache."""
    db_dir = os.path.dirname(db_path)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cve_cache (
            key TEXT PRIMARY KEY,
            data TEXT,
            fetched_at INTEGER
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cve_index (
            id TEXT PRIMARY KEY,
            product TEXT,
            version_range TEXT,
            severity TEXT,
            summary TEXT
        )
    """)
    conn.commit()
    return conn


def query_osv(ecosystem: str, package: str, version: str) -> list[dict[str, Any]]:
    """
    Query OSV.dev API for vulnerabilities matching a package version.
    API: https://api.osv.dev/v1/query
    """
    url = "https://api.osv.dev/v1/query"
    payload = json.dumps({
        "package": {"name": package, "ecosystem": ecosystem},
        "version": version,
    }).encode()

    req = Request(url, data=payload, headers={"Content-Type": "application/json"})

    try:
        with urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
            return data.get("vulns", [])
    except Exception:
        return []


def query_nvd(product: str, version: str) -> list[dict[str, Any]]:
    """
    Quick NVD CVE lookup for a product:version.
    Single query, short timeout. Returns empty list on failure.
    """
    search_term = f"{product} {version}"
    encoded = quote(search_term)
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={encoded}&resultsPerPage=10"

    try:
        with urlopen(url, timeout=8) as resp:
            data = json.loads(resp.read().decode())
    except Exception:
        return []

    results: list[dict[str, Any]] = []
    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id:
            continue

        metrics = cve.get("metrics", {})
        severity = "UNKNOWN"
        score = 0.0
        for cvss_type in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if cvss_type in metrics:
                cvss_data = metrics[cvss_type][0].get("cvssData", {})
                severity = cvss_data.get("baseSeverity", "UNKNOWN")
                score = cvss_data.get("baseScore", 0)
                break

        descriptions = cve.get("descriptions", [])
        summary = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                summary = desc.get("value", "")[:200]
                break

        # Filter false positives: if description mentions totally unrelated products
        fp_words = ["apache cxf", "apache groovy", "apache struts", "apache tomcat", "apache log4j"]
        if any(kw in summary.lower() for kw in fp_words):
            continue

        results.append({
            "id": cve_id,
            "severity": severity.upper(),
            "score": score,
            "summary": summary,
            "source": "nvd",
        })

    return results


def match_cves(versions: list[dict[str, str]], db: sqlite3.Connection) -> list[dict[str, Any]]:
    """
    Match detected versions against CVE database using NVD API.
    Deduplicates by product:version and by CVE ID.
    Caches results in SQLite to avoid re-querying.
    """
    findings: list[dict[str, Any]] = []
    seen_cves: set[str] = set()

    # Dedup versions: unique (product, version) pairs only
    # Normalize product names: "Apache" and "Apache HTTP Server" are the same
    PRODUCT_ALIASES = {
        "apache": "Apache HTTP Server",
        "apache http server": "Apache HTTP Server",
        "apache httpd": "Apache HTTP Server",
        "httpd": "Apache HTTP Server",
        "openssh": "OpenSSH",
        "openssl": "OpenSSL",
        "nginx": "nginx",
        "mysql": "MySQL",
        "mariadb": "MariaDB",
    }

    seen_versions: set[str] = set()
    unique_versions: list[tuple[str, str]] = []

    for v in versions:
        product = v["product"]
        version = v["version"]
        if len(version) > 25 or not any(c.isdigit() for c in version):
            continue
        # Normalize
        p_lower = product.lower().strip()
        normalized = PRODUCT_ALIASES.get(p_lower, product)
        key = f"{normalized.lower()}|{version}"
        if key not in seen_versions:
            seen_versions.add(key)
            unique_versions.append((normalized, version))

    print(f"    unique version entries: {len(unique_versions)} (from {len(versions)} total)")
    print()

    for idx, (product, version) in enumerate(unique_versions, 1):
        print(f"    [{idx}/{len(unique_versions)}] {product} {version}...", end=" ", flush=True)

        # Check cache first
        cache_key = f"{product}|{version}"
        cursor = db.execute("SELECT data FROM cve_cache WHERE key = ?", (cache_key,))
        cached = cursor.fetchone()

        if cached:
            cves = json.loads(cached[0])
            print(f"{len(cves)} CVEs (cached)")
        else:
            cves = query_nvd(product, version)
            cve_count = len(cves)
            print(f"{cve_count} CVEs")
            # Store in cache
            try:
                db.execute(
                    "INSERT OR REPLACE INTO cve_cache (key, data, fetched_at) VALUES (?, ?, ?)",
                    (cache_key, json.dumps(cves), int(time.time())),
                )
                db.commit()
            except Exception:
                pass

            # Delay between NVD queries to avoid rate limiting
            if idx < len(unique_versions):
                time.sleep(2.0)

        for cve in cves:
            cve_id = cve.get("id", "")
            if cve_id in seen_cves:
                continue
            seen_cves.add(cve_id)

            finding: dict[str, Any] = {
                "type": "cve",
                "id": cve_id,
                "product": product,
                "version": version,
                "severity": cve.get("severity", "UNKNOWN"),
                "score": cve.get("score", 0),
                "summary": cve.get("summary", "")[:300],
                "source": cve.get("source", "nvd"),
            }
            findings.append(finding)

    return findings


# ============================================================
# Nuclei integration
# ============================================================

def run_nuclei(targets_file: str, templates_path: str | None = None) -> list[dict[str, Any]]:
    """
    Run nuclei for template-based vulnerability scanning.
    Uses severity filter from config.
    """
    if not os.path.exists(targets_file):
        return []

    output_file = f"/tmp/netspy_nuclei_{int(time.time())}.jsonl"

    cmd = [
        "nuclei",
        "-l", targets_file,
        "-j",
        "-silent",
        "-s", "critical,high,medium",
        "-tags", "apache,http",
        "-rl", "20",
        "-c", "3",
        "-timeout", "5",
        "-retries", "1",
        "-jle", output_file,
    ]

    if templates_path and os.path.exists(templates_path):
        cmd.extend(["-templates", templates_path])

    print("    scanning (120s timeout)...", end=" ", flush=True)
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        print("done")
    except subprocess.TimeoutExpired:
        print("timed out (120s)")
        return []
    except FileNotFoundError:
        print("not found")
        print("  [!] nuclei not found. install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
        return []
    except Exception as e:
        print(f"error: {e}")
        pass

    results = []
    if os.path.exists(output_file):
        with open(output_file) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        results.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        try:
            os.remove(output_file)
        except Exception:
            pass

    return results


# ============================================================
# SSL/TLS audit
# ============================================================

def ssl_audit(targets: list[str]) -> list[dict[str, Any]]:
    """
    Basic SSL/TLS check using openssl.
    Checks: certificate expiry, protocol support, weak ciphers.
    """
    findings: list[dict[str, Any]] = []
    seen_hosts: set[str] = set()

    for target in targets:
        if ":" not in target:
            continue

        host, port = target.split(":")
        if not port.isdigit():
            continue

        # Skip non-SSL ports
        if int(port) not in (443, 8443, 465, 993, 995):
            continue

        host_key = f"{host}:{port}"
        if host_key in seen_hosts:
            continue
        seen_hosts.add(host_key)

        # Check certificate expiry
        cmd = [
            "openssl", "s_client",
            "-connect", f"{host}:{port}",
            "-servername", host,
            "-connect_timeout", "5",
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
                input="QUIT\n",
            )
            output = result.stdout + result.stderr

            # Extract certificate dates
            for line in output.split("\n"):
                if "notAfter" in line:
                    expiry = line.split("=")[-1].strip()
                    findings.append({
                        "type": "ssl-cert",
                        "host": host_key,
                        "issue": "certificate_expiry",
                        "detail": f"certificate expires: {expiry}",
                        "severity": "INFO",
                    })

            # Check if SSLv3 or TLSv1.0 is supported (weak)
            for proto in ["-ssl3", "-tls1", "-tls1_1"]:
                check = subprocess.run(
                    ["openssl", "s_client", proto, "-connect", f"{host}:{port}",
                     "-servername", host, "-connect_timeout", "3"],
                    capture_output=True, text=True, timeout=8, input="QUIT\n",
                )
                if "CONNECTED" in check.stdout + check.stderr and "alert" not in (check.stdout + check.stderr).lower():
                    proto_name = proto.lstrip("-").upper()
                    findings.append({
                        "type": "ssl-proto",
                        "host": host_key,
                        "issue": f"weak_protocol_{proto_name}",
                        "detail": f"{proto_name} is enabled (deprecated)",
                        "severity": "MEDIUM",
                    })

        except Exception:
            pass

    return findings


# ============================================================
# Misconfiguration checks
# ============================================================

def check_misconfigs(tech_data: dict) -> list[dict[str, Any]]:
    """
    Check for common web misconfigurations based on fingerprint data.
    """
    findings: list[dict[str, Any]] = []

    for host in tech_data.get("alive_hosts", []):
        server = host.get("server", "").lower()
        url = host.get("url", "")

        # Missing security headers
        # (httpx provides headers in response_header)
        # This is best done at HTTP response level, but we flag common issues

        if "apache" in server or "nginx" in server or "iis" in server:
            # Generic: check if directory listing might be enabled
            pass

        # Check for default pages or known patterns
        title = host.get("title", "")
        default_titles = ["index of /", "apache2 ubuntu default page",
                          "welcome to nginx", "iis windows server",
                          "tomcat", "jboss", "websphere"]

        for dt in default_titles:
            if dt in title.lower():
                findings.append({
                    "type": "misconfig",
                    "host": url,
                    "issue": "default_landing_page",
                    "detail": f"default/landing page detected: '{title}'",
                    "severity": "LOW" if "index of" not in title.lower() else "HIGH",
                })

    return findings


# ============================================================
# Main
# ============================================================

def run_vuln(input_dir: str, config: dict, output: str) -> dict[str, Any]:
    """Execute vulnerability assessment phase."""
    all_findings: list[dict[str, Any]] = []

    # Load previous phase data
    tech_path = os.path.join(input_dir, "tech.json")
    ports_path = os.path.join(input_dir, "ports.json")

    tech_data: dict = {}
    ports_data: dict = {}

    if os.path.exists(tech_path):
        with open(tech_path) as f:
            try:
                tech_data = json.load(f)
            except Exception:
                pass

    if os.path.exists(ports_path):
        with open(ports_path) as f:
            try:
                ports_data = json.load(f)
            except Exception:
                pass

    versions = tech_data.get("versions", [])

    print(f"  products with versions: {len(versions)}")
    print(f"  alive web hosts:        {tech_data.get('alive_count', 0)}")
    print()

    # -- CVE matching --
    if versions:
        print("  [CVE matching] querying vulnerability databases...")
        db_path = os.path.expanduser(config.get("vuln", {}).get("cve_db_path", "~/.netspy/cve.db"))
        db = init_cve_db(db_path)

        cve_findings = match_cves(versions, db)
        all_findings.extend(cve_findings)

        # Cache results in DB
        for f in cve_findings:
            try:
                db.execute(
                    "INSERT OR REPLACE INTO cve_index (id, product, version_range, severity, summary) VALUES (?, ?, ?, ?, ?)",
                    (f["id"], f["product"], f["version"], f["severity"], f["summary"]),
                )
            except Exception:
                pass
        db.commit()
        db.close()

    print()

    # -- Misconfiguration checks --
    print("  [misconfig] checking common issues...")
    misconfig_findings = check_misconfigs(tech_data)
    all_findings.extend(misconfig_findings)
    print(f"    {len(misconfig_findings)} misconfigurations found")
    print()

    # -- SSL/TLS audit --
    services = ports_data.get("services", [])
    ssl_targets = [f"{s['ip']}:{s['port']}" for s in services
                   if s.get("port") in (443, 8443, 993, 465, 995)]
    if ssl_targets:
        print(f"  [ssl audit] checking {len(ssl_targets)} SSL endpoints...")
        ssl_findings = ssl_audit(ssl_targets)
        all_findings.extend(ssl_findings)
        print(f"    {len(ssl_findings)} SSL findings")
    print()

    # -- Build results with everything found so far --
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "UNKNOWN": 5}
    all_findings.sort(key=lambda x: severity_order.get(x.get("severity", "UNKNOWN"), 99))

    by_severity: dict[str, int] = {}
    for f in all_findings:
        sev = f.get("severity", "UNKNOWN")
        by_severity[sev] = by_severity.get(sev, 0) + 1

    result: dict[str, Any] = {
        "summary": {
            "total_findings": len(all_findings),
            "critical": by_severity.get("CRITICAL", 0),
            "high": by_severity.get("HIGH", 0),
            "medium": by_severity.get("MEDIUM", 0),
            "low": by_severity.get("LOW", 0),
            "info": by_severity.get("INFO", 0),
        },
        "findings": all_findings,
        "scan_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    findings_path = os.path.join(output, "findings.json")

    # Save before nuclei (nuclei can crash or OOM)
    with open(findings_path, "w") as f:
        json.dump(result, f, indent=2, default=str)

    # -- Nuclei scan --
    urls_path = os.path.join(input_dir, "urls.txt")
    if os.path.exists(urls_path) and os.path.getsize(urls_path) > 0:
        print("  [nuclei] running vulnerability templates (this takes a while)...")
        nuclei_findings = run_nuclei(
            urls_path,
            templates_path=config.get("vuln", {}).get("nuclei_templates"),
        )
        print(f"    {len(nuclei_findings)} nuclei findings")

        if nuclei_findings:
            for nf in nuclei_findings:
                all_findings.append({
                    "type": "nuclei",
                    "id": nf.get("template-id", ""),
                    "name": nf.get("info", {}).get("name", ""),
                    "severity": nf.get("info", {}).get("severity", "UNKNOWN"),
                    "url": nf.get("matched-at", ""),
                    "detail": nf.get("info", {}).get("description", ""),
                    "source": "nuclei",
                })

            # Re-save with nuclei results
            result["findings"] = all_findings
            result["summary"]["total_findings"] = len(all_findings)
            for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                result["summary"][s.lower()] = sum(1 for f in all_findings if f.get("severity") == s)
            with open(findings_path, "w") as f:
                json.dump(result, f, indent=2, default=str)

    # Print summary
    print()
    print(f"  === Vulnerability Summary ===")
    print(f"  Total:  {result['summary']['total_findings']}")
    print(f"  Critical: {result['summary']['critical']}")
    print(f"  High:     {result['summary']['high']}")
    print(f"  Medium:   {result['summary']['medium']}")
    print(f"  Low:      {result['summary']['low']}")
    print(f"  Info:     {result['summary']['info']}")
    print()

    if all_findings:
        print("  Top findings:")
        for f in all_findings[:10]:
            sev = f.get("severity", "?")
            fid = f.get("id", f.get("name", "?"))
            prod = f.get("product", "")
            ver = f.get("version", "")
            detail = f.get("detail", "")[:80]
            if prod and ver:
                print(f"    [{sev}] {fid} | {prod} {ver} | {detail}")
            else:
                print(f"    [{sev}] {fid} | {detail}")
        if len(all_findings) > 10:
            print(f"    ... and {len(all_findings) - 10} more")

    print(f"\n  output: {findings_path}")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Phase 4: Vulnerability Assessment")
    parser.add_argument("--input", required=True, help="input directory with phase 3 data")
    parser.add_argument("--config", default="config/default.yaml")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    config = load_config(args.config)
    os.makedirs(args.output, exist_ok=True)

    run_vuln(args.input, config, args.output)


if __name__ == "__main__":
    main()
