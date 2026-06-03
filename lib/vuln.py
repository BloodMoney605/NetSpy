#!/usr/bin/env python3

import argparse
import json
import os
import re
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any
from urllib.parse import quote
from urllib.request import Request, urlopen

from common import load_config, apply_thread_override, t


def _parse_version(version_str: str) -> tuple[int, ...]:
    parts = []
    for segment in version_str.strip().split("."):
        match = re.match(r"(\d+)", segment)
        if match:
            parts.append(int(match.group(1)))
        else:
            parts.append(0)
    return tuple(parts) if parts else (0,)


def _version_in_range(our_ver: str, summary_lower: str) -> bool:
    our = _parse_version(our_ver)

    version_range_match = re.search(r"versions?\s+(\d+\.\d+(?:\.\d+)*)\s+(?:to|through)\s+(\d+\.\d+(?:\.\d+)*)", summary_lower)
    if version_range_match:
        low = _parse_version(version_range_match.group(1))
        high = _parse_version(version_range_match.group(2))
        return low <= our <= high

    version_range_match = re.search(r"(\d+\.\d+(?:\.\d+)*)\s+(?:to|through)\s+(\d+\.\d+(?:\.\d+)*)", summary_lower)
    if version_range_match:
        low = _parse_version(version_range_match.group(1))
        high = _parse_version(version_range_match.group(2))
        return low <= our <= high

    and_earlier_match = re.search(r"(\d+\.\d+(?:\.\d+)*)\s+(?:and earlier|and prior)", summary_lower)
    if and_earlier_match:
        threshold = _parse_version(and_earlier_match.group(1))
        return our <= threshold

    listed_versions = re.findall(r"(\d+\.\d+\.\d+)", summary_lower)
    if len(listed_versions) >= 2:
        parsed_versions = [_parse_version(v) for v in listed_versions]
        if our in parsed_versions:
            return True
        if all(our < v for v in parsed_versions):
            return False

    before_match = re.search(r"(?:before|prior to)\s+(\d+\.\d+(?:\.\d+)*)", summary_lower)
    if before_match:
        threshold = _parse_version(before_match.group(1))
        return our < threshold

    through_match = re.search(r"(?:through|up to)\s+(\d+\.\d+(?:\.\d+)*)", summary_lower)
    if through_match:
        threshold = _parse_version(through_match.group(1))
        return our <= threshold

    x_before_match = re.search(r"(\d+\.\d+)\.x\s+before\s+(\d+\.\d+(?:\.\d+)*)", summary_lower)
    if x_before_match:
        threshold = _parse_version(x_before_match.group(2))
        return our < threshold

    return None


RUNTIME_ECOSYSTEM_KEYWORDS = {
    "php": ["in php ", "php before", "php through", "php is a", "php interpreter", "zend engine", "php core", "php-src", "ext/"],
    "python": ["in python ", "python before", "python through", "cpython", "python interpreter", "pypy"],
    "node.js": ["in node.js", "node.js before", "node.js through", "nodejs before", "node core", "v8 engine", "libuv"],
    "nodejs": ["in node.js", "node.js before", "nodejs before", "nodejs through", "node core", "v8 engine", "libuv"],
    "ruby": ["in ruby ", "ruby before", "ruby through", "ruby interpreter", "ruby core"],
    "perl": ["in perl ", "perl before", "perl through", "perl interpreter"],
    "java": ["in java ", "java before", "jdk before", "jre before", "openjdk before", "jvm"],
    "go": ["in go ", "go before", "golang before", "go compiler", "go runtime"],
    "rust": ["in rust ", "rust before", "rustc before", "rust compiler"],
}

PRODUCT_VERSION_BOUNDS = {
    "wordpress": (0, 6),
    "joomla": (1, 5),
    "drupal": (7, 11),
    "magento": (2, 2),
    "woocommerce": (3, 9),
}


def _is_runtime_cve(product: str, summary_lower: str) -> bool:
    product_lower = product.lower().strip()
    if product_lower not in RUNTIME_ECOSYSTEM_KEYWORDS:
        return True

    keywords = RUNTIME_ECOSYSTEM_KEYWORDS[product_lower]
    first_100 = summary_lower[:100]

    for keyword in keywords:
        if keyword in first_100:
            return True

    return False


def _is_plausible_version(product: str, version: str) -> bool:
    product_lower = product.lower().strip()
    if product_lower not in PRODUCT_VERSION_BOUNDS:
        return True

    min_major, max_major = PRODUCT_VERSION_BOUNDS[product_lower]
    try:
        major = int(version.split(".")[0])
        return min_major <= major <= max_major
    except (ValueError, IndexError):
        return True


OSV_ECOSYSTEMS = {
    "php": ["PyPI"],
    "python": ["PyPI"],
    "django": ["PyPI"],
    "flask": ["PyPI"],
    "node.js": ["npm"],
    "nodejs": ["npm"],
    "express": ["npm"],
    "express.js": ["npm"],
    "react": ["npm"],
    "angular": ["npm"],
    "vue": ["npm"],
    "vue.js": ["npm"],
    "jquery": ["npm"],
    "bootstrap": ["npm"],
    "rails": ["RubyGems"],
    "ruby on rails": ["RubyGems"],
    "spring": ["Maven"],
    "spring framework": ["Maven"],
    "docker": ["Go"],
    "kubernetes": ["Go"],
    "redis": ["Go"],
    "elasticsearch": ["Go"],
    "mongodb": ["Go"],
}

LINUX_DISTRO_ECOSYSTEMS = [
    "Alpine:v3.20",
    "Alpine:v3.19",
    "Debian:12",
    "Debian:11",
    "Ubuntu:24.04",
    "Ubuntu:22.04",
]

BOLD = "\033[1m"
DIM = "\033[2m"
NC = "\033[0m"


def init_cve_db(db_path: str) -> sqlite3.Connection:
    db_dir = os.path.dirname(db_path)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    conn = sqlite3.connect(db_path, check_same_thread=False)
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
    url = "https://api.osv.dev/v1/query"
    payload = json.dumps({
        "package": {"name": package, "ecosystem": ecosystem},
        "version": version,
    }).encode()

    req = Request(url, data=payload, headers={"Content-Type": "application/json"})

    retries = 3
    for attempt in range(retries):
        try:
            with urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode())
                return data.get("vulns", [])
        except Exception as e:
            if "429" in str(e) and attempt < retries - 1:
                time.sleep(1.0 * (attempt + 1))
                continue
            return []
    return []


def query_nvd(product: str, version: str) -> list[dict[str, Any]]:
    version_parts = version.strip().split(".")
    major_ver = ".".join(version_parts[:2]) if len(version_parts) >= 2 else version_parts[0]
    keyword = f"{product} {major_ver}"
    encoded = quote(keyword)
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={encoded}&resultsPerPage=50"

    retries = 3
    for attempt in range(retries):
        try:
            with urlopen(url, timeout=15) as resp:
                data = json.loads(resp.read().decode())
            break
        except Exception as e:
            if "429" in str(e) and attempt < retries - 1:
                time.sleep(2.0 * (attempt + 1))
                continue
            return []
    else:
        return []

    product_lower = product.lower()
    version_clean = version.strip()
    results: list[dict[str, Any]] = []
    for vuln_entry in data.get("vulnerabilities", []):
        cve_data = vuln_entry.get("cve", {})
        cve_id = cve_data.get("id", "")
        if not cve_id:
            continue

        metrics = cve_data.get("metrics", {})
        severity = "UNKNOWN"
        score = 0.0
        for cvss_type in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if cvss_type in metrics:
                cvss_data = metrics[cvss_type][0].get("cvssData", {})
                severity = cvss_data.get("baseSeverity", "")
                score = cvss_data.get("baseScore", 0)
                if not severity and score > 0:
                    if score >= 9.0:
                        severity = "CRITICAL"
                    elif score >= 7.0:
                        severity = "HIGH"
                    elif score >= 4.0:
                        severity = "MEDIUM"
                    else:
                        severity = "LOW"
                break

        descriptions = cve_data.get("descriptions", [])
        summary = ""
        for desc_entry in descriptions:
            if desc_entry.get("lang") == "en":
                summary = desc_entry.get("value", "")[:300]
                break

        summary_lower = summary.lower()

        other_products = [
            "oracle", "bea", "weblogic", "mcafee", "hpe", "icewall",
            "sap", "ibm", "symantec", "trend micro", "kaspersky",
            "f5 big-ip", "citrix", "vmware", "juniper", "cisco",
            "fortinet", "checkpoint", "palo alto", "dell", "hp",
            "lenovo", "samsung", "huawei", "zte",
        ]
        is_about_other = False
        for other_product in other_products:
            if other_product in summary_lower and other_product not in product_lower:
                if f"for {product_lower}" in summary_lower or \
                   f"plugin" in summary_lower or \
                   f"plug-in" in summary_lower:
                    is_about_other = True
                    break
        if is_about_other:
            continue

        platform_patterns = [
            rf"when running on\s+(?:a\s+)?{re.escape(product_lower)}",
            rf"when used with\s+(?:a\s+)?{re.escape(product_lower)}",
            rf"running on\s+(?:a\s+)?{re.escape(product_lower)}",
            rf"on\s+(?:a\s+)?{re.escape(product_lower)}\s+server",
            rf"for\s+(?:a\s+)?{re.escape(product_lower)}",
            rf"in conjunction with\s+(?:a\s+)?{re.escape(product_lower)}",
            rf"used with\s+(?:a\s+)?{re.escape(product_lower)}",
            rf"deployed on\s+(?:a\s+)?{re.escape(product_lower)}",
            rf"installed on\s+(?:a\s+)?{re.escape(product_lower)}",
        ]
        is_platform = any(re.search(pattern, summary_lower) for pattern in platform_patterns)
        if is_platform:
            continue

        first_part = summary_lower[:150]
        product_words = product_lower.split()
        if len(product_words) >= 2:
            has_product = False
            for word_idx in range(len(product_words) - 1):
                bigram = f"{product_words[word_idx]} {product_words[word_idx+1]}"
                if bigram in first_part:
                    has_product = True
                    break
            if not has_product:
                continue
        else:
            if len(product_lower) < 4:
                word_boundary_pattern = r'\b' + re.escape(product_lower) + r'\b'
                if not re.search(word_boundary_pattern, first_part):
                    continue
            else:
                if product_lower not in first_part:
                    continue

            if len(product_lower) < 5:
                compound_words = [
                    "vault", "dashmachine", "privileged", "privilege",
                    "embedded", "extended", "redirected", "requested", "restricted",
                ]
                skip_cve = False
                for compound in compound_words:
                    if product_lower in compound and compound in summary_lower:
                        skip_cve = True
                        break
                if skip_cve:
                    continue

            if product_lower == "dash":
                if "alliance" in summary_lower or "protocol" in summary_lower or "iot" in summary_lower:
                    continue

        if "winnt" in summary_lower:
            continue

        if not _is_runtime_cve(product, summary_lower):
            continue

        if product_lower in ("wordpress", "joomla", "drupal", "magento", "prestashop", "woocommerce"):
            if re.search(r"\b\w+\s+plugin\b", summary_lower) or \
               re.search(r"\b\w+\s+theme\b", summary_lower) or \
               re.search(r"\bplugin\b.*\bwordpress\b", summary_lower) or \
               re.search(r"\bwordpress\b.*\bplugin\b", summary_lower):
                continue

        version_in_summary = version_clean in summary or \
                             f"before {version_clean}" in summary_lower or \
                             f"through {version_clean}" in summary_lower or \
                             f"up to {version_clean}" in summary_lower or \
                             f"prior to {version_clean}" in summary_lower or \
                             f"from {version_clean}" in summary_lower or \
                             f"since {version_clean}" in summary_lower

        range_check = _version_in_range(version_clean, summary_lower)
        if range_check is False:
            continue
        if range_check is True:
            results.append({
                "id": cve_id,
                "severity": severity.upper(),
                "score": score,
                "summary": summary,
                "source": "nvd",
            })
            continue

        mentioned_versions = re.findall(r"\b(\d+\.\d+(?:\.\d+)*|\d+\.x)\b", summary_lower)

        def _version_major_minor(ver_str: str) -> tuple[int, int]:
            ver_parts = ver_str.split(".")
            try:
                return (int(ver_parts[0]), int(ver_parts[1]))
            except (ValueError, IndexError):
                return (-1, -1)

        our_vm = _version_major_minor(version_clean)
        has_other_version = False
        for mentioned_ver in mentioned_versions:
            if len(mentioned_ver) < 3 or mentioned_ver == version_clean:
                continue
            vm = _version_major_minor(mentioned_ver)
            if vm != (-1, -1) and our_vm != (-1, -1) and vm != our_vm:
                has_other_version = True
                break

        if has_other_version and not version_in_summary:
            continue

        if not mentioned_versions and not version_in_summary:
            continue

        if range_check is None and not version_in_summary and not mentioned_versions:
            continue

        results.append({
            "id": cve_id,
            "severity": severity.upper(),
            "score": score,
            "summary": summary,
            "source": "nvd",
        })

    return results


def _is_distro_package(product: str) -> bool:
    product_lower = product.lower().strip()
    distro_packages = {
        "openssh", "openssl", "nginx", "apache", "httpd", "apache http server",
        "mysql", "mariadb", "postgres", "postgresql", "php", "python",
        "perl", "ruby", "node.js", "nodejs", "bind", "named", "postfix",
        "dovecot", "exim", "sendmail", "cron", "systemd", "glibc",
        "curl", "wget", "git", "sudo", "bash", "zsh", "vim", "emacs",
        "tar", "gzip", "rsync", "sshd", "ftp", "vsftpd", "proftpd",
        "samba", "smb", "cifs", "nfs", "iscsi",
    }
    if product_lower in distro_packages:
        return True
    for distro_pkg in distro_packages:
        if product_lower.startswith(distro_pkg) or distro_pkg.startswith(product_lower):
            return True
    return False


def _fetch_cves(product: str, version: str, db: sqlite3.Connection,
                cache_lock: threading.Lock) -> tuple[str, list[dict[str, Any]]]:
    cache_key = f"{product}|{version}"
    cursor = db.execute("SELECT data FROM cve_cache WHERE key = ?", (cache_key,))
    cached = cursor.fetchone()
    if cached:
        return cache_key, json.loads(cached[0])

    all_cves: list[dict[str, Any]] = []

    try:
        all_cves.extend(query_nvd(product, version))
    except Exception:
        pass

    product_lower = product.lower()
    if product_lower in OSV_ECOSYSTEMS:
        for eco in OSV_ECOSYSTEMS[product_lower]:
            try:
                all_cves.extend(query_osv(eco, product, version))
            except Exception:
                pass

    if _is_distro_package(product):
        for eco in LINUX_DISTRO_ECOSYSTEMS:
            try:
                all_cves.extend(query_osv(eco, product, version))
            except Exception:
                pass

    seen_ids: set[str] = set()
    cves_by_id: dict[str, dict[str, Any]] = {}
    for cve_entry in all_cves:
        cve_id = cve_entry.get("id", "")
        if not cve_id:
            continue

        if cve_id not in cves_by_id:
            cves_by_id[cve_id] = cve_entry
        else:
            existing = cves_by_id[cve_id]
            if cve_entry.get("source") == "nvd" and existing.get("source") != "nvd":
                cves_by_id[cve_id] = cve_entry
            elif cve_entry.get("severity", "UNKNOWN") != "UNKNOWN" and existing.get("severity", "UNKNOWN") == "UNKNOWN":
                cves_by_id[cve_id] = cve_entry
            elif cve_entry.get("score", 0) > existing.get("score", 0):
                cves_by_id[cve_id] = cve_entry

    cves = list(cves_by_id.values())

    try:
        with cache_lock:
            db.execute(
                "INSERT OR REPLACE INTO cve_cache (key, data, fetched_at) VALUES (?, ?, ?)",
                (cache_key, json.dumps(cves), int(time.time())),
            )
            db.commit()
    except Exception:
        pass

    return cache_key, cves


def match_cves(versions: list[dict[str, str]], db: sqlite3.Connection) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen_cves: set[str] = set()

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
        "postgres": "PostgreSQL",
        "postgresql": "PostgreSQL",
        "php": "PHP",
        "python": "Python",
        "node.js": "Node.js",
        "nodejs": "Node.js",
        "redis": "Redis",
        "mongodb": "MongoDB",
        "elasticsearch": "Elasticsearch",
        "docker": "Docker",
        "kubernetes": "Kubernetes",
        "tomcat": "Apache Tomcat",
        "apache tomcat": "Apache Tomcat",
        "log4j": "Apache Log4j",
        "apache log4j": "Apache Log4j",
        "struts": "Apache Struts",
        "apache struts": "Apache Struts",
        "wordpress": "WordPress",
        "joomla": "Joomla",
        "drupal": "Drupal",
        "django": "Django",
        "flask": "Flask",
        "rails": "Ruby on Rails",
        "ruby on rails": "Ruby on Rails",
        "spring": "Spring Framework",
        "spring framework": "Spring Framework",
        "express": "Express.js",
        "express.js": "Express.js",
        "react": "React",
        "angular": "Angular",
        "vue": "Vue.js",
        "vue.js": "Vue.js",
        "jquery": "jQuery",
        "bootstrap": "Bootstrap",
        "postfix": "Postfix",
        "dovecot": "Dovecot",
        "bind": "BIND",
        "named": "BIND",
        "microsoft-iis": "Microsoft IIS",
        "microsoft iis": "Microsoft IIS",
        "iis": "Microsoft IIS",
        "akamai": "Akamai",
        "akamaighost": "Akamai",
        "cloudflare": "Cloudflare",
        "envoy": "Envoy Proxy",
        "varnish": "Varnish Cache",
        "haproxy": "HAProxy",
    }

    SKIP_PRODUCTS = {
        "cloudflare", "akamai", "amazon cloudfront", "aws cloudfront",
        "google cloud cdn", "fastly", "cloudinary", "varnish cache",
        "envoy proxy", "haproxy", "nginx-ingress",
    }

    seen_versions: set[str] = set()
    unique_versions: list[tuple[str, str]] = []

    for version_entry in versions:
        product = version_entry["product"]
        version = version_entry["version"]
        if len(version) > 15 or not any(c.isdigit() for c in version):
            continue
        product = re.sub(r"[^a-zA-Z0-9\s._-]+$", "", product).strip()
        if not product:
            continue
        product_lower = product.lower().strip()
        normalized = PRODUCT_ALIASES.get(product_lower, product)
        if normalized.lower() in SKIP_PRODUCTS:
            continue
        if not _is_plausible_version(normalized, version):
            continue
        key = f"{normalized.lower()}|{version}"
        if key not in seen_versions:
            seen_versions.add(key)
            unique_versions.append((normalized, version))

    print(f"    {t('unique_version_entries')}: {len(unique_versions)} ({t('from')} {len(versions)} {t('total')})")
    print()

    cache_lock = threading.Lock()
    worker_count = min(2, len(unique_versions))
    phase_deadline = time.time() + 300

    with ThreadPoolExecutor(max_workers=worker_count) as pool:
        future_map = {
            pool.submit(_fetch_cves, prod, ver, db, cache_lock): (idx, prod, ver)
            for idx, (prod, ver) in enumerate(unique_versions, 1)
        }

        results_by_idx: dict[int, tuple[str, list[dict[str, Any]]]] = {}
        for future in as_completed(future_map):
            if time.time() > phase_deadline:
                print(f"    {t('cve_timeout_phase')}")
                pool.shutdown(wait=False, cancel_futures=True)
                break
            idx, product, version = future_map[future]
            try:
                cache_key, cves = future.result()
                results_by_idx[idx] = (product, version, cves)
            except Exception:
                results_by_idx[idx] = (product, version, [])

    for idx in range(1, len(unique_versions) + 1):
        product, version, cves = results_by_idx.get(idx, ("", "", []))
        print(f"    [{idx}/{len(unique_versions)}] {product} {version}... ", end="", flush=True)
        if cves:
            sources = set()
            for cve_entry in cves:
                src = cve_entry.get("source", "osv")
                if isinstance(src, str):
                    sources.add(src)
            print(f"{len(cves)} CVEs (sources: {', '.join(sorted(sources))})")
        else:
            print("0 CVEs")

        for cve_entry in cves:
            cve_id = cve_entry.get("id", "")
            if not isinstance(cve_id, str) or not cve_id:
                continue
            if cve_id in seen_cves:
                continue
            seen_cves.add(cve_id)

            findings.append({
                "type": "cve",
                "id": cve_id,
                "product": product,
                "version": version,
                "severity": cve_entry.get("severity", "UNKNOWN"),
                "score": cve_entry.get("score", 0),
                "summary": cve_entry.get("summary", "")[:300],
                "source": cve_entry.get("source", "osv") if isinstance(cve_entry.get("source"), str) else "osv",
            })

    return findings


def run_nuclei(targets_file: str, templates_path: str | None = None) -> list[dict[str, Any]]:
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

    print(f"    {t('nuclei_scanning')}...", end=" ", flush=True)
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        print(t('nuclei_done'))
    except subprocess.TimeoutExpired:
        print(t('nuclei_timeout'))
        return []
    except FileNotFoundError:
        print(t('nuclei_not_found_short'))
        print(f"  {t('nuclei_not_found')}")
        return []
    except Exception as err:
        print(f"{t('nuclei_error')}: {err}")
        pass

    results = []
    if os.path.exists(output_file):
        with open(output_file) as jsonl_file:
            for line in jsonl_file:
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


def ssl_audit(targets: list[str]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen_hosts: set[str] = set()

    for target in targets:
        if ":" not in target:
            continue

        host, port = target.split(":")
        if not port.isdigit():
            continue

        if int(port) not in (443, 8443, 465, 993, 995):
            continue

        host_key = f"{host}:{port}"
        if host_key in seen_hosts:
            continue
        seen_hosts.add(host_key)

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


def check_misconfigs(tech_data: dict) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    for host_entry in tech_data.get("alive_hosts", []):
        server = host_entry.get("server", "").lower()
        url = host_entry.get("url", "")

        if "apache" in server or "nginx" in server or "iis" in server:
            pass

        title = host_entry.get("title", "")
        default_titles = ["index of /", "apache2 ubuntu default page",
                          "welcome to nginx", "iis windows server",
                          "tomcat", "jboss", "websphere"]

        for default_title in default_titles:
            if default_title in title.lower():
                is_sensitive = any(sensitive in title.lower() for sensitive in [
                    "admin", "backup", "config", "database", "db", "etc",
                    "passwd", "shadow", "secret", "key", "credential",
                    "env", "git", "svn", "htpasswd", "wp-config",
                ])
                findings.append({
                    "type": "misconfig",
                    "host": url,
                    "issue": "default_landing_page",
                    "detail": f"default/landing page detected: '{title}'",
                    "severity": "HIGH" if is_sensitive else "LOW",
                })

    return findings


def run_vuln(input_dir: str, config: dict, output: str) -> dict[str, Any]:
    all_findings: list[dict[str, Any]] = []

    tech_path = os.path.join(input_dir, "tech.json")
    ports_path = os.path.join(input_dir, "ports.json")

    tech_data: dict = {}
    ports_data: dict = {}

    if os.path.exists(tech_path):
        with open(tech_path) as tech_file:
            try:
                tech_data = json.load(tech_file)
            except Exception:
                pass

    if os.path.exists(ports_path):
        with open(ports_path) as ports_file:
            try:
                ports_data = json.load(ports_file)
            except Exception:
                pass

    versions = tech_data.get("versions", [])

    print(f"  {t('products_versions')}: {len(versions)}")
    print(f"  {t('alive_hosts')}:        {tech_data.get('alive_count', 0)}")
    print()

    if versions:
        print(f"  [CVE matching] {t('cve_matching_query')}...")
        db_path = os.path.expanduser(config.get("vuln", {}).get("cve_db_path", "~/.netspy/cve.db"))
        db = init_cve_db(db_path)

        cve_findings = match_cves(versions, db)
        all_findings.extend(cve_findings)

        for finding_entry in cve_findings:
            try:
                db.execute(
                    "INSERT OR REPLACE INTO cve_index (id, product, version_range, severity, summary) VALUES (?, ?, ?, ?, ?)",
                    (finding_entry["id"], finding_entry["product"], finding_entry["version"], finding_entry["severity"], finding_entry["summary"]),
                )
            except Exception:
                pass
        db.commit()
        db.close()

    print()

    print(f"  [misconfig] {t('misconfig_checking')}...")
    misconfig_findings = check_misconfigs(tech_data)
    all_findings.extend(misconfig_findings)
    print(f"    {len(misconfig_findings)} {t('misconfig_found')}")
    print()

    services = ports_data.get("services", [])
    ssl_targets = [f"{svc['ip']}:{svc['port']}" for svc in services
                   if svc.get("port") in (443, 8443, 993, 465, 995)]
    if ssl_targets:
        print(f"  [ssl audit] {t('ssl_checking')} ({len(ssl_targets)})...")
        ssl_findings = ssl_audit(ssl_targets)
        all_findings.extend(ssl_findings)
        print(f"    {len(ssl_findings)} {t('ssl_findings')}")
    print()

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "UNKNOWN": 5}

    for finding_entry in all_findings:
        sev = finding_entry.get("severity", "UNKNOWN")
        if isinstance(sev, list):
            sev = sev[0] if sev else "UNKNOWN"
        if not isinstance(sev, str):
            sev = "UNKNOWN"
        finding_entry["severity"] = sev.upper()

    all_findings.sort(key=lambda x: severity_order.get(x.get("severity", "UNKNOWN"), 99))

    by_severity: dict[str, int] = {}
    for finding_entry in all_findings:
        sev = finding_entry.get("severity", "UNKNOWN")
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

    with open(findings_path, "w") as findings_file:
        json.dump(result, findings_file, indent=2, default=str)

    if config.get("vuln", {}).get("enable_nuclei", False):
        urls_path = os.path.join(input_dir, "urls.txt")
        if os.path.exists(urls_path) and os.path.getsize(urls_path) > 0:
            print(f"  [nuclei] {t('nuclei_running')}...")
            nuclei_findings = run_nuclei(
                urls_path,
                templates_path=config.get("vuln", {}).get("nuclei_templates"),
            )
            print(f"    {len(nuclei_findings)} {t('nuclei_findings')}")

            if nuclei_findings:
                for nuclei_entry in nuclei_findings:
                    all_findings.append({
                        "type": "nuclei",
                        "id": nuclei_entry.get("template-id", ""),
                        "name": nuclei_entry.get("info", {}).get("name", ""),
                        "severity": nuclei_entry.get("info", {}).get("severity", "UNKNOWN"),
                        "url": nuclei_entry.get("matched-at", ""),
                        "detail": nuclei_entry.get("info", {}).get("description", ""),
                        "source": "nuclei",
                    })

                result["findings"] = all_findings
                result["summary"]["total_findings"] = len(all_findings)
                for severity_label in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                    result["summary"][severity_label.lower()] = sum(1 for fe in all_findings if fe.get("severity") == severity_label)
                with open(findings_path, "w") as findings_file:
                    json.dump(result, findings_file, indent=2, default=str)

    SEV_COLORS = {
        "CRITICAL": "\033[1;31m",
        "HIGH":     "\033[0;31m",
        "MEDIUM":   "\033[0;33m",
        "LOW":      "\033[0;36m",
        "INFO":     "\033[0;37m",
    }
    NC = "\033[0m"

    print()
    print(f"  {BOLD}{t('vuln_summary_title')}{NC}")
    print(f"  {BOLD}{'─' * 40}{NC}")
    print(f"  {t('total')}:    {BOLD}{result['summary']['total_findings']}{NC}")
    summary_data = result['summary']
    if summary_data['critical']:
        print(f"  {SEV_COLORS['CRITICAL']}{t('critical')}: {summary_data['critical']}{NC}")
    if summary_data['high']:
        print(f"  {SEV_COLORS['HIGH']}{t('high')}:     {summary_data['high']}{NC}")
    if summary_data['medium']:
        print(f"  {SEV_COLORS['MEDIUM']}{t('medium')}:   {summary_data['medium']}{NC}")
    if summary_data['low']:
        print(f"  {SEV_COLORS['LOW']}{t('low')}:      {summary_data['low']}{NC}")
    if summary_data['info']:
        print(f"  {SEV_COLORS['INFO']}{t('info')}:     {summary_data['info']}{NC}")
    print()

    if all_findings:
        print(f"  {BOLD}{t('findings_title')}{NC}")
        print(f"  {BOLD}{'─' * 60}{NC}")
        for finding_entry in all_findings:
            sev = finding_entry.get("severity", "?")
            fid = finding_entry.get("id", finding_entry.get("name", "?"))
            prod = finding_entry.get("product", "")
            ver = finding_entry.get("version", "")
            detail = (finding_entry.get("summary") or finding_entry.get("detail", ""))[:100]
            color = SEV_COLORS.get(sev, "")
            badge = f"{color}[{sev}]{NC}"
            if prod and ver:
                print(f"  {badge} {fid} | {prod} {ver}")
            else:
                print(f"  {badge} {fid}")
            if detail:
                print(f"         {DIM}{detail}{NC}")
        if len(all_findings) > 20:
            print(f"  {DIM}{t('and_more').format(len(all_findings) - 20)}{NC}")

    print(f"\n  {t('output')}: {findings_path}")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Phase 4: Vulnerability Assessment")
    parser.add_argument("--input", required=True, help="input directory with phase 3 data")
    parser.add_argument("--config", default="config/default.yaml")
    parser.add_argument("--output", required=True)
    parser.add_argument("--threads", type=int, default=None)
    args = parser.parse_args()

    config = load_config(args.config)
    config = apply_thread_override(config, args.threads)
    os.makedirs(args.output, exist_ok=True)

    try:
        run_vuln(args.input, config, args.output)
    except KeyboardInterrupt:
        print("\n  [!] interrupted")
        sys.exit(130)


if __name__ == "__main__":
    main()
