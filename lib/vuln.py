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

    version_number = r"(\d+\.\d+(?:\.\d+)*)"
    version_range = version_number + r"\s+(?:to|through)\s+" + version_number

    # Check: "versions X to Y" or "version X to Y"
    match = re.search(r"versions?\s+" + version_range, summary_lower)
    if match:
        return _parse_version(match.group(1)) <= our <= _parse_version(match.group(2))

    # Check: "X to Y" or "X through Y"
    match = re.search(version_range, summary_lower)
    if match:
        return _parse_version(match.group(1)) <= our <= _parse_version(match.group(2))

    # Check: "X and earlier" or "X and prior"
    match = re.search(version_number + r"\s+(?:and earlier|and prior)", summary_lower)
    if match:
        return our <= _parse_version(match.group(1))

    # Check: "before X" or "prior to X"
    match = re.search(r"(?:before|prior to)\s+" + version_number, summary_lower)
    if match:
        return our < _parse_version(match.group(1))

    # Check: "through X" or "up to X"
    match = re.search(r"(?:through|up to)\s+" + version_number, summary_lower)
    if match:
        return our <= _parse_version(match.group(1))

    # Check: "X.x before Y" (e.g. "2.4.x before 2.4.10")
    match = re.search(version_number + r"\.x\s+before\s+" + version_number, summary_lower)
    if match:
        return our < _parse_version(match.group(2))

    # Check: if multiple versions are listed, ours must be one of them
    seen_versions = re.findall(version_number, summary_lower)
    if len(seen_versions) >= 2:
        parsed = [_parse_version(v) for v in seen_versions]
        if our in parsed:
            return True
        if all(our < v for v in parsed):
            return False

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
    # Build NVD API URL from product and version
    version_parts = version.strip().split(".")
    if len(version_parts) >= 2:
        major_version = ".".join(version_parts[:2])
    else:
        major_version = version_parts[0]

    keyword = f"{product} {major_version}"
    url = (
        f"https://services.nvd.nist.gov/rest/json/cves/2.0"
        f"?keywordSearch={quote(keyword)}&resultsPerPage=50"
    )

    # Fetch with retry for rate limiting
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

    return _filter_nvd_results(product, version, data)


def _filter_nvd_results(product: str, version: str, data: dict) -> list[dict[str, Any]]:
    product_lower = product.lower()
    clean_version = version.strip()
    results = []

    for vuln_entry in data.get("vulnerabilities", []):
        cve_data = vuln_entry.get("cve", {})
        cve_id = cve_data.get("id", "")
        if not cve_id:
            continue

        severity, score = _extract_nvd_severity(cve_data.get("metrics", {}))
        summary = _get_english_summary(cve_data.get("descriptions", [])[:300])
        if not summary:
            continue

        summary_lower = summary.lower()

        if not _product_in_summary(product_lower, summary_lower):
            continue

        if _is_false_positive(product_lower, summary_lower):
            continue

        version_range = _version_in_range(clean_version, summary_lower)

        if version_range is False:
            continue

        if version_range is True:
            results.append({
                "id": cve_id,
                "severity": severity.upper(),
                "score": score,
                "summary": summary,
                "source": "nvd",
            })
            continue

        version_in_summary = (
            clean_version in summary
            or f"before {clean_version}" in summary_lower
            or f"through {clean_version}" in summary_lower
            or f"up to {clean_version}" in summary_lower
            or f"prior to {clean_version}" in summary_lower
        )

        if not version_in_summary:
            mentioned_versions = re.findall(
                r"\b(\d+\.\d+(?:\.\d+)*)\b", summary_lower
            )
            if not mentioned_versions:
                continue

            our_major = clean_version.split(".")[0]
            compatible_version = False
            for mv in mentioned_versions:
                if mv.split(".")[0] == our_major:
                    compatible_version = True
                    break

            if not compatible_version:
                continue

        results.append({
            "id": cve_id,
            "severity": severity.upper(),
            "score": score,
            "summary": summary,
            "source": "nvd",
        })

    return results


def _extract_nvd_severity(metrics: dict) -> tuple[str, float]:
    severity = "UNKNOWN"
    score = 0.0

    cvss_types = ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]
    for cvss_type in cvss_types:
        if cvss_type not in metrics:
            continue

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

        if severity:
            break

    return severity.upper(), score


def _get_english_summary(descriptions: list) -> str:
    for entry in descriptions:
        if entry.get("lang") == "en":
            return entry.get("value", "")[:300]
    return ""


def _product_in_summary(product: str, summary: str) -> bool:
    first_part = summary[:150]
    product_words = product.split()

    # Multi-word products: check if bigram appears in summary
    if len(product_words) >= 2:
        for idx in range(len(product_words) - 1):
            bigram = f"{product_words[idx]} {product_words[idx + 1]}"
            if bigram in first_part:
                return True
        return False

    # Single-word products shorter than 4 chars: use word boundaries
    if len(product) < 4:
        word_boundary = r'\b' + re.escape(product) + r'\b'
        return bool(re.search(word_boundary, first_part))

    # Default: simple substring match
    return product in first_part


def _is_false_positive(product: str, summary: str) -> bool:
    # Short product names that appear inside longer words
    short_name_false_positives = {
        "ed": ["privileged", "vault", "needed", "embedded"],
        "acl": [],
        "dash": ["dashmachine", "alliance"],
    }

    for short_name, compounds in short_name_false_positives.items():
        if product != short_name:
            continue
        for compound in compounds:
            if compound in summary:
                return True

    # Windows-specific components (WinNT MPM, etc.)
    if "winnt" in summary:
        return True

    # CVEs about other runtimes (PHP, Python, etc.)
    other_runtimes = ["php", "python", "perl"]
    for runtime in other_runtimes:
        if runtime in summary and runtime not in product:
            version_pattern = runtime + r"\s+(before|through|up to)\s+\d+\.\d+"
            if re.search(version_pattern, summary):
                return True

    return False


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
        "libssh": "libssh",
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
        "couchdb": "Apache CouchDB",
        "apache couchdb": "Apache CouchDB",
        "elasticsearch": "Elasticsearch",
        "docker": "Docker",
        "kubernetes": "Kubernetes",
        "k8s": "Kubernetes",
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
        "jetty": "Eclipse Jetty",
        "eclipse jetty": "Eclipse Jetty",
        "jboss": "JBoss",
        "wildfly": "WildFly",
        "rabbitmq": "RabbitMQ",
        "apache zookeeper": "Apache ZooKeeper",
        "zookeeper": "Apache ZooKeeper",
        "apache kafka": "Apache Kafka",
        "kafka": "Apache Kafka",
        "grafana": "Grafana",
        "prometheus": "Prometheus",
        "postfix": "Postfix",
        "dovecot": "Dovecot",
        "exim": "Exim",
        "sendmail": "Sendmail",
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
        "gunicorn": "Gunicorn",
        "ats": "Apache Traffic Server",
        "apache traffic server": "Apache Traffic Server",
        "caddy": "Caddy",
        "lighttpd": "Lighttpd",
        "traefik": "Traefik",
        "squid": "Squid Proxy",
        "vault": "HashiCorp Vault",
        "hashicorp vault": "HashiCorp Vault",
        "consul": "Consul",
        "terraform": "Terraform",
        "ansible": "Ansible",
        "jenkins": "Jenkins",
        "gitlab": "GitLab",
        "github": "GitHub",
        "jira": "Jira",
        "confluence": "Confluence",
        "nexus": "Sonatype Nexus",
        "sonarqube": "SonarQube",
        "sentry": "Sentry",
        "samba": "Samba",
        "smb": "Samba",
        "cifs": "Samba",
        "nfs": "NFS",
        "iscsi": "iSCSI",
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

    tmp_dir = os.environ.get("NETSPY_TMP", os.path.expanduser("~/.netspy/tmp"))
    os.makedirs(tmp_dir, exist_ok=True)
    output_file = os.path.join(tmp_dir, f"nuclei_{int(time.time())}.jsonl")

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
