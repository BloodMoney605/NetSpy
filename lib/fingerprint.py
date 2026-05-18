#!/usr/bin/env python3
"""
Phase 3: Technology Fingerprinting
- HTTP probing with httpx
- Technology detection with whatweb
- WAF detection
- Version extraction from headers, body, certs
- Output: JSON with detected technologies and versions
"""

import argparse
import json
import os
import subprocess
import sys
import time
from typing import Any

from common import load_config, apply_thread_override


def run_httpx(urls: list[str], threads: int = 20) -> list[dict[str, Any]]:
    """
    Use httpx to probe URLs and extract:
    - status code, title, web server, content-type
    - content-length, technologies, response headers
    """
    if not urls:
        return []

    input_file = f"/tmp/netspy_httpx_input_{int(time.time())}.txt"
    output_file = f"/tmp/netspy_httpx_out_{int(time.time())}.json"

    with open(input_file, "w") as f:
        for url in urls:
            f.write(url + "\n")

    cmd = [
        "httpx",
        "-list", input_file,
        "-json",
        "-silent",
        "-threads", str(threads),
        "-timeout", "10",
        "-status-code",
        "-title",
        "-web-server",
        "-ct", "-cl",
        "-tech-detect",
        "-irh",
        "-o", output_file,
    ]

    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except FileNotFoundError:
        print("  [!] httpx not found. install: go install github.com/projectdiscovery/httpx/cmd/httpx@latest")
        return []
    except Exception:
        return []

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

    for tmp in [input_file, output_file]:
        try:
            os.remove(tmp)
        except Exception:
            pass

    return results


def run_whatweb(urls: list[str]) -> list[dict[str, Any]]:
    """
    Use whatweb for deep technology fingerprinting.
    Detects CMSes, JS frameworks, analytics, etc.
    """
    if not urls:
        return []

    results = []
    for url in urls[:20]:  # limit to 20 to avoid huge runtime
        cmd = ["whatweb", "-a", "3", "--no-errors", "--color=never", url]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.stdout.strip():
                results.append({"url": url, "raw": result.stdout.strip()})
        except Exception:
            pass

    return results


def extract_versions(results: list[dict[str, Any]]) -> list[dict[str, str]]:
    """
    Extract product + version pairs from httpx results.
    Aggregates from server header, tech-detect, and response headers.
    """
    versions: list[dict[str, str]] = []

    for r in results:
        # From web_server field
        server = r.get("webserver", "")
        if server:
            # "Apache/2.4.49 (Ubuntu)" -> ("Apache", "2.4.49")
            parts = server.split("/", 1)
            if len(parts) == 2:
                product = parts[0].strip()
                ver_part = parts[1].split()[0].strip()
                versions.append({
                    "source": r.get("url", ""),
                    "product": product,
                    "version": ver_part,
                    "from": "server-header",
                })

        # From tech-detect (httpx --tech-detect)
        tech = r.get("tech", [])
        if isinstance(tech, list):
            for t in tech:
                if ":" in t:
                    product, ver = t.split(":", 1)
                    versions.append({
                        "source": r.get("url", ""),
                        "product": product.strip(),
                        "version": ver.strip(),
                        "from": "tech-detect",
                    })

        # From response headers (httpx uses "header" field)
        headers = r.get("header", {}) or r.get("response_header", {})
        if isinstance(headers, dict):
            for hdr, val in headers.items():
                val_str = str(val)
                # X-Powered-By: PHP/7.4.33
                # X-AspNet-Version: 4.0.30319
                # x-generator: Drupal 9 (https://www.drupal.org)
                if "/" in val_str and any(c.isdigit() for c in val_str.split("/")[1][:10]):
                    product = val_str.split("/")[0].strip()
                    ver = val_str.split("/")[1].strip().split()[0]
                    if len(product) < 30 and len(ver) < 20:
                        versions.append({
                            "source": r.get("url", ""),
                            "product": product,
                            "version": ver,
                            "from": f"header-{hdr.lower()}",
                        })

    return versions


def run_fingerprint(input_dir: str, config: dict, output: str) -> dict[str, Any]:
    """Execute fingerprinting phase."""
    urls_path = os.path.join(input_dir, "urls.txt")
    ports_path = os.path.join(input_dir, "ports.json")
    recon_path = os.path.join(input_dir, "recon.json")

    # Collect URLs to probe
    urls: list[str] = []

    # From ports.json (open ports with http/https)
    if os.path.exists(urls_path):
        with open(urls_path) as f:
            urls = [line.strip() for line in f if line.strip()]

    if os.path.exists(ports_path):
        with open(ports_path) as f:
            try:
                ports_data = json.load(f)
                for svc in ports_data.get("services", []):
                    if svc.get("service") in ("http", "https", "ssl|http"):
                        proto = "https" if svc["port"] in (443, 8443) else "http"
                        url = f"{proto}://{svc['ip']}:{svc['port']}/"
                        if url not in urls:
                            urls.append(url)
            except Exception:
                pass

    # From recon.json (all resolved subdomains)
    if os.path.exists(recon_path):
        with open(recon_path) as f:
            try:
                recon_data = json.load(f)
                domain = recon_data.get("domain", "")
                for sub in recon_data.get("resolved", {}):
                    urls.append(f"http://{sub}/")
                    urls.append(f"https://{sub}/")
            except Exception:
                pass

    # Deduplicate
    seen: set[str] = set()
    unique_urls: list[str] = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            unique_urls.append(u)
    urls = unique_urls

    if not urls:
        print("  [!] no URLs to fingerprint")
        return {"error": "no urls", "technologies": [], "versions": []}

    print(f"  URLs to probe:     {len(urls)}")
    print()

    # httpx probe
    threads = config.get("target", {}).get("threads", 20)
    print("  httpx probing...", end=" ", flush=True)
    httpx_results = run_httpx(urls, threads)
    print(f"{len(httpx_results)} alive")

    # whatweb (limit to 10 to avoid OOM)
    ww_limit = config.get("fingerprint", {}).get("whatweb_limit", 10)
    ww_actual = min(len(urls), ww_limit)
    print(f"  whatweb deep scan ({ww_actual}/{len(urls)})...", end=" ", flush=True)
    whatweb_results = run_whatweb(urls[:ww_actual])
    print(f"{len(whatweb_results)} scanned")

    # Extract versions
    versions = extract_versions(httpx_results)

    # Build technology list
    technologies: list[dict[str, Any]] = []
    seen_tech: set[str] = set()

    for r in httpx_results:
        tech_list = r.get("tech", [])
        if isinstance(tech_list, list):
            for t in tech_list:
                t_name = t.split(":")[0] if ":" in t else t
                if t_name not in seen_tech:
                    seen_tech.add(t_name)
                    technologies.append({
                        "name": t_name,
                        "version": t.split(":")[1] if ":" in t else "",
                        "source": r.get("url", ""),
                    })
                else:
                    # Update existing with version if missing
                    for existing in technologies:
                        if existing["name"] == t_name and not existing["version"]:
                            existing["version"] = t.split(":")[1] if ":" in t else ""

    # Summarize alive hosts
    alive = []
    for r in httpx_results:
        alive.append({
            "url": r.get("url", ""),
            "status": r.get("status_code", 0),
            "title": r.get("title", ""),
            "server": r.get("webserver", ""),
            "content_length": r.get("content_length", 0),
            "content_type": r.get("content_type", ""),
        })

    result: dict[str, Any] = {
        "alive_hosts": alive,
        "alive_count": len(alive),
        "technologies": technologies,
        "tech_count": len(technologies),
        "versions": versions,
        "version_count": len(versions),
        "whatweb": whatweb_results,
    }

    # Save
    tech_path = os.path.join(output, "tech.json")
    with open(tech_path, "w") as f:
        json.dump(result, f, indent=2, default=str)

    # Print summary
    print()
    if technologies:
        print(f"  technologies found:")
        for t in technologies:
            ver_str = f" {t['version']}" if t['version'] else ""
            print(f"    - {t['name']}{ver_str}")
    if versions:
        print(f"\n  version strings extracted ({len(versions)}):")
        for v in versions:
            print(f"    {v['product']} {v['version']}  (from {v['source']})")

    print(f"\n  output: {tech_path}")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Phase 3: Fingerprinting")
    parser.add_argument("--input", required=True, help="input directory (from scan phase)")
    parser.add_argument("--config", default="config/default.yaml")
    parser.add_argument("--output", required=True)
    parser.add_argument("--threads", type=int, default=None)
    args = parser.parse_args()

    config = load_config(args.config)
    config = apply_thread_override(config, args.threads)
    os.makedirs(args.output, exist_ok=True)

    run_fingerprint(args.input, config, args.output)


if __name__ == "__main__":
    main()
