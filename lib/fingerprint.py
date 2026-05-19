#!/usr/bin/env python3

import argparse
import json
import os
import re
import subprocess
import sys
import time
from typing import Any

from common import load_config, apply_thread_override, t

BOLD = "\033[1m"
CYAN = "\033[0;36m"
GREEN = "\033[0;32m"
YELLOW = "\033[0;33m"
DIM = "\033[2m"
NC = "\033[0m"


def _normalize_product(name: str) -> str:
    name = name.strip()
    name = re.sub(r"[^a-zA-Z0-9\s._-]+$", "", name).strip()
    name = re.sub(r"\s+", " ", name)
    return name


def run_httpx(urls: list[str], threads: int = 20) -> list[dict[str, Any]]:
    if not urls:
        return []

    input_file = f"/tmp/netspy_httpx_input_{int(time.time())}.txt"
    output_file = f"/tmp/netspy_httpx_out_{int(time.time())}.json"

    with open(input_file, "w") as url_file:
        for url in urls:
            url_file.write(url + "\n")

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

    total = len(urls)
    bar_len = 30

    proc = None
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        checked = 0
        deadline = time.time() + 180
        last_check = 0

        while time.time() < deadline:
            line = proc.stdout.readline()
            if not line:
                if proc.poll() is not None:
                    break
                elapsed = time.time() - last_check if last_check > 0 else 0
                if elapsed > 5:
                    last_check = time.time()
                    pct = int((checked / total) * 100) if total > 0 else 0
                    filled = int(bar_len * pct // 100)
                    bar = "#" * filled + "-" * (bar_len - filled)
                    print(f"\r  [{bar}] {pct}% ({checked}/{total})", end="", flush=True)
                time.sleep(0.2)
                continue
            checked += 1
            last_check = time.time()
            pct = int((checked / total) * 100) if total > 0 else 0
            filled = int(bar_len * checked // total) if total > 0 else 0
            bar = "#" * filled + "-" * (bar_len - filled)
            print(f"\r  [{bar}] {pct}% ({checked}/{total})", end="", flush=True)
        if proc.poll() is None:
            proc.kill()
            proc.wait()
            print(f"\n  [!] httpx timeout (180s), {checked}/{total} completed")
    except FileNotFoundError:
        print(f"  {t('httpx_not_found')}")
        return []
    except Exception:
        if proc and proc.poll() is None:
            proc.kill()
            proc.wait()
        return []
    finally:
        print()

    results = []
    if os.path.exists(output_file):
        with open(output_file) as json_file:
            for line in json_file:
                line = line.strip()
                if line:
                    try:
                        results.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass

    for tmp_file in [input_file, output_file]:
        try:
            os.remove(tmp_file)
        except Exception:
            pass

    return results


def run_whatweb(urls: list[str]) -> list[dict[str, Any]]:
    if not urls:
        return []

    results = []
    scan_urls = urls[:20]
    total = len(scan_urls)
    bar_len = 30

    for idx, url in enumerate(scan_urls, 1):
        pct = int((idx / total) * 100) if total > 0 else 0
        filled = int(bar_len * idx // total) if total > 0 else 0
        bar = "#" * filled + "-" * (bar_len - filled)
        print(f"\r  [{bar}] {pct}% ({idx}/{total})", end="", flush=True)

        cmd = ["whatweb", "-a", "1", "--no-errors", "--color=never", "--connect-timeout", "10", url]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.stdout.strip():
                results.append({"url": url, "raw": result.stdout.strip()})
        except Exception:
            pass

    print()
    return results


def extract_versions(httpx_results: list[dict[str, Any]]) -> list[dict[str, str]]:
    versions: list[dict[str, str]] = []
    version_re = re.compile(r"\d+\.\d+(\.\d+)*")

    for httpx_entry in httpx_results:
        server = httpx_entry.get("webserver", "")
        if server:
            parts = server.split("/", 1)
            if len(parts) == 2:
                product = _normalize_product(parts[0])
                ver_part = parts[1].split()[0].strip()
                if version_re.match(ver_part):
                    versions.append({
                        "source": httpx_entry.get("url", ""),
                        "product": product,
                        "version": ver_part,
                        "from": "server-header",
                    })
            elif version_re.match(server):
                versions.append({
                    "source": httpx_entry.get("url", ""),
                    "product": "unknown",
                    "version": server,
                    "from": "server-header",
                })

        tech = httpx_entry.get("tech", [])
        if isinstance(tech, list):
            for tech_item in tech:
                if ":" in tech_item:
                    product, ver = tech_item.split(":", 1)
                    ver = ver.strip()
                    if version_re.match(ver):
                        versions.append({
                            "source": httpx_entry.get("url", ""),
                            "product": _normalize_product(product),
                            "version": ver,
                            "from": "tech-detect",
                        })

        headers = httpx_entry.get("header", {}) or httpx_entry.get("response_header", {})
        if isinstance(headers, dict):
            for hdr, val in headers.items():
                val_str = str(val)
                hdr_lower = hdr.lower()
                if hdr_lower not in ("x-powered-by", "x-aspnet-version", "x-generator",
                                      "x-runtime", "x-version", "server", "x-drupal-cache",
                                      "x-wordpress-cache", "x-joomla-version"):
                    continue
                if "/" in val_str:
                    parts = val_str.split("/", 1)
                    product = _normalize_product(parts[0])
                    ver = parts[1].strip().split()[0]
                    if version_re.match(ver) and len(product) < 30 and len(ver) < 20:
                        versions.append({
                            "source": httpx_entry.get("url", ""),
                            "product": product,
                            "version": ver,
                            "from": f"header-{hdr_lower}",
                        })
                elif version_re.search(val_str):
                    match = version_re.search(val_str)
                    ver = match.group(0)
                    product = _normalize_product(val_str[:match.start()].rstrip(" /"))
                    if product and len(product) < 30 and len(ver) < 20:
                        versions.append({
                            "source": httpx_entry.get("url", ""),
                            "product": product,
                            "version": ver,
                            "from": f"header-{hdr_lower}",
                        })

    return versions


def extract_versions_from_whatweb(ww_results: list[dict[str, Any]]) -> list[dict[str, str]]:
    versions: list[dict[str, str]] = []
    ww_re = re.compile(r"([A-Za-z][A-Za-z0-9 _./-]*?)\[(\d+\.\d+(\.\d+)*)\]")
    skip_products = {"ip", "html5", "html", "xhtml", "css", "javascript", "httpserver"}

    for ww_entry in ww_results:
        raw = ww_entry.get("raw", "")
        url = ww_entry.get("url", "")
        for match in ww_re.finditer(raw):
            product = _normalize_product(match.group(1))
            version = match.group(2).strip()
            if product.lower() in skip_products:
                continue
            if product and len(product) < 40:
                versions.append({
                    "source": url,
                    "product": product,
                    "version": version,
                    "from": "whatweb",
                })

    return versions


def run_fingerprint(input_dir: str, config: dict, output: str) -> dict[str, Any]:
    urls_path = os.path.join(input_dir, "urls.txt")
    ports_path = os.path.join(input_dir, "ports.json")
    recon_path = os.path.join(input_dir, "recon.json")

    urls: list[str] = []

    if os.path.exists(urls_path):
        with open(urls_path) as url_file:
            urls = [line.strip() for line in url_file if line.strip()]

    if os.path.exists(ports_path):
        with open(ports_path) as ports_file:
            try:
                ports_data = json.load(ports_file)
                for svc in ports_data.get("services", []):
                    if svc.get("service") in ("http", "https", "ssl|http"):
                        proto = "https" if svc["port"] in (443, 8443) else "http"
                        url = f"{proto}://{svc['ip']}:{svc['port']}/"
                        if url not in urls:
                            urls.append(url)
            except Exception:
                pass

    if os.path.exists(recon_path):
        with open(recon_path) as recon_file:
            try:
                recon_data = json.load(recon_file)
                for sub in recon_data.get("resolved", {}):
                    urls.append(f"http://{sub}/")
                    urls.append(f"https://{sub}/")
            except Exception:
                pass

    seen: set[str] = set()
    unique_urls: list[str] = []
    for url in urls:
        if url not in seen:
            seen.add(url)
            unique_urls.append(url)
    urls = unique_urls

    if not urls:
        print(f"  {t('no_urls_fingerprint')}")
        return {"error": "no urls", "technologies": [], "versions": []}

    print(f"  {t('urls_to_probe')}: {len(urls)}")
    print()

    threads = config.get("target", {}).get("threads", 20)
    print(f"  {t('httpx_probing')}...", end=" ", flush=True)
    httpx_results = run_httpx(urls, threads)
    print(f"{len(httpx_results)} {t('alive')}")

    ww_limit = config.get("fingerprint", {}).get("whatweb_limit", 10)
    ww_actual = min(len(urls), ww_limit)
    print(f"  {t('whatweb_deep_scan')} ({ww_actual}/{len(urls)})...", end=" ", flush=True)
    whatweb_results = run_whatweb(urls[:ww_actual])
    print(f"{len(whatweb_results)} {t('scanned')}")

    versions = extract_versions(httpx_results)
    versions += extract_versions_from_whatweb(whatweb_results)

    technologies: list[dict[str, Any]] = []
    seen_tech: set[str] = set()

    for httpx_entry in httpx_results:
        tech_list = httpx_entry.get("tech", [])
        if isinstance(tech_list, list):
            for tech_entry in tech_list:
                tech_name = tech_entry.split(":")[0] if ":" in tech_entry else tech_entry
                if tech_name not in seen_tech:
                    seen_tech.add(tech_name)
                    technologies.append({
                        "name": tech_name,
                        "version": tech_entry.split(":")[1] if ":" in tech_entry else "",
                        "source": httpx_entry.get("url", ""),
                    })
                else:
                    for existing in technologies:
                        if existing["name"] == tech_name and not existing["version"]:
                            existing["version"] = tech_entry.split(":")[1] if ":" in tech_entry else ""

    alive = []
    for httpx_entry in httpx_results:
        alive.append({
            "url": httpx_entry.get("url", ""),
            "status": httpx_entry.get("status_code", 0),
            "title": httpx_entry.get("title", ""),
            "server": httpx_entry.get("webserver", ""),
            "content_length": httpx_entry.get("content_length", 0),
            "content_type": httpx_entry.get("content_type", ""),
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

    tech_path = os.path.join(output, "tech.json")
    with open(tech_path, "w") as tech_file:
        json.dump(result, tech_file, indent=2, default=str)

    print()
    if technologies:
        print(f"\n  {BOLD}{t('tech_found')}{NC}")
        print(f"  {BOLD}{'─' * 40}{NC}")
        seen_names: set[str] = set()
        for tech_entry in technologies:
            key = f"{tech_entry['name']}|{tech_entry['version']}"
            if key in seen_names:
                continue
            seen_names.add(key)
            ver_str = f" {tech_entry['version']}" if tech_entry['version'] else ""
            print(f"  {YELLOW}{tech_entry['name']}{NC}{ver_str} {DIM}({tech_entry['source']}){NC}")
    if versions:
        print(f"\n  {BOLD}{t('version_strings')} ({len(versions)}){NC}")
        print(f"  {BOLD}{'─' * 40}{NC}")
        seen_versions: set[str] = set()
        for version_entry in versions:
            key = f"{version_entry['product']}|{version_entry['version']}"
            if key in seen_versions:
                continue
            seen_versions.add(key)
            print(f"  {GREEN}{version_entry['product']}{NC} {version_entry['version']} {DIM}(from {version_entry['source']}){NC}")

    print(f"\n  {t('output')}: {tech_path}")
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

    try:
        run_fingerprint(args.input, config, args.output)
    except KeyboardInterrupt:
        print("\n  [!] interrupted")
        sys.exit(130)


if __name__ == "__main__":
    main()
