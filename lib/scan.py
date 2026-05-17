#!/usr/bin/env python3
"""
Phase 2: Port and Service Scanning
- Quick port scan using nmap (top ports)
- Service version detection
- Output: JSON with ports, services, banners
"""

import argparse
import json
import os
import subprocess
import sys
import time
from typing import Any


def load_config(config_path: str) -> dict:
    try:
        import yaml
        with open(config_path) as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


def load_targets(targets_path: str) -> list[str]:
    """Load target IPs or domains from file, one per line."""
    if not os.path.exists(targets_path):
        print(f"  [!] target file not found: {targets_path}")
        return []

    with open(targets_path) as f:
        targets = [line.strip() for line in f if line.strip()]

    # Resolve domains to IPs if needed
    resolved = []
    for target in targets:
        if any(c.isalpha() for c in target):
            import socket
            try:
                ip = socket.gethostbyname(target)
                resolved.append(ip)
            except Exception:
                resolved.append(target)
        else:
            resolved.append(target)

    return resolved


def run_nmap_scan(targets: list[str], top_ports: int = 1000, timeout: int = 600) -> dict[str, Any]:
    """
    Run nmap scan against target IPs.
    Uses -sV for service version detection, top ports for speed.
    """
    target_str = " ".join(targets)
    output_file = f"/tmp/aegis_nmap_{int(time.time())}.xml"

    nmap_cmd = [
        "nmap",
        "-sT",          # TCP connect scan (no root needed)
        "-sV",          # version detection
        "--top-ports", str(top_ports),
        "-T4",          # timing aggressive
        "--max-retries", "2",
        "--min-rate", "100",
        "-oX", output_file,
        "-oN", "/dev/null",
    ] + targets

    print(f"  running nmap (top {top_ports} ports, version detection)...")

    try:
        subprocess.run(
            nmap_cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        print(f"  [!] nmap timed out after {timeout}s")
    except FileNotFoundError:
        print("  [!] nmap not found. install with: sudo apt install nmap")
        return {"error": "nmap not installed"}
    except Exception as e:
        print(f"  [!] nmap error: {e}")
        return {"error": str(e)}

    # Parse nmap XML output
    if not os.path.exists(output_file):
        print("  [!] nmap produced no output")
        return {"error": "no output"}

    results = parse_nmap_xml(output_file)
    os.remove(output_file)

    return results


def parse_nmap_xml(xml_path: str) -> dict[str, Any]:
    """Parse nmap XML output into structured JSON."""
    import xml.etree.ElementTree as ET

    results: dict[str, Any] = {
        "hosts": [],
        "total_open_ports": 0,
        "services": [],
    }

    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except Exception as e:
        return {"error": f"xml parse: {e}"}

    for host in root.findall("host"):
        host_data: dict[str, Any] = {
            "ip": "",
            "hostname": "",
            "status": "",
            "ports": [],
        }

        addr = host.find("address")
        if addr is not None:
            host_data["ip"] = addr.get("addr", "")

        hostnames = host.find("hostnames")
        if hostnames is not None:
            hn = hostnames.find("hostname")
            if hn is not None:
                host_data["hostname"] = hn.get("name", "")

        status = host.find("status")
        if status is not None:
            host_data["status"] = status.get("state", "")

        ports_elem = host.find("ports")
        if ports_elem is None:
            continue

        for port in ports_elem.findall("port"):
            port_data: dict[str, Any] = {
                "port": int(port.get("portid", 0)),
                "protocol": port.get("protocol", ""),
                "state": "",
                "service": "",
                "product": "",
                "version": "",
                "cpe": "",
            }

            state = port.find("state")
            if state is not None:
                port_data["state"] = state.get("state", "")

            service = port.find("service")
            if service is not None:
                port_data["service"] = service.get("name", "")
                port_data["product"] = service.get("product", "")
                port_data["version"] = service.get("version", "")
                port_data["cpe"] = service.get("cpe", "")

            if port_data["state"] == "open":
                results["total_open_ports"] += 1
                results["services"].append({
                    "ip": host_data["ip"],
                    "port": port_data["port"],
                    "protocol": port_data["protocol"],
                    "service": port_data["service"],
                    "product": port_data["product"],
                    "version": port_data["version"],
                    "cpe": port_data["cpe"],
                })

            host_data["ports"].append(port_data)

        results["hosts"].append(host_data)

    return results


def run_scan(targets_path: str, config: dict, output: str) -> dict[str, Any]:
    """Execute port scanning phase."""
    targets = load_targets(targets_path)
    if not targets:
        print("  [!] no targets to scan")
        return {"error": "no targets"}

    print(f"  targets:           {len(targets)} IPs")
    print(f"  top ports:         {config.get('scan', {}).get('ports', {}).get('top', 1000)}")
    print()

    results = run_nmap_scan(
        targets,
        top_ports=config.get("scan", {}).get("ports", {}).get("top", 1000),
    )

    # Save results
    scan_path = os.path.join(output, "ports.json")
    with open(scan_path, "w") as f:
        json.dump(results, f, indent=2, default=str)

    if "error" not in results:
        services = results.get("services", [])
        print(f"  open ports:        {results.get('total_open_ports', 0)}")
        print(f"  unique services:   {len(set(s['service'] for s in services if s.get('service')))}")

        # Save service list for next phase
        svc_path = os.path.join(output, "services.txt")
        with open(svc_path, "w") as f:
            for s in services:
                line = f"{s['ip']}:{s['port']} {s['service']}"
                if s['product']:
                    line += f" ({s['product']} {s['version']})"
                f.write(line + "\n")

        # Save URLs for HTTP probing
        url_path = os.path.join(output, "urls.txt")
        with open(url_path, "w") as f:
            for s in services:
                if s['service'] in ("http", "https", "http-proxy"):
                    proto = "https" if s['port'] in (443, 8443) or s['service'] == "https" else "http"
                    f.write(f"{proto}://{s['ip']}:{s['port']}/\n")
                elif s['service'] == "ssl|http":
                    f.write(f"https://{s['ip']}:{s['port']}/\n")

    print(f"\n  output: {scan_path}")
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Phase 2: Port Scanning")
    parser.add_argument("--targets", required=True, help="file with targets (one per line)")
    parser.add_argument("--config", default="config/default.yaml")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    config = load_config(args.config)
    os.makedirs(args.output, exist_ok=True)

    run_scan(args.targets, config, args.output)


if __name__ == "__main__":
    main()
