#!/usr/bin/env python3
"""
Phase 2: Port and Service Scanning
- Custom TCP connect scanner (fast, no root needed)
- Nmap service version detection on found ports only
- Output: JSON with ports, services, versions
"""

import argparse
import json
import os
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from common import load_config, apply_thread_override

BOLD = "\033[1m"
CYAN = "\033[0;36m"
GREEN = "\033[0;32m"
NC = "\033[0m"


def load_targets(targets_path: str) -> list[str]:
    """Load target IPs from file. Resolves domains if needed."""
    if not os.path.exists(targets_path):
        print(f"  [!] target file not found: {targets_path}")
        return []

    with open(targets_path) as f:
        targets = [line.strip() for line in f if line.strip()]

    resolved = []
    for target in targets:
        if any(c.isalpha() for c in target):
            try:
                ip = socket.gethostbyname(target)
                resolved.append(ip)
            except Exception:
                resolved.append(target)
        else:
            resolved.append(target)

    return resolved


TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 161, 162, 389,
    443, 445, 465, 500, 512, 513, 514, 523, 548, 554, 587, 593, 636, 646,
    873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1434,
    1521, 1604, 1720, 1723, 1883, 1900, 2049, 2082, 2083, 2086, 2087,
    2095, 2096, 2181, 2222, 2375, 2376, 2443, 2483, 2484, 2525, 3000,
    3128, 3306, 3389, 3690, 3868, 4000, 4001, 4040, 4041, 4333, 4443,
    4444, 4500, 4567, 4646, 4711, 4712, 4848, 4899, 5000, 5001, 5003,
    5004, 5005, 5006, 5007, 5008, 5009, 5050, 5060, 5061, 5140, 5222,
    5353, 5432, 5443, 5445, 5555, 5556, 5631, 5632, 5666, 5672, 5673,
    5800, 5801, 5802, 5900, 5901, 5902, 5903, 5984, 5985, 5986, 6000,
    6001, 6002, 6003, 6379, 6443, 6580, 6665, 6666, 6667, 6668, 6669,
    6697, 7001, 7002, 7070, 7071, 7077, 7777, 7778, 8000, 8001, 8002,
    8008, 8009, 8010, 8020, 8030, 8040, 8050, 8060, 8070, 8080, 8081,
    8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8091, 8092,
    8093, 8094, 8095, 8096, 8097, 8098, 8099, 8100, 8111, 8112, 8123,
    8161, 8172, 8200, 8222, 8243, 8280, 8300, 8332, 8333, 8400, 8403,
    8443, 8500, 8530, 8531, 8600, 8649, 8800, 8834, 8880, 8888, 8889,
    8899, 8900, 8983, 9000, 9001, 9002, 9003, 9004, 9005, 9006, 9007,
    9008, 9009, 9010, 9042, 9043, 9050, 9060, 9080, 9090, 9091, 9092,
    9100, 9150, 9200, 9290, 9300, 9418, 9443, 9595, 9600, 9900, 9999,
    10000, 10001, 10050, 10051, 10080, 10082, 11000, 11211, 11371,
    12000, 12345, 12346, 12443, 14000, 16080, 16110, 16992, 16993,
    17017, 18080, 18081, 18090, 18101, 18200, 18201, 19000, 20000,
    20001, 20720, 21000, 21306, 22222, 23000, 23101, 24000, 24444,
    25000, 25565, 26000, 26208, 27000, 27017, 27374, 27017, 28017,
    28080, 30000, 30704, 31138, 31337, 31339, 32764, 32768, 32769,
    32770, 32771, 32772, 32773, 32774, 32775, 32776, 32777, 32778,
    32779, 32780, 32781, 32782, 32783, 32784, 32785, 33354, 33890,
    34571, 34572, 34573, 35500, 38292, 40193, 40911, 41511, 44176,
    44334, 44442, 44443, 44501, 45100, 48080, 49152, 49153, 49154,
    49155, 49156, 49157, 49158, 49159, 49160, 49161, 49163, 49165,
    49167, 49175, 49176, 49400, 50000, 50001, 50002, 50003, 50006,
    50300, 50389, 50500, 50636, 50800, 51103, 51493, 52673, 52822,
    52848, 52869, 54045, 54328, 55055, 55056, 55553, 55554, 55555,
    55600, 56737, 56738, 57294, 57797, 58080, 60000, 60001, 60020,
    60443, 61532, 61900, 62078, 63331, 64623, 64680, 65000, 65129,
    65389, 65535,
]


def tcp_scan_port(ip: str, port: int, timeout: float = 2.0) -> int | None:
    """Try TCP connect to a port. Returns port if open, None if closed."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return port if result == 0 else None
    except Exception:
        return None


def custom_port_scan(
    ips: list[str],
    ports: list[int] | None = None,
    threads: int = 50,
    timeout: float = 1.0,
) -> dict[str, list[int]]:
    """
    Custom TCP connect port scanner.
    Scans IP-by-IP so a slow/dead host doesn't block others.
    Each IP's ports are scanned concurrently with thread pool.
    Returns dict of ip -> [open ports].
    """
    if ports is None:
        ports = TOP_PORTS

    results: dict[str, list[int]] = {ip: [] for ip in ips}
    total_checks = len(ips) * len(ports)
    global_checked = 0

    print(f"  scanning {len(ips)} IPs x {len(ports)} ports ({total_checks} checks)...")

    for idx, ip in enumerate(ips, 1):
        ip_ports: list[int] = []
        ip_checks = len(ports)

        def check_port(port: int) -> int | None:
            return tcp_scan_port(ip, port, timeout)

        with ThreadPoolExecutor(max_workers=min(threads, ip_checks)) as pool:
            futures = {pool.submit(check_port, p): p for p in ports}
            for future in as_completed(futures):
                global_checked += 1
                if global_checked % 500 == 0:
                    print(f"    {global_checked}/{total_checks} checks", end="\r", flush=True)
                if future.result() is not None:
                    ip_ports.append(futures[future])

        if ip_ports:
            results[ip] = sorted(ip_ports)
            print(f"    [{idx}/{len(ips)}] {ip}: {len(ip_ports)} open ports")
        else:
            print(f"    [{idx}/{len(ips)}] {ip}: no open ports")

    print(f"    {global_checked}/{total_checks} checks done")
    return results


def run_nmap_version_scan(
    ip_ports: dict[str, list[int]],
    timeout: int = 300,
) -> dict[str, Any]:
    """
    Run nmap only on the specific (ip, port) pairs found open.
    Uses -sV for version detection, connects only to the ports we found.
    """
    # Build nmap target expressions like: 1.2.3.4 -p 80,443,8080
    nmap_targets = []
    for ip, ports in ip_ports.items():
        if ports:
            port_list = ",".join(str(p) for p in ports)
            nmap_targets.append(f"{ip} -p {port_list}")

    if not nmap_targets:
        return {"hosts": [], "total_open_ports": 0, "services": []}

    output_file = f"/tmp/netspy_nmap_{int(time.time())}.xml"

    # nmap needs targets as separate arguments, not combined strings
    nmap_cmd = [
        "nmap",
        "-sT",
        "-sV",
        "-T4",
        "--max-retries", "2",
        "-oX", output_file,
    ]

    # Add each target separately
    for ip, ports in ip_ports.items():
        if ports:
            port_list = ",".join(str(p) for p in sorted(ports))
            nmap_cmd.append(ip)
            nmap_cmd.append("-p")
            nmap_cmd.append(port_list)

    print(f"  nmap version detection on {sum(len(v) for v in ip_ports.values())} ports...")

    try:
        subprocess.run(nmap_cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        print("  [!] nmap not found. install with: sudo apt install nmap")
        print("  [!] returning port scan results without versions")
        return None
    except Exception as e:
        print(f"  [!] nmap error: {e}")
        return None

    if not os.path.exists(output_file):
        return None

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


def run_nmap_direct_scan(
    ips: list[str],
    top_n: int = 1000,
    timeout: int = 600,
) -> dict[str, Any] | None:
    """Run nmap with -sV and --top-ports against all IPs in one go."""
    output_file = f"/tmp/netspy_nmap_{int(time.time())}.xml"
    nmap_cmd = [
        "nmap", "-sT", "-sV", "-T4",
        "--top-ports", str(top_n),
        "--max-retries", "2",
        "-oX", output_file,
    ] + ips

    print(f"  nmap -sV --top-ports {top_n} on {len(ips)} IPs...")
    try:
        subprocess.run(nmap_cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        print("  [!] nmap not found")
        return None
    except Exception as e:
        print(f"  [!] nmap error: {e}")
        return None

    if not os.path.exists(output_file):
        return None

    results = parse_nmap_xml(output_file)
    os.remove(output_file)
    return results


def run_scan(targets_path: str, config: dict, output: str) -> dict[str, Any]:
    """Execute port scanning phase.

    Default: nmap -sV --top-ports on all targets (fast, accurate).
    Custom scanner: TCP connect + nmap -sV on found ports (opt-in via config).
    """
    ips = load_targets(targets_path)
    if not ips:
        print("  [!] no targets to scan")
        return {"error": "no targets"}

    top_n = config.get("scan", {}).get("ports", {}).get("top", 1000)
    use_custom = config.get("scan", {}).get("use_custom_scanner", False)

    print(f"  targets: {len(ips)} IPs")

    if use_custom:
        # Phase A: custom TCP connect (no root needed)
        print("  [custom scan] TCP connect port scan...")
        ports = TOP_PORTS[:top_n] if top_n < len(TOP_PORTS) else TOP_PORTS
        threads = config.get("target", {}).get("threads", 50)
        open_ports = custom_port_scan(ips, ports, threads=threads, timeout=1.0)
        ip_ports = {ip: pts for ip, pts in open_ports.items() if pts}
        print(f"  hosts with open ports: {len(ip_ports)}")
        print()

        # Phase B: nmap -sV only on found ports
        print("  [nmap] service version detection on found ports...")
        nmap_results = run_nmap_version_scan(ip_ports)
        scan_method = "custom+nmap"
    else:
        # Direct nmap scan with version detection
        print("  [nmap] full port and service scan...")
        nmap_results = run_nmap_direct_scan(ips, top_n)
        scan_method = "nmap-direct"

    if nmap_results is None:
        return {"error": "scan failed"}

    results = nmap_results
    results["scan_method"] = scan_method

    # Save
    scan_path = os.path.join(output, "ports.json")
    with open(scan_path, "w") as f:
        json.dump(results, f, indent=2, default=str)

    # Generate aux files
    services = results.get("services", [])
    unique_services = len(set(s["service"] for s in services if s.get("service")))
    print(f"  {BOLD}Services detected: {unique_services}{NC}")
    if services:
        print(f"  {BOLD}{'─' * 50}{NC}")
        for s in services:
            proto = s.get("service", "?")
            port = s["port"]
            ip = s["ip"]
            product = s.get("product", "")
            version = s.get("version", "")
            ver_str = f" {product} {version}" if product else ""
            print(f"  {GREEN}{ip}{NC}:{port}/{proto}{ver_str}")

    svc_path = os.path.join(output, "services.txt")
    with open(svc_path, "w") as f:
        for s in services:
            line = f"{s['ip']}:{s['port']} {s['service']}"
            if s.get("product"):
                line += f" ({s['product']} {s.get('version', '')})"
            f.write(line + "\n")

    url_path = os.path.join(output, "urls.txt")
    with open(url_path, "w") as f:
        for s in services:
            svc = s.get("service", "")
            if svc in ("http", "https", "http-proxy", "ssl|http"):
                proto = "https" if s["port"] in (443, 8443) or svc == "https" else "http"
                f.write(f"{proto}://{s['ip']}:{s['port']}/\n")

    print(f"\n  output: {scan_path}")
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Phase 2: Port Scanning")
    parser.add_argument("--targets", required=True, help="file with targets (one per line)")
    parser.add_argument("--config", default="config/default.yaml")
    parser.add_argument("--output", required=True)
    parser.add_argument("--threads", type=int, default=None)
    args = parser.parse_args()

    config = load_config(args.config)
    config = apply_thread_override(config, args.threads)
    os.makedirs(args.output, exist_ok=True)

    run_scan(args.targets, config, args.output)


if __name__ == "__main__":
    main()
