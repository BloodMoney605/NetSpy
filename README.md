# NetSPy

Network surveillance pipeline for reconnaissance and vulnerability assessment. Feed it a domain and get structured data about subdomains, open ports, technologies, and CVEs.

## Pipeline

```
Recon  ->  Port Scan  ->  Fingerprint  ->  CVE Matching  ->  HTML Report
(1)        (2)           (3)             (4 + nuclei)       (5)
```

- Phase 1: Subdomain enumeration (crt.sh + wordlist fallback), DNS resolution, WHOIS, ASN
- Phase 2: Port scan with nmap, service version detection
- Phase 3: HTTP probing (httpx), technology detection (whatweb), version extraction
- Phase 4: CVE matching via NVD API, nuclei template scanning, SSL audit
- Phase 5: Consolidated HTML report with severity cards

## Quick start

```bash
# Install dependencies
bash install.sh

# Audit a domain
netspy audit --domain example.com

# Individual phases
netspy recon --domain example.com
netspy scan --target 192.168.1.0/24
netspy report --dir output/example.com

# Override thread count
netspy recon --domain example.com --threads 50
```

## Requirements

- Python 3.10+
- nmap, whois, whatweb, jq, curl, openssl
- httpx (projectdiscovery), nuclei (optional)

## Configuration

Edit `config/default.yaml` to adjust:

- `scan.ports.top` — number of ports to scan (default: 200)
- `target.threads` — concurrency (default: 20)
- `vuln.enable_nuclei` — enable nuclei scanning (default: false, consumes significant memory)
- `scan.use_custom_scanner` — use TCP connect scanner instead of nmap (default: false)

## Output

```
output/<domain>/
├── recon.json           # Phase 1: subdomains, IPs, DNS, WHOIS, ASN
├── ips.txt              # Target IP list
├── subdomains.txt       # Resolved subdomains
├── ports.json           # Phase 2: open ports, services, versions
├── urls.txt             # Web URLs for scanning
├── tech.json            # Phase 3: technologies, versions, headers
├── findings.json        # Phase 4: CVEs, nuclei results, misconfigs
└── report.html          # Phase 5: consolidated HTML report
```

## CVE matching

Each detected product:version is queried against the NVD API. Results include CVE ID, severity (CRITICAL/HIGH/MEDIUM/LOW), CVSS score, and description. Results are cached locally in `~/.netspy/cve.db` to avoid re-querying.

## License

MIT
