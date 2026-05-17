# NetSPy

Network surveillance pipeline for reconnaissance and vulnerability assessment. Feed it a domain and get structured data about subdomains, open ports, technologies, and CVEs.

## Pipeline

```
Recon  ->  Port Scan  ->  Fingerprint  ->  CVE Matching  ->  JSON output
(1)        (2)           (3)             (4 + nuclei)
```

- Phase 1: Subdomain enumeration (crt.sh), DNS resolution, WHOIS, ASN
- Phase 2: Port scan with nmap, service version detection
- Phase 3: HTTP probing (httpx), technology detection (whatweb), version extraction
- Phase 4: CVE matching via NVD API, nuclei template scanning, SSL audit

## Quick start

```bash
# Install dependencies
bash install.sh

# Audit a domain
./netspy audit --domain ejemplo.com

# Individual phases
./netspy recon --domain ejemplo.com
./netspy scan --target 192.168.1.0/24

# Regenerate report from existing data
./netspy report --dir output/ejemplo.com
```

## Requirements

- Python 3.10+
- nmap, whois, whatweb, jq, curl, openssl
- httpx (projectdiscovery), nuclei

## Output

```
output/<domain>/
├── recon.json           # Phase 1: subdomains, IPs, DNS, WHOIS
├── ips.txt              # Target IP list
├── ports.json           # Phase 2: open ports, services, versions
├── urls.txt             # Web URLs for scanning
├── tech.json            # Phase 3: technologies, versions, headers
├── findings.json        # Phase 4: CVEs, nuclei results, misconfigs
└── report.html          # Phase 5: consolidated HTML report
```

## CVE matching

Each detected product:version is queried against the NVD API. Results include CVE ID, severity (CRITICAL/HIGH/MEDIUM/LOW), CVSS score, and description. Results are cached locally in `~/.netspy/cve.db`.
