# aegis-audit

Automated vulnerability assessment pipeline for pentesters. Feed it a domain and get a complete report with CVEs, open ports, technologies, and misconfigurations.

## Pipeline

```
Recon  →  Port Scan  →  Fingerprint  →  CVE Matching  →  HTML Report
(0)        (1)           (2)             (3 + nuclei)     (4)
```

- Phase 0: Subdomain enumeration (crt.sh), DNS resolution, WHOIS, ASN
- Phase 1: Port scan with nmap, service version detection
- Phase 2: HTTP probing (httpx), technology detection (whatweb), version extraction
- Phase 3: CVE matching via NVD API, nuclei template scanning, SSL audit
- Phase 4: Consolidated HTML report with severity cards

## Quick start

```bash
# Install dependencies
bash install.sh

# Audit a domain
./aegis audit --domain ejemplo.com

# Individual phases
./aegis recon --domain ejemplo.com
./aegis scan --target 192.168.1.0/24

# Regenerate report from existing data
./aegis report --dir output/ejemplo.com
```

## Requirements

- Python 3.10+
- nmap, whois, whatweb, jq, curl, openssl
- httpx (projectdiscovery), nuclei

## Output

```
output/<domain>/
├── recon.json           # Phase 0: subdomains, IPs, DNS, WHOIS
├── ips.txt              # Target IP list
├── ports.json           # Phase 1: open ports, services, versions
├── urls.txt             # Web URLs for scanning
├── tech.json            # Phase 2: technologies, versions, headers
├── findings.json        # Phase 3: CVEs, nuclei results, misconfigs
└── report.html          # Phase 4: consolidated HTML report
```

## CVE matching

Each detected product:version is queried against the NVD API. Results include CVE ID, severity (CRITICAL/HIGH/MEDIUM/LOW), CVSS score, and description. Results are cached locally in `~/.aegis/cve.db`.

## License

MIT
