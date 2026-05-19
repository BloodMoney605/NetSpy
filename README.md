# NetSpy

Pipeline de vigilancia de red para reconocimiento y evaluación de vulnerabilidades. Alimentalo con un dominio y obtené datos estructurados sobre subdominios, puertos abiertos, tecnologías y CVEs.

## Pipeline

```
Recon  ->  Escaneo de Puertos  ->  Fingerprint  ->  CVE Matching  ->  Reporte TXT
(1)           (2)                  (3)             (4 + nuclei)       (5)
```

- **Fase 1:** Enumeración de subdominios (crt.sh + wordlist), resolución DNS, WHOIS, ASN
- **Fase 2:** Escaneo de puertos con nmap, detección de versiones de servicios
- **Fase 3:** Sondeo HTTP (httpx), detección de tecnologías (whatweb), extracción de versiones
- **Fase 4:** Búsqueda de CVEs vía API NVD, escaneo con nuclei, auditoría SSL
- **Fase 5:** Reporte TXT consolidado con desglose por severidad

## Inicio rápido

```bash
# Instalar dependencias
bash install.sh

# Auditar un dominio
netspy audit --domain ejemplo.com

# Fases individuales
netspy recon --domain ejemplo.com
netspy portscan --target 192.168.1.0/24
netspy report --dir output/ejemplo.com

# Sobreescribir cantidad de hilos
netspy recon --domain ejemplo.com --threads 50
```

## Requisitos

- Python 3.10+
- nmap, whois, whatweb, openssl
- httpx (projectdiscovery), nuclei (opcional)

## Configuración

Editá `config/default.yaml` para ajustar:

- `scan.ports.top` — cantidad de puertos a escanear (default: 200)
- `target.threads` — concurrencia (default: 20)
- `vuln.enable_nuclei` — habilitar escaneo nuclei (default: false, consume mucha memoria)
- `scan.use_custom_scanner` — usar escáner TCP connect en vez de nmap (default: false)

## Salida

```
output/<dominio>/
├── recon.json           # Fase 1: subdominios, IPs, DNS, WHOIS, ASN
├── ips.txt              # Lista de IPs objetivo
├── subdomains.txt       # Subdominios resueltos
├── ports.json           # Fase 2: puertos abiertos, servicios, versiones
├── urls.txt             # URLs web para escaneo
├── tech.json            # Fase 3: tecnologías, versiones, headers
├── findings.json        # Fase 4: CVEs, resultados nuclei, misconfigs
└── report.txt           # Fase 5: reporte de texto consolidado
```

## Búsqueda de CVEs

Cada producto:versión detectado se consulta contra la API de NVD. Los resultados incluyen ID de CVE, severidad (CRITICAL/HIGH/MEDIUM/LOW), puntaje CVSS y descripción. Los resultados se cachean localmente en `~/.netspy/cve.db` para evitar reconsultas.

## Sigilo

NetSpy incluye un menú de sigilo configurable con 4 niveles:

1. **MAC spoof** — cambia la MAC durante el escaneo y la restaura al salir
2. **Delays moderados** — retrasos entre requests
3. **MAC spoof + delays** — combinación de ambos
4. **Sin sigilo** — modo normal (default)

## Licencia

Ver [LICENSE](LICENSE) — Uso Educativo y Ético

## Créditos

Ver [SALUDOS](SALUDOS)
