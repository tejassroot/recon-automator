# ⚡ ReconAutomator

> Multi-stage, high-performance reconnaissance and attack surface mapping pipeline.

`ReconAutomator` automates passive and active external asset discovery, DNS resolution, HTTP probing, technology stack detection, port scanning, web endpoint crawling, and deep JavaScript secret/route extraction with built-in rate-limiting and structured reporting.

---

## 🚀 Pipeline Stages

- **Stage 1: Passive Subdomain Enumeration**
  - Queries Certificate Transparency logs (`crt.sh`)
  - Runs multi-source passive OSINT (`subfinder`) with rate limiting
  - Normalizes and deduplicates subdomains
- **Stage 2: DNS Resolution & Active Filtering**
  - Resolves alive hosts using `dnsx`
  - Extracts unique public IP addresses and CNAME mappings
- **Stage 3: HTTP Probing & Technology Fingerprinting**
  - Probes live services on common web ports (`httpx`)
  - Extracts HTTP status codes, page titles, server banners, CDN/WAF detection, and tech stacks
- **Stage 4: Port & Service Scanning (`naabu`)**
  - Fast port enumeration on discovered target hosts/IPs using `naabu` with TCP Connect (`-s c`) mode for non-root reliability and CDN avoidance (`-ec`)
- **Stage 5: Web Crawling & Endpoint Discovery (`katana`)**
  - Deep URL and JavaScript spidering using `katana` with headless and JavaScript parsing
- **Stage 6: JavaScript Analysis, API Route Extraction & Secret Mining**
  - Filters all `.js` asset files from crawls and live hosts
  - Extracts internal API routes (`/api/`, `/v1/`, `/graphql`, etc.)
  - Searches for hardcoded tokens (AWS keys, Google API keys, JWTs, Slack tokens, Stripe keys, Bearer headers)
- **Stage 7: Structured Executive Reporting**
  - Automatically compiles an executive `SUMMARY.md` report with markdown tables for all discovered live assets, open ports, and potential secrets

---

## 📋 Prerequisites

The following tools should be installed and available in your `$PATH`:

- `subfinder`
- `dnsx`
- `httpx`
- `naabu`
- `katana`
- `jq`, `curl`, `python3`

### Quick Install on Kali / Debian
```bash
sudo apt update && sudo apt install -y jq curl python3

# Install ProjectDiscovery tools (Go required)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
```

---

## 🛠️ Installation

```bash
git clone https://github.com/tejassroot/recon-automator.git
cd recon-automator
chmod +x recon.sh

# Optional: Add to system PATH
sudo ln -sf "$(pwd)/recon.sh" /usr/local/bin/recon-automator
```

---

## 📖 Usage & Options

```bash
./recon.sh -d <domain> [options]
```

### Options Reference

| Flag | Long Flag | Description | Default |
| :--- | :--- | :--- | :---: |
| `-d` | `--domain` | Target root domain (e.g. `example.com`) | **Required** |
| `-o` | `--output` | Base output directory | `./recon_results` |
| `-t` | `--threads` | Concurrency / Worker threads | `25` |
| `-r` | `--rate-limit` | Max requests per second across tools | `100` |
| | `--delay` | Delay in seconds between crawler requests | `0` |
| | `--ports` | Custom port list for naabu (`100`, `1000`, `80,443,8080`) | `top-100` |
| | `--skip-ports` | Skip port scanning stage | `false` |
| | `--skip-crawl` | Skip web crawling stage | `false` |
| | `--skip-js` | Skip JavaScript analysis stage | `false` |
| `-p` | `--passive` | Run passive enumeration only (no active probing) | `false` |
| `-f` | `--full` | Full run (top-1000 ports + deep crawl) | `false` |
| `-h` | `--help` | Display help message and exit | - |

---

## 💡 Examples

### 1. Standard Recon (Subdomains + DNS + HTTP + Ports + Katana + JS Filter)
```bash
./recon.sh -d example.com -r 50 -t 20
```

### 2. Custom Ports Scan
```bash
./recon.sh -d example.com --ports 80,443,8080,8443,8000,8888,3000,5000
```

### 3. Passive-Only Enumeration (Zero Packets Sent to Target)
```bash
./recon.sh -d example.com --passive
```

### 4. Full Deep Scan (Top-1000 Ports + Delay)
```bash
./recon.sh -d example.com --full -r 30 --delay 1 -o ./targets
```

---

## 📁 Output Structure

All artifacts and reports are saved in `recon_results/<domain>/`:

```text
recon_results/example.com/
├── subdomains/
│   ├── raw_subs.txt                # Raw harvested subdomains
│   └── unique_subdomains.txt       # Clean, deduplicated subdomains
├── dns/
│   ├── resolved_subdomains.txt     # Verified live DNS hosts
│   ├── unique_ips.txt              # Resolved IP addresses
│   └── dns_records.json            # Full DNS record JSON
├── web/
│   ├── alive_urls.txt              # Responsive HTTP/HTTPS URLs
│   ├── httpx_summary.txt           # Formatted tabular overview
│   └── httpx_detailed.json         # Raw JSON with headers & tech stack
├── ports/
│   └── open_ports.txt              # Open ports detected by naabu
├── endpoints/
│   └── endpoints.txt               # Crawled routes & URL parameters
├── js/
│   ├── js_urls.txt                 # Extracted JavaScript asset URLs
│   ├── js_endpoints.txt            # Internal API routes extracted from JS
│   └── js_secrets.txt              # Potential keys/secrets found in JS
├── reports/
│   └── SUMMARY.md                  # Executive Markdown Summary Report
└── recon.log                       # Full execution log
```

---

## ⚖️ Legal Disclaimer

This tool is designed strictly for educational purposes, authorized security auditing, and legitimate bug bounty research. Only run this tool against domains and assets you own or have explicit, documented authorization to test.
