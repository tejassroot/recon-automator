# ⚡ ReconAutomator

> Multi-stage, high-performance reconnaissance and attack surface mapping pipeline.

`ReconAutomator` automates passive and active external asset discovery, DNS resolution, HTTP probing, technology stack detection, port scanning, and web endpoint crawling with built-in rate-limiting and structured reporting.

---

## 🚀 Features

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
- **Stage 4: Port & Service Scanning (Optional)**
  - Fast port enumeration on discovered target IPs using `naabu`
- **Stage 5: Web Crawling & Endpoint Discovery (Optional)**
  - Deep URL and JavaScript spidering using `katana`
- **Rate-Limiting & Anti-Throttle Protection**
  - Configurable requests-per-second (`--rate-limit`) and crawler delays (`--delay`) across all tools
- **Structured Markdown Reporting**
  - Automatically compiles an executive `SUMMARY.md` report with markdown tables for all discovered live assets

---

## 📋 Prerequisites

The following tools should be installed and available in your `$PATH`:

- `subfinder`
- `dnsx`
- `httpx`
- `naabu` (optional, for `--full` port scan)
- `katana` (optional, for `--full` spidering)
- `jq`, `curl`

### Quick Install on Kali / Debian
```bash
sudo apt update && sudo apt install -y jq curl

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
| `-p` | `--passive` | Run passive enumeration only (no active probing) | `false` |
| `-f` | `--full` | Full run (includes port scan and web crawling) | `false` |
| `-h` | `--help` | Display help message and exit | - |

---

## 💡 Examples

### 1. Standard Recon (Subdomains + DNS + HTTP Tech Detection)
```bash
./recon.sh -d example.com -r 50 -t 20
```

### 2. Passive-Only Enumeration (Zero Packets Sent to Target)
```bash
./recon.sh -d example.com --passive
```

### 3. Full Deep Scan (With Port Scan & Katana Spidering)
```bash
./recon.sh -d example.com --full -r 30 --delay 1 -o ./targets
```

---

## 📁 Output Structure

All artifacts and reports are saved in `recon_results/<domain>/`:

```text
recon_results/example.com/
├── subdomains/
│   ├── raw_subs.txt
│   └── unique_subdomains.txt
├── dns/
│   ├── resolved_subdomains.txt
│   ├── unique_ips.txt
│   └── dns_records.json
├── web/
│   ├── alive_urls.txt
│   ├── httpx_summary.txt
│   └── httpx_detailed.json
├── ports/                          # (Generated when using --full)
│   └── open_ports.txt
├── endpoints/                      # (Generated when using --full)
│   └── endpoints.txt
├── reports/
│   └── SUMMARY.md                  # Executive Markdown Summary
└── recon.log
```

---

## ⚖️ Legal Disclaimer

This tool is designed strictly for educational purposes, authorized security auditing, and legitimate bug bounty research. Only run this tool against domains and assets you own or have explicit, documented authorization to test.
