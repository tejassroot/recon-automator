#!/usr/bin/env bash
# ==============================================================================
# ReconAutomator - Multi-Stage Reconnaissance Pipeline
# ==============================================================================
# Pipeline Stages:
#   1. Subdomain Discovery (Passive: crt.sh, subfinder)
#   2. DNS Resolution & Live Asset Filtering (dnsx)
#   3. HTTP Probing, Tech Fingerprinting & Web Titles (httpx)
#   4. Port Scanning & Service Identification (naabu)
#   5. Web Crawling & Endpoint Discovery (katana)
#   6. JavaScript Asset Filtering, API Extraction & Secret Mining
# ==============================================================================

set -eo pipefail

# Color Codes
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Default Configuration
THREADS=25
RATE_LIMIT=100
DELAY=0
PASSIVE_ONLY=0
SKIP_PORTS=0
SKIP_CRAWL=0
SKIP_JS=0
FULL_SCAN=0
PORT_LIST="top-100"
OUTPUT_BASE="./recon_results"

banner() {
    echo -e "${CYAN}${BOLD}"
    cat << "BANNER_END"
  ____                        _         _        
 |  _ \ ___  ___ ___  _ __   / \  _   _| |_ ___  
 | |_) / _ \/ __/ _ \| '_ \ / _ \| | | | __/ _ \ 
 |  _ <  __/ (_| (_) | | | / ___ \ |_| | || (_) |
 |_| \_\___|\___\___/|_| |/_/   \_\__,_|\__\___/ 
                                                 
BANNER_END
    echo -e "${NC}${YELLOW}Multi-Stage Recon & Attack Surface Mapping Pipeline${NC}"
    echo -e "${CYAN}------------------------------------------------------------${NC}"
}

usage() {
    local code=${1:-0}
    banner
    echo -e "${BOLD}Usage:${NC}"
    echo "  $0 -d <domain> [options]"
    echo ""
    echo -e "${BOLD}Core Options:${NC}"
    echo "  -d, --domain <domain>        Target root domain (e.g. example.com) [Required]"
    echo "  -o, --output <dir>           Base output directory (default: ./recon_results)"
    echo "  -t, --threads <num>          Concurrency / Worker threads (default: 25)"
    echo "  -r, --rate-limit <rps>       Max requests per second rate limit (default: 100)"
    echo "      --delay <sec>            Delay in seconds between crawler requests (default: 0)"
    echo ""
    echo -e "${BOLD}Scan Scope Options:${NC}"
    echo "  -p, --passive                Passive enumeration only (crt.sh, subfinder)"
    echo "  -f, --full                   Full aggressive scan (all ports + deep crawl)"
    echo "      --ports <ports>          Port list/spec for naabu (e.g. 100, 1000, 80,443,8080) (default: 100)"
    echo "      --skip-ports             Skip port scanning stage"
    echo "      --skip-crawl             Skip web crawling stage"
    echo "      --skip-js                Skip JavaScript parsing & secret extraction"
    echo "  -h, --help                   Display this help message"
    echo ""
    echo -e "${BOLD}Examples:${NC}"
    echo "  $0 -d example.com -r 50 -t 20"
    echo "  $0 -d example.com --ports 80,443,8080,8443,8000,8888,3000,5000"
    echo "  $0 -d example.com --passive"
    echo "  $0 -d example.com -o ./targets -r 30 --delay 1 --full"
    echo ""
    exit $code
}

# Parse Command Line Arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -d|--domain) DOMAIN="$2"; shift ;;
        -o|--output) OUTPUT_BASE="$2"; shift ;;
        -t|--threads) THREADS="$2"; shift ;;
        -r|--rate-limit) RATE_LIMIT="$2"; shift ;;
        --delay) DELAY="$2"; shift ;;
        --ports) PORT_LIST="$2"; shift ;;
        --skip-ports) SKIP_PORTS=1 ;;
        --skip-crawl) SKIP_CRAWL=1 ;;
        --skip-js) SKIP_JS=1 ;;
        -p|--passive) PASSIVE_ONLY=1 ;;
        -f|--full) FULL_SCAN=1; PORT_LIST="1000" ;;
        -h|--help) usage 0 ;;
        *) echo -e "${RED}[!] Unknown parameter: $1${NC}"; usage 1 ;;
    esac
    shift
done

if [[ -z "${DOMAIN:-}" ]]; then
    echo -e "${RED}[!] Error: Target domain is required.${NC}"
    usage 1
fi

# Directory Structure Setup
TARGET_DIR="${OUTPUT_BASE}/${DOMAIN}"
mkdir -p "${TARGET_DIR}/subdomains" \
         "${TARGET_DIR}/dns" \
         "${TARGET_DIR}/web" \
         "${TARGET_DIR}/ports" \
         "${TARGET_DIR}/endpoints" \
         "${TARGET_DIR}/js" \
         "${TARGET_DIR}/reports"

LOG_FILE="${TARGET_DIR}/recon.log"
exec > >(tee -a "${LOG_FILE}") 2>&1

log_info()    { echo -e "${BLUE}[*]${NC} $1"; }
log_success() { echo -e "${GREEN}[+]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
log_stage()   { echo -e "\n${CYAN}${BOLD}=== Stage $1: $2 ===${NC}"; }

banner
echo -e "${BOLD}Target Domain :${NC} ${GREEN}${DOMAIN}${NC}"
echo -e "${BOLD}Output Path   :${NC} ${TARGET_DIR}"
echo -e "${BOLD}Threads       :${NC} ${THREADS}"
echo -e "${BOLD}Rate Limit    :${NC} ${RATE_LIMIT} req/sec $([[ $DELAY -gt 0 ]] && echo "(Delay: ${DELAY}s)")"
echo -e "${BOLD}Scan Mode     :${NC} $([[ $PASSIVE_ONLY -eq 1 ]] && echo 'Passive Only' || echo 'Active Recon')$([[ $FULL_SCAN -eq 1 ]] && echo ' (Full Mode)')"
echo -e "${CYAN}------------------------------------------------------------${NC}\n"

check_tool() {
    if ! command -v "$1" &> /dev/null; then
        log_warn "Tool '$1' not found. Related stage will be skipped."
        return 1
    fi
    return 0
}

# ==============================================================================
# STAGE 1: Subdomain Discovery
# ==============================================================================
log_stage "1" "Passive Subdomain Discovery"

SUB_OUTPUT="${TARGET_DIR}/subdomains/raw_subs.txt"
> "${SUB_OUTPUT}"

# 1.1: crt.sh Certificate Transparency
log_info "Querying crt.sh Certificate Transparency logs..."
curl -s --max-time 30 --retry 2 "https://crt.sh/?q=%25.${DOMAIN}&output=json" 2>/dev/null | \
    jq -r '.[].name_value' 2>/dev/null | \
    sed 's/\*\.//g' | tr '[:upper:]' '[:lower:]' | sort -u >> "${SUB_OUTPUT}" || true

# 1.2: Subfinder (with rate-limiting)
if check_tool subfinder; then
    log_info "Running subfinder (rate limit: ${RATE_LIMIT} rps)..."
    subfinder -d "${DOMAIN}" \
              -silent \
              -t "${THREADS}" \
              -rate-limit "${RATE_LIMIT}" >> "${SUB_OUTPUT}" || true
fi

# 1.3: Deduplicate
CLEAN_SUBS="${TARGET_DIR}/subdomains/unique_subdomains.txt"
grep -E "([a-zA-Z0-9_-]+\.)+${DOMAIN}$" "${SUB_OUTPUT}" 2>/dev/null | sort -u > "${CLEAN_SUBS}" || true

SUB_COUNT=$(wc -l < "${CLEAN_SUBS:-/dev/null}" || echo "0")
log_success "Discovered ${BOLD}${SUB_COUNT}${NC} unique subdomains for ${DOMAIN}."

if [[ "${SUB_COUNT}" -eq 0 ]]; then
    log_warn "No subdomains found. Adding apex domain (${DOMAIN}) to list."
    echo "${DOMAIN}" > "${CLEAN_SUBS}"
    SUB_COUNT=1
fi

if [[ "${PASSIVE_ONLY}" -eq 1 ]]; then
    log_success "Passive recon completed. Results stored in: ${TARGET_DIR}"
    exit 0
fi

# ==============================================================================
# STAGE 2: DNS Resolution & Active Asset Filtering
# ==============================================================================
log_stage "2" "DNS Resolution & Host Verification"

RESOLVED_SUBS="${TARGET_DIR}/dns/resolved_subdomains.txt"
RESOLVED_JSON="${TARGET_DIR}/dns/dns_records.json"
IPS_FILE="${TARGET_DIR}/dns/unique_ips.txt"

if check_tool dnsx; then
    log_info "Resolving subdomains using dnsx (rate limit: ${RATE_LIMIT} rps)..."
    dnsx -l "${CLEAN_SUBS}" \
         -silent \
         -t "${THREADS}" \
         -rate-limit "${RATE_LIMIT}" \
         -a -cname -resp \
         -json -o "${RESOLVED_JSON}" || true

    if [[ -f "${RESOLVED_JSON}" ]]; then
        jq -r '.host' "${RESOLVED_JSON}" 2>/dev/null | sort -u > "${RESOLVED_SUBS}" || true
        jq -r '.a[]? // empty' "${RESOLVED_JSON}" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | sort -u > "${IPS_FILE}" || true
    fi
fi

if [[ ! -s "${RESOLVED_SUBS}" ]]; then
    log_warn "dnsx yielded no hosts, falling back to raw subdomain list."
    cp "${CLEAN_SUBS}" "${RESOLVED_SUBS}"
fi

ALIVE_COUNT=$(wc -l < "${RESOLVED_SUBS:-/dev/null}" || echo "0")
IP_COUNT=$(wc -l < "${IPS_FILE:-/dev/null}" || echo "0")
log_success "Resolved ${BOLD}${ALIVE_COUNT}${NC} live subdomains (${IP_COUNT} unique IPs)."

# ==============================================================================
# STAGE 3: HTTP Probing & Technology Detection
# ==============================================================================
log_stage "3" "HTTP Probing & Fingerprinting"

HTTPX_OUTPUT="${TARGET_DIR}/web/httpx_summary.txt"
HTTPX_JSON="${TARGET_DIR}/web/httpx_detailed.json"
WEB_URLS="${TARGET_DIR}/web/alive_urls.txt"

if check_tool httpx; then
    log_info "Probing web services with httpx (rate limit: ${RATE_LIMIT} rps)..."
    httpx -l "${RESOLVED_SUBS}" \
          -silent \
          -threads "${THREADS}" \
          -rate-limit "${RATE_LIMIT}" \
          -status-code \
          -tech-detect \
          -title \
          -web-server \
          -cdn \
          -follow-redirects \
          -json -o "${HTTPX_JSON}" || true

    if [[ -f "${HTTPX_JSON}" ]]; then
        jq -r '.url' "${HTTPX_JSON}" 2>/dev/null | sort -u > "${WEB_URLS}" || true
        
        # Formatted readable summary table
        jq -r '[.url, (.status_code|tostring), (.title // "-"), (.tech // [] | join(","))] | @tsv' "${HTTPX_JSON}" 2>/dev/null | \
            awk -F'\t' '{printf "%-40s | %-4s | %-30s | %s\n", $1, $2, substr($3,1,30), $4}' > "${HTTPX_OUTPUT}" || true
    fi
fi

WEB_COUNT=$(wc -l < "${WEB_URLS:-/dev/null}" || echo "0")
log_success "Found ${BOLD}${WEB_COUNT}${NC} responsive web endpoints."

# ==============================================================================
# STAGE 4: Port & Service Discovery (Naabu)
# ==============================================================================
OPEN_PORTS="${TARGET_DIR}/ports/open_ports.txt"
> "${OPEN_PORTS}"

if [[ "${SKIP_PORTS}" -eq 0 ]] && check_tool naabu; then
    log_stage "4" "Port & Service Discovery (Naabu)"

    # Determine targets: Use unique IPs if available, else resolved subdomains
    PORT_TARGETS="${IPS_FILE}"
    if [[ ! -s "${PORT_TARGETS}" ]]; then
        PORT_TARGETS="${RESOLVED_SUBS}"
    fi

    if [[ -s "${PORT_TARGETS}" ]]; then
        log_info "Scanning ports (${PORT_LIST}) with naabu (TCP connect mode, rate: ${RATE_LIMIT} pps)..."
        
        NAABU_ARGS=("-l" "${PORT_TARGETS}" "-rate" "${RATE_LIMIT}" "-scan-type" "c" "-ec" "-silent" "-o" "${OPEN_PORTS}")
        
        if [[ "${PORT_LIST}" == "top-100" || "${PORT_LIST}" == "100" ]]; then
            NAABU_ARGS+=("-top-ports" "100")
        elif [[ "${PORT_LIST}" == "top-1000" || "${PORT_LIST}" == "1000" ]]; then
            NAABU_ARGS+=("-top-ports" "1000")
        elif [[ "${PORT_LIST}" == "full" ]]; then
            NAABU_ARGS+=("-p" "-")
        else
            NAABU_ARGS+=("-p" "${PORT_LIST}")
        fi

        naabu "${NAABU_ARGS[@]}" || true
        
        PORT_COUNT=$(wc -l < "${OPEN_PORTS:-/dev/null}" || echo "0")
        log_success "Discovered ${BOLD}${PORT_COUNT}${NC} open ports/services."
    else
        log_warn "No hosts available for port scanning."
    fi
fi

# ==============================================================================
# STAGE 5: Web Crawling & Endpoint Discovery (Katana)
# ==============================================================================
ENDPOINTS_FILE="${TARGET_DIR}/endpoints/endpoints.txt"
> "${ENDPOINTS_FILE}"

if [[ "${SKIP_CRAWL}" -eq 0 ]] && [[ -s "${WEB_URLS}" ]] && check_tool katana; then
    log_stage "5" "Web Crawling & Endpoint Discovery (Katana)"
    
    log_info "Crawling web assets with katana (depth: 2, concurrency: ${THREADS}, rate limit: ${RATE_LIMIT})..."
    
    KATANA_ARGS=("-list" "${WEB_URLS}" "-depth" "2" "-jc" "-kf" "all" "-crawl-duration" "2m" "-silent" "-concurrency" "${THREADS}" "-rate-limit" "${RATE_LIMIT}" "-o" "${ENDPOINTS_FILE}")
    if [[ "${DELAY}" -gt 0 ]]; then
        KATANA_ARGS+=("-delay" "${DELAY}")
    fi
    
    katana "${KATANA_ARGS[@]}" || true
    
    EP_COUNT=$(wc -l < "${ENDPOINTS_FILE:-/dev/null}" || echo "0")
    log_success "Discovered ${BOLD}${EP_COUNT}${NC} endpoints & web assets."
fi

# ==============================================================================
# STAGE 6: JavaScript Extraction, API Endpoint Filter & Secret Mining
# ==============================================================================
JS_URLS_FILE="${TARGET_DIR}/js/js_urls.txt"
JS_ENDPOINTS_FILE="${TARGET_DIR}/js/js_endpoints.txt"
JS_SECRETS_FILE="${TARGET_DIR}/js/js_secrets.txt"

> "${JS_URLS_FILE}"
> "${JS_ENDPOINTS_FILE}"
> "${JS_SECRETS_FILE}"

if [[ "${SKIP_JS}" -eq 0 ]]; then
    log_stage "6" "JavaScript Analysis, Route Filtering & Secret Mining"

    log_info "Extracting and deduplicating JavaScript URLs..."
    
    # 6.1: Filter JS files from endpoints and live URLs
    if [[ -s "${ENDPOINTS_FILE}" ]]; then
        grep -iE '\.js(\?|$)' "${ENDPOINTS_FILE}" | grep -E '^https?://' | sort -u >> "${JS_URLS_FILE}" || true
    fi
    
    if [[ -s "${WEB_URLS}" ]]; then
        # Append direct JS files if any exist in alive_urls
        grep -iE '\.js(\?|$)' "${WEB_URLS}" | sort -u >> "${JS_URLS_FILE}" || true
    fi

    sort -u -o "${JS_URLS_FILE}" "${JS_URLS_FILE}" 2>/dev/null || true
    JS_COUNT=$(wc -l < "${JS_URLS_FILE:-/dev/null}" || echo "0")
    log_success "Identified ${BOLD}${JS_COUNT}${NC} unique JavaScript URLs."

    # 6.2: Python-based JS Inspector (Endpoints & Secret Patterns)
    if [[ "${JS_COUNT}" -gt 0 ]]; then
        log_info "Analyzing JavaScript files for API routes, endpoints, and sensitive credentials..."
        
        python3 - "${JS_URLS_FILE}" "${JS_ENDPOINTS_FILE}" "${JS_SECRETS_FILE}" "${THREADS}" "${RATE_LIMIT}" << 'PYEOF'
import sys
import re
import urllib.request
import ssl
from concurrent.futures import ThreadPoolExecutor

js_urls_file, ep_out_file, sec_out_file, threads_str, rate_str = sys.argv[1:6]
threads = max(1, min(int(threads_str), 30))

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

with open(js_urls_file, "r", encoding="utf-8", errors="ignore") as f:
    urls = [line.strip() for line in f if line.strip().startswith("http")]

endpoints_found = set()
secrets_found = set()

# Regex Patterns
EP_PATTERN = re.compile(r'["\'](/api/[a-zA-Z0-9_\-\./\?=&%#]+|/v[0-9]/[a-zA-Z0-9_\-\./\?=&%#]+|/graphql[a-zA-Z0-9_\-\./\?=&%#]*|/rest/[a-zA-Z0-9_\-\./\?=&%#]+)["\']')
GENERIC_ROUTE = re.compile(r'["\'](/[a-zA-Z0-9_-]+/[a-zA-Z0-9_\-\./\?=&%#]+)["\']')

SECRET_PATTERNS = [
    ("AWS Access Key", re.compile(r'AKIA[0-9A-Z]{16}')),
    ("Google API Key", re.compile(r'AIza[0-9A-Za-z\-_]{35}')),
    ("JWT Token", re.compile(r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}')),
    ("Slack Token/Webhook", re.compile(r'xox[baprs]-[0-9a-zA-Z]{10,48}|https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9a-zA-Z]+')),
    ("Stripe Key", re.compile(r'sk_live_[0-9a-zA-Z]{24}')),
    ("GitHub Token", re.compile(r'gh[pousr]_[0-9a-zA-Z]{36}')),
    ("Bearer Header", re.compile(r'["\']Bearer\s+([a-zA-Z0-9_\-\.]{20,})["\']', re.I)),
    ("Hardcoded Password/Secret", re.compile(r'["\']?(?:secret|api_?key|auth_?token|client_?secret)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{12,})["\']', re.I))
]

def scan_url(url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            content = resp.read().decode("utf-8", errors="ignore")
            
            # Extract Endpoints
            for match in EP_PATTERN.findall(content):
                endpoints_found.add(f"{match} (from {url})")
            
            # Extract Secrets
            for name, pat in SECRET_PATTERNS:
                for s in pat.findall(content):
                    if isinstance(s, tuple):
                        s = s[0]
                    secrets_found.add(f"[{name}] {s} (in {url})")
    except Exception:
        pass

with ThreadPoolExecutor(max_workers=threads) as executor:
    executor.map(scan_url, urls[:300]) # Cap at first 300 JS files for speed & rate limits

with open(ep_out_file, "w", encoding="utf-8") as f:
    for ep in sorted(endpoints_found):
        f.write(ep + "\n")

with open(sec_out_file, "w", encoding="utf-8") as f:
    for sec in sorted(secrets_found):
        f.write(sec + "\n")
PYEOF
        
        EXT_EP_COUNT=$(wc -l < "${JS_ENDPOINTS_FILE:-/dev/null}" || echo "0")
        EXT_SEC_COUNT=$(wc -l < "${JS_SECRETS_FILE:-/dev/null}" || echo "0")
        log_success "Extracted ${BOLD}${EXT_EP_COUNT}${NC} API endpoints & ${BOLD}${EXT_SEC_COUNT}${NC} potential secrets from JS files."
    fi
fi

# ==============================================================================
# SUMMARY REPORT
# ==============================================================================
REPORT_FILE="${TARGET_DIR}/reports/SUMMARY.md"

{
    echo "# 📋 Reconnaissance Summary: ${DOMAIN}"
    echo ""
    echo "- **Target Domain:** \`${DOMAIN}\`"
    echo "- **Scan Date:** $(date -u +'%Y-%m-%d %H:%M:%S UTC')"
    echo "- **Subdomains Discovered:** ${SUB_COUNT}"
    echo "- **Resolved Hosts:** ${ALIVE_COUNT}"
    echo "- **Unique IP Addresses:** ${IP_COUNT}"
    echo "- **Active Web Services:** ${WEB_COUNT}"
    echo "- **Open Ports/Services:** $(wc -l < "${OPEN_PORTS:-/dev/null}" || echo "0")"
    echo "- **Crawled Endpoints:** $(wc -l < "${ENDPOINTS_FILE:-/dev/null}" || echo "0")"
    echo "- **JavaScript Files:** $(wc -l < "${JS_URLS_FILE:-/dev/null}" || echo "0")"
    echo "- **Extracted JS Routes:** $(wc -l < "${JS_ENDPOINTS_FILE:-/dev/null}" || echo "0")"
    echo ""
    echo "---"
    echo ""
    echo "## 🌐 Active Web Services"
    echo ""
    echo "| URL | Status | Title | Technologies |"
    echo "| :--- | :---: | :--- | :--- |"
    if [[ -f "${HTTPX_JSON}" ]]; then
        jq -r '[.url, (.status_code|tostring), (.title // "-"), (.tech // [] | join(", "))] | "| " + .[0] + " | `" + .[1] + "` | " + (.[2]|gsub("\\|";"-")) + " | " + .[3] + " |"' "${HTTPX_JSON}" 2>/dev/null || true
    fi
    echo ""
    if [[ -s "${OPEN_PORTS}" ]]; then
        echo "---"
        echo ""
        echo "## 🔌 Discovered Open Ports"
        echo "\`\`\`text"
        cat "${OPEN_PORTS}"
        echo "\`\`\`"
        echo ""
    fi
    if [[ -s "${JS_SECRETS_FILE}" ]]; then
        echo "---"
        echo ""
        echo "## 🔑 Potential Leaked Secrets in JS"
        echo "\`\`\`text"
        head -n 25 "${JS_SECRETS_FILE}"
        echo "\`\`\`"
        echo ""
    fi
    echo "---"
    echo ""
    echo "## 📁 Artifact Inventory"
    echo "- **Subdomains:** \`${TARGET_DIR}/subdomains/unique_subdomains.txt\`"
    echo "- **DNS Records:** \`${TARGET_DIR}/dns/dns_records.json\`"
    echo "- **Live HTTP Services:** \`${TARGET_DIR}/web/alive_urls.txt\`"
    echo "- **Open Ports:** \`${TARGET_DIR}/ports/open_ports.txt\`"
    echo "- **Endpoints:** \`${TARGET_DIR}/endpoints/endpoints.txt\`"
    echo "- **JavaScript URLs:** \`${TARGET_DIR}/js/js_urls.txt\`"
    echo "- **Extracted JS Endpoints:** \`${TARGET_DIR}/js/js_endpoints.txt\`"
    echo "- **Extracted JS Secrets:** \`${TARGET_DIR}/js/js_secrets.txt\`"
} > "${REPORT_FILE}"

log_stage "COMPLETE" "Recon Workflow Finished"
log_success "Full summary report generated: ${BOLD}${REPORT_FILE}${NC}"
echo -e "${CYAN}------------------------------------------------------------${NC}\n"
