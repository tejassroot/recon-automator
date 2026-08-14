#!/usr/bin/env bash
# ==============================================================================
# ReconAutomator - Multi-Stage Reconnaissance Pipeline
# ==============================================================================
# Pipeline Stages:
#   1. Subdomain Discovery (Passive: crt.sh, subfinder)
#   2. DNS Resolution & Live Asset Filtering (dnsx)
#   3. HTTP Probing, Tech Fingerprinting & Web Titles (httpx)
#   4. Port Scanning & Service Identification (naabu) [Optional]
#   5. Web Crawling & Endpoint Discovery (katana) [Optional]
# ==============================================================================

set -eo pipefail

# Color Codes
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Default Configuration
THREADS=25
RATE_LIMIT=100
DELAY=0
PASSIVE_ONLY=0
FULL_SCAN=0
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
    echo -e "${NC}${YELLOW}Multi-Stage Recon & Attack Surface Mapping Tool${NC}"
    echo -e "${CYAN}------------------------------------------------------------${NC}"
}

usage() {
    local code=${1:-0}
    banner
    echo -e "${BOLD}Usage:${NC}"
    echo "  $0 -d <domain> [options]"
    echo ""
    echo -e "${BOLD}Options:${NC}"
    echo "  -d, --domain <domain>        Target root domain (e.g. example.com) [Required]"
    echo "  -o, --output <dir>           Base output directory (default: ./recon_results)"
    echo "  -t, --threads <num>          Concurrency / Threads (default: 25)"
    echo "  -r, --rate-limit <rps>       Max requests per second rate limit (default: 100)"
    echo "      --delay <sec>            Delay in seconds between crawler requests (default: 0)"
    echo "  -p, --passive                Run passive enumeration only (no direct host probing)"
    echo "  -f, --full                   Full run including port scan (naabu) and spidering (katana)"
    echo "  -h, --help                   Display this help message"
    echo ""
    echo -e "${BOLD}Examples:${NC}"
    echo "  $0 -d example.com -r 50 -t 20"
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
        -p|--passive) PASSIVE_ONLY=1 ;;
        -f|--full) FULL_SCAN=1 ;;
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
mkdir -p "${TARGET_DIR}/subdomains" "${TARGET_DIR}/dns" "${TARGET_DIR}/web" "${TARGET_DIR}/ports" "${TARGET_DIR}/endpoints" "${TARGET_DIR}/reports"

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
echo -e "${BOLD}Scan Mode     :${NC} $([[ $PASSIVE_ONLY -eq 1 ]] && echo 'Passive Only' || echo 'Active Recon')$([[ $FULL_SCAN -eq 1 ]] && echo ' (Full: Ports + Spider)')"
echo -e "${CYAN}------------------------------------------------------------${NC}\n"

# Check Tool Availability
check_tool() {
    if ! command -v "$1" &> /dev/null; then
        log_warn "Tool '$1' not found. Some functionality may be skipped."
        return 1
    fi
    return 0
}

# ==============================================================================
# STAGE 1: Subdomain Discovery
# ==============================================================================
log_stage "1" "Subdomain Discovery"

SUB_OUTPUT="${TARGET_DIR}/subdomains/raw_subs.txt"
> "${SUB_OUTPUT}"

# 1.1: crt.sh Certificate Transparency
log_info "Querying crt.sh Certificate Transparency logs..."
curl -s --max-time 30 --retry 2 "https://crt.sh/?q=%25.${DOMAIN}&output=json" 2>/dev/null | \
    jq -r '.[].name_value' 2>/dev/null | \
    sed 's/\*\.//g' | tr '[:upper:]' '[:lower:]' | sort -u >> "${SUB_OUTPUT}" || true

# 1.2: Subfinder (with rate-limiting)
if check_tool subfinder; then
    log_info "Running subfinder (passive sources, rate limit: ${RATE_LIMIT} rps)..."
    subfinder -d "${DOMAIN}" \
              -silent \
              -t "${THREADS}" \
              -rate-limit "${RATE_LIMIT}" >> "${SUB_OUTPUT}" || true
fi

# 1.3: Deduplicate
CLEAN_SUBS="${TARGET_DIR}/subdomains/unique_subdomains.txt"
grep -E "([a-zA-Z0-9_-]+\.)+${DOMAIN}$" "${SUB_OUTPUT}" | sort -u > "${CLEAN_SUBS}" || true

SUB_COUNT=$(wc -l < "${CLEAN_SUBS}")
log_success "Discovered ${BOLD}${SUB_COUNT}${NC} unique subdomains for ${DOMAIN}."

if [[ "${SUB_COUNT}" -eq 0 ]]; then
    log_warn "No subdomains found. Adding apex domain (${DOMAIN}) to list."
    echo "${DOMAIN}" > "${CLEAN_SUBS}"
fi

if [[ "${PASSIVE_ONLY}" -eq 1 ]]; then
    log_success "Passive recon completed. Results stored in: ${TARGET_DIR}"
    exit 0
fi

# ==============================================================================
# STAGE 2: DNS Resolution & Active Asset Filtering
# ==============================================================================
log_stage "2" "DNS Resolution & Verification"

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

    # Extract alive hosts and IP addresses
    if [[ -f "${RESOLVED_JSON}" ]]; then
        jq -r '.host' "${RESOLVED_JSON}" 2>/dev/null | sort -u > "${RESOLVED_SUBS}" || true
        jq -r '.a[]? // empty' "${RESOLVED_JSON}" 2>/dev/null | sort -u > "${IPS_FILE}" || true
    fi
else
    log_info "dnsx not found, copying raw list for web probing."
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
            awk -F'\t' '{printf "%-35s | %-4s | %-30s | %s\n", $1, $2, substr($3,1,30), $4}' > "${HTTPX_OUTPUT}" || true
    fi
fi

WEB_COUNT=$(wc -l < "${WEB_URLS:-/dev/null}" || echo "0")
log_success "Found ${BOLD}${WEB_COUNT}${NC} responsive web endpoints."

# ==============================================================================
# STAGE 4: Port & Service Discovery (Optional / Full Scan)
# ==============================================================================
if [[ "${FULL_SCAN}" -eq 1 ]]; then
    log_stage "4" "Port & Service Discovery"

    OPEN_PORTS="${TARGET_DIR}/ports/open_ports.txt"
    if [[ -s "${IPS_FILE}" ]] && check_tool naabu; then
        log_info "Scanning open ports on target IPs with naabu (rate: ${RATE_LIMIT} pps)..."
        naabu -l "${IPS_FILE}" \
              -top-ports 100 \
              -rate "${RATE_LIMIT}" \
              -silent \
              -o "${OPEN_PORTS}" || true
        log_success "Port scan completed. Output saved to: ${OPEN_PORTS}"
    fi

    # ==============================================================================
    # STAGE 5: Web Crawling & Endpoint Discovery (Optional / Full Scan)
    # ==============================================================================
    log_stage "5" "Endpoint Crawling & Discovery"

    ENDPOINTS_FILE="${TARGET_DIR}/endpoints/endpoints.txt"
    if [[ -s "${WEB_URLS}" ]] && check_tool katana; then
        log_info "Crawling alive web assets with katana (rate limit: ${RATE_LIMIT} rps, delay: ${DELAY}s)..."
        
        KATANA_ARGS=("-list" "${WEB_URLS}" "-depth" "2" "-crawl-duration" "2m" "-silent" "-concurrency" "${THREADS}" "-rate-limit" "${RATE_LIMIT}")
        if [[ "${DELAY}" -gt 0 ]]; then
            KATANA_ARGS+=("-delay" "${DELAY}")
        fi
        
        katana "${KATANA_ARGS[@]}" -o "${ENDPOINTS_FILE}" || true
        
        EP_COUNT=$(wc -l < "${ENDPOINTS_FILE:-/dev/null}" || echo "0")
        log_success "Discovered ${BOLD}${EP_COUNT}${NC} web endpoints / scripts."
    fi
fi

# ==============================================================================
# SUMMARY REPORT
# ==============================================================================
REPORT_FILE="${TARGET_DIR}/reports/SUMMARY.md"

{
    echo "# Reconnaissance Summary Report: ${DOMAIN}"
    echo ""
    echo "- **Target Domain:** \`${DOMAIN}\`"
    echo "- **Execution Date:** $(date -u +'%Y-%m-%d %H:%M:%S UTC')"
    echo "- **Rate Limit:** ${RATE_LIMIT} req/sec"
    echo "- **Subdomains Discovered:** ${SUB_COUNT}"
    echo "- **DNS Resolved Hosts:** ${ALIVE_COUNT}"
    echo "- **Unique IP Addresses:** ${IP_COUNT}"
    echo "- **Active Web Services:** ${WEB_COUNT}"
    echo ""
    echo "---"
    echo ""
    echo "## Discovered Active Web Services"
    echo ""
    echo "| URL | Status | Title | Technologies |"
    echo "| :--- | :---: | :--- | :--- |"
    if [[ -f "${HTTPX_JSON}" ]]; then
        jq -r '[.url, (.status_code|tostring), (.title // "-"), (.tech // [] | join(", "))] | "| " + .[0] + " | `" + .[1] + "` | " + (.[2]|gsub("\\|";"-")) + " | " + .[3] + " |"' "${HTTPX_JSON}" 2>/dev/null || true
    fi
    echo ""
    echo "---"
    echo ""
    echo "## Artifact Inventory"
    echo "- **Subdomains:** \`${TARGET_DIR}/subdomains/unique_subdomains.txt\`"
    echo "- **DNS Records:** \`${TARGET_DIR}/dns/dns_records.json\`"
    echo "- **Live HTTP Services:** \`${TARGET_DIR}/web/alive_urls.txt\`"
    echo "- **HTTP Details (JSON):** \`${TARGET_DIR}/web/httpx_detailed.json\`"
    if [[ -f "${TARGET_DIR}/endpoints/endpoints.txt" ]]; then
        echo "- **Crawled Endpoints:** \`${TARGET_DIR}/endpoints/endpoints.txt\`"
    fi
    if [[ -f "${TARGET_DIR}/ports/open_ports.txt" ]]; then
        echo "- **Port Scan:** \`${TARGET_DIR}/ports/open_ports.txt\`"
    fi
} > "${REPORT_FILE}"

log_stage "COMPLETE" "Recon Workflow Finished"
log_success "Full summary report generated: ${BOLD}${REPORT_FILE}${NC}"
echo -e "${CYAN}------------------------------------------------------------${NC}\n"
