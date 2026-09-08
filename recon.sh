#!/usr/bin/env bash
# ==============================================================================
# ReconAutomator - Multi-Stage Reconnaissance Pipeline
# ==============================================================================
# Pipeline Stages:
#   1. Subdomain Discovery (Passive: crt.sh, subfinder)
#   2. DNS Resolution & Live Asset Filtering (dnsx with auto wildcard filtering)
#   3. HTTP Probing, Tech Fingerprinting & Web Titles (httpx)
#   4. Port Scanning & Service Identification (naabu with CDN exclusion)
#   5. Web Crawling & Endpoint Discovery (katana with scope controls)
#   6. JavaScript Asset Filtering, API Extraction & Secret Mining (Entropy-filtered)
# ==============================================================================

set -eo pipefail

# Signal trap for clean termination of pipeline and subprocesses
cleanup_exit() {
    echo -e "\n\033[0;31m[!] Execution interrupted by user. Cleaning up...\033[0m"
    kill 0 2>/dev/null || true
    exit 130
}
trap cleanup_exit SIGINT SIGTERM

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
PORTS_USER_SPECIFIED=0
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
    echo "      --delay <sec>            Delay in seconds between crawler/analyzer requests (default: 0)"
    echo ""
    echo -e "${BOLD}Scan Scope Options:${NC}"
    echo "  -p, --passive                Passive enumeration only (crt.sh, subfinder)"
    echo "  -f, --full                   Full aggressive scan (all ports + deep crawl)"
    echo "      --ports <ports>          Port list/spec for naabu (e.g. 100, 1000, full, or 80,443,8080) (default: 100)"
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
        --ports) PORT_LIST="$2"; PORTS_USER_SPECIFIED=1; shift ;;
        --skip-ports) SKIP_PORTS=1 ;;
        --skip-crawl) SKIP_CRAWL=1 ;;
        --skip-js) SKIP_JS=1 ;;
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

if [[ "${FULL_SCAN}" -eq 1 && "${PORTS_USER_SPECIFIED}" -eq 0 ]]; then
    PORT_LIST="full"
fi

# Pre-flight Core Dependencies Check
check_core_deps() {
    local missing=()
    for tool in curl jq python3; do
        if ! command -v "$tool" &> /dev/null; then
            missing+=("$tool")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "${RED}[!] Critical dependency missing: ${missing[*]}. Please install required packages.${NC}" >&2
        exit 1
    fi
}
check_core_deps

# Clean up domain input (strip protocol, trailing slash, port, and www prefix if any)
DOMAIN=$(echo "${DOMAIN}" | sed -e 's|^https\?://||' -e 's|/.*$||' -e 's|^www\.||' -e 's|:[0-9]\+$||' | tr '[:upper:]' '[:lower:]')

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
    jq -r '.[].name_value // empty' 2>/dev/null | \
    tr '\r' '\n' | sed -e 's/^\*\.//' -e 's/^\*//' -e 's/^[ \t]*//' -e 's/[ \t]*$//' | tr '[:upper:]' '[:lower:]' >> "${SUB_OUTPUT}" || true

# 1.2: Subfinder (with rate-limiting)
if check_tool subfinder; then
    log_info "Running subfinder (rate limit: ${RATE_LIMIT} rps)..."
    subfinder -d "${DOMAIN}" \
              -silent \
              -t "${THREADS}" \
              -rate-limit "${RATE_LIMIT}" >> "${SUB_OUTPUT}" || true
fi

# 1.3: Deduplicate with strict regex anchoring & domain escaping
CLEAN_SUBS="${TARGET_DIR}/subdomains/unique_subdomains.txt"
ESCAPED_DOMAIN=$(printf '%s\n' "${DOMAIN}" | sed 's/[^^]/[&]/g; s/\^/\\^/g')
grep -Ei "^([a-zA-Z0-9_-]+\.)*${ESCAPED_DOMAIN}$" "${SUB_OUTPUT}" 2>/dev/null | tr '[:upper:]' '[:lower:]' | sort -u > "${CLEAN_SUBS}" || true

# Ensure apex domain is included
echo "${DOMAIN}" >> "${CLEAN_SUBS}"
sort -u -o "${CLEAN_SUBS}" "${CLEAN_SUBS}"

SUB_COUNT=$(wc -l < "${CLEAN_SUBS}" || echo "0")
log_success "Discovered ${BOLD}${SUB_COUNT}${NC} unique subdomains for ${DOMAIN}."

if [[ "${PASSIVE_ONLY}" -eq 1 ]]; then
    log_success "Passive recon completed. Results stored in: ${TARGET_DIR}"
    exit 0
fi

# ==============================================================================
# STAGE 2: DNS Resolution & Active Asset Filtering (Wildcard Aware)
# ==============================================================================
log_stage "2" "DNS Resolution & Host Verification"

RESOLVED_SUBS="${TARGET_DIR}/dns/resolved_subdomains.txt"
RESOLVED_JSON="${TARGET_DIR}/dns/dns_records.json"
IPS_FILE="${TARGET_DIR}/dns/unique_ips.txt"

> "${RESOLVED_SUBS}"
> "${IPS_FILE}"

if check_tool dnsx; then
    log_info "Resolving subdomains using dnsx (with auto wildcard detection, rate limit: ${RATE_LIMIT} rps)..."
    dnsx -l "${CLEAN_SUBS}" \
         -silent \
         -t "${THREADS}" \
         -rate-limit "${RATE_LIMIT}" \
         -auto-wildcard \
         -wt 5 \
         -a -cname -resp \
         -json -o "${RESOLVED_JSON}" || true

    if [[ -f "${RESOLVED_JSON}" ]]; then
        jq -r '.host' "${RESOLVED_JSON}" 2>/dev/null | sort -u > "${RESOLVED_SUBS}" || true
        jq -r '.a[]? // empty' "${RESOLVED_JSON}" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | sort -u > "${IPS_FILE}" || true
    fi
else
    log_warn "dnsx not installed. Falling back to unique subdomains without active DNS filtering."
    cp "${CLEAN_SUBS}" "${RESOLVED_SUBS}"
fi

ALIVE_COUNT=$(wc -l < "${RESOLVED_SUBS}" || echo "0")
IP_COUNT=$(wc -l < "${IPS_FILE}" || echo "0")
log_success "Resolved ${BOLD}${ALIVE_COUNT}${NC} live subdomains (${IP_COUNT} unique IPs)."

# ==============================================================================
# STAGE 3: HTTP Probing & Technology Detection
# ==============================================================================
log_stage "3" "HTTP Probing & Fingerprinting"

HTTPX_OUTPUT="${TARGET_DIR}/web/httpx_summary.txt"
HTTPX_JSON="${TARGET_DIR}/web/httpx_detailed.json"
WEB_URLS="${TARGET_DIR}/web/alive_urls.txt"

> "${WEB_URLS}"

if [[ -s "${RESOLVED_SUBS}" ]] && check_tool httpx; then
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
        # Filter URLs to retain in-scope target domains (suppress third-party redirect targets)
        jq -r --arg dom "${DOMAIN}" 'select(.url | test("^[a-z]+://([a-zA-Z0-9_-]+\\.)*" + ($dom|gsub("\\."; "\\.")) + "(/|:|$)"; "i")) | .url' "${HTTPX_JSON}" 2>/dev/null | sort -u > "${WEB_URLS}" || true
        
        # Formatted readable summary table
        jq -r '[.url, (.status_code|tostring), (.title // "-"), (.tech // [] | join(","))] | @tsv' "${HTTPX_JSON}" 2>/dev/null | \
            awk -F'\t' '{printf "%-40s | %-4s | %-30s | %s\n", $1, $2, substr($3,1,30), $4}' > "${HTTPX_OUTPUT}" || true
    fi
fi

WEB_COUNT=$(wc -l < "${WEB_URLS}" || echo "0")
log_success "Found ${BOLD}${WEB_COUNT}${NC} responsive in-scope web endpoints."

# ==============================================================================
# STAGE 4: Port & Service Discovery (Naabu - CDN Excluded)
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
        log_info "Scanning ports (${PORT_LIST}) with naabu (excluding CDN edge nodes, TCP connect mode, rate: ${RATE_LIMIT} pps)..."
        
        NAABU_ARGS=("-l" "${PORT_TARGETS}" "-exclude-cdn" "-rate" "${RATE_LIMIT}" "-scan-type" "c" "-silent" "-o" "${OPEN_PORTS}")
        
        if [[ "${PORT_LIST}" == "top-100" || "${PORT_LIST}" == "100" ]]; then
            NAABU_ARGS+=("-top-ports" "100")
        elif [[ "${PORT_LIST}" == "top-1000" || "${PORT_LIST}" == "1000" ]]; then
            NAABU_ARGS+=("-top-ports" "1000")
        elif [[ "${PORT_LIST}" == "full" || "${PORT_LIST}" == "all" ]]; then
            NAABU_ARGS+=("-p" "-")
        else
            NAABU_ARGS+=("-p" "${PORT_LIST}")
        fi

        naabu "${NAABU_ARGS[@]}" || true
        
        PORT_COUNT=$(wc -l < "${OPEN_PORTS}" || echo "0")
        log_success "Discovered ${BOLD}${PORT_COUNT}${NC} open ports/services on origin assets."
    else
        log_warn "No hosts available for port scanning."
    fi
fi

# ==============================================================================
# STAGE 5: Web Crawling & Endpoint Discovery (Katana - Scope Restricted)
# ==============================================================================
ENDPOINTS_FILE="${TARGET_DIR}/endpoints/endpoints.txt"
> "${ENDPOINTS_FILE}"

if [[ "${SKIP_CRAWL}" -eq 0 ]] && [[ -s "${WEB_URLS}" ]] && check_tool katana; then
    log_stage "5" "Web Crawling & Endpoint Discovery (Katana)"
    
    CRAWL_DEPTH=3
    CRAWL_DURATION="2m"
    if [[ "${FULL_SCAN}" -eq 1 ]]; then
        CRAWL_DEPTH=4
        CRAWL_DURATION="5m"
    fi

    log_info "Crawling web assets with katana (depth: ${CRAWL_DEPTH}, duration: ${CRAWL_DURATION}, strictly in-scope, concurrency: ${THREADS}, rate limit: ${RATE_LIMIT})..."
    
    KATANA_ARGS=(
        "-list" "${WEB_URLS}"
        "-depth" "${CRAWL_DEPTH}"
        "-jc"
        "-kf" "all"
        "-crawl-duration" "${CRAWL_DURATION}"
        "-crawl-scope" "([a-zA-Z0-9_-]+\\.)*${ESCAPED_DOMAIN}"
        "-extension-filter" "png,jpg,jpeg,gif,svg,ico,css,woff,woff2,ttf,eot,mp4,avi,pdf,docx"
        "-silent"
        "-concurrency" "${THREADS}"
        "-rate-limit" "${RATE_LIMIT}"
        "-o" "${ENDPOINTS_FILE}"
    )
    if [[ "${DELAY}" -gt 0 ]]; then
        KATANA_ARGS+=("-delay" "${DELAY}")
    fi
    
    katana "${KATANA_ARGS[@]}" || true
    
    EP_COUNT=$(wc -l < "${ENDPOINTS_FILE}" || echo "0")
    log_success "Discovered ${BOLD}${EP_COUNT}${NC} endpoints & web assets."
fi

# ==============================================================================
# STAGE 6: JavaScript Extraction, API Endpoint Filter & Secret Mining
# ==============================================================================
JS_URLS_FILE="${TARGET_DIR}/js/js_urls.txt"
JS_ENDPOINTS_FILE="${TARGET_DIR}/js/js_endpoints.txt"
JS_SECRETS_FILE="${TARGET_DIR}/js/js_secrets.txt"
JS_SECRETS_REDACTED="${TARGET_DIR}/js/js_secrets_redacted.txt"

> "${JS_URLS_FILE}"
> "${JS_ENDPOINTS_FILE}"
> "${JS_SECRETS_FILE}"
> "${JS_SECRETS_REDACTED}"

if [[ "${SKIP_JS}" -eq 0 ]]; then
    log_stage "6" "JavaScript Analysis, Route Filtering & Secret Mining"

    log_info "Extracting and deduplicating JavaScript URLs..."
    
    # 6.1: Filter JS files from endpoints and live URLs (strictly in-scope)
    if [[ -s "${ENDPOINTS_FILE}" ]]; then
        grep -iE '\.js(\?|$)' "${ENDPOINTS_FILE}" | grep -Ei "^https?://([a-zA-Z0-9_-]+\.)*${ESCAPED_DOMAIN}" | sort -u >> "${JS_URLS_FILE}" || true
    fi
    
    if [[ -s "${WEB_URLS}" ]]; then
        grep -iE '\.js(\?|$)' "${WEB_URLS}" | grep -Ei "^https?://([a-zA-Z0-9_-]+\.)*${ESCAPED_DOMAIN}" | sort -u >> "${JS_URLS_FILE}" || true
    fi

    sort -u -o "${JS_URLS_FILE}" "${JS_URLS_FILE}" 2>/dev/null || true
    JS_COUNT=$(wc -l < "${JS_URLS_FILE}" || echo "0")
    log_success "Identified ${BOLD}${JS_COUNT}${NC} unique in-scope JavaScript URLs."

    # 6.2: Python-based JS Inspector (Endpoints & High-Fidelity Secret Patterns)
    if [[ "${JS_COUNT}" -gt 0 ]]; then
        log_info "Analyzing JavaScript files with entropy checks and false-positive suppression..."
        
        python3 - "${JS_URLS_FILE}" "${JS_ENDPOINTS_FILE}" "${JS_SECRETS_FILE}" "${JS_SECRETS_REDACTED}" "${THREADS}" "${RATE_LIMIT}" "${DELAY}" << 'PYEOF'
import sys
import re
import math
import time
import threading
import urllib.request
import ssl
from concurrent.futures import ThreadPoolExecutor

js_urls_file, ep_out_file, sec_out_file, sec_redacted_file, threads_str, rate_str, delay_str = sys.argv[1:8]
threads = max(1, min(int(threads_str), 30))
try:
    delay_sec = float(delay_str)
except ValueError:
    delay_sec = 0.0

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

# 1. Ignore 3rd-party vendor and analytics libraries (massive source of false positives)
VENDOR_BLACKLIST = re.compile(
    r'(jquery|bootstrap|react|vue|angular|gtm|analytics|sentry|recaptcha|polyfill|moment|lodash|clarity|intercom|segment|newrelic|tinymce|ckeditor|mathjax|core-js)\b',
    re.I
)

# 2. Known false-positive strings / placeholder keywords
FP_KEYWORDS = {
    "example", "sample", "dummy", "placeholder", "undefined", "null", 
    "your_key", "your_secret", "changeme", "default", "xxxx", "test",
    "true", "false", "bearer", "authorization", "none", "secret_key"
}

def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy to ensure value is random enough to be a real secret."""
    if not data:
        return 0.0
    entropy = 0.0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        entropy += - p_x * math.log2(p_x)
    return entropy

def is_valid_secret(val: str, min_entropy: float = 3.2) -> bool:
    v_clean = val.strip().strip("'\"").lower()
    if len(v_clean) < 12:
        return False
    if any(fp in v_clean for fp in FP_KEYWORDS):
        return False
    if re.match(r'^(.)\1+$', v_clean): # e.g. 00000000000000
        return False
    return shannon_entropy(val) >= min_entropy

def mask_secret(val: str) -> str:
    """Redact secret string to first 4 characters for safe reporting."""
    clean = val.strip().strip("'\"")
    if len(clean) <= 6:
        return "****REDACTED"
    return clean[:4] + "****REDACTED"

SECRET_PATTERNS = [
    ("AWS Access Key", re.compile(r'\bAKIA[0-9A-Z]{16}\b')),
    ("Google API Key", re.compile(r'\bAIza[0-9A-Za-z\-_]{35}\b')),
    ("Slack Webhook", re.compile(r'https://hooks\.slack\.com/services/T[0-9A-Z]{8,12}/B[0-9A-Z]{8,12}/[0-9a-zA-Z]{24}')),
    ("Slack Bot Token", re.compile(r'\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*\b')),
    ("Stripe Secret Key", re.compile(r'\bsk_live_[0-9a-zA-Z]{24,}\b')),
    ("GitHub Personal Access Token", re.compile(r'\bgh[pousr]_[0-9a-zA-Z]{36}\b')),
    ("GitLab Personal Access Token", re.compile(r'\bglpat-[0-9a-zA-Z_\-]{20}\b')),
    ("JSON Web Token", re.compile(r'\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-\.\+\/=]{10,}\b')),
    ("Private RSA/DSA/EC Key", re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----')),
    ("High-Entropy Secret Variable", re.compile(r'["\'](?:api_?secret|client_?secret|jwt_?secret|auth_?token)["\']\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']', re.I))
]

# Refined Endpoint Pattern: Discard CSS/fonts/images/source-maps
EP_PATTERN = re.compile(r'["\'](/(?:api|v[0-9]|rest|graphql)/[a-zA-Z0-9_\-\./\?=&%]+)["\']', re.I)
STATIC_EXTS = re.compile(r'\.(png|jpg|jpeg|gif|svg|ico|css|woff|woff2|ttf|eot|map)$', re.I)

with open(js_urls_file, "r", encoding="utf-8", errors="ignore") as f:
    urls = [
        line.strip() for line in f 
        if line.strip().startswith("http") and not VENDOR_BLACKLIST.search(line)
    ]

endpoints_found = set()
secrets_found = set()
secrets_redacted = set()
lock = threading.Lock()

def scan_url(url):
    if delay_sec > 0:
        time.sleep(delay_sec)
    try:
        req = urllib.request.Request(
            url, 
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        )
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            content_type = resp.headers.get("Content-Type", "").lower()
            is_js_ext = bool(re.search(r'\.js(\?|$)', url, re.I))
            valid_ct = any(t in content_type for t in ("javascript", "ecmascript", "json", "text"))
            if not is_js_ext and not valid_ct:
                return
            content = resp.read(2 * 1024 * 1024).decode("utf-8", errors="ignore") # Max 2MB per file
            
            local_eps = set()
            local_secs = set()
            local_redacted = set()

            # 1. Extract API Endpoints
            for match in EP_PATTERN.findall(content):
                if not STATIC_EXTS.search(match.split("?")[0]):
                    local_eps.add(f"{match} (from {url})")
            
            # 2. Extract Sensitive Credentials
            for name, pat in SECRET_PATTERNS:
                for match in pat.findall(content):
                    candidate = match[0] if isinstance(match, tuple) else match
                    if name in ("High-Entropy Secret Variable", "JSON Web Token"):
                        if not is_valid_secret(candidate, min_entropy=3.3):
                            continue
                    local_secs.add(f"[{name}] {candidate} (in {url})")
                    local_redacted.add(f"[{name}] {mask_secret(candidate)} (in {url})")

            with lock:
                endpoints_found.update(local_eps)
                secrets_found.update(local_secs)
                secrets_redacted.update(local_redacted)
    except Exception:
        pass

with ThreadPoolExecutor(max_workers=threads) as executor:
    executor.map(scan_url, urls)

with open(ep_out_file, "w", encoding="utf-8") as f:
    for ep in sorted(endpoints_found):
        f.write(ep + "\n")

with open(sec_out_file, "w", encoding="utf-8") as f:
    for sec in sorted(secrets_found):
        f.write(sec + "\n")

with open(sec_redacted_file, "w", encoding="utf-8") as f:
    for sec in sorted(secrets_redacted):
        f.write(sec + "\n")
PYEOF
        
        EXT_EP_COUNT=$(wc -l < "${JS_ENDPOINTS_FILE}" || echo "0")
        EXT_SEC_COUNT=$(wc -l < "${JS_SECRETS_FILE}" || echo "0")
        log_success "Extracted ${BOLD}${EXT_EP_COUNT}${NC} API endpoints & ${BOLD}${EXT_SEC_COUNT}${NC} validated secrets from proprietary JS."
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
    echo "- **Open Ports/Services:** $(wc -l < "${OPEN_PORTS}" || echo "0")"
    echo "- **Crawled Endpoints:** $(wc -l < "${ENDPOINTS_FILE}" || echo "0")"
    echo "- **In-Scope JavaScript Files:** $(wc -l < "${JS_URLS_FILE}" || echo "0")"
    echo "- **Extracted JS Routes:** $(wc -l < "${JS_ENDPOINTS_FILE}" || echo "0")"
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
        echo "## 🔌 Discovered Open Ports (Origin Hosts)"
        echo "\`\`\`text"
        cat "${OPEN_PORTS}"
        echo "\`\`\`"
        echo ""
    fi
    if [[ -s "${JS_SECRETS_REDACTED}" ]]; then
        echo "---"
        echo ""
        echo "## 🔑 Discovered Secrets in JS (Redacted)"
        echo "\`\`\`text"
        head -n 25 "${JS_SECRETS_REDACTED}"
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
    echo "- **Extracted JS Secrets (Redacted):** \`${TARGET_DIR}/js/js_secrets_redacted.txt\`"
} > "${REPORT_FILE}"

log_stage "COMPLETE" "Recon Workflow Finished"
log_success "Full summary report generated: ${BOLD}${REPORT_FILE}${NC}"
echo -e "${CYAN}------------------------------------------------------------${NC}\n"
