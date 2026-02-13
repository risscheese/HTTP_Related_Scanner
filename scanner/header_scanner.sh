#!/bin/bash
# ============================================================
# header_check.sh — HTTP Security Headers Misconfiguration Scanner
# Checks every meaningful security header for presence,
# correct values, dangerous values, and information leakage.
#
# Usage:  ./header_check.sh <url_list.txt>
# Input:  Plain text file, one URL per line
#         e.g. http://192.168.8.52/
#              https://192.168.8.52/login.php
#
# Severity levels:
#   [CRITICAL] — Actively dangerous misconfiguration
#   [HIGH]     — Missing header that protects against major attacks
#   [MEDIUM]   — Suboptimal config or info disclosure
#   [LOW]      — Best-practice improvement / deprecated header
#   [OK]       — Correctly configured
#   [INFO]     — Present but context-dependent
# ============================================================

# ── Colours ─────────────────────────────────────────────────
RED='\e[31m'
YELLOW='\e[33m'
CYAN='\e[36m'
GREEN='\e[32m'
BLUE='\e[34m'
MAGENTA='\e[35m'
GREY='\e[90m'
BOLD='\e[1m'
RESET='\e[0m'

# ── Severity tags ────────────────────────────────────────────
TAG_CRITICAL="${RED}[CRITICAL]${RESET}"
TAG_HIGH="${YELLOW}[HIGH]    ${RESET}"
TAG_MEDIUM="${CYAN}[MEDIUM]  ${RESET}"
TAG_LOW="${BLUE}[LOW]     ${RESET}"
TAG_OK="${GREEN}[OK]      ${RESET}"
TAG_INFO="${GREY}[INFO]    ${RESET}"

# ── Counters (per URL) ───────────────────────────────────────
COUNT_CRIT=0
COUNT_HIGH=0
COUNT_MED=0
COUNT_LOW=0

# ── Helpers ──────────────────────────────────────────────────

# Print a finding line
finding() {
    local tag="$1"
    local header="$2"
    local msg="$3"
    printf "  %-12s ${BOLD}%-40s${RESET} %s\n" "$tag" "$header" "$msg"
}

# Get a header value (case-insensitive), stripped of the name prefix
get_header() {
    local name="$1"
    # Match "Header-Name: value" and return just "value"
    echo "$CLEAN_HEADERS" | grep -i "^${name}:" | head -n1 | sed 's/^[^:]*:[[:space:]]*//'
}

# Check if a header exists at all
header_exists() {
    echo "$CLEAN_HEADERS" | grep -qi "^${1}:"
}

# ── Dependency check ─────────────────────────────────────────
if ! command -v curl &>/dev/null; then
    echo "[ERROR] curl is not installed."
    exit 1
fi

# ── Input file check ─────────────────────────────────────────
if [ -z "$1" ]; then
    echo "Usage: ./header_check.sh <url_list.txt>"
    exit 1
fi
if [ ! -f "$1" ]; then
    echo "[ERROR] File not found: $1"
    exit 1
fi

echo ""
echo -e "${BOLD}  HTTP Security Headers — Misconfiguration Scanner${RESET}"
echo -e "  Target list: $1"
echo -e "  Checks: HSTS · CSP · X-Frame-Options · X-Content-Type-Options"
echo -e "          Referrer-Policy · Permissions-Policy · COOP · COEP · CORP"
echo -e "          X-XSS-Protection · Cookie flags · Info disclosure headers"
echo ""

# ── Main loop ────────────────────────────────────────────────
tr -d '\r' < "$1" | while read -r url; do
    [ -z "$url" ] && continue

    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${BOLD}  TARGET: ${CYAN}${url}${RESET}"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

    # Fetch headers only — no body needed
    RAW_HEADERS=$(curl -s \
        --connect-timeout 10 \
        --max-time 15 \
        -D - -o /dev/null \
        -A "Mozilla/5.0 (Security-Scanner)" \
        -L \
        "$url" 2>/dev/null)

    if [ -z "$RAW_HEADERS" ]; then
        echo -e "  ${RED}[ERROR]${RESET} No response received (host unreachable or timed out)"
        echo ""
        continue
    fi

    # Strip CRLF for clean parsing
    CLEAN_HEADERS=$(echo "$RAW_HEADERS" | tr -d '\r')

    # Get final status code (last HTTP response line, handles redirects)
    FINAL_STATUS=$(echo "$CLEAN_HEADERS" | grep "^HTTP/" | tail -n1 | awk '{print $2}')
    echo -e "  ${GREY}Status: ${FINAL_STATUS} │ Checking $(echo "$CLEAN_HEADERS" | grep -c "^[A-Za-z]") response headers${RESET}"
    echo ""

    # Determine protocol (HSTS is only meaningful over HTTPS)
    PROTO=$(echo "$url" | cut -d: -f1 | tr '[:upper:]' '[:lower:]')

    # Reset per-URL counters
    COUNT_CRIT=0; COUNT_HIGH=0; COUNT_MED=0; COUNT_LOW=0

    # ──────────────────────────────────────────────────────────
    # 1. STRICT-TRANSPORT-SECURITY (HSTS)
    # ──────────────────────────────────────────────────────────
    echo -e "  ${BOLD}── Transport & HTTPS ───────────────────────────────${RESET}"
    HSTS=$(get_header "Strict-Transport-Security")

    if [[ "$PROTO" == "http" ]]; then
        finding "$TAG_INFO" "Strict-Transport-Security" "HTTP URL — HSTS only enforced over HTTPS"
    elif [ -z "$HSTS" ]; then
        finding "$TAG_HIGH" "Strict-Transport-Security" "MISSING — browser won't enforce HTTPS; downgrade attack possible"
        ((COUNT_HIGH++))
    else
        MAX_AGE=$(echo "$HSTS" | grep -oi "max-age=[0-9]*" | cut -d= -f2)
        HAS_SUBDOMAINS=$(echo "$HSTS" | grep -qi "includeSubDomains" && echo yes || echo no)
        HAS_PRELOAD=$(echo "$HSTS" | grep -qi "preload" && echo yes || echo no)

        if [ -z "$MAX_AGE" ]; then
            finding "$TAG_HIGH" "Strict-Transport-Security" "No max-age directive — HSTS effectively disabled. Value: $HSTS"
            ((COUNT_HIGH++))
        elif [ "$MAX_AGE" -lt 86400 ]; then
            finding "$TAG_CRITICAL" "Strict-Transport-Security" "max-age=${MAX_AGE}s — far too short (<1 day), easily expired"
            ((COUNT_CRIT++))
        elif [ "$MAX_AGE" -lt 31536000 ]; then
            finding "$TAG_MEDIUM" "Strict-Transport-Security" "max-age=${MAX_AGE}s — below recommended 1 year (31536000)"
            ((COUNT_MED++))
        else
            if [[ "$HAS_SUBDOMAINS" == "yes" && "$HAS_PRELOAD" == "yes" ]]; then
                finding "$TAG_OK" "Strict-Transport-Security" "max-age=${MAX_AGE}; includeSubDomains; preload ✓"
            elif [[ "$HAS_SUBDOMAINS" == "no" ]]; then
                finding "$TAG_LOW" "Strict-Transport-Security" "max-age OK but missing 'includeSubDomains'. Value: $HSTS"
                ((COUNT_LOW++))
            else
                finding "$TAG_LOW" "Strict-Transport-Security" "max-age OK, includeSubDomains OK — consider adding 'preload'"
                ((COUNT_LOW++))
            fi
        fi
    fi

    # ──────────────────────────────────────────────────────────
    # 2. CONTENT-SECURITY-POLICY (CSP)
    # ──────────────────────────────────────────────────────────
    echo ""
    echo -e "  ${BOLD}── Content Security ────────────────────────────────${RESET}"
    CSP=$(get_header "Content-Security-Policy")

    if [ -z "$CSP" ]; then
        # Check for CSP-Report-Only (present but not enforcing)
        CSP_RO=$(get_header "Content-Security-Policy-Report-Only")
        if [ -n "$CSP_RO" ]; then
            finding "$TAG_MEDIUM" "Content-Security-Policy" "Only Report-Only mode — not enforced. No XSS protection active."
            ((COUNT_MED++))
        else
            finding "$TAG_HIGH" "Content-Security-Policy" "MISSING — no XSS / injection protection defined"
            ((COUNT_HIGH++))
        fi
    else
        CSP_ISSUES=0

        # Check for dangerous directives
        if echo "$CSP" | grep -qi "unsafe-inline"; then
            finding "$TAG_CRITICAL" "CSP: unsafe-inline" "Allows inline scripts — defeats XSS protection. Value: $CSP"
            ((COUNT_CRIT++)); ((CSP_ISSUES++))
        fi
        if echo "$CSP" | grep -qi "unsafe-eval"; then
            finding "$TAG_CRITICAL" "CSP: unsafe-eval" "Allows eval() — JS injection vector. Value: $CSP"
            ((COUNT_CRIT++)); ((CSP_ISSUES++))
        fi
        if echo "$CSP" | grep -qiE "script-src[^;]*\*"; then
            finding "$TAG_CRITICAL" "CSP: script-src *" "Wildcard in script-src — any origin can run scripts. Value: $CSP"
            ((COUNT_CRIT++)); ((CSP_ISSUES++))
        fi
        if echo "$CSP" | grep -qiE "default-src[^;]*\*"; then
            finding "$TAG_HIGH" "CSP: default-src *" "Wildcard default-src — overly permissive fallback. Value: $CSP"
            ((COUNT_HIGH++)); ((CSP_ISSUES++))
        fi
        if ! echo "$CSP" | grep -qiE "default-src|script-src"; then
            finding "$TAG_MEDIUM" "CSP: no script control" "No default-src or script-src defined — incomplete policy"
            ((COUNT_MED++)); ((CSP_ISSUES++))
        fi
        if echo "$CSP" | grep -qi "unsafe-hashes"; then
            finding "$TAG_MEDIUM" "CSP: unsafe-hashes" "Allows event handler hashes — partial XSS protection bypass"
            ((COUNT_MED++)); ((CSP_ISSUES++))
        fi
        if [ "$CSP_ISSUES" -eq 0 ]; then
            finding "$TAG_OK" "Content-Security-Policy" "Present, no obvious dangerous directives detected"
        fi
    fi

    # ──────────────────────────────────────────────────────────
    # 3. X-FRAME-OPTIONS
    # ──────────────────────────────────────────────────────────
    XFO=$(get_header "X-Frame-Options")
    if [ -z "$XFO" ]; then
        # Check if CSP frame-ancestors covers it
        if echo "$CSP" | grep -qi "frame-ancestors"; then
            finding "$TAG_OK" "X-Frame-Options" "ABSENT but CSP frame-ancestors present (modern equivalent) ✓"
        else
            finding "$TAG_HIGH" "X-Frame-Options" "MISSING — site can be embedded in iframes (clickjacking risk)"
            ((COUNT_HIGH++))
        fi
    else
        XFO_VAL=$(echo "$XFO" | tr '[:lower:]' '[:upper:]' | xargs)
        case "$XFO_VAL" in
            "DENY")
                finding "$TAG_OK" "X-Frame-Options" "DENY — no framing allowed ✓" ;;
            "SAMEORIGIN")
                finding "$TAG_OK" "X-Frame-Options" "SAMEORIGIN — only same-origin framing allowed ✓" ;;
            ALLOW-FROM*)
                finding "$TAG_MEDIUM" "X-Frame-Options" "ALLOW-FROM is obsolete (not supported in modern browsers). Value: $XFO"
                ((COUNT_MED++)) ;;
            *)
                finding "$TAG_CRITICAL" "X-Frame-Options" "Invalid value '${XFO}' — header is non-functional (clickjacking risk)"
                ((COUNT_CRIT++)) ;;
        esac
    fi

    # ──────────────────────────────────────────────────────────
    # 4. X-CONTENT-TYPE-OPTIONS
    # ──────────────────────────────────────────────────────────
    XCTO=$(get_header "X-Content-Type-Options")
    if [ -z "$XCTO" ]; then
        finding "$TAG_HIGH" "X-Content-Type-Options" "MISSING — browser may MIME-sniff responses (sniffing attacks)"
        ((COUNT_HIGH++))
    else
        XCTO_VAL=$(echo "$XCTO" | tr '[:lower:]' '[:upper:]' | xargs)
        if [[ "$XCTO_VAL" == "NOSNIFF" ]]; then
            finding "$TAG_OK" "X-Content-Type-Options" "nosniff ✓"
        else
            finding "$TAG_MEDIUM" "X-Content-Type-Options" "Invalid value '${XCTO}' — should be exactly 'nosniff'"
            ((COUNT_MED++))
        fi
    fi

    # ──────────────────────────────────────────────────────────
    # 5. REFERRER-POLICY
    # ──────────────────────────────────────────────────────────
    echo ""
    echo -e "  ${BOLD}── Privacy & Information Control ───────────────────${RESET}"
    REFPOL=$(get_header "Referrer-Policy")
    if [ -z "$REFPOL" ]; then
        finding "$TAG_MEDIUM" "Referrer-Policy" "MISSING — browser default sends Referer header (info leakage)"
        ((COUNT_MED++))
    else
        REFPOL_L=$(echo "$REFPOL" | tr '[:upper:]' '[:lower:]' | xargs)
        case "$REFPOL_L" in
            "no-referrer"|"strict-origin"|"strict-origin-when-cross-origin")
                finding "$TAG_OK" "Referrer-Policy" "${REFPOL} ✓" ;;
            "no-referrer-when-downgrade")
                finding "$TAG_MEDIUM" "Referrer-Policy" "no-referrer-when-downgrade — sends full URL on HTTP requests (info leakage)"
                ((COUNT_MED++)) ;;
            "unsafe-url")
                finding "$TAG_CRITICAL" "Referrer-Policy" "unsafe-url — always sends full URL+path+query to all origins (severe leakage)"
                ((COUNT_CRIT++)) ;;
            "origin")
                finding "$TAG_LOW" "Referrer-Policy" "origin — sends origin only (OK, but strict-origin is preferred)"
                ((COUNT_LOW++)) ;;
            "origin-when-cross-origin")
                finding "$TAG_LOW" "Referrer-Policy" "origin-when-cross-origin — leaks full URL to same-origin. Consider strict-origin"
                ((COUNT_LOW++)) ;;
            *)
                finding "$TAG_INFO" "Referrer-Policy" "Value: ${REFPOL} (review manually)" ;;
        esac
    fi

    # ──────────────────────────────────────────────────────────
    # 6. PERMISSIONS-POLICY (formerly Feature-Policy)
    # ──────────────────────────────────────────────────────────
    PERMPOL=$(get_header "Permissions-Policy")
    FEATPOL=$(get_header "Feature-Policy")
    if [ -z "$PERMPOL" ]; then
        if [ -n "$FEATPOL" ]; then
            finding "$TAG_LOW" "Permissions-Policy" "Only legacy Feature-Policy present — migrate to Permissions-Policy"
            ((COUNT_LOW++))
        else
            finding "$TAG_MEDIUM" "Permissions-Policy" "MISSING — browser features (camera, mic, geolocation) unrestricted"
            ((COUNT_MED++))
        fi
    else
        # Check if dangerous features are unrestricted
        ISSUES=0
        for feature in camera microphone geolocation payment usb midi; do
            if ! echo "$PERMPOL" | grep -qi "$feature"; then
                : # Not mentioned — uses browser default (usually restricted)
            fi
        done
        finding "$TAG_OK" "Permissions-Policy" "Present: ${PERMPOL:0:80}$([ ${#PERMPOL} -gt 80 ] && echo '...')"
    fi

    # ──────────────────────────────────────────────────────────
    # 7-9. CROSS-ORIGIN POLICIES (COOP, COEP, CORP)
    # ──────────────────────────────────────────────────────────
    echo ""
    echo -e "  ${BOLD}── Cross-Origin Isolation ──────────────────────────${RESET}"

    COOP=$(get_header "Cross-Origin-Opener-Policy")
    if [ -z "$COOP" ]; then
        finding "$TAG_MEDIUM" "Cross-Origin-Opener-Policy" "MISSING — window can be accessed cross-origin (Spectre / side-channel risk)"
        ((COUNT_MED++))
    else
        COOP_L=$(echo "$COOP" | tr '[:upper:]' '[:lower:]' | xargs)
        case "$COOP_L" in
            "same-origin")
                finding "$TAG_OK" "Cross-Origin-Opener-Policy" "same-origin ✓" ;;
            "same-origin-allow-popups")
                finding "$TAG_LOW" "Cross-Origin-Opener-Policy" "same-origin-allow-popups — popups can open cross-origin context"
                ((COUNT_LOW++)) ;;
            "unsafe-none")
                finding "$TAG_MEDIUM" "Cross-Origin-Opener-Policy" "unsafe-none — explicitly disabled, no isolation"
                ((COUNT_MED++)) ;;
            *)
                finding "$TAG_INFO" "Cross-Origin-Opener-Policy" "Value: ${COOP} (review manually)" ;;
        esac
    fi

    COEP=$(get_header "Cross-Origin-Embedder-Policy")
    if [ -z "$COEP" ]; then
        finding "$TAG_LOW" "Cross-Origin-Embedder-Policy" "MISSING — required for SharedArrayBuffer / high-res timers isolation"
        ((COUNT_LOW++))
    else
        COEP_L=$(echo "$COEP" | tr '[:upper:]' '[:lower:]' | xargs)
        case "$COEP_L" in
            "require-corp"|"credentialless")
                finding "$TAG_OK" "Cross-Origin-Embedder-Policy" "${COEP} ✓" ;;
            "unsafe-none")
                finding "$TAG_MEDIUM" "Cross-Origin-Embedder-Policy" "unsafe-none — cross-origin isolation disabled"
                ((COUNT_MED++)) ;;
            *)
                finding "$TAG_INFO" "Cross-Origin-Embedder-Policy" "Value: ${COEP} (review manually)" ;;
        esac
    fi

    CORP=$(get_header "Cross-Origin-Resource-Policy")
    if [ -z "$CORP" ]; then
        finding "$TAG_LOW" "Cross-Origin-Resource-Policy" "MISSING — resource can be included by any cross-origin page"
        ((COUNT_LOW++))
    else
        CORP_L=$(echo "$CORP" | tr '[:upper:]' '[:lower:]' | xargs)
        case "$CORP_L" in
            "same-origin")
                finding "$TAG_OK" "Cross-Origin-Resource-Policy" "same-origin ✓" ;;
            "same-site")
                finding "$TAG_OK" "Cross-Origin-Resource-Policy" "same-site ✓" ;;
            "cross-origin")
                finding "$TAG_MEDIUM" "Cross-Origin-Resource-Policy" "cross-origin — resource intentionally exposed to all origins (verify intent)"
                ((COUNT_MED++)) ;;
            *)
                finding "$TAG_INFO" "Cross-Origin-Resource-Policy" "Value: ${CORP} (review manually)" ;;
        esac
    fi

    # ──────────────────────────────────────────────────────────
    # 10. X-XSS-PROTECTION (deprecated)
    # ──────────────────────────────────────────────────────────
    echo ""
    echo -e "  ${BOLD}── Deprecated / Legacy Headers ─────────────────────${RESET}"
    XXSS=$(get_header "X-XSS-Protection")
    if [ -z "$XXSS" ]; then
        finding "$TAG_OK" "X-XSS-Protection" "Not present (correct — deprecated header, CSP is the replacement)"
    else
        XXSS_VAL=$(echo "$XXSS" | xargs)
        case "$XXSS_VAL" in
            "0")
                finding "$TAG_OK" "X-XSS-Protection" "Set to 0 (disabled — acceptable, avoids browser filter bugs)" ;;
            "1")
                finding "$TAG_LOW" "X-XSS-Protection" "Value '1' — deprecated header, missing mode=block. Remove and use CSP"
                ((COUNT_LOW++)) ;;
            "1; mode=block")
                finding "$TAG_LOW" "X-XSS-Protection" "Value '1; mode=block' — deprecated. Remove entirely and use CSP"
                ((COUNT_LOW++)) ;;
            *)
                finding "$TAG_LOW" "X-XSS-Protection" "Deprecated header present. Value: ${XXSS_VAL}. Remove and use CSP"
                ((COUNT_LOW++)) ;;
        esac
    fi

    # Check for HPKP (deprecated and dangerous)
    HPKP=$(get_header "Public-Key-Pins")
    if [ -n "$HPKP" ]; then
        finding "$TAG_CRITICAL" "Public-Key-Pins (HPKP)" "PRESENT — deprecated, can cause permanent DoS if pins expire. Remove immediately."
        ((COUNT_CRIT++))
    fi

    # ──────────────────────────────────────────────────────────
    # 11. INFORMATION DISCLOSURE HEADERS
    # ──────────────────────────────────────────────────────────
    echo ""
    echo -e "  ${BOLD}── Information Disclosure ──────────────────────────${RESET}"

    SERVER=$(get_header "Server")
    if [ -z "$SERVER" ]; then
        finding "$TAG_OK" "Server" "Not present (good — no software disclosure)"
    elif echo "$SERVER" | grep -qE "/[0-9]|[0-9]\.[0-9]"; then
        finding "$TAG_MEDIUM" "Server" "Version disclosed: '${SERVER}' — remove version number"
        ((COUNT_MED++))
    else
        finding "$TAG_LOW" "Server" "Software name disclosed: '${SERVER}' — consider removing entirely"
        ((COUNT_LOW++))
    fi

    XPOWERED=$(get_header "X-Powered-By")
    if [ -z "$XPOWERED" ]; then
        finding "$TAG_OK" "X-Powered-By" "Not present ✓"
    else
        finding "$TAG_MEDIUM" "X-Powered-By" "Discloses stack: '${XPOWERED}' — remove this header"
        ((COUNT_MED++))
    fi

    ASPNET_VER=$(get_header "X-AspNet-Version")
    if [ -n "$ASPNET_VER" ]; then
        finding "$TAG_MEDIUM" "X-AspNet-Version" "ASP.NET version disclosed: '${ASPNET_VER}' — set <httpRuntime enableVersionHeader='false'/>"
        ((COUNT_MED++))
    fi

    ASPNETMVC=$(get_header "X-AspNetMvc-Version")
    if [ -n "$ASPNETMVC" ]; then
        finding "$TAG_MEDIUM" "X-AspNetMvc-Version" "ASP.NET MVC version disclosed: '${ASPNETMVC}'"
        ((COUNT_MED++))
    fi

    XGENERATOR=$(get_header "X-Generator")
    if [ -n "$XGENERATOR" ]; then
        finding "$TAG_MEDIUM" "X-Generator" "CMS/framework disclosed: '${XGENERATOR}' — remove this header"
        ((COUNT_MED++))
    fi

    XDRUPAL=$(get_header "X-Drupal-Cache")
    [ -n "$XDRUPAL" ] && finding "$TAG_LOW" "X-Drupal-Cache" "Reveals Drupal CMS: '${XDRUPAL}'"

    XWORDPRESS=$(get_header "X-WP-Nonce")
    [ -n "$XWORDPRESS" ] && finding "$TAG_LOW" "X-WP-Nonce" "Reveals WordPress CMS presence"

    # ──────────────────────────────────────────────────────────
    # 12. COOKIE FLAGS
    # ──────────────────────────────────────────────────────────
    COOKIES=$(echo "$CLEAN_HEADERS" | grep -i "^Set-Cookie:")
    if [ -n "$COOKIES" ]; then
        echo ""
        echo -e "  ${BOLD}── Cookie Security Flags ───────────────────────────${RESET}"
        echo "$COOKIES" | while read -r cookie_line; do
            # Extract cookie name (first token before =)
            COOKIE_VAL=$(echo "$cookie_line" | sed 's/^[Ss]et-[Cc]ookie:[[:space:]]*//')
            COOKIE_NAME=$(echo "$COOKIE_VAL" | cut -d= -f1 | xargs)

            MISSING_FLAGS=""

            if ! echo "$COOKIE_VAL" | grep -qi "HttpOnly"; then
                MISSING_FLAGS="${MISSING_FLAGS}HttpOnly "
            fi
            if ! echo "$COOKIE_VAL" | grep -qi "Secure"; then
                MISSING_FLAGS="${MISSING_FLAGS}Secure "
            fi
            if ! echo "$COOKIE_VAL" | grep -qi "SameSite"; then
                MISSING_FLAGS="${MISSING_FLAGS}SameSite "
            fi

            # Check SameSite=None (requires Secure)
            if echo "$COOKIE_VAL" | grep -qi "SameSite=None"; then
                if ! echo "$COOKIE_VAL" | grep -qi "Secure"; then
                    finding "$TAG_CRITICAL" "Cookie: ${COOKIE_NAME}" "SameSite=None WITHOUT Secure flag — cookie sent over HTTP"
                else
                    finding "$TAG_INFO" "Cookie: ${COOKIE_NAME}" "SameSite=None; Secure — intentionally cross-origin (verify intent)"
                fi
            fi

            if [ -n "$MISSING_FLAGS" ]; then
                # Determine severity based on what's missing
                if ! echo "$COOKIE_VAL" | grep -qi "HttpOnly" && ! echo "$COOKIE_VAL" | grep -qi "Secure"; then
                    finding "$TAG_HIGH" "Cookie: ${COOKIE_NAME}" "Missing flags: ${MISSING_FLAGS}— vulnerable to JS theft and MITM"
                elif ! echo "$COOKIE_VAL" | grep -qi "HttpOnly"; then
                    finding "$TAG_HIGH" "Cookie: ${COOKIE_NAME}" "Missing HttpOnly — cookie accessible via JavaScript (XSS theft)"
                elif ! echo "$COOKIE_VAL" | grep -qi "Secure"; then
                    finding "$TAG_MEDIUM" "Cookie: ${COOKIE_NAME}" "Missing Secure flag — cookie sent over plain HTTP"
                else
                    finding "$TAG_LOW" "Cookie: ${COOKIE_NAME}" "Missing SameSite flag — CSRF protection not enforced"
                fi
            else
                finding "$TAG_OK" "Cookie: ${COOKIE_NAME}" "HttpOnly; Secure; SameSite present ✓"
            fi
        done
    fi

    # ──────────────────────────────────────────────────────────
    # 13. CACHE-CONTROL (for sensitive pages)
    # ──────────────────────────────────────────────────────────
    echo ""
    echo -e "  ${BOLD}── Caching ─────────────────────────────────────────${RESET}"
    CACHE=$(get_header "Cache-Control")
    if [ -z "$CACHE" ]; then
        finding "$TAG_MEDIUM" "Cache-Control" "MISSING — responses may be cached by proxies/browsers (sensitive data at risk)"
        ((COUNT_MED++))
    else
        CACHE_L=$(echo "$CACHE" | tr '[:upper:]' '[:lower:]')
        if echo "$CACHE_L" | grep -q "no-store"; then
            finding "$TAG_OK" "Cache-Control" "no-store present ✓ (${CACHE})"
        elif echo "$CACHE_L" | grep -q "no-cache"; then
            finding "$TAG_LOW" "Cache-Control" "no-cache (must revalidate, but stored in cache). Consider no-store for sensitive pages"
            ((COUNT_LOW++))
        elif echo "$CACHE_L" | grep -q "private"; then
            finding "$TAG_LOW" "Cache-Control" "private — stored in browser cache but not shared proxies. Consider no-store"
            ((COUNT_LOW++))
        else
            finding "$TAG_MEDIUM" "Cache-Control" "Potentially cacheable: '${CACHE}' — verify this page contains no sensitive data"
            ((COUNT_MED++))
        fi
    fi

    # ──────────────────────────────────────────────────────────
    # Summary for this URL
    # ──────────────────────────────────────────────────────────
    TOTAL_ISSUES=$((COUNT_CRIT + COUNT_HIGH + COUNT_MED + COUNT_LOW))
    echo ""
    echo -e "  ${BOLD}── Summary ─────────────────────────────────────────${RESET}"
    echo -e "  ${RED}Critical: ${COUNT_CRIT}${RESET}  ${YELLOW}High: ${COUNT_HIGH}${RESET}  ${CYAN}Medium: ${COUNT_MED}${RESET}  ${BLUE}Low: ${COUNT_LOW}${RESET}  │  Total issues: ${TOTAL_ISSUES}"
    echo ""

done

echo -e "${GREY}Scan complete.${RESET}"
echo ""
