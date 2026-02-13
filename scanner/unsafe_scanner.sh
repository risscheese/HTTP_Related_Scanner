#!/bin/bash
# ============================================================
# unsafe_methods.sh - HTTP Unsafe Methods Scanner
# Checks for dangerous/unsafe HTTP methods on target URLs
# ============================================================
# Status code logic (no false positives):
#   PUT:    201=Created, 200=Updated, 204=No Content, 202=Accepted → CRITICAL
#   DELETE: 204=Deleted, 200=Deleted w/body, 202=Accepted         → CRITICAL
#   TRACE:  200 only flagged if body reflection confirmed (XST)
#   DEBUG:  200 only flagged if ASP.NET headers present
# ============================================================

METHODS=("OPTIONS" "TRACE" "PUT" "DELETE" "DEBUG")

# 2. Dependency check
if ! command -v curl &>/dev/null; then
    echo "[ERROR] curl is not installed. Please install curl and retry."
    exit 1
fi

# 3. Check for input file
if [ -z "$1" ]; then
    echo "Usage: ./unsafe_methods.sh <url_list.txt>"
    exit 1
fi

if [ ! -f "$1" ]; then
    echo "[ERROR] File not found: $1"
    exit 1
fi

echo "[-] Scanning for Unsafe Methods: ${METHODS[*]}"
echo "[-] Target List: $1"
echo "---------------------------------------------------"

# 4. Loop through URLs (strip Windows \r line endings)
tr -d '\r' < "$1" | while read -r url; do
    [ -z "$url" ] && continue
    echo "[*] Checking: $url"

    for method in "${METHODS[@]}"; do

        # --------------------------------------------------------
        # TRACE requires a full request (not HEAD/-I) to detect
        # Cross-Site Tracing (XST) via reflected body.
        # All other methods use -D - -o /dev/null to get headers only.
        # --------------------------------------------------------
        if [ "$method" == "TRACE" ]; then
            # Capture BOTH headers (-D -) AND body - needed to confirm XST reflection
            RESPONSE=$(curl -s -X TRACE \
                --connect-timeout 10 \
                --max-time 15 \
                -D - \
                "$url" 2>/dev/null)
        else
            # FIX: Use -D - -o /dev/null instead of -I.
            #      -I sends HEAD which can behave differently server-side.
            #      -D - dumps headers to stdout; -o /dev/null discards body.
            # FIX: Removed -L for PUT/DELETE to prevent redirect-induced false positives.
            if [[ "$method" == "PUT" || "$method" == "DELETE" ]]; then
                RESPONSE=$(curl -s -X "$method" \
                    --connect-timeout 10 \
                    --max-time 15 \
                    -D - \
                    -o /dev/null \
                    "$url" 2>/dev/null)
            else
                RESPONSE=$(curl -s -X "$method" \
                    --connect-timeout 10 \
                    --max-time 15 \
                    -L \
                    -D - \
                    -o /dev/null \
                    "$url" 2>/dev/null)
            fi
        fi

        # FIX: Use awk instead of cut -d$' ' which fails in many environments.
        #      Also strip \r (CRLF) from curl's raw header output.
        CLEAN_RESPONSE=$(echo "$RESPONSE" | tr -d '\r')
        CODE=$(echo "$CLEAN_RESPONSE" | head -n 1 | awk '{print $2}')

        # --------------------------------------------------------
        # Per-method logic
        # --------------------------------------------------------
        if [ "$method" == "OPTIONS" ]; then
            ALLOW=$(echo "$CLEAN_RESPONSE" | grep -i "^Allow:")
            if [ -n "$ALLOW" ]; then
                echo -e "    \e[36m[INFO] OPTIONS: ${ALLOW}\e[0m"
            else
                echo -e "    \e[37m[INFO] OPTIONS: No Allow header returned (Status: ${CODE:-N/A})\e[0m"
            fi

        # --------------------------------------------------------
        # TRACE - confirm XST by checking body for reflected request.
        # A generic 200 from a catch-all handler is a false positive.
        # Real TRACE reflection: response body starts with "TRACE / HTTP"
        # --------------------------------------------------------
        elif [ "$method" == "TRACE" ]; then
            if [[ "$CODE" == "200" ]]; then
                if echo "$RESPONSE" | grep -qi "^TRACE"; then
                    echo -e "    \e[31m[VULN] TRACE Allowed - XST Confirmed (request reflected in body)\e[0m"
                else
                    echo -e "    \e[33m[WARN] TRACE returned 200 but no body reflection found (possible false positive)\e[0m"
                fi
            elif [[ "$CODE" == "405" || "$CODE" == "501" ]]; then
                echo -e "    \e[32m[OK]   TRACE Disabled (Status: $CODE)\e[0m"
            else
                echo -e "    \e[37m[INFO] TRACE Status: ${CODE:-N/A}\e[0m"
            fi

        # --------------------------------------------------------
        # PUT - each code has a specific meaning, not just "any 2xx"
        #   201 = new resource CREATED          → definitive CRITICAL
        #   200 = existing resource UPDATED     → definitive CRITICAL
        #   204 = success, no body              → definitive CRITICAL
        #   202 = request accepted (async)      → definitive CRITICAL
        #   207 = WebDAV multi-status           → method accepted, CRITICAL
        # --------------------------------------------------------
        elif [ "$method" == "PUT" ]; then
            if [[ "$CODE" == "201" ]]; then
                echo -e "    \e[31m[CRITICAL] PUT Allowed - New resource CREATED (Status: 201)\e[0m"
            elif [[ "$CODE" == "200" || "$CODE" == "204" ]]; then
                echo -e "    \e[31m[CRITICAL] PUT Allowed - Resource accepted/updated (Status: $CODE)\e[0m"
            elif [[ "$CODE" == "202" ]]; then
                echo -e "    \e[31m[CRITICAL] PUT Accepted async - likely enabled (Status: 202)\e[0m"
            elif [[ "$CODE" == "207" ]]; then
                echo -e "    \e[31m[CRITICAL] PUT WebDAV Multi-Status - method accepted (Status: 207)\e[0m"
            elif [[ "$CODE" == "403" ]]; then
                echo -e "    \e[33m[WARN] PUT Forbidden (403) - Method exists, access control blocks it\e[0m"
            elif [[ "$CODE" == "401" || "$CODE" == "407" ]]; then
                echo -e "    \e[33m[WARN] PUT Requires Authentication (Status: $CODE) - may exist behind auth\e[0m"
            elif [[ "$CODE" == "405" || "$CODE" == "501" ]]; then
                echo -e "    \e[32m[OK]   PUT Not Allowed (Status: $CODE)\e[0m"
            else
                echo -e "    \e[37m[INFO] PUT Status: ${CODE:-N/A}\e[0m"
            fi

        # --------------------------------------------------------
        # DELETE - same principle: enumerate exact codes
        #   204 = deleted, no body              → most common success
        #   200 = deleted with response body
        #   202 = accepted (async delete)
        # --------------------------------------------------------
        elif [ "$method" == "DELETE" ]; then
            if [[ "$CODE" == "204" ]]; then
                echo -e "    \e[31m[CRITICAL] DELETE Allowed - Resource deleted, no body (Status: 204)\e[0m"
            elif [[ "$CODE" == "200" || "$CODE" == "202" ]]; then
                echo -e "    \e[31m[CRITICAL] DELETE Allowed/Accepted (Status: $CODE)\e[0m"
            elif [[ "$CODE" == "207" ]]; then
                echo -e "    \e[31m[CRITICAL] DELETE WebDAV Multi-Status - method accepted (Status: 207)\e[0m"
            elif [[ "$CODE" == "403" ]]; then
                echo -e "    \e[33m[WARN] DELETE Forbidden (403) - Method exists, access control blocks it\e[0m"
            elif [[ "$CODE" == "401" || "$CODE" == "407" ]]; then
                echo -e "    \e[33m[WARN] DELETE Requires Authentication (Status: $CODE) - may exist behind auth\e[0m"
            elif [[ "$CODE" == "405" || "$CODE" == "501" ]]; then
                echo -e "    \e[32m[OK]   DELETE Not Allowed (Status: $CODE)\e[0m"
            else
                echo -e "    \e[37m[INFO] DELETE Status: ${CODE:-N/A}\e[0m"
            fi

        # --------------------------------------------------------
        # DEBUG (ASP.NET specific)
        # 200 alone is not enough - confirm via ASP.NET response headers
        # to avoid false positives on non-.NET servers
        # --------------------------------------------------------
        elif [ "$method" == "DEBUG" ]; then
            if [[ "$CODE" == "200" ]]; then
                ASPNET=$(echo "$CLEAN_RESPONSE" | grep -i "X-AspNet-Version\|X-Powered-By:.*ASP")
                if [ -n "$ASPNET" ]; then
                    echo -e "    \e[31m[VULN] DEBUG Enabled on ASP.NET server (Status: 200 + ASP.NET headers confirmed)\e[0m"
                else
                    echo -e "    \e[33m[WARN] DEBUG returned 200 but no ASP.NET headers found (possible false positive)\e[0m"
                fi
            elif [[ "$CODE" == "405" || "$CODE" == "501" ]]; then
                echo -e "    \e[32m[OK]   DEBUG Not Allowed (Status: $CODE)\e[0m"
            else
                echo -e "    \e[37m[INFO] DEBUG Status: ${CODE:-N/A}\e[0m"
            fi
        fi

    done
    echo "" # Blank line between URLs for readability
done
