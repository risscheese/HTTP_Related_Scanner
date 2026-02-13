import requests
import sys
import urllib3
from datetime import datetime

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
JUNK_METHOD = "JUNK"
TIMEOUT = 5

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    WHITE = '\033[0;37m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def scan_url(url):
    """
    Scans a single URL and returns the status category:
    'VULN', 'SAFE', 'WARN', 'INFO', or 'ERR'
    """
    try:
        # allow_redirects=False is CRITICAL to see the real code
        response = requests.request(
            method=JUNK_METHOD,
            url=url,
            verify=False,
            allow_redirects=False,
            timeout=TIMEOUT
        )
        
        code = response.status_code
        length = len(response.content)

        # --- LOGIC ---
        
        if code == 200:
            print(f"{Colors.GREEN}[VULN] {url} => {code} OK (Size: {length}){Colors.RESET}")
            return "VULN"
        
        elif code in [405, 501]:
            print(f"{Colors.BLUE}[SAFE] {url} => {code} (Blocked){Colors.RESET}")
            return "SAFE"
            
        elif code == 403:
            print(f"{Colors.YELLOW}[WARN] {url} => {code} Forbidden{Colors.RESET}")
            return "WARN"

        elif code in [301, 302]:
            location = response.headers.get('Location', 'Unknown')
            print(f"{Colors.WHITE}[INFO] {url} => {code} Redirect -> {location}{Colors.RESET}")
            return "INFO"

        else:
            print(f"[INFO] {url} => {code}")
            return "INFO"

    except requests.exceptions.Timeout:
        print(f"{Colors.RED}[ERR ] {url} => Timeout{Colors.RESET}")
        return "ERR"
    except requests.exceptions.ConnectionError:
        print(f"{Colors.RED}[ERR ] {url} => Connection Refused{Colors.RESET}")
        return "ERR"
    except Exception as e:
        print(f"{Colors.RED}[ERR ] {url} => Error: {e}{Colors.RESET}")
        return "ERR"

def main():
    if len(sys.argv) < 2:
        print(f"Usage: python3 {sys.argv[0]} <urls_list.txt>")
        sys.exit(1)

    list_file = sys.argv[1]
    
    # Initialize Counters
    stats = {
        "VULN": 0,
        "WARN": 0,
        "SAFE": 0,
        "INFO": 0,
        "ERR": 0
    }

    print(f"[-] Scanning list: {list_file}")
    print(f"[-] Method: {JUNK_METHOD}")
    print("-" * 60)

    try:
        with open(list_file, 'r') as f:
            for line in f:
                url = line.strip()
                if not url: continue
                
                # Run scan and get result type
                result_type = scan_url(url)
                
                # Increment the specific counter
                stats[result_type] += 1
                
    except FileNotFoundError:
        print(f"Error: File {list_file} not found.")
        sys.exit(1)

    # --- PRINT SUMMARY ---
    print("-" * 60)
    print(f"{Colors.BOLD}SCAN COMPLETE{Colors.RESET}")
    print("-" * 60)
    print(f"{Colors.GREEN}[+] VULNERABLE (200 OK):      {stats['VULN']}{Colors.RESET}")
    print(f"{Colors.YELLOW}[!] WARNINGS (403 Forbidden): {stats['WARN']}{Colors.RESET}")
    print(f"{Colors.BLUE}[*] SAFE (405/501 Blocked):   {stats['SAFE']}{Colors.RESET}")
    print(f"{Colors.WHITE}[i] INFO (Redirects/Others):  {stats['INFO']}{Colors.RESET}")
    print(f"{Colors.RED}[-] ERRORS (Timeout/Conn):    {stats['ERR']}{Colors.RESET}")
    print("-" * 60)
    
    total = sum(stats.values())
    print(f"Total URLs Scanned: {total}")

if __name__ == "__main__":
    main()
