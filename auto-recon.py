#!/usr/bin/env python3
"""
auto-recon.py — Subdomain Enumeration Tool
Finds subdomains via:
  1. Certificate Transparency logs (crt.sh)
  2. DNS brute-force with built-in wordlist
  3. HackerTarget passive DNS API
"""

import argparse
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib import request, error as urllib_error

# ── Built-in wordlist (extend or replace with a file via --wordlist) ───────────
DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "vpn", "m", "remote", "blog", "admin", "dev", "staging", "api", "app",
    "portal", "secure", "test", "demo", "beta", "mobile", "cdn", "static",
    "media", "img", "images", "assets", "files", "docs", "support", "help",
    "status", "monitor", "dashboard", "panel", "cp", "cpanel", "whm",
    "shop", "store", "pay", "payment", "billing", "login", "auth", "sso",
    "cloud", "gateway", "proxy", "api2", "v1", "v2", "internal", "corp",
    "intranet", "extranet", "mx", "mx1", "mx2", "email", "autodiscover",
    "autoconfig", "imap", "pop3", "exchange", "owa", "office", "sharepoint",
    "git", "gitlab", "github", "svn", "jira", "confluence", "jenkins",
    "ci", "cd", "build", "deploy", "prod", "production", "qa", "uat",
    "sandbox", "db", "database", "mysql", "postgres", "redis", "mongo",
    "backup", "archive", "old", "new", "web", "web1", "web2", "server",
    "srv1", "srv2", "host", "node", "lb", "loadbalancer", "fw", "firewall",
    "vpn1", "vpn2", "remote", "access", "citrix", "rdp",
]

CYAN   = "\033[96m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
BOLD   = "\033[1m"
RESET  = "\033[0m"


# ── Helpers ────────────────────────────────────────────────────────────────────

def banner():
    print(f"""{CYAN}{BOLD}
  ██████╗ ██████╗ ██████╗ ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
 ██╔══██╗██╔════╝██╔═══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
 ███████║██║     ██║   ██║██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
 ██╔══██║██║     ██║   ██║██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
 ██║  ██║╚██████╗╚██████╔╝██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
 ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝╚═╝  ╚═══╝
                     Subdomain Enumeration Tool{RESET}
""")


def strip_scheme(domain: str) -> str:
    """Remove http(s):// and trailing slashes."""
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    return domain.rstrip("/").split("/")[0]


def resolve(hostname: str) -> str | None:
    """Return the IPv4 address for hostname, or None if it doesn't resolve."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def fetch_json(url: str, timeout: int = 10):
    """Fetch a URL and return parsed JSON, or None on failure."""
    try:
        req = request.Request(url, headers={"User-Agent": "auto-recon/1.0"})
        with request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return None


def fetch_text(url: str, timeout: int = 10) -> str:
    """Fetch a URL and return raw text, or empty string on failure."""
    try:
        req = request.Request(url, headers={"User-Agent": "auto-recon/1.0"})
        with request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode(errors="ignore")
    except Exception:
        return ""


# ── Enumeration sources ────────────────────────────────────────────────────────

def from_crtsh(domain: str) -> set[str]:
    """Query crt.sh Certificate Transparency logs."""
    print(f"  {YELLOW}[*]{RESET} Querying crt.sh …")
    data = fetch_json(f"https://crt.sh/?q=%.{domain}&output=json")
    found: set[str] = set()
    if not data:
        print(f"  {RED}[-]{RESET} crt.sh returned no data")
        return found
    for entry in data:
        name_value = entry.get("name_value", "")
        for name in name_value.splitlines():
            name = name.strip().lstrip("*.")
            if name.endswith(f".{domain}") or name == domain:
                found.add(name.lower())
    print(f"  {GREEN}[+]{RESET} crt.sh found {len(found)} candidate(s)")
    return found


def from_hackertarget(domain: str) -> set[str]:
    """Query HackerTarget passive DNS API (free tier, no key required)."""
    print(f"  {YELLOW}[*]{RESET} Querying HackerTarget …")
    text = fetch_text(f"https://api.hackertarget.com/hostsearch/?q={domain}")
    found: set[str] = set()
    if not text or "error" in text.lower():
        print(f"  {RED}[-]{RESET} HackerTarget returned no data")
        return found
    for line in text.splitlines():
        parts = line.split(",")
        if parts:
            sub = parts[0].strip().lower()
            if sub.endswith(f".{domain}") or sub == domain:
                found.add(sub)
    print(f"  {GREEN}[+]{RESET} HackerTarget found {len(found)} candidate(s)")
    return found


def brute_force(domain: str, wordlist: list[str], threads: int) -> set[str]:
    """DNS brute-force the wordlist concurrently."""
    print(f"  {YELLOW}[*]{RESET} DNS brute-force ({len(wordlist)} words, {threads} threads) …")
    found: set[str] = set()
    targets = [f"{word}.{domain}" for word in wordlist]

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(resolve, host): host for host in targets}
        done = 0
        for future in as_completed(futures):
            done += 1
            host = futures[future]
            ip = future.result()
            if ip:
                found.add(host)
            # simple progress indicator
            if done % 50 == 0 or done == len(targets):
                print(f"\r  {YELLOW}[*]{RESET} Progress: {done}/{len(targets)}", end="", flush=True)

    print()  # newline after progress
    print(f"  {GREEN}[+]{RESET} Brute-force found {len(found)} candidate(s)")
    return found


# ── Resolution & deduplication ─────────────────────────────────────────────────

def resolve_all(candidates: set[str], threads: int) -> dict[str, str]:
    """Resolve all candidates; return {hostname: ip} for those that resolve."""
    resolved: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(resolve, host): host for host in candidates}
        for future in as_completed(futures):
            host = futures[future]
            ip = future.result()
            if ip:
                resolved[host] = ip
    return resolved


# ── Output ─────────────────────────────────────────────────────────────────────

def print_results(resolved: dict[str, str], domain: str):
    if not resolved:
        print(f"\n{RED}No live subdomains found for {domain}.{RESET}")
        return

    sorted_hosts = sorted(resolved.items())
    max_len = max(len(h) for h, _ in sorted_hosts)

    print(f"\n{BOLD}{GREEN}{'─'*60}{RESET}")
    print(f"{BOLD}{GREEN} Live subdomains for {domain} ({len(sorted_hosts)} found){RESET}")
    print(f"{BOLD}{GREEN}{'─'*60}{RESET}")
    print(f"  {'Hostname':<{max_len}}  IP Address")
    print(f"  {'─'*max_len}  ─────────────")
    for host, ip in sorted_hosts:
        print(f"  {CYAN}{host:<{max_len}}{RESET}  {ip}")
    print(f"{BOLD}{GREEN}{'─'*60}{RESET}\n")


def save_results(resolved: dict[str, str], domain: str, output_file: str):
    lines = [f"{host},{ip}" for host, ip in sorted(resolved.items())]
    with open(output_file, "w") as f:
        f.write("hostname,ip\n")
        f.write("\n".join(lines) + "\n")
    print(f"{GREEN}[+]{RESET} Results saved to {output_file}")


# ── Entry point ────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        prog="auto-recon",
        description="Subdomain enumeration via CT logs, passive DNS, and brute-force",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  python auto-recon.py -d example.com
  python auto-recon.py -d example.com --brute --wordlist subdomains.txt
  python auto-recon.py -d example.com --brute --threads 100 -o results.csv
  python auto-recon.py -d example.com --passive-only
""",
    )
    p.add_argument("-d", "--domain", required=True, help="Target domain (e.g. example.com)")
    p.add_argument("--brute", action="store_true", help="Enable DNS brute-force (default: off)")
    p.add_argument("--wordlist", metavar="FILE", help="Path to wordlist file for brute-force")
    p.add_argument("--passive-only", action="store_true", help="Only use passive sources (no DNS brute-force)")
    p.add_argument("--threads", type=int, default=50, metavar="N", help="Concurrent threads (default: 50)")
    p.add_argument("-o", "--output", metavar="FILE", help="Save results to CSV file")
    p.add_argument("--no-resolve", action="store_true", help="Skip live-host DNS verification")
    return p.parse_args()


def main():
    banner()
    args = parse_args()

    domain = strip_scheme(args.domain).lower()
    print(f"{BOLD}Target:{RESET} {CYAN}{domain}{RESET}\n")

    candidates: set[str] = set()

    # ── Passive sources ────────────────────────────────────────────────────────
    print(f"{BOLD}[1/3] Passive enumeration{RESET}")
    candidates |= from_crtsh(domain)
    time.sleep(0.5)          # be polite to free APIs
    candidates |= from_hackertarget(domain)

    # ── Brute-force ────────────────────────────────────────────────────────────
    if args.brute and not args.passive_only:
        print(f"\n{BOLD}[2/3] DNS brute-force{RESET}")
        wordlist = DEFAULT_WORDLIST
        if args.wordlist:
            try:
                with open(args.wordlist) as f:
                    wordlist = [line.strip() for line in f if line.strip()]
                print(f"  {GREEN}[+]{RESET} Loaded {len(wordlist)} words from {args.wordlist}")
            except OSError as e:
                print(f"  {RED}[-]{RESET} Could not read wordlist: {e}")
                sys.exit(1)
        candidates |= brute_force(domain, wordlist, args.threads)
    else:
        print(f"\n{BOLD}[2/3] DNS brute-force{RESET}")
        print(f"  {YELLOW}[~]{RESET} Skipped (use --brute to enable)")

    print(f"\n  Total unique candidates: {len(candidates)}")

    # ── DNS verification ───────────────────────────────────────────────────────
    print(f"\n{BOLD}[3/3] Resolving live hosts{RESET}")
    if args.no_resolve:
        print(f"  {YELLOW}[~]{RESET} Skipped (--no-resolve)")
        resolved = {h: "unverified" for h in candidates}
    else:
        print(f"  {YELLOW}[*]{RESET} Resolving {len(candidates)} candidates …")
        resolved = resolve_all(candidates, args.threads)

    # ── Output ─────────────────────────────────────────────────────────────────
    print_results(resolved, domain)

    if args.output:
        save_results(resolved, domain, args.output)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!]{RESET} Interrupted by user.")
        sys.exit(0)
