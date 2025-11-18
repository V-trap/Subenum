#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Subenum - Combined Lite/Full Subdomain Enumeration Framework
One script with two modes:
  --mode full   (advanced, threaded brute, dependency manager, APIs)
  --mode lite   (fast, simpler, fewer external calls)
"""

import argparse
import subprocess
import shutil
import sys
import os
import threading
import queue
import time
import requests

# ---------------------------
# Metadata
# ---------------------------
VERSION = "1.2.0"
AUTHOR = "YourName"

# ---------------------------
# Colors
# ---------------------------
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"

# ---------------------------
# Tools & install instructions (simplified)
# Adjust install commands to your distro if necessary
# ---------------------------
TOOLS = {
    "subfinder": {
        "check": "subfinder",
        "install_cmd": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    },
    "assetfinder": {
        "check": "assetfinder",
        "install_cmd": "go install github.com/tomnomnom/assetfinder@latest"
    },
    "amass": {
        "check": "amass",
        "install_cmd": "sudo apt update && sudo apt install -y amass"
    },
    "findomain": {
        "check": "findomain",
        "install_cmd": "sudo apt update && sudo apt install -y findomain"
    },
    "sublist3r": {
        "check": "sublist3r",
        "install_cmd": "sudo apt update && sudo apt install -y sublist3r"
    },
    "knockpy": {
        "check": "knockpy",
        "install_cmd": "git clone https://github.com/guelfoweb/knockpy.git /tmp/knockpy && cd /tmp/knockpy && sudo python3 setup.py install"
    },
    "waybackurls": {
        "check": "waybackurls",
        "install_cmd": "go install github.com/tomnomnom/waybackurls@latest"
    },
    "gau": {
        "check": "gau",
        "install_cmd": "go install github.com/lc/gau/v2/cmd/gau@latest"
    },
    "crtsh": {
        "check": None,  # crt.sh is HTTP API; treat as available
        "install_cmd": ""
    },
    "httpx": {
        "check": "httpx",
        "install_cmd": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
    },
    "massdns": {
        "check": "massdns",
        "install_cmd": "sudo apt update && sudo apt install -y massdns"
    },
    "dnsrecon": {
        "check": "dnsrecon",
        "install_cmd": "sudo apt update && sudo apt install -y dnsrecon"
    },
    "dnsenum": {
        "check": "dnsenum",
        "install_cmd": "sudo apt update && sudo apt install -y dnsenum"
    },
    "fierce": {
        "check": "fierce",
        "install_cmd": "sudo apt update && sudo apt install -y fierce"
    },
    "theHarvester": {
        "check": "theHarvester",
        "install_cmd": "sudo apt update && sudo apt install -y theharvester"
    },
    "chaos": {
        "check": "chaos",
        "install_cmd": "go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
    },
    "anubis": {
        "check": "anubis",
        "install_cmd": ""  # anubis may not be packaged; left blank as placeholder
    }
}

# Tools list used in lite and full (ensure at least 15 unique names across script)
TOOL_LIST = list(TOOLS.keys())

# ---------------------------
# Helpers
# ---------------------------
def echo(msg, color=RESET, end="\n"):
    sys.stdout.write(f"{color}{msg}{RESET}{end}")
    sys.stdout.flush()

def check_program(prog):
    """Return True if program is present in PATH, or if None (treated as API)."""
    if prog is None:
        return True
    return shutil.which(prog) is not None

def run_cmd(cmd, timeout=300):
    """Run a shell command and return stdout lines (list)."""
    try:
        proc = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        out = proc.stdout.strip().splitlines()
        return out
    except subprocess.TimeoutExpired:
        return []
    except Exception:
        return []

# ---------------------------
# Dependency manager
# ---------------------------
def install_tool_sequence(tool_name, mode):
    """Install a single tool depending on mode: auto / ask / warn"""
    info = TOOLS.get(tool_name, {})
    check = info.get("check")
    install_cmd = info.get("install_cmd", "")
    installed = check_program(check)
    if installed:
        echo(f"[+] {tool_name} already present", GREEN)
        return True

    # warn
    if mode == "warn":
        echo(f"[!] {tool_name} missing (warn mode) — skipping install", YELLOW)
        return False

    # ask
    if mode == "ask":
        resp = input(f"[?] {tool_name} not found. Install now? (y/N): ").strip().lower()
        if resp not in ("y", "yes"):
            echo(f"[-] Skipped {tool_name}", YELLOW)
            return False

    # auto or user agreed: attempt install
    if not install_cmd:
        echo(f"[!] No automatic install command for {tool_name}, please install manually.", RED)
        return False

    echo(f"[+] Installing {tool_name} ... (this may require sudo / network)", CYAN)
    return_code = os.system(install_cmd)
    if return_code == 0:
        echo(f"[+] Install command finished for {tool_name}", GREEN)
        # allow PATH changes (e.g., go bin) — do not guarantee success
        time.sleep(1)
        return check_program(check)
    else:
        echo(f"[!] Installation command returned {return_code} for {tool_name}", RED)
        return False

def dependency_manager(mode="warn"):
    echo("=== Dependency check & installer ===", CYAN)
    results = {}
    for t in TOOL_LIST:
        ok = check_program(TOOLS[t]["check"])
        if ok:
            results[t] = True
            echo(f"[+] {t} OK", GREEN)
            continue
        # try installing depending on mode
        results[t] = install_tool_sequence(t, mode)
    echo("=== Dependency check complete ===\n", CYAN)
    return results

# ---------------------------
# Subdomain enumeration helpers
# ---------------------------
def save_lines(path, lines):
    try:
        with open(path, "a", encoding="utf-8") as fh:
            for l in lines:
                fh.write(l.rstrip() + "\n")
    except Exception as e:
        echo(f"[!] Error saving to {path}: {e}", RED)

def uniq_lines(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            items = {line.strip() for line in fh if line.strip()}
        return sorted(items)
    except FileNotFoundError:
        return []

# -------------
# Python threaded brute
# -------------
def dns_brute_worker(q, domain, found):
    import dns.resolver  # local import to avoid hard dependency unless used
    while True:
        try:
            prefix = q.get(timeout=3)
        except Exception:
            break
        if prefix is None:
            break
        fqdn = f"{prefix}.{domain}"
        try:
            dns.resolver.resolve(fqdn, lifetime=3)
            found.append(fqdn)
        except Exception:
            pass
        q.task_done()

def python_dns_bruteforce(domain, wordlist, threads):
    q = queue.Queue()
    found = []
    try:
        with open(wordlist, "r", encoding="utf-8") as f:
            for line in f:
                word = line.strip()
                if word:
                    q.put(word)
    except Exception as e:
        echo(f"[!] Failed to open wordlist {wordlist}: {e}", RED)
        return found

    workers = []
    for _ in range(max(1, threads)):
        t = threading.Thread(target=dns_brute_worker, args=(q, domain, found))
        t.daemon = True
        t.start()
        workers.append(t)

    q.join()
    # signal stop
    for _ in workers:
        try:
            q.put(None)
        except Exception:
            pass
    for w in workers:
        w.join(timeout=1)
    return sorted(set(found))

# ---------------------------
# Full mode (advanced)
# ---------------------------
def run_full(domain, output, wordlist, threads, no_passive, no_api, no_brute):
    echo(f"[★] Running FULL mode for {domain}", CYAN)
    tmp_out = output + ".tmp"
    # Clear tmp file
    open(tmp_out, "w", encoding="utf-8").close()

    # Passive tools
    if not no_passive:
        echo("[*] Running passive tools", CYAN)
        if check_program("subfinder"):
            lines = run_cmd(f"subfinder -silent -d {domain}")
            save_lines(tmp_out, lines)
        if check_program("assetfinder"):
            lines = run_cmd(f"assetfinder --subs-only {domain}")
            save_lines(tmp_out, lines)
        if check_program("amass"):
            lines = run_cmd(f"amass enum -passive -d {domain}")
            save_lines(tmp_out, lines)
        if check_program("findomain"):
            lines = run_cmd(f"findomain -t {domain} --quiet")
            save_lines(tmp_out, lines)
        if check_program("sublist3r"):
            lines = run_cmd(f"sublist3r -d {domain} -o /tmp/sublist3r_{domain}.txt")
            # sublist3r outputs file - try to read if exists
            subfile = f"/tmp/sublist3r_{domain}.txt"
            if os.path.exists(subfile):
                save_lines(tmp_out, run_cmd(f"cat {subfile}"))
        # wayback + gau
        if check_program("waybackurls"):
            save_lines(tmp_out, run_cmd(f"waybackurls {domain} | cut -d'/' -f3 | sort -u"))
        if check_program("gau"):
            save_lines(tmp_out, run_cmd(f"gau {domain} | cut -d'/' -f3 | sort -u"))

    # API & CT logs
    if not no_api:
        echo("[*] Running API / CT lookups", CYAN)
        # crt.sh
        try:
            r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=8)
            data = r.json()
            for ent in data:
                nv = ent.get("name_value")
                if nv:
                    # name_value may have multiple lines
                    for sub in str(nv).splitlines():
                        save_lines(tmp_out, [sub.strip()])
        except Exception:
            pass
        # certspotter
        try:
            r = requests.get(f"https://api.certspotter.com/v1/issuances?domain={domain}&expand=dns_names", timeout=8)
            for ent in r.json():
                dns_names = ent.get("dns_names", [])
                for n in dns_names:
                    save_lines(tmp_out, [n])
        except Exception:
            pass
        # virustotal (public usage limited; requires API key for full results)
        # NOTE: user can replace header with their API key for better results
        try:
            headers = {"x-apikey": "PUBLIC-API-NO-KEY"}
            r = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains", headers=headers, timeout=8)
            for item in r.json().get("data", []):
                save_lines(tmp_out, [item.get("id")])
        except Exception:
            pass

    # Brute / DNS-based modules
    if not no_brute:
        echo("[*] Running brute / DNS tools", CYAN)
        # knockpy
        if check_program("knockpy"):
            save_lines(tmp_out, run_cmd(f"knockpy {domain} --no-color | awk '{{print $1}}'"))
        # dnsrecon
        if check_program("dnsrecon"):
            save_lines(tmp_out, run_cmd(f"dnsrecon -d {domain} -t brt | grep Name | awk '{{print $NF}}'"))
        # dnsenum
        if check_program("dnsenum"):
            save_lines(tmp_out, run_cmd(f"dnsenum {domain} --threads 5"))
        # python brute
        brute_found = python_dns_bruteforce(domain, wordlist, threads)
        save_lines(tmp_out, brute_found)

    # Alive checking with httpx (if available)
    final_out = []
    if check_program("httpx"):
        # deduplicate and feed httpx
        candidates = uniq_lines(tmp_out)
        if candidates:
            # write to a tmp file for httpx input
            feed = "/tmp/subenum_httpx_feed.txt"
            with open(feed, "w", encoding="utf-8") as fh:
                for c in candidates:
                    fh.write(c + "\n")
            try:
                alive = run_cmd(f"httpx -silent -l {feed}")
                final_out = alive
            except Exception:
                final_out = candidates
    else:
        final_out = uniq_lines(tmp_out)

    # Save final results
    final_unique = sorted(set([f.strip() for f in final_out if f and domain in f]))
    with open(output, "w", encoding="utf-8") as fh:
        for s in final_unique:
            fh.write(s + "\n")

    echo(f"[+] FULL mode finished. Results: {output} (total {len(final_unique)})", GREEN)

# ---------------------------
# Lite mode (simple / fast)
# ---------------------------
def run_lite(domain, output, no_passive, no_api, no_brute):
    echo(f"[★] Running LITE mode for {domain}", CYAN)
    open(output, "w", encoding="utf-8").close()
    # Run a fixed set of lightweight commands; write raw output
    if not no_passive:
        if check_program("subfinder"):
            save_lines(output, run_cmd(f"subfinder -silent -d {domain}"))
        elif check_program("assetfinder"):
            save_lines(output, run_cmd(f"assetfinder --subs-only {domain}"))
        else:
            echo("[!] Neither subfinder nor assetfinder available for lite passive checks", YELLOW)

    if not no_api:
        # crt.sh quick fetch
        try:
            r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=6)
            for ent in r.json():
                nv = ent.get("name_value")
                if nv:
                    for s in str(nv).splitlines():
                        save_lines(output, [s.strip()])
        except Exception:
            pass

    if not no_brute:
        # simple DNS brute using knockpy if present
        if check_program("knockpy"):
            save_lines(output, run_cmd(f"knockpy {domain} --no-color | awk '{{print $1}}'"))
        else:
            echo("[!] knockpy not available for lite brute-force", YELLOW)

    # Dedupe
    unique = sorted(set(uniq_lines(output)))
    with open(output, "w", encoding="utf-8") as fh:
        for u in unique:
            fh.write(u + "\n")

    echo(f"[+] LITE mode finished. Results: {output} (total {len(unique)})", GREEN)

# ---------------------------
# Argument parsing / main
# ---------------------------
def build_parser():
    p = argparse.ArgumentParser(prog="subenum.py", description="Subenum — Lite + Full subdomain enumerator")
    p.add_argument("-d", "--domain", required=True, help="Target domain (example.com)")
    p.add_argument("-o", "--output", default="subdomains.txt", help="Output file path")
    p.add_argument("-w", "--wordlist", default="/usr/share/wordlists/dirb/common.txt", help="Wordlist for python brute")
    p.add_argument("-t", "--threads", type=int, default=20, help="Threads for python brute")
    p.add_argument("--no-passive", action="store_true", help="Disable passive methods")
    p.add_argument("--no-api", action="store_true", help="Disable API/CT methods")
    p.add_argument("--no-brute", action="store_true", help="Disable brute-force methods")
    p.add_argument("--install", choices=["auto", "ask", "warn"], default="warn",
                   help="Dependency install mode (auto / ask / warn)")
    p.add_argument("-i", "--install-deps", action="store_true", help="Shortcut: run dependency manager (uses --install mode)")
    p.add_argument("-v", "--version", action="store_true", help="Show version")
    p.add_argument("--mode", choices=["full", "lite"], default="full", help="Run mode: full or lite")
    return p

def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.version:
        echo(f"Subenum version {VERSION} by {AUTHOR}", CYAN)
        sys.exit(0)

    # If user asked to install deps, run dependency manager with specified install mode
    if args.install_deps:
        dependency_manager(args.install)
        sys.exit(0)

    # If install mode was set to auto/ask/warn explicitly (without -i), still run manager at start
    if args.install != "warn":
        dependency_manager(args.install)

    # Ensure domain simple sanity
    domain = args.domain.strip()
    if domain.startswith("http://") or domain.startswith("https://"):
        echo("[!] Please pass root domain only (example.com), not with http(s) prefix", YELLOW)
        domain = domain.split("://", 1)[-1].split("/", 1)[0]

    # Route to chosen mode
    try:
        if args.mode == "full":
            run_full(domain, args.output, args.wordlist, args.threads, args.no_passive, args.no_api, args.no_brute)
        else:
            run_lite(domain, args.output, args.no_passive, args.no_api, args.no_brute)
    except KeyboardInterrupt:
        echo("\n[!] Interrupted by user", RED)
        sys.exit(1)
    except Exception as e:
        echo(f"[!] Fatal error: {e}", RED)
        sys.exit(2)

if __name__ == "__main__":
    main()
