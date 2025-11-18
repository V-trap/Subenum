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

VERSION = "1.2.0"
AUTHOR = "YourName"

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"

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
        "check": None,
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
        "install_cmd": ""
    }
}

TOOL_LIST = list(TOOLS.keys())

def echo(msg, color=RESET, end="\n"):
    sys.stdout.write(f"{color}{msg}{RESET}{end}")
    sys.stdout.flush()

def check_program(prog):
    if prog is None:
        return True
    return shutil.which(prog) is not None

def run_cmd(cmd, timeout=300):
    try:
        proc = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        return proc.stdout.strip().splitlines()
    except Exception:
        return []

def install_tool_sequence(tool_name, mode):
    info = TOOLS.get(tool_name, {})
    check = info.get("check")
    install_cmd = info.get("install_cmd", "")
    installed = check_program(check)
    if installed:
        echo(f"[+] {tool_name} already present", GREEN)
        return True

    if mode == "warn":
        echo(f"[!] {tool_name} missing (warn mode) — skipping install", YELLOW)
        return False

    if mode == "ask":
        resp = input(f"[?] {tool_name} not found. Install now? (y/N): ").strip().lower()
        if resp not in ("y", "yes"):
            echo(f"[-] Skipped {tool_name}", YELLOW)
            return False

    if not install_cmd:
        echo(f"[!] No automatic install command for {tool_name}", RED)
        return False

    echo(f"[+] Installing {tool_name} ...", CYAN)
    return_code = os.system(install_cmd)
    if return_code == 0:
        echo(f"[+] Installed {tool_name}", GREEN)
        return check_program(check)

    echo(f"[!] Install failed for {tool_name}", RED)
    return False

def dependency_manager(mode="warn"):
    echo("=== Dependency check ===", CYAN)
    results = {}
    for t in TOOL_LIST:
        ok = check_program(TOOLS[t]["check"])
        if ok:
            echo(f"[+] {t} OK", GREEN)
            results[t] = True
        else:
            results[t] = install_tool_sequence(t, mode)
    echo("=== Dependency check complete ===\n", CYAN)
    return results

def save_lines(path, lines):
    try:
        with open(path, "a") as fh:
            for l in lines:
                fh.write(l.rstrip() + "\n")
    except:
        pass

def uniq_lines(path):
    try:
        with open(path, "r") as fh:
            items = {line.strip() for line in fh if line.strip()}
            return sorted(items)
    except:
        return []

def dns_brute_worker(q, domain, found):
    import dns.resolver
    while True:
        try:
            prefix = q.get(timeout=3)
        except:
            break
        if prefix is None:
            break
        fqdn = f"{prefix}.{domain}"
        try:
            dns.resolver.resolve(fqdn, lifetime=3)
            found.append(fqdn)
        except:
            pass
        q.task_done()

def python_dns_bruteforce(domain, wordlist, threads):
    q = queue.Queue()
    found = []

    try:
        with open(wordlist) as f:
            for line in f:
                w = line.strip()
                if w:
                    q.put(w)
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

    for _ in workers:
        q.put(None)

    for w in workers:
        w.join(timeout=1)

    return sorted(set(found))

def run_full(domain, output, wordlist, threads, no_passive, no_api, no_brute):
    echo(f"[★] Running FULL mode for {domain}", CYAN)
    tmp_out = output + ".tmp"
    open(tmp_out, "w").close()

    if not no_passive:
        echo("[*] Passive tools", CYAN)
        if check_program("subfinder"):
            save_lines(tmp_out, run_cmd(f"subfinder -silent -d {domain}"))
        if check_program("assetfinder"):
            save_lines(tmp_out, run_cmd(f"assetfinder --subs-only {domain}"))
        if check_program("amass"):
            save_lines(tmp_out, run_cmd(f"amass enum -passive -d {domain}"))
        if check_program("findomain"):
            save_lines(tmp_out, run_cmd(f"findomain -t {domain} --quiet"))
        if check_program("sublist3r"):
            temp = f"/tmp/sublist3r_{domain}.txt"
            run_cmd(f"sublist3r -d {domain} -o {temp}")
            if os.path.exists(temp):
                save_lines(tmp_out, run_cmd(f"cat {temp}"))
        if check_program("waybackurls"):
            save_lines(tmp_out, run_cmd(f"waybackurls {domain} | cut -d'/' -f3 | sort -u"))
        if check_program("gau"):
            save_lines(tmp_out, run_cmd(f"gau {domain} | cut -d'/' -f3 | sort -u"))

    if not no_api:
        echo("[*] API tools", CYAN)
        try:
            r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=8)
            for ent in r.json():
                nv = ent.get("name_value", "")
                for s in nv.splitlines():
                    save_lines(tmp_out, [s.strip()])
        except:
            pass

    if not no_brute:
        echo("[*] Brute-force tools", CYAN)
        if check_program("knockpy"):
            save_lines(tmp_out, run_cmd(f"knockpy {domain} --no-color | awk '{{print $1}}'"))
        if check_program("dnsrecon"):
            save_lines(tmp_out, run_cmd(f"dnsrecon -d {domain} -t brt | grep Name | awk '{{print $NF}}'"))
        if check_program("dnsenum"):
            save_lines(tmp_out, run_cmd(f"dnsenum {domain}"))
        brute = python_dns_bruteforce(domain, wordlist, threads)
        save_lines(tmp_out, brute)

    candidates = uniq_lines(tmp_out)
    if check_program("httpx"):
        temp = "/tmp/httpx_feed.txt"
        with open(temp, "w") as f:
            for c in candidates:
                f.write(c + "\n")
        alive = run_cmd(f"httpx -silent -l {temp}")
        final = alive
    else:
        final = candidates

    final = sorted(set([x for x in final if domain in x]))

    with open(output, "w") as f:
        for x in final:
            f.write(x + "\n")

    echo(f"[+] FULL mode complete. Saved: {output}", GREEN)

def run_lite(domain, output, no_passive, no_api, no_brute):
    echo(f"[★] Running LITE mode for {domain}", CYAN)
    open(output, "w").close()

    if not no_passive:
        if check_program("subfinder"):
            save_lines(output, run_cmd(f"subfinder -silent -d {domain}"))
        elif check_program("assetfinder"):
            save_lines(output, run_cmd(f"assetfinder --subs-only {domain}"))
        else:
            echo("[!] No passive tools available", YELLOW)

    if not no_api:
        try:
            r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=6)
            for ent in r.json():
                nv = ent.get("name_value", "")
                for s in nv.splitlines():
                    save_lines(output, [s.strip()])
        except:
            pass

    if not no_brute:
        if check_program("knockpy"):
            save_lines(output, run_cmd(f"knockpy {domain} --no-color | awk '{{print $1}}'"))
        else:
            echo("[!] knockpy not found for brute-force", YELLOW)

    final = sorted(set(uniq_lines(output)))

    with open(output, "w") as f:
        for x in final:
            f.write(x + "\n")

    echo(f"[+] LITE mode complete. Saved: {output}", GREEN)

def build_parser():
    p = argparse.ArgumentParser(description="Subdomain Enumeration Tool")
    p.add_argument("-d", "--domain", required=True)
    p.add_argument("-o", "--output", default="subdomains.txt")
    p.add_argument("-w", "--wordlist", default="/usr/share/wordlists/dirb/common.txt")
    p.add_argument("-t", "--threads", type=int, default=20)
    p.add_argument("--no-passive", action="store_true")
    p.add_argument("--no-api", action="store_true")
    p.add_argument("--no-brute", action="store_true")
    p.add_argument("--install", choices=["auto", "ask", "warn"], default="warn")
    p.add_argument("-i", "--install-deps", action="store_true")
    p.add_argument("-v", "--version", action="store_true")
    p.add_argument("--mode", choices=["full", "lite"], default="full")
    return p

def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.version:
        echo(f"Subenum v{VERSION}", CYAN)
        sys.exit(0)

    if args.install_deps:
        dependency_manager(args.install)
        sys.exit(0)

    if args.install != "warn":
        dependency_manager(args.install)

    domain = args.domain.strip()
    if domain.startswith("http"):
        domain = domain.split("://", 1)[-1].split("/", 1)[0]

    if args.mode == "full":
        run_full(domain, args.output, args.wordlist, args.threads,
                 args.no_passive, args.no_api, args.no_brute)
    else:
        run_lite(domain, args.output,
                 args.no_passive, args.no_api, args.no_brute)

if __name__ == "__main__":
    main()
