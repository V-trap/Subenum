#!/usr/bin/env python3
import os
import argparse
import subprocess
import shutil
import requests
import json
import threading
import queue
import dns.resolver

#############################################################
#                 DEPENDENCY CHECKER + INSTALLER
#############################################################

TOOLS = {
    "subfinder": {
        "check": "subfinder -h",
        "install": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    },
    "assetfinder": {
        "check": "assetfinder -h",
        "install": "go install github.com/tomnomnom/assetfinder@latest"
    },
    "amass": {
        "check": "amass -h",
        "install": "sudo apt install amass -y"
    },
    "findomain": {
        "check": "findomain -h",
        "install": "sudo apt install finddomain -y"
    },
    "sublist3r": {
        "check": "sublist3r -h",
        "install": "sudo apt install sublist3r -y"
    },
    "gau": {
        "check": "gau -h",
        "install": "go install github.com/lc/gau/v2/cmd/gau@latest"
    },
    "waybackurls": {
        "check": "waybackurls -h",
        "install": "go install github.com/tomnomnom/waybackurls@latest"
    },
    "dnsrecon": {
        "check": "dnsrecon -h",
        "install": "sudo apt install dnsrecon -y"
    },
    "dnsmap": {
        "check": "dnsmap -h",
        "install": "sudo apt install dnsmap -y"
    },
    "knockpy": {
        "check": "knockpy -h",
        "install": "git clone https://github.com/guelfoweb/knockpy && cd knockpy && sudo python3 setup.py install"
    }
}


def run(cmd):
    try:
        subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL)
        return True
    except:
        return False


def install_tool(name, mode):
    tool = TOOLS[name]
    print(f"\n[!] Checking: {name}")

    if run(tool["check"]):
        print(f"[+] Installed: {name}")
        return

    print(f"[!] Missing: {name}")

    # warn only
    if mode == "warn":
        print(f"[!] WARNING: {name} not installed.")
        return

    # ask mode
    if mode == "ask":
        ch = input(f"Install {name}? (y/n): ")
        if ch.lower() != "y":
            print(f"[!] Skipped installing {name}")
            return

    # auto install
    print(f"[+] Installing {name} ...")
    os.system(tool["install"])
    print(f"[✓] Done.")


def dependency_manager(mode):
    print("\n============ DEPENDENCY CHECK ============")
    for tool in TOOLS:
        install_tool(tool, mode)
    print("===========================================\n")


#############################################################
#               ENUMERATION ENGINE (15+ TOOLS)
#############################################################

def run_out(cmd):
    try:
        output = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL)
        return output.splitlines()
    except:
        return []


def banner(name):
    print(f"\n{'='*60}\n[+] {name}\n{'='*60}")


# ---- Passive Tools ----

def subfinder(domain):
    banner("Subfinder")
    return run_out(f"subfinder -silent -d {domain}")


def assetfinder(domain):
    banner("Assetfinder")
    return run_out(f"assetfinder --subs-only {domain}")


def amass(domain):
    banner("Amass")
    return run_out(f"amass enum -passive -d {domain}")


def findomain(domain):
    banner("Findomain")
    return run_out(f"findomain -t {domain} --quiet")


def sublist3r(domain):
    banner("Sublist3r")
    run_out(f"sublist3r -d {domain} -o sub_tmp.txt")
    return run_out("cat sub_tmp.txt")


def crtsh(domain):
    banner("crt.sh")
    subs = set()
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=7)
        for d in r.json():
            subs.add(d["name_value"])
    except:
        pass
    return list(subs)


def wayback(domain):
    banner("Wayback")
    urls = run_out(f"waybackurls {domain}")
    subs = []
    for u in urls:
        try:
            host = u.split("/")[2]
            if domain in host:
                subs.append(host)
        except:
            pass
    return subs


def gau(domain):
    banner("GAU")
    urls = run_out(f"gau {domain}")
    subs = []
    for u in urls:
        try:
            host = u.split("/")[2]
            if domain in host:
                subs.append(host)
        except:
            pass
    return subs


# ---- API Tools ----

def certspotter(domain):
    banner("CertSpotter")
    subs = []
    try:
        r = requests.get(
            f"https://api.certspotter.com/v1/issuances?domain={domain}&expand=dns_names"
        )
        for x in r.json():
            subs.extend(x["dns_names"])
    except:
        pass
    return subs


def virustotal(domain):
    banner("VirusTotal")
    subs = []
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains",
            headers={"x-apikey": "PUBLIC-API-NO-KEY"}
        )
        for x in r.json().get("data", []):
            subs.append(x["id"])
    except:
        pass
    return subs


# ---- Brute Force Tools ----

def dnsrecon(domain):
    banner("DNSRecon")
    return run_out(f"dnsrecon -d {domain} -t brt | grep Name | awk '{{print $NF}}'")


def dnsmap(domain):
    banner("DNSMap")
    return run_out(f"dnsmap {domain}")


def knockpy(domain):
    banner("Knockpy")
    return run_out(f"knockpy {domain} --no-color | awk '{{print $1}}'")


# Python DNS Brute Force
def brute_thread(q, domain, out):
    while True:
        word = q.get()
        if word is None:
            break
        sub = f"{word}.{domain}"
        try:
            dns.resolver.resolve(sub)
            out.append(sub)
        except:
            pass
        q.task_done()


def python_bruteforce(domain, wordlist, threads):
    banner("Python Bruteforce")
    q = queue.Queue()
    out = []

    with open(wordlist, "r") as f:
        for w in f:
            q.put(w.strip())

    th = []
    for _ in range(threads):
        t = threading.Thread(target=brute_thread, args=(q, domain, out))
        t.start()
        th.append(t)

    q.join()

    for _ in th:
        q.put(None)
    for t in th:
        t.join()

    return out


#############################################################
#                           MAIN
#############################################################

def main():
    parser = argparse.ArgumentParser(description="Advanced Subdomain Enumeration Tool")

    parser.add_argument("-d", "--domain", required=True, help="Target Domain")
    parser.add_argument("-o", "--output", default="subdomains.txt", help="Output File")
    parser.add_argument("-w", "--wordlist", default="/usr/share/wordlists/dirb/common.txt",
                        help="Wordlist for brute force")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Bruteforce Threads")

    parser.add_argument("--no-passive", action="store_true", help="Disable passive tools")
    parser.add_argument("--no-brute", action="store_true", help="Disable brute tools")
    parser.add_argument("--no-api", action="store_true", help="Disable API tools")

    parser.add_argument("--install", choices=["auto", "ask", "warn"], default="warn",
                        help="Dependency install mode")

    args = parser.parse_args()

    # ---- Dependency Check ----
    dependency_manager(args.install)

    domain = args.domain
    allsubs = set()

    passive = [subfinder, assetfinder, amass, findomain, sublist3r, crtsh, wayback, gau]
    api = [certspotter, virustotal]
    brute = [dnsrecon, dnsmap, knockpy]

    if not args.no_passive:
        for tool in passive:
            allsubs.update(tool(domain))

    if not args.no_api:
        for tool in api:
            allsubs.update(tool(domain))

    if not args.no_brute:
        for tool in brute:
            allsubs.update(tool(domain))
        allsubs.update(python_bruteforce(domain, args.wordlist, args.threads))

    # ---- Save Output ----
    allsubs = sorted(set(allsubs))
    with open(args.output, "w") as f:
        for s in allsubs:
            f.write(s + "\n")

    print(f"\n[+] Total Unique: {len(allsubs)}")
    print(f"[+] Saved to: {args.output}\n")


if __name__ == "__main__":
    main()
