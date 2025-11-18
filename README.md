# Subenum
Combined Lite / Full Subdomain Enumeration Framework  
Version: v1.2.0  
Author: V-trap

---

## Overview
Subenum is a Python3-based subdomain enumeration tool that combines multiple methods into one script.

It supports:
- **lite mode** → fast, minimal, quick results  
- **full mode** → detailed enumeration using passive tools, APIs & brute-force  

---

## Features
- Lite & Full modes in a single script  
- Dependency checker & auto-installer  
- Passive enumeration (`subfinder`, `assetfinder`, `amass`, etc.)  
- API-based enumeration (`crt.sh`, `certspotter`, `VirusTotal`)  
- Built-in Python brute-force + external brute tools  
- Deduplication & alive-check (`httpx`)  
- Linux-ready (#!/usr/bin/env python3)  
- Can be added to `/usr/local/bin` for global use  

---

## Requirements
- Linux / Unix system  
- Python3  
- git  
- Optional tools for full mode:  
  `subfinder`, `assetfinder`, `amass`, `findomain`, `sublist3r`,  
  `knockpy`, `waybackurls`, `gau`, `httpx`, `massdns`,  
  `dnsrecon`, `dnsenum`, `fierce`, `theHarvester`, `chaos`

---

## Installation

```bash
# Clone the repository
git clone https://github.com/V-trap/Subenum.git
cd Subenum

# Make executable (optional)
chmod +x subenum.py

sed -i 's/\r$//' subenum.py

# Option A: Run locally
./subenum.py -h

# Option B: Install globally
sudo cp subenum.py /usr/local/bin/subenum
sudo chmod +x /usr/local/bin/subenum

# Test tool
subenum -h
