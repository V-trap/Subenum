🔎 Enumeration Automation Script

A powerful and beginner-friendly Bash/Python enumeration script for penetration testing labs like HTB, TryHackMe, and CTF challenges.
This script automates the most common recon and enumeration steps to help you quickly gather information about a target.

🚀 Features
🔥 Common Host Enumeration

Ping check

Host discovery

DNS lookup

Reverse DNS lookup

Traceroute

Banner grabbing

🌐 Port & Service Scanning

Full Nmap scan

Top 1000 ports

Version detection (-sV)

OS detection (-O)

Script scan (-sC)

Full TCP & UDP scans

Save results in organized output files

📂 Web Enumeration

gobuster / dirsearch directory brute-forcing

HTTP headers

Web server fingerprinting

Robots.txt check

SSL certificate info

📦 Service-Specific Enumeration

FTP anonymous login test

SMB shares enumeration

SSH service info

SNMP check

SMTP enumeration

MySQL server probing

📁 Project Structure
/enumeration-script

│

├── enum.sh                # Main enumeration script

├── output/                # Auto-created folder for storing results

│   ├── nmap/

│   ├── web/

│   ├── smb/

│   └── ftp/

│

└── README.md


🧰 Requirements

Your system should have:

Bash (Linux or WSL recommended)

nmap

gobuster or dirsearch

curl / wget

smbclient (for SMB enumeration)

python3 (if part of your script needs it)

Install dependencies (Debian/Kali):

sudo apt update && sudo apt install nmap gobuster smbclient curl -y

▶️ Usage
Run basic enumeration:
./enum.sh <target-ip>

Run full aggressive enumeration:
./enum.sh <target-ip> --full

Save results in a custom folder:
./enum.sh <target-ip> -o results/

Example:
./enum.sh 10.10.11.125 --full -o htb_box

💡 Output Examples

The script automatically organizes output like this:

output/

├── nmap/full_scan.txt

├── web/dirbuster.txt

├── smb/shares.txt

├── ftp/banner.txt

└── host_info.txt

🛡️ Notes

⚠️ Use only on machines you have permission to test.
This tool is intended for:

HTB machines

TryHackMe labs

Local testing environments

CTF challenges

Unauthorized scanning of external systems is illegal.

👨‍💻 Ideal For

This script is perfect for:

Cybersecurity students

Bug bounty beginners

HTB / THM solvers

Pentesters who want fast enumeration

Anyone who wants automated recon

🤝 Contributing

PRs are welcome!
You can contribute by adding:

More enumeration modules

OS detection improvements

Better output formatting

Parallel scanning support

A menu-driven UI version

📜 License

MIT License — free to use, modify, and distribute.
