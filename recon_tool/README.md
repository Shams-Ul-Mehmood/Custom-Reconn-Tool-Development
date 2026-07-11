# Recon Tool

A lightweight, modular command-line reconnaissance tool built for penetration
testing engagements. It automates the early information-gathering phase of a
pentest — passive recon (WHOIS, DNS, subdomains) and active recon (port
scanning, banner grabbing, technology detection) — and outputs a consolidated
report in `.txt`, `.html`, and `.json` formats.

Built as part of an internship red-teaming/tooling exercise to practice
offensive-security scripting and modular Python architecture.

## Features

- **Passive recon**
  - WHOIS lookup (registrar, org, name servers, emails, expiry dates)
  - DNS enumeration (A, MX, TXT, NS records + SPF/DMARC/provider analysis)
  - Subdomain enumeration via `crt.sh` and AlienVault OTX
- **Active recon**
  - Port scanning (raw sockets or Nmap backend, threaded)
  - Banner grabbing on open ports
  - Web technology detection
- **Reporting**
  - Auto-generated `.txt`, `.html`, and `.json` reports with timestamps and
    resolved IP details, saved to `reports/`
- **Modular design** — every recon type is its own module under `modules/`
  and is toggled independently via CLI flags
- **Verbosity levels** via `-v` for debug-level logging

## Installation

Requires Python 3.9+.

```bash
git clone https://github.com/za1n-n0p/Custom-Reconnaissance-Tool-Development
cd recon_tool
pip install -r requirements.txt
```

(Optional, for full port-scan features) install Nmap on your system if you
want to use the `--nmap` backend:

```bash
sudo apt install nmap
```

## Usage

```bash
python3 main.py <target> --whois --dns --subdomains --ports 80,443 --banners --techdetect
```

Example, running every module against a test domain with verbose logging:

```bash
python3 main.py tesla.com --whois --dns --subdomains --ports 80,443 --banners --techdetect -v
```

Only need a couple of checks? Flags are independent — mix and match:

```bash
python3 main.py tesla.com --whois --dns
python3 main.py 192.168.1.10 --ports 1-1024 --banners --nmap
```

Reports are written to `reports/<target>_report.{txt,html,json}` after every
run.

## CLI Flags

| Flag | Description |
|---|---|
| `target` | Target domain or IP address (positional, required) |
| `--whois` | Perform a WHOIS lookup on the target |
| `--dns` | Enumerate DNS records (A, MX, TXT, NS) and analyze SPF/DMARC/providers |
| `--subdomains` | Enumerate subdomains via crt.sh and AlienVault OTX |
| `--ports [SPEC]` | Scan ports. Optional spec e.g. `22,80,443` or `1-1024` (defaults to `1-1024` if flag given without a value) |
| `--banners` | Attempt banner grabbing on discovered open ports (used with `--ports`) |
| `--techdetect` | Detect web technologies running on the target |
| `--nmap` | Use the Nmap backend instead of raw sockets for port scanning |
| `--nmap-args` | Arguments passed to Nmap when `--nmap` is used (default: `-sV --version-light`) |
| `--timeout` | Per-port socket timeout in seconds (default: `0.75`) |
| `-t`, `--threads` | Max concurrent socket workers for port scanning (default: `100`) |
| `-v`, `--verbose` | Increase logging verbosity (stackable, e.g. `-vv`) |

## Sample Output

A sample report generated against `tesla.com` is committed at
[`reports/tesla.com_report.html`](reports/tesla.com_report.html)
(and the matching `.txt` version alongside it), so you can see the report
format without running the tool first.

## Project Structure

```
recon_tool/
├── main.py                  # CLI entrypoint — parses flags, runs modules, triggers report
├── requirements.txt
├── modules/
│   ├── whois_lookup.py      # WHOIS lookup
│   ├── dns_enum.py          # DNS record enumeration + analysis
│   ├── subdomains.py        # Subdomain enumeration (crt.sh, AlienVault OTX)
│   ├── portscan.py          # Port scanning (sockets / Nmap) + arg parser
│   ├── banner.py            # Banner grabbing on open ports
│   ├── techdetect.py        # Web technology detection
│   └── report.py            # Report generation (txt / html / json)
├── utils/
│   └── logger.py            # Logging setup with verbosity levels
└── reports/                 # Generated reports land here (tesla report committed)
```

## Team Credits

| Module | Contributor |
|---|---|
| Project structure, CLI, logging integration & documentation| Member 1 |
| WHOIS lookup & DNS enumeration | Member 2 |
| Subdomain enumeration | Member 3 |
| Port scanning, banner grabbing and Docker Packaging| Member 4 |
| Technology detection, testing, reporting & GitHub submission | Member 5 |


## Docker

*Coming soon* — a `Dockerfile` and `docker-compose.yml` are being added in a
follow-up commit to allow running the tool in a container without a local
Python setup.

## Disclaimer

This tool is intended for authorized security testing and educational
purposes only. Only run it against targets you own or have explicit written
permission to test.
