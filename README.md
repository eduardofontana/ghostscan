# GhostScan

GhostScan is an aggressive TCP recon CLI forged for red-team style enumeration drills.
It fuses high-concurrency port scanning with asynchronous service fingerprinting (banner probes + TLS checks) to expose breach points fast.

## Why GhostScan

- Fast strike cycles: concurrent TCP connect scanning with tunable worker pool and timeout
- Higher signal intel: async active probes with protocol signatures, version extraction, and TLS handshake verification
- Operator-first CLI: clear commands, practical defaults, hard input validation, readable output
- Clean architecture: focused modules for scan engine, detection, and output control

## Features

- TCP connect sweep across custom ranges and comma-separated targets
- Top Ports mode with presets (`--top-ports quick|standard|deep`) or numeric (`--top-ports N`)
- Hardened port parsing and validation (`1-65535`, invalid ranges rejected)
- Asynchronous banner grabbing and fingerprinting on discovered open ports
- Service version detection from banners (SSH/HTTP/SMTP/FTP/Redis/MySQL/PostgreSQL patterns)
- Detection pipeline: banner grab, protocol-aware probes (HTTP/SMTP/POP3/IMAP/Redis), TLS confirmation
- Optional WAF fingerprinting (`--detect-waf`) via safe HTTP header/body signatures
- Optional firewall heuristic (`--detect-firewall`) with score/confidence in final report
- Professional final report with service density and high-risk exposure snapshot
- Structured export: `--output txt|json|csv` with optional `--output-file`
- Matrix-style terminal output with graceful no-color fallback

## Installation

```bash
git clone https://github.com/yourusername/ghostscan.git
cd ghostscan
pip install -r requirements.txt
```

## Usage

```bash
python cli.py scan <target> [options]
```

Quick strike:

```bash
python cli.py scan <target> -p 1-1024
```

Examples:

```bash
python cli.py scan 127.0.0.1 -p 1-1024
python cli.py scan 127.0.0.1 --top-ports quick
python cli.py scan 127.0.0.1 --top-ports standard
python cli.py scan 127.0.0.1 --top-ports deep
python cli.py scan 127.0.0.1 --top-ports 100
python cli.py scan target.local --top-ports standard --detect-firewall
python cli.py scan https://target.local --top-ports quick --detect-waf --output json
python cli.py scan scanme.nmap.org -p 22,80,443 -t 200
python cli.py scan https://scanme.nmap.org -p 80,443
python cli.py scan http://example.com:8080/admin -p 1-2000
python cli.py scan 10.10.10.10 -p 1-2000 --output json
python cli.py scan target.local -p 22,80,443 --output csv --output-file breach_report.csv
python cli.py scan 10.0.0.5 -p 1-5000 --timeout 0.6 --no-detect
python cli.py scan example.com -p 80,443,8080 -v
```

Options:

- `-p, --ports`: Ports/ranges like `22,80,443` or `1-1024` (default: `1-1024`)
- `--top-ports`: Scan by preset (`quick=50`, `standard=100`, `deep=1000`) or numeric (example: `--top-ports 150`)
- `-t, --threads`: Max scan workers (default: `200`)
- `--timeout`: Socket timeout in seconds (default: `0.8`)
- `--no-detect`: Skip service detection for maximum speed
- `--detect-firewall`: Enable firewall heuristic analysis with score/confidence
- `--detect-waf`: Enable fast WAF fingerprinting on web endpoints
- `--output`: Report format: `txt`, `json`, or `csv` (default: `txt`)
- `--output-file`: Explicit report filename/path
- `--no-banner`: Hide startup ASCII banner
- `-v, --verbose`: Print extra runtime details
- `target`: Accepts hostname/IP or full URL (host is auto-extracted)

Sample output flow:

```text
[ STRIKE PROFILE ]
  Target   : target.local
  IP       : 203.0.113.10
[*] >>> Weaponizing scan threads and priming sockets...
[+] Strike complete in 0.42s
[*] >>> BREACH POINTS IDENTIFIED:
  [OPEN]     22  ->  SSH OpenSSH_8.9 (conf 0.90)
  [OPEN]     80  ->  HTTP nginx/1.24.0 (conf 0.90)
[*] >>> FINAL OPERATION REPORT
[::] Runtime: 0.42s | Breach points: 2
[::] Firewall presence: YES
[+] Report exported: /path/to/ghostscan_report_20260425_101230.txt
```

## Project Layout

```text
ghostscan/
|-- cli.py            # Command parsing and user workflow
|-- scanner.py        # Concurrent TCP scan engine
|-- services.py       # Service fingerprinting and TLS checks
|-- utils.py          # Styled terminal output helpers
|-- requirements.txt
`-- README.md
```

## Disclaimer

This project is for education and authorized testing only.
Do not scan infrastructure without explicit permission.
You are responsible for legal and ethical use.

## License

MIT
