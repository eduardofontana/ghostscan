# GhostScan

GhostScan is an aggressive TCP/UDP recon CLI forged for red-team style enumeration drills.
It fuses high-concurrency port scanning with asynchronous service fingerprinting (banner probes + TLS checks) to expose breach points fast.

## Why GhostScan

- Fast strike cycles: concurrent TCP/UDP scanning with tunable worker pool and timeout
- Higher signal intel: async active probes with protocol signatures, version extraction, and TLS handshake verification
- Operator-first CLI: clear commands, practical defaults, hard input validation, readable output
- Clean architecture: focused modules for scan engine, detection, and output control
- Stealth capabilities: scan profiles, rate limiting, proxy support

## Features

- TCP and UDP port scanning with concurrent probes
- Scan profiles: stealth, normal, aggressive, parallel
- Rate limiting to control scan speed (requests per second)
- Proxy support: SOCKS5, SOCKS4, HTTP/HTTPS tunneling
- Top Ports mode with presets (`--top-ports quick|standard|deep`) or numeric (`--top-ports N`)
- Hardened port parsing and validation (`1-65535`, invalid ranges rejected)
- Asynchronous banner grabbing and fingerprinting on discovered open ports
- Service version detection from banners (SSH/HTTP/SMTP/FTP/Redis/MySQL/PostgreSQL patterns)
- Detection pipeline: banner grab, protocol-aware probes (HTTP/SMTP/POP3/IMAP/Redis), TLS confirmation
- Optional WAF fingerprinting (`--detect-waf`) via safe HTTP header/body signatures
- Optional quiet firewall check (`--detect-firewall`) with binary presence output (`YES/NO`)
- Professional final report with service density and high-risk exposure snapshot
- Structured export: `--output txt|json|csv|html` with optional `--output-file`
- Interactive HTML dashboard report
- Matrix-style terminal output with graceful no-color fallback

## Installation

```bash
git clone https://github.com/yourusername/ghostscan.git
cd ghostscan
pip install -r requirements.txt
```

## Quick Start

```bash
python cli.py scan <target> -p 1-1024
```

## Scan Profiles

GhostScan includes preset profiles optimized for different scenarios:

| Profile | Description | Threads | Timeout | Rate Limit | Retry |
|--------|-------------|---------|---------|-----------|-------|
| stealth | Low-profile scan | 10 | 1.5s | 5/s | 1 |
| normal | Balanced | 200 | 0.8s | unlimited | 0 |
| aggressive | Fast aggressive | 500 | 0.3s | unlimited | 2 |
| parallel | Massively parallel | 1000 | 0.2s | unlimited | 0 |

## Usage Examples

### Basic Scans

```bash
python cli.py scan 127.0.0.1 -p 1-1024
python cli.py scan 127.0.0.1 --top-ports quick
python cli.py scan 127.0.0.1 --top-ports standard
python cli.py scan 127.0.0.1 --top-ports deep
python cli.py scan 127.0.0.1 --top-ports 100
```

### Scan Types

```bash
# TCP scan (default)
python cli.py scan target -p 1-1000

# UDP scan
python cli.py scan target --scan-type udp -p 53,161

# Scan specific ports
python cli.py scan target -p 22,80,443,3306,5432
```

### Using Profiles

```bash
# Stealth mode (low profile, slower but quieter)
python cli.py scan target --profile stealth

# Aggressive mode (fast, more threads)
python cli.py scan target --profile aggressive
```

### Rate Limiting

```bash
# Limit to 10 requests per second
python cli.py scan target --rate-limit 10

# Limit to 5 requests per second
python cli.py scan target --rate-limit 5
```

### Proxy Support

```bash
# SOCKS5 proxy
python cli.py scan target --proxy socks5://127.0.0.1:1080 -p 22,80

# SOCKS4 proxy
python cli.py scan target --proxy socks4://127.0.0.1:1080 -p 22,80

# HTTP proxy
python cli.py scan target --proxy http://proxy.company.com:8080 -p 22,80

# Proxy with authentication
python cli.py scan target --proxy socks5://user:pass@127.0.0.1:1080 -p 22,80
```

### Output Formats

```bash
# Text output (default)
python cli.py scan target -p 1-1000

# JSON output
python cli.py scan target -p 1-1000 --output json

# CSV output
python cli.py scan target -p 1-1000 --output csv --output-file results.csv

# HTML dashboard
python cli.py scan target -p 1-1000 --output html
```

### Advanced Options

```bash
# Skip service detection (faster)
python cli.py scan target -p 1-1000 --no-detect

# Detect firewall presence
python cli.py scan target --detect-firewall

# Detect WAF
python cli.py scan target --detect-waf

# Custom threads and timeout
python cli.py scan target -p 1-1000 -t 500 --timeout 0.5

# Verbose output
python cli.py scan target -p 1-1000 -v

# Hide banner
python cli.py scan target --no-banner
```

## Command Options

| Option | Description | Default |
|--------|------------|---------|
| `-p, --ports` | Port list/range | 1-1024 |
| `--top-ports` | Scan top N ports | - |
| `-t, --threads` | Max worker threads | 200 |
| `--timeout` | Socket timeout (seconds) | 0.8 |
| `--scan-type` | Protocol: tcp or udp | tcp |
| `--profile` | Scan profile | - |
| `--rate-limit` | Requests per second | unlimited |
| `--proxy` | Proxy URL | - |
| `--no-detect` | Skip detection | - |
| `--detect-firewall` | Check firewall | - |
| `--detect-waf` | Check WAF | - |
| `--output` | Output format | txt |
| `--output-file` | Output file | auto |
| `--no-banner` | Hide banner | - |
| `-v, --verbose` | Verbose output | - |

## Project Layout

```
ghostscan/
|-- cli.py            # Command parsing and user workflow
|-- scanner.py        # TCP/UDP scan engine, profiles, rate limiter
|-- services.py       # Service fingerprinting and TLS checks
|-- proxies.py        # Proxy/SOCKS support
|-- html_report.py     # HTML dashboard generator
|-- utils.py         # Styled terminal output helpers
|-- requirements.txt
`-- README.md
```

## Disclaimer

This project is for education and authorized testing only.
Do not scan infrastructure without explicit permission.
You are responsible for legal and ethical use.

## License

MIT