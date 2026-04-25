#!/usr/bin/env python3
"""
GhostScan CLI - fast TCP port scanner with service detection.
Educational tool. Scan only systems you are authorized to test.
"""

import argparse
import asyncio
import csv
import ipaddress
import json
import ssl
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib import error as url_error
from urllib import request as url_request
from urllib.parse import urlsplit

from scanner import PortScanner, RateLimiter, ScanProfile
from services import ServiceDetector
from utils import (
    print_banner,
    print_error,
    print_info,
    print_open_port,
    print_scan_header,
    print_success,
    print_warning,
)
from proxies import parse_proxy_string

try:
    from html_report import generate_html_report as _generate_html_report
except ImportError:
    _generate_html_report = None

MIN_PORT = 1
MAX_PORT = 65535
DEFAULT_PORT_RANGE = "1-1024"
TOP_PORTS_PRESETS = {
    "quick": 50,
    "standard": 100,
    "deep": 1000,
}
WEB_PROBE_PORTS = (80, 443, 8080, 8443)

# Ordered by practical scan priority (based on common exposure patterns).
TOP_PORTS_BASE = [
    80, 443, 22, 21, 25, 53, 110, 143, 23, 445, 3389, 3306, 8080, 8443, 5900, 6379,
    111, 135, 139, 993, 995, 587, 465, 389, 636, 1521, 1433, 5432, 27017, 9200, 11211,
    2049, 873, 161, 162, 67, 68, 69, 123, 514, 515, 631, 1080, 2375, 2376, 5672, 5000,
    8000, 8081, 9000, 8888, 7001, 9930, 9090, 27018, 27019, 5001, 9201, 15672, 61616,
    10000, 81, 88, 109, 119, 179, 194, 264, 318, 427, 4433, 554, 563, 5870, 902, 989,
    990, 992, 1025, 1081, 1099, 1194, 1434, 1723, 1883, 1900, 2000, 2001, 2082, 2083,
    2181, 2379, 3128, 3690, 4000, 4040, 4369, 4444, 4500, 4786, 5060, 5222, 5433, 5555,
]


def parse_ports(ports_str: str) -> List[int]:
    """Parse ports string like '1-1024' or '22,80,443' into a sorted unique list."""
    if not ports_str or not ports_str.strip():
        raise ValueError("Port list is empty.")

    ports = set()
    tokens = [token.strip() for token in ports_str.split(",")]

    for token in tokens:
        if not token:
            continue

        if "-" in token:
            bounds = token.split("-", 1)
            if len(bounds) != 2:
                raise ValueError(f"Invalid port range: '{token}'")
            start_str, end_str = bounds
            try:
                start = int(start_str)
                end = int(end_str)
            except ValueError as exc:
                raise ValueError(f"Invalid port range: '{token}'") from exc

            if start > end:
                raise ValueError(f"Invalid port range '{token}': start must be <= end.")
            if start < MIN_PORT or end > MAX_PORT:
                raise ValueError(f"Port range '{token}' must be between {MIN_PORT} and {MAX_PORT}.")
            ports.update(range(start, end + 1))
            continue

        try:
            port = int(token)
        except ValueError as exc:
            raise ValueError(f"Invalid port value: '{token}'") from exc

        if not (MIN_PORT <= port <= MAX_PORT):
            raise ValueError(f"Port '{port}' is outside valid range {MIN_PORT}-{MAX_PORT}.")
        ports.add(port)

    if not ports:
        raise ValueError("No valid ports were provided.")

    return sorted(ports)


def get_top_ports(limit: int) -> List[int]:
    """Return first N top-priority ports."""
    if limit < 1:
        raise ValueError("Top ports value must be >= 1.")
    if limit > MAX_PORT:
        raise ValueError(f"Top ports value must be <= {MAX_PORT}.")

    unique_ranked = []
    seen = set()
    for port in TOP_PORTS_BASE:
        if MIN_PORT <= port <= MAX_PORT and port not in seen:
            unique_ranked.append(port)
            seen.add(port)
            if len(unique_ranked) >= limit:
                return unique_ranked

    # If limit exceeds curated list, fill with remaining ports in ascending order.
    for port in range(MIN_PORT, MAX_PORT + 1):
        if port in seen:
            continue
        unique_ranked.append(port)
        if len(unique_ranked) >= limit:
            break
    return unique_ranked


def resolve_top_ports(value: str) -> tuple[int, str]:
    """Resolve top-ports argument from preset name or numeric value."""
    raw = (value or "").strip().lower()
    if not raw:
        raise ValueError("Top ports value is empty.")

    if raw in TOP_PORTS_PRESETS:
        amount = TOP_PORTS_PRESETS[raw]
        return amount, f"{raw}({amount})"

    try:
        amount = int(raw)
    except ValueError as exc:
        presets = ", ".join(TOP_PORTS_PRESETS.keys())
        raise ValueError(f"Invalid --top-ports value '{value}'. Use a number or preset: {presets}.") from exc

    return amount, str(amount)


def recommend_threads(port_count: int, scan_type: str) -> int:
    """Return adaptive thread count tuned for scan size and protocol."""
    protocol = (scan_type or "tcp").lower()
    if protocol == "udp":
        if port_count >= 10000:
            return 350
        if port_count >= 1000:
            return 220
        return 150

    if port_count >= 50000:
        return 600
    if port_count >= 10000:
        return 450
    if port_count >= 1000:
        return 300
    return 200


def normalize_target(target_input: str) -> str:
    """Normalize user target into a hostname/IP accepted by socket APIs."""
    target = (target_input or "").strip()
    if not target:
        raise ValueError("Target is empty.")

    if "://" in target or target.startswith("//"):
        parsed = urlsplit(target)
        host = parsed.hostname
        if not host:
            raise ValueError(f"Could not extract host from URL: '{target_input}'")
        return host

    if "/" in target:
        target = target.split("/", 1)[0]

    if "@" in target:
        target = target.rsplit("@", 1)[1]
    if target.count(":") == 1 and target.rsplit(":", 1)[1].isdigit():
        target = target.rsplit(":", 1)[0]

    if not target:
        raise ValueError(f"Invalid target: '{target_input}'")
    return target


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        prog="ghostscan",
        description="GhostScan CLI - aggressive TCP/UDP recon with async fingerprinting and version detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Basic scan:
    ghostscan scan 127.0.0.1 -p 1-1024
    ghostscan scan scanme.nmap.org -p 22,80,443 -t 200

  Scan types and profiles:
    ghostscan scan target --scan-type udp -p 53,161
    ghostscan scan target --profile stealth
    ghostscan scan target --profile aggressive

  Rate limiting and proxy:
    ghostscan scan target --rate-limit 10
    ghostscan scan target --proxy socks5://127.0.0.1:1080 -p 22,80

  Output formats:
    ghostscan scan target -p 1-1000 --output html
    ghostscan scan target --output json --output-file results.json

Note: Use only on systems you have authorization to test.
""",
    )
    parser.add_argument("--version", action="version", version="ghostscan 1.2.0")

    subparsers = parser.add_subparsers(dest="command", required=True, help="Commands")

    scan_parser = subparsers.add_parser("scan", help="Run a TCP connect scan against a target")
    scan_parser.add_argument("target", help="Target hostname, IPv4 address, or URL")
    scan_mode = scan_parser.add_mutually_exclusive_group()
    scan_mode.add_argument(
        "-p",
        "--ports",
        help=f"Port list/range. Examples: 22,80,443 or 1-1024 (default: {DEFAULT_PORT_RANGE})",
    )
    scan_mode.add_argument(
        "--top-ports",
        help="Scan top ports by preset or number: quick|standard|deep|N (example: --top-ports standard)",
    )
    scan_mode.add_argument(
        "--all-ports",
        action="store_true",
        help="Scan all possible ports (1-65535)",
    )
    scan_parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=None,
        help="Maximum worker threads for port scan (default: adaptive by scan size)",
    )
    scan_parser.add_argument(
        "--timeout",
        type=float,
        default=0.8,
        help="Socket timeout in seconds (default: 0.8)",
    )
    scan_parser.add_argument(
        "--no-detect",
        action="store_true",
        help="Skip service/version detection for fastest scan output",
    )
    scan_parser.add_argument(
        "--detect-firewall",
        action="store_true",
        help="Enable heuristic firewall analysis from scan behavior",
    )
    scan_parser.add_argument(
        "--detect-waf",
        action="store_true",
        help="Enable fast WAF fingerprinting on discovered web endpoints",
    )
    scan_parser.add_argument(
        "--scan-type",
        choices=("tcp", "udp"),
        default="tcp",
        help="Scan protocol type (default: tcp)",
    )
    scan_parser.add_argument(
        "--profile",
        choices=("stealth", "normal", "aggressive", "parallel"),
        help="Use scan profile preset (overrides -t, --timeout, --rate-limit)",
    )
    scan_parser.add_argument(
        "--retries",
        type=int,
        default=0,
        help="Retry attempts per port when not open (default: 0)",
    )
    scan_parser.add_argument(
        "--confirm-filtered",
        action="store_true",
        help="Rescan filtered ports once to reduce false negatives",
    )
    scan_parser.add_argument(
        "--confirm-filtered-limit",
        type=int,
        default=5000,
        help="Maximum filtered ports to rescan on confirmation pass (default: 5000)",
    )
    scan_parser.add_argument(
        "--rate-limit",
        type=float,
        default=0.0,
help="Rate limit in requests per second (default: unlimited)",
    )
    scan_parser.add_argument(
        "--proxy",
        help="Proxy URL (e.g., socks5://127.0.0.1:1080 or http://proxy:8080)",
    )
    scan_parser.add_argument(
        "--output",
        choices=("txt", "json", "csv", "html"),
        default="txt",
        help="Final report format (default: txt)",
    )
    scan_parser.add_argument(
        "--output-file",
        help="Write report to explicit file path (works with txt/json/csv)",
    )
    scan_parser.add_argument("--no-banner", action="store_true", help="Hide ASCII banner")
    scan_parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    return parser.parse_args()


def _detect_services_async(target: str, open_ports: List[int], timeout: float) -> Dict[int, Dict[str, Any]]:
    """Detect service details asynchronously for open ports."""
    detector = ServiceDetector(timeout=timeout)
    if not open_ports:
        return {}
    return asyncio.run(detector.detect_services_async(target, open_ports))


def _build_report_data(
    input_target: str,
    normalized_target: str,
    resolved_target: str,
    ports: List[int],
    open_ports: List[int],
    service_data: Dict[int, Dict[str, Any]],
    scan_elapsed: float,
    total_elapsed: float,
    started_at: datetime,
    finished_at: datetime,
    detect_enabled: bool,
    firewall_assessment: Optional[Dict[str, Any]] = None,
    waf_assessment: Optional[Dict[str, Any]] = None,
scan_type: str = "tcp",
) -> Dict[str, Any]:
    service_counter: Counter[str] = Counter()
    for port in open_ports:
        service_counter[service_data.get(port, {}).get("service", "Unknown")] += 1

    high_risk_services = {
        "TELNET",
        "FTP",
        "SMB",
        "RDP",
        "MSSQL",
        "Redis",
        "MongoDB",
        "Docker",
        "VNC",
    }
    exposed_high_risk = [
        service for service in service_counter if any(token.lower() in service.lower() for token in high_risk_services)
    ]

    results = [service_data.get(port, {"port": port, "service": "Unknown"}) for port in open_ports]

    return {
        "scan": {
            "input_target": input_target,
            "normalized_target": normalized_target,
            "resolved_target": resolved_target,
            "started_at": started_at.isoformat(timespec="seconds"),
            "finished_at": finished_at.isoformat(timespec="seconds"),
            "scan_duration_seconds": round(scan_elapsed, 3),
            "total_duration_seconds": round(total_elapsed, 3),
            "ports_scanned": len(ports),
            "open_ports_count": len(open_ports),
            "detection_enabled": detect_enabled,
            "scan_type": scan_type,
        },
        "summary": {
            "services_detected": dict(service_counter),
            "high_risk_exposures": exposed_high_risk,
            "firewall_assessment": firewall_assessment or {},
            "waf_assessment": waf_assessment or {},
        },
        "results": results,
    }


def _assess_firewall(scan_stats: Dict[str, Dict[str, int]], total_ports: int, target: str) -> Dict[str, Any]:
    """Infer likely firewall presence from scan-state distribution."""
    states = scan_stats.get("states", {})
    reasons = scan_stats.get("reasons", {})

    open_count = int(states.get("open", 0))
    closed_count = int(states.get("closed", 0))
    filtered_count = int(states.get("filtered", 0))
    error_count = int(states.get("error", 0))
    total = max(1, total_ports)

    filtered_ratio = filtered_count / total
    closed_ratio = closed_count / total
    timeout_count = int(reasons.get("timeout", 0))
    blocked_count = int(reasons.get("blocked", 0))
    unreachable_count = int(reasons.get("unreachable", 0))

    score = 0
    signals: List[str] = []

    if filtered_ratio >= 0.60:
        score += 55
        signals.append(f"High filtered ratio ({filtered_ratio:.0%})")
    elif filtered_ratio >= 0.35:
        score += 35
        signals.append(f"Moderate filtered ratio ({filtered_ratio:.0%})")
    elif filtered_ratio >= 0.20:
        score += 18
        signals.append(f"Noticeable filtered ratio ({filtered_ratio:.0%})")

    if timeout_count >= max(5, int(total * 0.10)):
        score += 15
        signals.append(f"Frequent TCP timeouts ({timeout_count})")
    if blocked_count > 0:
        score += 12
        signals.append(f"Explicit access denied signals ({blocked_count})")
    if unreachable_count > 0:
        score += 10
        signals.append(f"Host/network unreachable responses ({unreachable_count})")
    if open_count > 0 and filtered_count > 0 and closed_ratio < 0.25:
        score += 10
        signals.append("Mixed open+filtered pattern with low closed ratio")
    if error_count > max(8, int(total * 0.20)) and filtered_count > 0:
        score += 4
        signals.append(f"Elevated socket error count ({error_count})")

    local_target = False
    try:
        ip_obj = ipaddress.ip_address(target)
        local_target = ip_obj.is_loopback
    except ValueError:
        local_target = target.lower() in {"localhost", "ip6-localhost"}

    if local_target:
        if blocked_count == 0 and unreachable_count == 0:
            score = min(score, 20)
            signals.append("Loopback target: reduced firewall confidence due local stack behavior")
        if filtered_count == 0 and timeout_count == 0:
            score = min(score, 8)
            signals.append("Loopback target with no filtering indicators")

    if filtered_count == 0 and timeout_count == 0 and blocked_count == 0:
        score = min(score, 15)

    score = max(0, min(99, score))
    confidence = round(score / 100.0, 2)

    if score >= 70:
        verdict = "likely"
    elif score >= 40:
        verdict = "possible"
    else:
        verdict = "unlikely"

    behind_firewall = verdict in {"likely", "possible"}
    if filtered_count == 0 and blocked_count == 0 and timeout_count == 0:
        firewall_type = "none-observed"
    elif blocked_count > 0:
        firewall_type = "active-reject-filter"
    elif filtered_count > 0 and timeout_count > 0:
        firewall_type = "silent-drop-filter"
    else:
        firewall_type = "network-filter-possible"

    return {
        "enabled": True,
        "behind_firewall": behind_firewall,
        "verdict": verdict,
        "firewall_type": firewall_type,
        "score": score,
        "confidence": confidence,
        "states": {
            "open": open_count,
            "closed": closed_count,
            "filtered": filtered_count,
            "error": error_count,
        },
        "signals": signals,
    }


def _http_probe(url: str, timeout: float) -> Tuple[Dict[str, str], str, int]:
    """Issue a safe HTTP probe and return (headers, body_excerpt, status_code)."""
    req = url_request.Request(
        url,
        headers={
            "User-Agent": "GhostScan-WAF-Probe/1.0",
            "Accept": "text/html,application/json,*/*;q=0.8",
            "Connection": "close",
        },
        method="GET",
    )
    context = ssl._create_unverified_context()
    try:
        with url_request.urlopen(req, timeout=timeout, context=context) as resp:
            body = resp.read(2048).decode("utf-8", errors="ignore")
            return dict(resp.headers.items()), body.lower(), int(getattr(resp, "status", 200))
    except url_error.HTTPError as exc:
        try:
            body = exc.read(2048).decode("utf-8", errors="ignore").lower()
        except Exception:
            body = ""
        return dict(exc.headers.items()), body, int(exc.code)
    except Exception:
        return {}, "", 0


def _detect_waf(target: str, open_ports: List[int], timeout: float) -> Dict[str, Any]:
    """Fast WAF fingerprinting based on response headers/body."""
    candidate_ports = [p for p in open_ports if p in WEB_PROBE_PORTS]
    if not candidate_ports:
        return {
            "enabled": True,
            "detected": False,
            "confidence": 0.0,
            "vendors": [],
            "signals": ["No web ports available for probe"],
            "tested_endpoints": [],
        }

    endpoints = []
    for port in candidate_ports:
        if port in (443, 8443):
            scheme = "https"
        else:
            scheme = "http"
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            endpoints.append(f"{scheme}://{target}/")
        else:
            endpoints.append(f"{scheme}://{target}:{port}/")

    signals: List[str] = []
    score = 0
    tested: List[str] = []

    fingerprints = {
        "Cloudflare": ("cf-ray", "cf-cache-status", "server:cloudflare", "__cf_bm", "attention required | cloudflare"),
        "Akamai": ("akamai", "x-akamai", "akamai-origin-hop"),
        "Imperva": ("incapsula", "x-iinfo", "visid_incap", "x-cdn:incapsula"),
        "F5 BIG-IP ASM": ("x-waf-event-info", "bigip", "ts01"),
        "AWS WAF": ("x-amzn-requestid", "request blocked", "awswaf"),
        "Sucuri": ("x-sucuri-id", "x-sucuri-cache", "sucuri"),
        "ModSecurity": ("mod_security", "modsecurity", "not acceptable!"),
    }

    for endpoint in endpoints:
        headers, body, status = _http_probe(endpoint, timeout=max(1.0, timeout))
        tested.append(endpoint)
        if not headers and status == 0:
            continue

        header_blob = " ".join(f"{k.lower()}:{v.lower()}" for k, v in headers.items())
        combined = f"{header_blob} {body}"

        if status in (401, 403, 406, 429):
            score += 5
            signals.append(f"{endpoint} returned status {status}")

        for vendor, patterns in fingerprints.items():
            if any(pattern in combined for pattern in patterns):
                score += 25
                signals.append(f"WAF signature matched on {endpoint}")

    score = max(0, min(99, score))
    detected = score >= 25
    confidence = round(score / 100.0, 2) if detected else round(min(score, 20) / 100.0, 2)

    return {
        "enabled": True,
        "detected": detected,
        "confidence": confidence,
        "score": score,
        "signals": signals[:10],
        "tested_endpoints": tested,
    }


def _write_json_report(path: Path, payload: Dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def _write_csv_report(path: Path, payload: Dict[str, Any]) -> None:
    rows = payload.get("results", [])
    fields = ["port", "service", "version", "transport", "confidence", "probe_used", "banner"]
    with path.open("w", newline="", encoding="utf-8") as fp:
        writer = csv.DictWriter(fp, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fields})


def _write_text_report(path: Path, payload: Dict[str, Any]) -> None:
    scan = payload["scan"]
    summary = payload["summary"]
    results = payload["results"]

    lines = [
        "GHOSTSCAN // OPERATION REPORT",
        "=" * 44,
        f"Input target      : {scan['input_target']}",
        f"Resolved target   : {scan['resolved_target']}",
        f"Started           : {scan['started_at']}",
        f"Finished          : {scan['finished_at']}",
        f"Scan duration (s) : {scan['scan_duration_seconds']}",
        f"Total duration(s) : {scan['total_duration_seconds']}",
        f"Ports scanned     : {scan['ports_scanned']}",
        f"Open ports        : {scan['open_ports_count']}",
        f"Detection enabled : {scan['detection_enabled']}",
        "",
        "SERVICE BREAKDOWN",
        "-" * 44,
    ]

    services = summary.get("services_detected", {})
    if services:
        for service, count in sorted(services.items(), key=lambda item: (-item[1], item[0])):
            lines.append(f"{service:<20} {count}")
    else:
        lines.append("No services detected")

    lines.extend(["", "OPEN PORT DETAILS", "-" * 44])
    if results:
        for row in results:
            version = f" {row.get('version')}" if row.get("version") else ""
            lines.append(
                f"{row.get('port', ''):>5}  {row.get('service', 'Unknown')}{version} "
                f"[{row.get('transport', 'tcp')}] conf={row.get('confidence', 0)}"
            )
    else:
        lines.append("No open ports")

    risks = summary.get("high_risk_exposures", [])
    lines.extend(["", "RISK SNAPSHOT", "-" * 44])
    if risks:
        lines.append("Potentially risky exposed services: " + ", ".join(risks))
    else:
        lines.append("No high-risk service exposure pattern detected.")

    firewall = summary.get("firewall_assessment", {})
    if firewall.get("enabled"):
        lines.extend(["", "FIREWALL HEURISTIC", "-" * 44])
        lines.append(f"Firewall present: {'yes' if firewall.get('behind_firewall') else 'no'}")

    waf = summary.get("waf_assessment", {})
    if waf.get("enabled"):
        lines.extend(["", "WAF FINGERPRINT", "-" * 44])
        if waf.get("detected"):
            lines.append(f"Detected: yes | Confidence: {waf.get('confidence', 0):.2f}")
        else:
            lines.append(f"Detected: no | Confidence: {waf.get('confidence', 0):.2f}")
        for signal in waf.get("signals", [])[:6]:
            lines.append(f"- {signal}")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _export_report(args: argparse.Namespace, payload: Dict[str, Any]) -> Path:
    ext = args.output
    if args.output_file:
        path = Path(args.output_file)
    else:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = Path(f"ghostscan_report_{ts}.{ext}")

    if ext == "json":
        _write_json_report(path, payload)
    elif ext == "csv":
        _write_csv_report(path, payload)
    elif ext == "html":
        if _generate_html_report is None:
            raise ValueError("HTML report not available. Install template engine if needed.")
        _generate_html_report(payload, path)
    else:
        _write_text_report(path, payload)

    return path.resolve()


def _print_professional_report(payload: Dict[str, Any]) -> None:
    scan = payload["scan"]
    summary = payload["summary"]

    print_warning(">>> FINAL OPERATION REPORT")
    print("  " + "-" * 45)
    print_info(f"Target: {scan['resolved_target']} | Ports scanned: {scan['ports_scanned']}")
    print_info(
        f"Scan: {scan['scan_duration_seconds']:.2f}s | Total: {scan['total_duration_seconds']:.2f}s | Open: {scan['open_ports_count']}"
    )

    services = summary.get("services_detected", {})
    if services:
        top = ", ".join(
            f"{name}:{count}" for name, count in sorted(services.items(), key=lambda item: (-item[1], item[0]))[:6]
        )
        print_info(f"Service density: {top}")

    risks = summary.get("high_risk_exposures", [])
    if risks:
        print_warning(f">>> High-risk exposure patterns: {', '.join(risks)}")
    else:
        print_success("No obvious high-risk exposure pattern detected.")

    firewall = summary.get("firewall_assessment", {})
    if firewall.get("enabled"):
        presence = "YES" if firewall.get("behind_firewall") else "NO"
        print_info(f"Firewall presence: {presence}")

    waf = summary.get("waf_assessment", {})
    if waf.get("enabled"):
        if waf.get("detected"):
            print_warning(f">>> WAF fingerprint detected (conf={waf.get('confidence', 0):.2f})")
        else:
            print_info(f"WAF fingerprint: not detected (conf={waf.get('confidence', 0):.2f})")


def main() -> None:
    """Main entry point."""
    args = parse_args()

    if not args.no_banner:
        print_banner()

    try:
        if args.timeout <= 0:
            raise ValueError("Timeout must be > 0.")
        if args.retries < 0:
            raise ValueError("Retries must be >= 0.")
        if args.confirm_filtered_limit < 1:
            raise ValueError("Confirm-filtered-limit must be >= 1.")

        if args.proxy:
            print_info(f"[*] Using proxy: {args.proxy}")

        profile = None
        if args.profile:
            profile = PortScanner.PROFILES.get(args.profile)
            if profile:
                print_info(f"[*] Using profile: {args.profile} - {profile.description}")
                args.threads = profile.threads
                args.timeout = profile.timeout
                if profile.rate_limit > 0:
                    args.rate_limit = profile.rate_limit

        if args.top_ports is not None:
            top_count, top_label = resolve_top_ports(args.top_ports)
            ports = get_top_ports(top_count)
            scan_ports_label = f"top-{top_label}"
        elif args.all_ports:
            ports = list(range(MIN_PORT, MAX_PORT + 1))
            scan_ports_label = f"{MIN_PORT}-{MAX_PORT}"
        else:
            chosen_ports = args.ports if args.ports else DEFAULT_PORT_RANGE
            ports = parse_ports(chosen_ports)
            scan_ports_label = chosen_ports

        if args.threads is None:
            args.threads = profile.threads if profile else recommend_threads(len(ports), args.scan_type)
            print_info(f"[*] Adaptive threads selected: {args.threads}")
        if args.threads < 1:
            raise ValueError("Threads must be >= 1.")
        normalized_target = normalize_target(args.target)

        rate_limiter = None
        if args.rate_limit > 0:
            rate_limiter = RateLimiter(requests_per_second=args.rate_limit)
            print_info(f"[*] Rate limit: {args.rate_limit} req/s")

        profile_retry = profile.retry_count if profile else 0
        retry_count = max(args.retries, profile_retry)

        scanner = PortScanner(
            normalized_target,
            ports,
            args.threads,
            args.timeout,
            args.verbose,
            scan_type=args.scan_type,
            rate_limiter=rate_limiter,
            retry_count=retry_count,
        )
        resolved_target = scanner.get_target()

        scan_type_display = args.scan_type.upper()
        print_scan_header(normalized_target, resolved_target, scan_ports_label, len(ports), args.threads, args.timeout)
        print_warning(f">>> Weaponizing {scan_type_display} scan threads and priming sockets...\n")

        operation_started = datetime.now()
        scan_start = datetime.now()
        open_ports = scanner.scan()
        scan_elapsed = (datetime.now() - scan_start).total_seconds()
        scan_stats = scanner.get_scan_stats()
        port_results = scanner.get_port_results()

        if args.confirm_filtered and args.scan_type == "tcp":
            filtered_ports = sorted(port for port, result in port_results.items() if result[0] == "filtered")
            if filtered_ports:
                if len(filtered_ports) > args.confirm_filtered_limit:
                    original_count = len(filtered_ports)
                    filtered_ports = filtered_ports[: args.confirm_filtered_limit]
                    print_warning(
                        f">>> Confirmation limited to first {len(filtered_ports)} filtered ports "
                        f"(of {original_count}). Increase --confirm-filtered-limit to expand."
                    )
                print_info(f"[*] Confirming {len(filtered_ports)} filtered ports with a second pass...")
                confirm_start = datetime.now()
                confirm_scanner = PortScanner(
                    normalized_target,
                    filtered_ports,
                    args.threads,
                    args.timeout,
                    args.verbose,
                    scan_type=args.scan_type,
                    rate_limiter=rate_limiter,
                    retry_count=max(1, retry_count),
                )
                confirmed_open_ports = confirm_scanner.scan()
                if confirmed_open_ports:
                    open_ports = sorted(set(open_ports).union(confirmed_open_ports))
                    print_info(f"[*] Confirmation promoted {len(confirmed_open_ports)} port(s) to open.")
                scan_elapsed += (datetime.now() - confirm_start).total_seconds()

        print()
        print_success(f"Strike complete in {scan_elapsed:.2f}s")
        print()

        service_data: Dict[int, Dict[str, Any]] = {}
        if open_ports:
            print_warning(">>> BREACH POINTS IDENTIFIED:")
            print("  " + "-" * 45)

            if args.no_detect:
                for port in open_ports:
                    service_data[port] = {
                        "port": port,
                        "service": "OPEN",
                        "version": "",
                        "banner": "",
                        "transport": args.scan_type,
                        "confidence": 0.3,
                        "probe_used": False,
                    }
                    print_open_port(port, "OPEN (fingerprint bypassed)")
            else:
                print_warning(">>> Running async fingerprinting and version extraction...")
                service_data = _detect_services_async(resolved_target, open_ports, args.timeout)
                for port in open_ports:
                    row = service_data.get(port, {"service": "Unknown", "version": "", "confidence": 0.0})
                    service_label = row["service"]
                    if row.get("version"):
                        service_label = f"{service_label} {row['version']}"
                    service_label = f"{service_label} (conf {row.get('confidence', 0):.2f})"
                    print_open_port(port, service_label)
        else:
            print_warning(">>> Surface hardened: no open ports detected")

        operation_finished = datetime.now()
        total_elapsed = (operation_finished - operation_started).total_seconds()
        firewall_assessment = _assess_firewall(scan_stats, len(ports), resolved_target) if args.detect_firewall else {}
        waf_assessment = _detect_waf(resolved_target, open_ports, args.timeout) if args.detect_waf else {}

        report_payload = _build_report_data(
            input_target=args.target,
            normalized_target=normalized_target,
            resolved_target=resolved_target,
            ports=ports,
            open_ports=open_ports,
            service_data=service_data,
            scan_elapsed=scan_elapsed,
            total_elapsed=total_elapsed,
            started_at=operation_started,
            finished_at=operation_finished,
            detect_enabled=not args.no_detect,
            firewall_assessment=firewall_assessment,
            waf_assessment=waf_assessment,
            scan_type=args.scan_type,
        )

        print()
        print_info(f"Runtime: {total_elapsed:.2f}s | Breach points: {len(open_ports)}")
        if args.verbose:
            if normalized_target != args.target:
                print_info(f"Normalized target: {args.target} -> {normalized_target}")
            print_info(f"Resolved target: {normalized_target} -> {resolved_target}")

        _print_professional_report(report_payload)
        report_path = _export_report(args, report_payload)
        print_success(f"Report exported: {report_path}")
        print()

    except KeyboardInterrupt:
        print_error("Operation aborted by operator.")
        sys.exit(130)
    except Exception as exc:
        print_error(str(exc))
        sys.exit(1)


if __name__ == "__main__":
    main()
