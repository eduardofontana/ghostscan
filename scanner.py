"""TCP/UDP port scanning engine with concurrent connect probes."""

import concurrent.futures
import errno
import ipaddress
import random
import select
import socket
import struct
import time
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple, Union

from dataclasses import dataclass, field

@dataclass
class RateLimiter:
    """Token bucket rate limiter for controlling scan speed."""
    requests_per_second: float = 0.0
    _tokens: float = field(default=0.0)
    _last_update: float = field(default=0.0)
    _bucket_size: float = field(default=0.0)

    def __post_init__(self):
        self._bucket_size = max(1.0, self.requests_per_second)
        self._tokens = self._bucket_size
        self._last_update = time.monotonic()

    def acquire(self, tokens: int = 1) -> None:
        if self.requests_per_second <= 0:
            return
        while True:
            now = time.monotonic()
            elapsed = now - self._last_update
            self._tokens = min(self._bucket_size, self._tokens + elapsed * self.requests_per_second)
            self._last_update = now
            if self._tokens >= tokens:
                self._tokens -= tokens
                return
            sleep_time = (tokens - self._tokens) / self.requests_per_second
            if sleep_time > 0:
                time.sleep(sleep_time)


@dataclass
class ScanProfile:
    """Scan profile with preset configurations."""
    name: str
    description: str
    threads: int = 200
    timeout: float = 0.8
    rate_limit: float = 0.0
    retry_count: int = 0
    scan_type: str = "tcp"
    aggressive: bool = False


class PortScanner:
    """TCP connect scanner with simple concurrency controls."""

    PROFILES: Dict[str, ScanProfile] = {
        "stealth": ScanProfile(
            name="stealth",
            description="Low-profile scan with minimal requests",
            threads=10,
            timeout=1.5,
            rate_limit=5,
            retry_count=1,
            aggressive=False,
        ),
        "normal": ScanProfile(
            name="normal",
            description="Balanced for most targets",
            threads=200,
            timeout=0.8,
            rate_limit=0,
            retry_count=0,
            aggressive=False,
        ),
        "aggressive": ScanProfile(
            name="aggressive",
            description="Fast aggressive scan",
            threads=500,
            timeout=0.3,
            rate_limit=0,
            retry_count=2,
            aggressive=True,
        ),
        "parallel": ScanProfile(
            name="parallel",
            description="Massive parallel scan",
            threads=1000,
            timeout=0.2,
            rate_limit=0,
            retry_count=0,
            aggressive=True,
        ),
    }

    def __init__(
        self,
        target: str,
        ports: List[int],
        threads: int = 200,
        timeout: float = 0.8,
        verbose: bool = False,
        scan_type: str = "tcp",
        rate_limiter: Optional[RateLimiter] = None,
        retry_count: int = 0,
    ):
        if not ports:
            raise ValueError("No ports provided for scanning.")

        self.target = target
        self.ports = sorted(set(ports))
        self.threads = max(1, int(threads))
        self.timeout = float(timeout)
        self.verbose = verbose
        self.scan_type = scan_type.lower()
        self.rate_limiter = rate_limiter
        self.retry_count = max(0, int(retry_count))
        self.open_ports: List[int] = []
        self._resolved_target: Optional[str] = None
        self._scan_stats: Dict[str, Dict[str, int]] = {
            "states": {"open": 0, "closed": 0, "filtered": 0, "error": 0},
            "reasons": {},
        }

    def _resolve_host(self) -> str:
        """Resolve and cache hostname to IPv4 address."""
        if self._resolved_target:
            return self._resolved_target
        try:
            self._resolved_target = socket.gethostbyname(self.target)
            return self._resolved_target
        except socket.gaierror as exc:
            raise ValueError(f"Cannot resolve host: {self.target}") from exc

    @staticmethod
    def _is_loopback_ip(value: str) -> bool:
        try:
            return ipaddress.ip_address(value).is_loopback
        except ValueError:
            return value.lower() in {"localhost", "ip6-localhost"}

    def _scan_port(self, port: int) -> Tuple[str, str]:
        """Return (state, reason) for a single TCP connect probe."""
        target_ip = self._resolved_target or self._resolve_host()
        is_loopback = self._is_loopback_ip(target_ip)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                code = sock.connect_ex((target_ip, port))

                # Windows often returns WSAEWOULDBLOCK/INPROGRESS for connect_ex.
                # Resolve that transitional state by waiting for writability and reading SO_ERROR.
                if code in {errno.EINPROGRESS, errno.EALREADY, errno.EWOULDBLOCK, 10035}:
                    _, writable, _ = select.select([], [sock], [], self.timeout)
                    if not writable:
                        if is_loopback:
                            return "closed", "loopback_timeout"
                        return "filtered", "timeout"
                    code = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        except TimeoutError:
            if is_loopback:
                return "closed", "loopback_timeout"
            return "filtered", "timeout"
        except OSError as exc:
            err = exc.errno if exc.errno is not None else -1
            if err in {errno.ETIMEDOUT, 10060}:
                if is_loopback:
                    return "closed", "loopback_timeout"
                return "filtered", "timeout"
            if err in {errno.EHOSTUNREACH, errno.ENETUNREACH, 10065, 10051}:
                return "filtered", "unreachable"
            return "error", f"oserror_{err}"

        if code == 0:
            return "open", "syn_ack"
        if code in {errno.ECONNREFUSED, 10061}:
            return "closed", "conn_refused"
        if code in {errno.ETIMEDOUT, 10060}:
            return "filtered", "timeout"
        if code in {errno.EHOSTUNREACH, errno.ENETUNREACH, 10065, 10051}:
            return "filtered", "unreachable"
        if code in {errno.ECONNRESET, 10054}:
            return "closed", "conn_reset"
        if code in {errno.EACCES, 10013}:
            return "filtered", "blocked"
        return "error", f"code_{code}"

    def _scan_port_udp(self, port: int) -> Tuple[str, str]:
        """Return (state, reason) for a single UDP probe."""
        target_ip = self._resolved_target or self._resolve_host()
        is_loopback = self._is_loopback_ip(target_ip)

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(self.timeout)
                sock.sendto(b"\x00", (target_ip, port))

                try:
                    data, addr = sock.recvfrom(1024)
                    if data:
                        return "open", "udp_response"
                except socket.timeout:
                    pass

        except OSError as exc:
            err = exc.errno if exc.errno is not None else -1
            if err in {errno.ETIMEDOUT, 10060}:
                if is_loopback:
                    return "closed", "loopback_timeout"
                return "filtered", "no_response"
            if err in {errno.EHOSTUNREACH, errno.ENETUNREACH, 10065, 10051}:
                return "filtered", "unreachable"
            if err in {errno.EACCES, 10013}:
                return "filtered", "blocked"
            return "error", f"oserror_{err}"

        return "filtered", "no_response"

    def scan(self) -> List[int]:
        """Scan all requested ports and return open ports sorted ascending."""
        resolved = self._resolve_host()
        if self.verbose:
            print(f"Resolved {self.target} -> {resolved}")

        scan_func = self._scan_port_udp if self.scan_type == "udp" else self._scan_port

        self.open_ports = []
        state_counter = Counter({"open": 0, "closed": 0, "filtered": 0, "error": 0})
        reason_counter = Counter()
        max_workers = min(self.threads, len(self.ports)) or 1

        def scan_with_retry(port: int) -> Tuple[str, str]:
            for attempt in range(self.retry_count + 1):
                state, reason = scan_func(port)
                if state == "open" or attempt == self.retry_count:
                    return state, reason
                time.sleep(0.1 * (attempt + 1))
            return "error", "max_retries"

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_port = {}
            for port in self.ports:
                if self.rate_limiter:
                    self.rate_limiter.acquire(1)
                future_to_port[executor.submit(scan_with_retry if self.retry_count > 0 else scan_func, port)] = port

            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    state, reason = future.result()
                    state_counter[state] += 1
                    reason_counter[reason] += 1
                    if state == "open":
                        self.open_ports.append(port)
                except Exception:
                    state_counter["error"] += 1
                    reason_counter["executor_exception"] += 1
                    continue

        self._scan_stats = {
            "states": {
                "open": int(state_counter["open"]),
                "closed": int(state_counter["closed"]),
                "filtered": int(state_counter["filtered"]),
                "error": int(state_counter["error"]),
            },
            "reasons": dict(reason_counter),
        }
        self.open_ports.sort()
        return self.open_ports

    def get_target(self) -> str:
        """Return resolved target IP."""
        return self._resolve_host()

    def get_scan_stats(self) -> Dict[str, Dict[str, int]]:
        """Return summarized scan states and low-level reasons."""
        return self._scan_stats
