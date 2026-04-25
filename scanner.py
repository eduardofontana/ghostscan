"""TCP/UDP port scanning engine with async I/O and optimizations."""

import asyncio
import concurrent.futures
import errno
import ipaddress
import random
import socket
import struct
import threading
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
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def __post_init__(self):
        self._bucket_size = max(1.0, self.requests_per_second)
        self._tokens = self._bucket_size
        self._last_update = time.monotonic()

    def acquire(self, tokens: int = 1) -> None:
        if self.requests_per_second <= 0:
            return
        while True:
            with self._lock:
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


class AsyncPortScanner:
    """Async TCP/UDP scanner with asyncio for high performance."""

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

    COMMON_PORTS_TIMEOUTS = {
        80: 0.5,
        443: 0.5,
        22: 0.8,
        21: 0.8,
        25: 0.8,
        53: 0.8,
        110: 0.8,
        143: 0.8,
        3306: 0.8,
        5432: 0.8,
        27017: 0.8,
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
        self._port_results: Dict[int, Tuple[str, str]] = {}
        self._scan_stats: Dict[str, Dict[str, int]] = {
            "states": {"open": 0, "closed": 0, "filtered": 0, "error": 0},
            "reasons": {},
        }
        self._results_lock = threading.Lock()
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._socket_cache: Dict[int, socket.socket] = {}
        self._cache_lock = threading.Lock()

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

    def _get_adaptive_timeout(self, port: int) -> float:
        """Return adaptive timeout based on port known behavior."""
        return self.COMMON_PORTS_TIMEOUTS.get(port, self.timeout)

    async def _async_scan_port(self, port: int) -> Tuple[str, str]:
        """Async TCP connect scan for a single port."""
        target_ip = self._resolved_target or self._resolve_host()
        is_loopback = self._is_loopback_ip(target_ip)
        timeout = self._get_adaptive_timeout(port)

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target_ip, port),
                timeout=timeout
            )
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=0.05)
            except Exception:
                pass
            return "open", "async_connect"
        except asyncio.TimeoutError:
            if is_loopback:
                return "closed", "loopback_timeout"
            return "filtered", "timeout"
        except ConnectionRefusedError:
            return "closed", "conn_refused"
        except BrokenPipeError:
            return "open", "broken_pipe"
        except OSError as exc:
            err = exc.errno if exc.errno is not None else -1
            if err in {errno.ETIMEDOUT, 10060}:
                if is_loopback:
                    return "closed", "loopback_timeout"
                return "filtered", "timeout"
            if err in {errno.EHOSTUNREACH, errno.ENETUNREACH, 10065, 10051}:
                return "filtered", "unreachable"
            if err in {errno.ECONNRESET, 10054}:
                return "closed", "conn_reset"
            if err in {errno.EACCES, 10013}:
                return "filtered", "blocked"
            return "error", f"oserror_{err}"
        except Exception as e:
            return "error", str(e)

        return "error", "unknown"

    async def _async_scan_port_udp(self, port: int) -> Tuple[str, str]:
        """Async UDP scan for a single port."""
        target_ip = self._resolved_target or self._resolve_host()
        is_loopback = self._is_loopback_ip(target_ip)
        timeout = self._get_adaptive_timeout(port)

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(False)

            loop = asyncio.get_event_loop()
            await loop.sock_sendto(sock, b"\x00", (target_ip, port))

            try:
                await asyncio.wait_for(
                    loop.sock_recvfrom(sock, 1024),
                    timeout=timeout
                )
                return "open", "udp_response"
            except asyncio.TimeoutError:
                pass
            finally:
                sock.close()

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

    async def _scan_with_retry(self, port: int, scan_func) -> Tuple[str, str]:
        """Scan with retry logic."""
        for attempt in range(self.retry_count + 1):
            state, reason = await scan_func(port)
            if state == "open" or attempt == self.retry_count:
                return state, reason
            await asyncio.sleep(0.1 * (attempt + 1))
        return "error", "max_retries"

    async def _batch_worker(
        self,
        ports: List[int],
        state_counter: Counter,
        reason_counter: Counter,
        results: Dict[int, Tuple[str, str]],
        scan_func,
    ) -> None:
        """Process a batch of ports asynchronously."""
        for port in ports:
            if self.rate_limiter:
                self.rate_limiter.acquire(1)

            if self.retry_count > 0:
                state, reason = await self._scan_with_retry(port, scan_func)
            else:
                state, reason = await scan_func(port)

            results[port] = (state, reason)
            state_counter[state] += 1
            reason_counter[reason] += 1

    async def scan_async(self) -> List[int]:
        """Scan all ports using async I/O."""
        resolved = self._resolve_host()
        target_ip = resolved
        if self.verbose:
            print(f"Resolved {self.target} -> {resolved}")

        scan_func = self._async_scan_port_udp if self.scan_type == "udp" else self._async_scan_port

        self.open_ports = []
        self._port_results = {}
        state_counter = Counter({"open": 0, "closed": 0, "filtered": 0, "error": 0})
        reason_counter = Counter()
        results: Dict[int, Tuple[str, str]] = {}

        batch_size = min(1000, len(self.ports))
        ports_batches = [
            self.ports[i:i + batch_size]
            for i in range(0, len(self.ports), batch_size)
        ]

        semaphore = asyncio.Semaphore(self.threads)

        async def bounded_scan(port: int) -> Tuple[str, str]:
            async with semaphore:
                return await scan_func(port)

        async def process_batch(ports_batch: List[int]) -> None:
            tasks = [bounded_scan(port) for port in ports_batch]
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)

            for port, result in zip(ports_batch, batch_results):
                if isinstance(result, Exception):
                    state, reason = "error", str(result)
                else:
                    state, reason = result

                results[port] = (state, reason)
                state_counter[state] += 1
                reason_counter[reason] += 1
                if state == "open":
                    self.open_ports.append(port)

        for batch in ports_batches:
            await process_batch(batch)

        self._port_results = results
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

    def scan(self) -> List[int]:
        """Main scan entry point - runs async scan in event loop."""
        return asyncio.run(self.scan_async())

    def get_target(self) -> str:
        """Return resolved target IP."""
        return self._resolve_host()

    def get_scan_stats(self) -> Dict[str, Dict[str, int]]:
        """Return summarized scan states and low-level reasons."""
        return self._scan_stats

    def get_port_results(self) -> Dict[int, Tuple[str, str]]:
        """Return per-port (state, reason) results from the latest scan."""
        return dict(self._port_results)


class PortScanner:
    """TCP connect scanner - wrapper for async scanner."""

    PROFILES: Dict[str, ScanProfile] = AsyncPortScanner.PROFILES

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
        self._async_scanner = AsyncPortScanner(
            target, ports, threads, timeout, verbose, scan_type, rate_limiter, retry_count
        )

    def _resolve_host(self) -> str:
        return self._async_scanner._resolve_host()

    def scan(self) -> List[int]:
        return self._async_scanner.scan()

    def get_target(self) -> str:
        return self._async_scanner.get_target()

    def get_scan_stats(self) -> Dict[str, Dict[str, int]]:
        return self._async_scanner.get_scan_stats()

    def get_port_results(self) -> Dict[int, Tuple[str, str]]:
        return self._async_scanner.get_port_results()