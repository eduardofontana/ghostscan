"""Service detection via async banner analysis, probes, TLS, and version parsing."""

import asyncio
import re
import socket
import ssl
from typing import Any, Dict, List, Optional


COMMON_SERVICES: Dict[int, str] = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    111: "RPCBIND",
    119: "NNTP",
    123: "NTP",
    135: "MS-RPC",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    139: "NetBIOS-SSN",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP-TRAP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "SYSLOG",
    515: "LPD",
    587: "SMTP",
    631: "IPP",
    636: "LDAPS",
    873: "RSYNC",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS",
    1433: "MSSQL",
    1521: "Oracle",
    2049: "NFS",
    2375: "Docker",
    2376: "Docker-TLS",
    3306: "MySQL",
    3389: "RDP",
    5000: "HTTP-ALT",
    5432: "PostgreSQL",
    5672: "AMQP",
    5900: "VNC",
    6379: "Redis",
    8000: "HTTP-ALT",
    8080: "HTTP-ALT",
    8081: "HTTP-ALT",
    8443: "HTTPS-ALT",
    9000: "HTTP-ALT",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
}

WEB_PORTS = {80, 443, 5000, 7001, 8000, 8080, 8081, 8443, 8888, 9000}
TLS_PORTS = {443, 465, 563, 636, 853, 989, 990, 992, 993, 995, 2376, 8443, 9443}

PORT_PROBES: Dict[int, bytes] = {
    21: b"HELP\r\n",
    22: b"\r\n",
    25: b"EHLO ghostscan.local\r\n",
    110: b"CAPA\r\n",
    143: b". CAPABILITY\r\n",
    6379: b"PING\r\n",
}

BANNER_SIGNATURES = {
    b"http/": "HTTP",
    b"server:": "HTTP",
    b"ssh-": "SSH",
    b"smtp": "SMTP",
    b"220 ": "FTP",
    b"220-": "FTP",
    b"+ok": "POP3",
    b"* ok": "IMAP",
    b"imap": "IMAP",
    b"mysql": "MySQL",
    b"postgresql": "PostgreSQL",
    b"redis": "Redis",
    b"-err": "Redis",
    b"mongodb": "MongoDB",
    b"rdp": "RDP",
}


class ServiceDetector:
    """Detect likely service name/version for open TCP ports."""

    def __init__(self, timeout: float = 0.8):
        self.timeout = timeout

    def _open_socket(self, host: str, port: int) -> socket.socket:
        sock = socket.create_connection((host, port), timeout=self.timeout)
        sock.settimeout(self.timeout)
        return sock

    def _grab_banner(self, host: str, port: int, probe: Optional[bytes] = None) -> bytes:
        """Connect and try to read a service banner."""
        try:
            with self._open_socket(host, port) as sock:
                if probe is not None:
                    sock.sendall(probe)
                return sock.recv(2048)
        except OSError:
            return b""

    def _try_http_probe(self, host: str, port: int) -> bytes:
        request = (
            f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: GhostScan/1.1\r\nConnection: close\r\n\r\n"
        ).encode("ascii", errors="ignore")
        return self._grab_banner(host, port, request)

    def _identify_from_banner(self, banner: bytes) -> Optional[str]:
        if not banner:
            return None

        lower = banner.lower()
        for signature, service in BANNER_SIGNATURES.items():
            if signature in lower:
                return service
        return None

    def _decode_banner(self, banner: bytes) -> str:
        if not banner:
            return ""
        return banner.decode("utf-8", errors="ignore").strip()

    def _extract_version(self, service: str, banner_text: str) -> Optional[str]:
        """Try to extract a useful version string from banner text."""
        if not banner_text:
            return None

        patterns: List[re.Pattern[str]] = []
        lower_service = service.lower()

        if "ssh" in lower_service:
            patterns.append(re.compile(r"ssh-\d+\.\d+-([^\s\r\n]+)", re.IGNORECASE))
            patterns.append(re.compile(r"openssh[_/\-]([0-9][\w\.\-p]+)", re.IGNORECASE))
        elif "http" in lower_service:
            patterns.append(re.compile(r"server:\s*([^\r\n]+)", re.IGNORECASE))
            patterns.append(re.compile(r"(apache/?[0-9][\w\.\-]*)", re.IGNORECASE))
            patterns.append(re.compile(r"(nginx/?[0-9][\w\.\-]*)", re.IGNORECASE))
            patterns.append(re.compile(r"(microsoft-iis/[0-9\.]+)", re.IGNORECASE))
        elif "smtp" in lower_service:
            patterns.append(re.compile(r"(postfix[^\r\n]*)", re.IGNORECASE))
            patterns.append(re.compile(r"(exim\s+[0-9][\w\.\-]*)", re.IGNORECASE))
        elif "ftp" in lower_service:
            patterns.append(re.compile(r"(vsftpd\s+[0-9][\w\.\-]*)", re.IGNORECASE))
            patterns.append(re.compile(r"(proftpd\s+[0-9][\w\.\-]*)", re.IGNORECASE))
        elif "redis" in lower_service:
            patterns.append(re.compile(r"redis.*v=([0-9][^,\s]*)", re.IGNORECASE))
        elif "mysql" in lower_service:
            patterns.append(re.compile(r"([0-9]+\.[0-9]+\.[0-9]+-mariadb)", re.IGNORECASE))
            patterns.append(re.compile(r"([0-9]+\.[0-9]+\.[0-9]+)", re.IGNORECASE))
        elif "postgres" in lower_service:
            patterns.append(re.compile(r"postgres(?:ql)?\s*([0-9][\w\.\-]*)", re.IGNORECASE))

        patterns.append(re.compile(r"\b([0-9]+\.[0-9]+(?:\.[0-9]+)?)\b"))

        for pattern in patterns:
            match = pattern.search(banner_text)
            if match:
                return match.group(1).strip()
        return None

    def _is_tls_service(self, host: str, port: int) -> bool:
        """Attempt a TLS handshake. True implies an SSL/TLS service."""
        raw_sock = None
        tls_sock = None
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            raw_sock = self._open_socket(host, port)
            tls_sock = context.wrap_socket(raw_sock, server_hostname=host)
            return True
        except OSError:
            return False
        finally:
            if tls_sock is not None:
                tls_sock.close()
            elif raw_sock is not None:
                raw_sock.close()

    def detect_service(self, host: str, port: int) -> str:
        """Detect service using active probes and resilient fallbacks."""
        banner = b""

        if port in PORT_PROBES:
            banner = self._grab_banner(host, port, PORT_PROBES[port])
        if not banner and port in WEB_PORTS:
            banner = self._try_http_probe(host, port)
        if not banner:
            banner = self._grab_banner(host, port)

        detected = self._identify_from_banner(banner)
        if detected:
            if detected == "HTTP" and port in TLS_PORTS and self._is_tls_service(host, port):
                return "HTTPS"
            return detected

        if port in TLS_PORTS and self._is_tls_service(host, port):
            if port in COMMON_SERVICES and "HTTPS" in COMMON_SERVICES[port]:
                return COMMON_SERVICES[port]
            return "TLS"

        if port in COMMON_SERVICES:
            return COMMON_SERVICES[port]

        return "Unknown"

    async def _grab_banner_async(self, host: str, port: int, probe: Optional[bytes] = None) -> bytes:
        """Asynchronous banner grab using asyncio streams."""
        writer: Optional[asyncio.StreamWriter] = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout,
            )
            if probe:
                writer.write(probe)
                await writer.drain()
            return await asyncio.wait_for(reader.read(2048), timeout=self.timeout)
        except Exception:
            return b""
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

    async def _try_http_probe_async(self, host: str, port: int) -> bytes:
        request = (
            f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: GhostScan/1.2\r\nConnection: close\r\n\r\n"
        ).encode("ascii", errors="ignore")
        return await self._grab_banner_async(host, port, request)

    async def _is_tls_service_async(self, host: str, port: int) -> bool:
        writer: Optional[asyncio.StreamWriter] = None
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=context, server_hostname=host),
                timeout=self.timeout,
            )
            return True
        except Exception:
            return False
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

    async def _detect_port_details_async(self, host: str, port: int) -> Dict[str, Any]:
        """Asynchronously detect service details for one port."""
        banner = b""
        probe_used = False

        if port in PORT_PROBES:
            banner = await self._grab_banner_async(host, port, PORT_PROBES[port])
            probe_used = True
        if not banner and port in WEB_PORTS:
            banner = await self._try_http_probe_async(host, port)
            probe_used = True
        if not banner:
            banner = await self._grab_banner_async(host, port)

        detected = self._identify_from_banner(banner)
        tls_detected = False

        if detected == "HTTP" and port in TLS_PORTS:
            tls_detected = await self._is_tls_service_async(host, port)
            if tls_detected:
                detected = "HTTPS"
        elif port in TLS_PORTS and detected is None:
            tls_detected = await self._is_tls_service_async(host, port)
            if tls_detected:
                if port in COMMON_SERVICES and "HTTPS" in COMMON_SERVICES[port]:
                    detected = COMMON_SERVICES[port]
                else:
                    detected = "TLS"

        if not detected:
            detected = COMMON_SERVICES.get(port, "Unknown")

        banner_text = self._decode_banner(banner)
        version = self._extract_version(detected, banner_text)

        confidence = 0.25
        if detected != "Unknown":
            confidence = 0.5
        if banner_text:
            confidence = 0.75
        if version:
            confidence = 0.9
        if tls_detected and "https" in detected.lower():
            confidence = 0.95

        return {
            "port": port,
            "service": detected,
            "version": version or "",
            "banner": banner_text[:240],
            "transport": "tls" if tls_detected else "tcp",
            "confidence": round(confidence, 2),
            "probe_used": probe_used,
        }

    async def detect_services_async(self, host: str, ports: List[int], concurrency: int = 120) -> Dict[int, Dict[str, Any]]:
        """Asynchronously fingerprint all open ports."""
        if not ports:
            return {}

        semaphore = asyncio.Semaphore(max(1, concurrency))

        async def _wrapped(port: int) -> Dict[str, Any]:
            async with semaphore:
                return await self._detect_port_details_async(host, port)

        tasks = [_wrapped(port) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        mapped: Dict[int, Dict[str, Any]] = {}
        for port, result in zip(ports, results):
            if isinstance(result, Exception):
                mapped[port] = {
                    "port": port,
                    "service": "Unknown",
                    "version": "",
                    "banner": "",
                    "transport": "tcp",
                    "confidence": 0.0,
                    "probe_used": False,
                }
            else:
                mapped[port] = result
        return mapped
