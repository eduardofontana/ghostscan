"""Tor/Proxy support for GhostScan."""

import socket
import ssl
import struct
from typing import Any, Dict, List, Optional, Tuple
from urllib import parse as url_parse


class ProxyManager:
    """Manages proxy connections for scanning through SOCKS/HTTP proxies."""

    SUPPORTED_PROXIES = {"socks5", "socks4", "http", "https"}

    def __init__(
        self,
        proxy_url: Optional[str] = None,
        proxy_type: Optional[str] = None,
        proxy_host: Optional[str] = None,
        proxy_port: Optional[int] = None,
        proxy_user: Optional[str] = None,
        proxy_pass: Optional[str] = None,
    ):
        self.proxy_url = proxy_url
        self.proxy_type = (proxy_type or "socks5").lower()
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.proxy_user = proxy_user
        self.proxy_pass = proxy_pass
        self._configured = False

        if proxy_url:
            self._parse_proxy_url(proxy_url)
        elif proxy_host and proxy_port:
            self._configured = True

    def _parse_proxy_url(self, url: str) -> None:
        """Parse proxy URL into components."""
        parsed = url_parse.urlparse(url)
        scheme = parsed.scheme.lower()

        if scheme not in self.SUPPORTED_PROXIES:
            raise ValueError(f"Unsupported proxy type: {scheme}")

        self.proxy_type = scheme
        self.proxy_host = parsed.hostname or parsed.path.split(":")[0]
        self.proxy_port = parsed.port or (1080 if "socks" in scheme else 8080)

        if parsed.username:
            self.proxy_user = parsed.username
        if parsed.password:
            self.proxy_pass = parsed.password

        self._configured = bool(self.proxy_host and self.proxy_port)

    @property
    def is_configured(self) -> bool:
        """Check if proxy is properly configured."""
        return self._configured

    def get_proxy_dict(self) -> Dict[str, Any]:
        """Return proxy configuration as dict."""
        return {
            "type": self.proxy_type,
            "host": self.proxy_host,
            "port": self.proxy_port,
            "user": self.proxy_user,
            "configured": self._configured,
        }

    def create_connection(
        self,
        target_host: str,
        target_port: int,
        timeout: float = 5.0,
    ) -> socket.socket:
        """Create a socket tunneled through the proxy."""
        if not self._configured:
            raise ValueError("Proxy not configured")

        if self.proxy_type in {"socks5", "socks4"}:
            return self._create_socks_connection(target_host, target_port, timeout)
        else:
            return self._create_http_connect(target_host, target_port, timeout)

    def _create_socks_connection(
        self,
        target_host: str,
        target_port: int,
        timeout: float,
    ) -> socket.socket:
        """Create connection through SOCKS proxy."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        try:
            sock.connect((self.proxy_host, self.proxy_port))

            if self.proxy_type == "socks5":
                self._socks5_handshake(sock, target_host, target_port)
            elif self.proxy_type == "socks4":
                self._socks4_handshake(sock, target_host, target_port)

            return sock
        except Exception:
            sock.close()
            raise

    def _socks5_handshake(
        self,
        sock: socket.socket,
        target_host: str,
        target_port: int,
    ) -> None:
        """Perform SOCKS5 handshake."""
        auth_methods = b"\x05\x02\x00\x02"
        if self.proxy_user and self.proxy_pass:
            auth_methods = b"\x05\x02\x00\x02"
        else:
            auth_methods = b"\x05\x01\x00"

        sock.sendall(auth_methods)
        resp = sock.recv(2)

        if resp[0] != 0x05:
            raise ValueError(f"SOCKS5 handshake failed: {resp[0]:02x}")

        if resp[1] == 0x02:
            if not self.proxy_user or not self.proxy_pass:
                raise ValueError("SOCKS5 auth required but credentials missing")
            username = self.proxy_user.encode("utf-8")
            password = self.proxy_pass.encode("utf-8")
            auth_pkt = bytes([0x01, len(username)]) + username + bytes([len(password)]) + password
            sock.sendall(auth_pkt)
            resp = sock.recv(2)
            if resp[1] != 0x00:
                raise ValueError(f"SOCKS5 auth failed: {resp[1]:02x}")
        elif resp[1] != 0x00:
            raise ValueError(f"SOCKS5 auth method not acceptable: {resp[1]:02x}")

        target_ip = socket.gethostbyname(target_host)
        cmd = 0x01
        atype = 0x01
        request = (
            bytes([0x05, cmd, 0x00, atype])
            + socket.inet_aton(target_ip)
            + struct.pack("!H", target_port)
        )
        sock.sendall(request)
        resp = sock.recv(10)

        if resp[0] != 0x05 or resp[1] != 0x00:
            raise ValueError(f"SOCKS5 connect failed: {resp[1]:02x}")

    def _socks4_handshake(
        self,
        sock: socket.socket,
        target_host: str,
        target_port: int,
    ) -> None:
        """Perform SOCKS4 handshake."""
        user_id = (self.proxy_user or "").encode("utf-8") + b"\x00"
        target_ip = socket.inet_aton(socket.gethostbyname(target_host))
        request = (
            bytes([0x04, 0x01])
            + struct.pack("!H", target_port)
            + target_ip
            + user_id
        )
        sock.sendall(request)
        resp = sock.recv(8)

        if resp[0] != 0x00 or resp[1] != 0x5a:
            raise ValueError(f"SOCKS4 connect failed: {resp[1]:02x}")

    def _create_http_connect(
        self,
        target_host: str,
        target_port: int,
        timeout: float,
    ) -> socket.socket:
        """Create connection through HTTP CONNECT proxy."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        try:
            sock.connect((self.proxy_host, self.proxy_port))

            target = f"{target_host}:{target_port}"
            credentials = ""
            if self.proxy_user and self.proxy_pass:
                import base64
                creds = f"{self.proxy_user}:{self.proxy_pass}"
                credentials = f"Proxy-Authorization: Basic {base64.b64encode(creds.encode()).decode()}\r\n"

            request = (
                f"CONNECT {target} HTTP/1.1\r\n"
                f"Host: {target}\r\n"
                f"Proxy-Connection: Keep-Alive\r\n"
                f"{credentials}"
                "\r\n"
            ).encode("utf-8")

            sock.sendall(request)

            response = b""
            while b"\r\n\r\n" not in response:
                chunk = sock.recv(1)
                if not chunk:
                    break
                response += chunk

            if b"200" not in response.split(b"\r\n")[0]:
                raise ValueError(f"HTTP CONNECT failed: {response.decode('utf-8', errors='ignore')}")

            return sock
        except Exception:
            sock.close()
            raise


def parse_proxy_string(proxy_str: str) -> ProxyManager:
    """Parse proxy string into ProxyManager."""
    if not proxy_str:
        return None

    parts = proxy_str.split("://")
    if len(parts) == 2:
        scheme, rest = parts
        if "@" in rest:
            auth, host = rest.split("@")
            return ProxyManager(proxy_url=f"{scheme}://{proxy_str}")
        return ProxyManager(proxy_url=f"{scheme}://{rest}")

    if ":" in proxy_str:
        return ProxyManager(proxy_url=f"socks5://{proxy_str}")

    return ProxyManager(proxy_url=proxy_str)