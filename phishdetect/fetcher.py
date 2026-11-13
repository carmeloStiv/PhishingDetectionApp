"""SSRF-hardened retrieval of a user-submitted URL.

Controls:
  * http/https only, ports 80 and 443 only
  * the host is resolved once; every resolved address must be globally routable
    (no loopback, private, link-local, CGNAT, multicast, metadata or reserved ranges)
  * the socket connects to the *validated IP* (no second DNS lookup, so DNS
    rebinding cannot swap the target after validation)
  * redirects are followed manually and each hop is validated again
  * strict timeouts, a hard response-size cap, no cookies, no credentials,
    no content decoding (identity only) and no script execution
Environment proxies are deliberately ignored. Deploy behind an egress policy
as well (see docs/SECURITY.md); this module is defence in depth, not a sandbox.
"""
from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urljoin

from .urltools import ParsedURL, URLParseError, parse_url

USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
ALLOWED_PORTS = {80, 443}


class FetchBlocked(Exception):
    """The request was refused by a safety control."""


@dataclass
class FetchResult:
    ok: bool = False
    error: str = ""                 # machine-readable reason when not ok
    detail: str = ""
    final_url: str = ""
    status: int = 0
    chain: list[tuple[str, int]] = field(default_factory=list)
    content_type: str = ""
    body: str = ""
    truncated: bool = False
    cert: dict | None = None
    tls_error: str = ""


def _is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return addr.is_global and not addr.is_multicast


def resolve_public(host: str, port: int, resolver=socket.getaddrinfo) -> str:
    """Resolve `host` and return one address, refusing unless *all* answers are public."""
    try:
        infos = resolver(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise FetchBlocked("dns_failure") from exc
    addrs = sorted({info[4][0] for info in infos})
    if not addrs:
        raise FetchBlocked("dns_failure")
    if not all(_is_public(a) for a in addrs):
        raise FetchBlocked("non_public_address")
    v4 = [a for a in addrs if ":" not in a]
    return (v4 or addrs)[0]


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host, ip, port, timeout):
        super().__init__(host, port, timeout=timeout)
        self._ip = ip

    def connect(self):
        self.sock = socket.create_connection((self._ip, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, ip, port, timeout, context):
        super().__init__(host, port, timeout=timeout, context=context)
        self._ip = ip
        self.peer_cert = None

    def connect(self):
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        # Read the certificate now: http.client drops the socket as soon as a
        # "Connection: close" response has been received.
        self.peer_cert = self.sock.getpeercert()


def _cert_summary(cert: dict | None) -> dict | None:
    if not cert:
        return None
    def flat(name):
        return {k: v for rdn in cert.get(name, ()) for k, v in rdn}
    out = {"issuer": flat("issuer").get("organizationName") or flat("issuer").get("commonName", ""),
           "subject": flat("subject").get("commonName", "")}
    try:
        nb = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        out["age_days"] = (datetime.now(timezone.utc) - nb).days
    except (KeyError, ValueError):
        pass
    return out


def safe_fetch(url: str, *, timeout: float = 8.0, max_bytes: int = 750_000, max_redirects: int = 5,
               resolver=socket.getaddrinfo, allow_private: bool = False, allowed_ports=ALLOWED_PORTS,
               ssl_context: ssl.SSLContext | None = None) -> FetchResult:
    """Fetch `url` under the controls above. `allow_private` and `ssl_context` exist only for tests."""
    res = FetchResult()
    deadline = time.monotonic() + timeout * 2
    current = url
    for _hop in range(max_redirects + 1):
        try:
            p: ParsedURL = parse_url(current)
        except URLParseError as exc:
            res.error, res.detail = "invalid_url", str(exc)
            return res
        port = p.port or (443 if p.scheme == "https" else 80)
        if port not in allowed_ports:
            res.error, res.detail = "blocked_port", f"port {port} is not fetched"
            return res
        try:
            if allow_private:
                ip = resolver(p.host_ascii, port, type=socket.SOCK_STREAM)[0][4][0]
            elif p.is_ip:
                if not _is_public(p.host):
                    raise FetchBlocked("non_public_address")
                ip = p.host
            else:
                ip = resolve_public(p.host_ascii, port, resolver)
        except FetchBlocked as exc:
            res.error = str(exc)
            res.detail = {"dns_failure": "the host name does not resolve",
                          "non_public_address": "the host resolves to a private or reserved address"}.get(str(exc), "")
            return res
        except (socket.gaierror, IndexError):
            res.error, res.detail = "dns_failure", "the host name does not resolve"
            return res

        remaining = max(deadline - time.monotonic(), 0.5)
        conn = None
        try:
            if p.scheme == "https":
                ctx = ssl_context or ssl.create_default_context()
                conn = _PinnedHTTPSConnection(p.host_ascii, ip, port, min(timeout, remaining), ctx)
            else:
                conn = _PinnedHTTPConnection(p.host_ascii, ip, port, min(timeout, remaining))
            target = p.path + ("?" + p.query if p.query else "")
            conn.request("GET", target, headers={
                "Host": p.host_ascii if not p.port else f"{p.host_ascii}:{p.port}", "User-Agent": USER_AGENT,
                "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.5", "Accept-Language": "en",
                "Accept-Encoding": "identity", "Connection": "close",
            })
            resp = conn.getresponse()
            if p.scheme == "https":
                res.cert = _cert_summary(conn.peer_cert)
            res.chain.append((p.url, resp.status))
            res.status, res.final_url = resp.status, p.url
            location = resp.getheader("Location")
            if resp.status in (301, 302, 303, 307, 308) and location:
                current = urljoin(p.url, location)
                continue
            res.content_type = (resp.getheader("Content-Type") or "").split(";")[0].strip().lower()
            chunks, total = [], 0
            while total < max_bytes and time.monotonic() < deadline:
                chunk = resp.read(min(65536, max_bytes - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
            else:
                res.truncated = True
            raw = b"".join(chunks)
            res.body = raw.decode("utf-8", "replace") if res.content_type.startswith(("text/", "application/xhtml")) or not res.content_type else ""
            res.ok = True
            return res
        except ssl.SSLCertVerificationError as exc:
            res.error, res.tls_error, res.final_url = "tls_invalid_certificate", exc.verify_message or "certificate verification failed", p.url
            return res
        except ssl.SSLError as exc:
            res.error, res.detail = "tls_error", str(exc)[:120]
            return res
        except (socket.timeout, TimeoutError):
            res.error, res.detail = "timeout", "the server did not answer in time"
            return res
        except (OSError, http.client.HTTPException) as exc:
            res.error, res.detail = "connection_failed", type(exc).__name__
            return res
        finally:
            if conn is not None:
                conn.close()
    res.ok, res.error, res.detail = False, "too_many_redirects", f"more than {max_redirects} redirects"
    return res
