"""SSRF controls of the page fetcher."""
import http.server
import socket
import threading

import pytest

from phishdetect.fetcher import FetchBlocked, resolve_public, safe_fetch


def fake_resolver(*addresses):
    def resolver(host, port, type=None):  # noqa: A002
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, port)) for a in addresses]
    return resolver


@pytest.mark.parametrize("addr", ["127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.3.4", "169.254.169.254", "100.64.0.1",
                                  "0.0.0.0", "::1", "fe80::1", "fd00::1", "::ffff:127.0.0.1", "224.0.0.1"])
def test_non_public_addresses_are_refused(addr):
    with pytest.raises(FetchBlocked):
        resolve_public("attacker-test.com", 80, fake_resolver(addr))


def test_mixed_dns_answers_are_refused():
    # DNS rebinding style: one public and one internal record
    with pytest.raises(FetchBlocked):
        resolve_public("attacker-test.com", 80, fake_resolver("93.184.216.34", "127.0.0.1"))


def test_public_address_is_pinned():
    assert resolve_public("example.com", 80, fake_resolver("93.184.216.34")) == "93.184.216.34"


@pytest.mark.parametrize("url", ["http://127.0.0.1/", "http://2130706433/", "http://0x7f.1/", "http://[::1]/",
                                 "http://169.254.169.254/latest/meta-data/", "http://192.168.0.1/admin"])
def test_literal_internal_ips_are_refused(url):
    res = safe_fetch(url, timeout=1)
    assert not res.ok and res.error == "non_public_address"


def test_hostname_resolving_to_internal_address_is_refused():
    res = safe_fetch("http://internal.attacker-test.com/", resolver=fake_resolver("10.1.2.3"), timeout=1)
    assert not res.ok and res.error == "non_public_address"


def test_non_web_ports_and_schemes_are_refused():
    assert safe_fetch("http://example.com:22/", resolver=fake_resolver("93.184.216.34")).error == "blocked_port"
    assert safe_fetch("file:///etc/passwd").error == "invalid_url"
    assert safe_fetch("gopher://example.com/").error == "invalid_url"


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/redirect-internal":
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
            self.end_headers()
        elif self.path == "/loop":
            self.send_response(302)
            self.send_header("Location", "/loop")
            self.end_headers()
        elif self.path == "/big":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            try:
                for _ in range(400):
                    self.wfile.write(b"A" * 10000)
            except OSError:
                pass
        else:
            body = b"<html><title>hello</title><form><input type=password></form></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)


@pytest.fixture(scope="module")
def local_server():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()


def _local(port, path, **kw):
    """Tests reach the local server only through the explicit test-only override."""
    return safe_fetch(f"http://test-host.com:{port}{path}", resolver=fake_resolver("127.0.0.1"), allow_private=True,
                      allowed_ports={port, 80, 443}, timeout=3, **kw)


def test_fetch_works_through_pinned_connection(local_server):
    res = _local(local_server, "/")
    assert res.ok and res.status == 200 and "type=password" in res.body


def test_local_server_is_unreachable_without_override(local_server):
    res = safe_fetch(f"http://test-host.com:{local_server}/", resolver=fake_resolver("127.0.0.1"), allowed_ports={local_server})
    assert not res.ok and res.error == "non_public_address"


def test_redirect_to_internal_address_is_refused_even_from_allowed_host(local_server):
    # first hop is allowed by the test override, the redirect target is a literal metadata IP on port 80
    res = safe_fetch(f"http://test-host.com:{local_server}/redirect-internal", resolver=fake_resolver("127.0.0.1"),
                     allowed_ports={local_server, 80}, timeout=2, allow_private=False)
    assert not res.ok
    res2 = _local(local_server, "/redirect-internal")
    assert res2.chain and res2.chain[0][1] == 302   # redirect was seen and re-validated, never silently followed by a library


def test_redirect_loops_are_bounded(local_server):
    res = _local(local_server, "/loop", max_redirects=3)
    assert not res.ok and res.error == "too_many_redirects" and len(res.chain) == 4


def test_response_size_is_capped(local_server):
    res = _local(local_server, "/big", max_bytes=50_000)
    assert res.ok and res.truncated and len(res.body) <= 50_000
