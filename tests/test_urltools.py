import pytest

from phishdetect.urltools import URLParseError, defang, extract_urls, looks_like_single_url, parse_url


def test_scheme_is_optional_and_host_is_normalised():
    p = parse_url("  WWW.Example.COM/Path?a=1 ")
    assert p.url == "http://www.example.com/Path?a=1"
    assert p.registered_domain == "example.com"


@pytest.mark.parametrize("raw,ip", [("http://0x7f.1/", "127.0.0.1"), ("http://2130706433/", "127.0.0.1"), ("http://017700000001/", "127.0.0.1")])
def test_obfuscated_ip_hosts_are_decoded(raw, ip):
    p = parse_url(raw)
    assert p.is_ip and p.ip_obfuscated and p.host == ip


def test_userinfo_does_not_hide_the_real_host():
    p = parse_url("https://www.paypal.com@evil.example.ru/signin")
    assert p.host == "evil.example.ru" and p.userinfo == "www.paypal.com"


def test_private_suffix_sites_are_distinct_from_their_platform():
    p = parse_url("https://victim-login.github.io/x")
    assert p.registered_domain == "github.io" and p.site_domain == "victim-login.github.io" and p.domain_label == "victim-login"
    p = parse_url("https://shop.ru.com/")
    assert p.site_domain == "shop.ru.com"


def test_punycode_is_decoded_for_display_but_kept_for_lookup():
    p = parse_url("http://xn--pypal-4ve.com/")
    assert p.host_ascii == "xn--pypal-4ve.com" and p.host != p.host_ascii


@pytest.mark.parametrize("raw", ["", "javascript:alert(1)", "file:///etc/passwd", "ftp://example.com/x", "not a url", "http://localhost/", "http:///nohost"])
def test_unsupported_input_is_rejected(raw):
    with pytest.raises(URLParseError):
        parse_url(raw)


def test_defanged_urls_are_accepted_and_output_is_defanged():
    p = parse_url("hxxp://evil[.]example[.]com/a")
    assert p.host == "evil.example.com"
    assert "http://" not in defang(p.url) and "[.]" in defang(p.url)


def test_extract_urls_from_text_and_html():
    text = ('See report.zip and visit www.example.com/a, or paypal-login.xyz. Mail a@b.com. '
            '<a href="http://evil.ru/x">https://paypal.com</a> Node.js is nice, e.g. this.')
    urls = extract_urls(text)
    assert "http://evil.ru/x" in urls and "www.example.com/a" in urls and "paypal-login.xyz" in urls
    assert not any("b.com" == u or "report.zip" in u or "Node.js" in u for u in urls)


def test_single_url_detection():
    assert looks_like_single_url("example.com/login")
    assert not looks_like_single_url("please visit example.com/login")
