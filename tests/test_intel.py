"""Threat-intelligence providers against mocked HTTP responses (no real network, no real keys)."""
import json
from datetime import datetime, timedelta, timezone

import httpx

from phishdetect.config import Settings
from phishdetect.intel import DomainAge, GoogleSafeBrowsing, OpenPhishFeed, URLhaus, VirusTotal
from phishdetect.urltools import parse_url

URL = parse_url("http://bad-site-zz.com/login.php")


def make(cls, handler, **settings):
    s = Settings.offline()
    for k, v in settings.items():
        setattr(s, k, v)
    return cls(s, httpx.Client(transport=httpx.MockTransport(handler)))


def test_not_configured_makes_no_request():
    def handler(request):
        raise AssertionError("no request expected")
    for cls in (GoogleSafeBrowsing, VirusTotal, URLhaus):
        assert make(cls, handler).lookup(URL).status == "not_configured"


def test_openphish_exact_host_and_clean():
    feed = "http://bad-site-zz.com/login.php\nhttps://other-bad-zz.net/a/b\nhttps://sites.google.com/view/evil\n"
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(200, text=feed)
    prov = make(OpenPhishFeed, handler, enable_openphish=True)
    assert prov.lookup(URL).status == "match"
    r = prov.lookup(parse_url("https://other-bad-zz.net/different"))
    assert r.status == "match" and r.indicators[0].id == "openphish_host_match"
    shared = prov.lookup(parse_url("https://sites.google.com/view/innocent"))
    assert shared.status == "clean" and shared.indicators[0].severity == "low"   # shared host: not a confirmed match
    assert prov.lookup(parse_url("https://fine-site-zz.org/")).status == "clean"
    assert len(calls) == 1   # feed downloaded once and reused


def test_openphish_download_failure_is_an_error_not_clean():
    prov = make(OpenPhishFeed, lambda r: httpx.Response(503), enable_openphish=True)
    assert prov.lookup(URL).status == "error"


def test_safe_browsing_match_clean_and_key_not_in_body():
    seen = {}

    def handler(request):
        seen["url"] = str(request.url)
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"matches": [{"threatType": "SOCIAL_ENGINEERING"}]})
    r = make(GoogleSafeBrowsing, handler, google_safe_browsing_key="k123").lookup(URL)
    assert r.status == "match" and r.indicators[0].severity == "critical"
    assert seen["body"]["threatInfo"]["threatEntries"] == [{"url": URL.url}] and "key=k123" in seen["url"]
    assert make(GoogleSafeBrowsing, lambda r: httpx.Response(200, json={}), google_safe_browsing_key="k").lookup(URL).status == "clean"
    assert make(GoogleSafeBrowsing, lambda r: httpx.Response(403, json={}), google_safe_browsing_key="k").lookup(URL).status == "error"


def vt(mal, sus=0):
    return {"data": {"attributes": {"last_analysis_stats": {"malicious": mal, "suspicious": sus, "harmless": 60, "undetected": 20}}}}


def test_virustotal_thresholds():
    r = make(VirusTotal, lambda r: httpx.Response(200, json=vt(7)), virustotal_key="k").lookup(URL)
    assert r.status == "match"
    r = make(VirusTotal, lambda r: httpx.Response(200, json=vt(1)), virustotal_key="k").lookup(URL)
    assert r.status == "clean" and r.indicators[0].severity == "medium"   # single vendor: warning, not confirmation
    r = make(VirusTotal, lambda r: httpx.Response(200, json=vt(0)), virustotal_key="k").lookup(URL)
    assert r.status == "clean" and not r.indicators
    assert make(VirusTotal, lambda r: httpx.Response(404), virustotal_key="k").lookup(URL).status == "clean"
    assert make(VirusTotal, lambda r: httpx.Response(429), virustotal_key="k").lookup(URL).status == "error"


def test_urlhaus():
    ok = {"query_status": "ok", "threat": "malware_download", "url_status": "online"}
    assert make(URLhaus, lambda r: httpx.Response(200, json=ok), urlhaus_key="k").lookup(URL).status == "match"
    assert make(URLhaus, lambda r: httpx.Response(200, json={"query_status": "no_results"}), urlhaus_key="k").lookup(URL).status == "clean"
    assert make(URLhaus, lambda r: httpx.Response(200, json={"query_status": "weird"}), urlhaus_key="k").lookup(URL).status == "error"


def rdap(days):
    date = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {"events": [{"eventAction": "registration", "eventDate": date}]}


def test_domain_age_bands():
    def age(days):
        return make(DomainAge, lambda r: httpx.Response(200, json=rdap(days)), enable_domain_age=True).lookup(URL)
    assert age(5).indicators[0].id == "domain_very_new" and age(5).age_days == 5
    assert age(100).indicators[0].id == "domain_new"
    assert not age(400).indicators
    assert age(3000).indicators[0].severity == "positive"
    assert make(DomainAge, lambda r: httpx.Response(404), enable_domain_age=True).lookup(URL).status == "error"


def test_results_are_cached():
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(200, json={})
    prov = make(GoogleSafeBrowsing, handler, google_safe_browsing_key="k")
    prov.lookup(URL)
    prov.lookup(URL)
    assert len(calls) == 1
