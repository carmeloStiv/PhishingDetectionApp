import pytest

from phishdetect.brands import find_brand_matches, official_brand
from phishdetect.url_rules import analyse_url
from phishdetect.urltools import parse_url


def ids(url):
    return {i.id for i in analyse_url(parse_url(url))}


def kinds(url):
    return {(m.brand, m.kind) for m in find_brand_matches(parse_url(url))}


@pytest.mark.parametrize("url,brand", [
    ("paypa1.com", "paypal"), ("arnazon.com", "amazon"), ("micros0ft-support.com", "microsoft"),
    ("mircosoft.com", "microsoft"), ("wellsfarg0.com", "wellsfargo"), ("steamcomrnunity.com", "steam"),
    ("login.auth.mscrosoftonline.msk.ru", "microsoft"),
])
def test_typosquats_are_detected(url, brand):
    assert (brand, "typo") in kinds(url)
    assert "brand_typosquat" in ids(url)


@pytest.mark.parametrize("url", ["pineapple.com", "purchase-orders.com", "communitybank.com", "mycommunity.org", "blockchains.com"])
def test_ordinary_words_are_not_brand_matches(url):
    assert kinds(url) == set()


@pytest.mark.parametrize("url,brand", [
    ("https://accounts.google.com/signin", "google"), ("https://login.microsoftonline.com/common", "microsoft"),
    ("https://aws.amazon.com/", "amazon"), ("https://www.paypal.com/signin", "paypal"), ("https://github.com/login", "github"),
])
def test_official_domains_have_no_impersonation_findings(url, brand):
    p = parse_url(url)
    assert official_brand(p) == brand
    found = ids(url)
    assert "official_brand_domain" in found
    assert not {i for i in found if i.startswith("brand_")}


def test_real_domain_as_subdomain_is_critical():
    inds = analyse_url(parse_url("https://paypal.com.account-security-check.info/webscr"))
    hit = [i for i in inds if i.id == "brand_domain_in_subdomain"]
    assert hit and hit[0].severity == "critical"


def test_homograph_is_critical():
    inds = {i.id: i for i in analyse_url(parse_url("https://xn--pypal-4ve.com/signin"))}
    assert inds["brand_homoglyph"].severity == "critical" and "mixed_script" in inds


def test_plain_idn_is_only_a_note():
    inds = {i.id: i for i in analyse_url(parse_url("https://münchen.de/"))}
    assert inds["idn_host"].severity == "info"
    assert not [i for i in inds.values() if i.weight > 0]


def test_structural_tricks():
    assert "userinfo_in_url" in ids("https://www.paypal.com@secure-login.example-host.ru/signin")
    assert {"ip_host", "obfuscated_ip"} <= ids("http://0x5bd4c821/secure/login")
    assert "url_shortener" in ids("https://bit.ly/3abc")
    assert "email_in_url" in ids("https://unknown-site-zz.com/x.php?email=a@b.com")
    assert "nonstandard_port" in ids("http://unknown-site-zz.com:8081/")


def test_brand_on_free_hosting():
    found = ids("https://netflix-billing-update.web.app/")
    assert {"brand_in_host", "user_content_platform", "auth_words_on_free_hosting"} <= found


def test_ambiguous_brand_words_need_context():
    assert "brand_in_host" not in ids("https://apple-orchard-farm.com/")
    assert "brand_in_host" in ids("https://chase.smsx01.co/login")


def test_https_is_never_positive_evidence():
    for i in analyse_url(parse_url("https://unknown-site-zz.com/")):
        assert i.severity != "positive"
