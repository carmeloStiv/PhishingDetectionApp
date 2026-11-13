import pytest

from phishdetect.engine import InputError


def test_four_classes_are_reachable(offline_engine):
    e = offline_engine
    assert e.analyse("https://www.google.com")["classification"] == "likely_safe"
    assert e.analyse("http://paypa1-secure-login.xyz/verify")["classification"] == "likely_phishing"
    assert e.analyse("https://some-unknown-site-qq.net/")["classification"] == "unable_to_determine"
    assert e.analyse("https://unknown-site-zz.com/x.php?email=a@b.com")["classification"] in ("suspicious", "likely_phishing")


def test_unknown_domain_without_findings_is_not_called_safe(offline_engine):
    r = offline_engine.analyse("https://some-unknown-site-qq.net/")
    assert r["classification"] == "unable_to_determine" and r["confidence"]["level"] == "low"
    assert r["missing_information"]


def test_unresolved_shortener_is_undetermined(offline_engine):
    r = offline_engine.analyse("https://bit.ly/3xYzAbC")
    assert r["classification"] == "unable_to_determine"
    assert "shortener" in r["summary"].lower()


def test_long_genuine_signin_urls_are_safe(offline_engine):
    for url in ("https://accounts.google.com/v3/signin/identifier?continue=https%3A%2F%2Fmail.google.com%2Fmail%2F&service=mail",
                "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=4765445b&redirect_uri=https%3A%2F%2Fwww.office.com%2Flandingv2",
                "https://www.paypal.com/signin?returnUri=https%3A%2F%2Fwww.paypal.com%2Fmyaccount"):
        assert offline_engine.analyse(url)["classification"] == "likely_safe", url


def test_open_redirect_destination_is_judged(offline_engine):
    bad = offline_engine.analyse("https://www.google.com/url?q=https://secure-wallet-verify.top/connect&sa=D")
    good = offline_engine.analyse("https://www.google.com/url?q=https://www.python.org/&sa=D")
    assert bad["classification"] in ("suspicious", "likely_phishing")
    assert good["classification"] == "likely_safe"


def test_report_shape_and_source_separation(offline_engine):
    r = offline_engine.analyse("http://paypa1-secure-login.xyz/verify")
    assert {"id", "classification", "label", "risk_score", "confidence", "summary", "indicators", "checks",
            "recommendations", "score_breakdown", "missing_information"} <= r.keys()
    assert {i["source"] for i in r["indicators"]} >= {"heuristic", "ml"}
    for i in r["indicators"]:
        assert i["evidence"] and i["explanation"] and i["severity"] and i["source"]
    assert "http://" not in r["subject"]     # shown defanged


def test_message_verdicts(offline_engine):
    e = offline_engine
    phish = ("Dear Customer, your PayPal account has been limited due to unusual activity. Verify your account "
             "within 24 hours or it will be permanently closed: http://paypal-secure.account-verify.xyz/login")
    assert e.analyse(phish)["classification"] == "likely_phishing"
    assert e.analyse("Hi team, the meeting is moved to 3pm tomorrow in room 4B. Thanks, Sam")["classification"] == "likely_safe"
    legit = "Your Amazon order has shipped. Track it at https://www.amazon.co.uk/gp/your-account/order-history"
    assert e.analyse(legit)["classification"] == "likely_safe"
    assert e.analyse("ok thanks")["classification"] == "unable_to_determine"


def test_genuine_security_alert_is_not_flagged(offline_engine):
    msg = ("From: Google <no-reply@accounts.google.com>\nSubject: Security alert\n\nWe noticed a new sign-in to your "
           "Google Account. If this wasn't you, we'll help you secure your account.\nhttps://myaccount.google.com/notifications")
    assert offline_engine.analyse(msg)["classification"] == "likely_safe"


def test_sender_and_link_deception(offline_engine):
    spoof = ("From: Apple Support <apple.support.team881@gmail.com>\nSubject: Your Apple ID has been locked\n\n"
             "Dear Customer, verify your identity to unlock your account: https://appleid.apple.com-unlock.id/")
    r = offline_engine.analyse(spoof)
    assert r["classification"] == "likely_phishing"
    assert "sender_brand_mismatch" in {i["id"] for i in r["indicators"]}
    html = '<p>Review now:</p><a href="http://chase-review.online-secure-banking.net/logon">https://www.chase.com/secure</a>'
    assert "link_text_mismatch" in {i["id"] for i in offline_engine.analyse(html, mode="message")["indicators"]}


def test_bec_without_links(offline_engine):
    msg = ("Are you at your desk? I'm in a meeting and can't talk. I need you to buy 5 Apple gift cards right away "
           "and send me the codes. Keep this between us.")
    assert offline_engine.analyse(msg)["classification"] in ("suspicious", "likely_phishing")


@pytest.mark.parametrize("text", ["", "   ", "x" * 60000])
def test_invalid_input(offline_engine, text):
    with pytest.raises(InputError):
        offline_engine.analyse(text)


def test_url_mode_rejects_non_urls(offline_engine):
    with pytest.raises(InputError):
        offline_engine.analyse("javascript:alert(1)", mode="url")
