import sys
from pathlib import Path
import random
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import analyzer

DATA = Path(__file__).resolve().parent / "data"


def score_of(name):

    msg = analyzer.parse_eml(str(DATA / name))
    return analyzer.compute_score(msg)


def score_of_text(tmp_path, raw):

    path = tmp_path / "mail.eml"
    path.write_text(raw, encoding="utf-8")
    msg = analyzer.parse_eml(str(path))
    return analyzer.compute_score(msg)


def test_legit_mail_has_low_score():
    score, reasons = score_of("legit.eml")
    assert score < 40
    assert reasons == []


def test_phishing_mail_has_high_score():
    score, _ = score_of("phishing.eml")
    assert score >= 70


def test_double_extension_detected():

    _, reasons = score_of("attach.eml")
    assert any("double extension" in r for r in reasons)


def test_misleading_link_detected():
    _, reasons = score_of("phishing.eml")
    assert any("lien trompeur" in r for r in reasons)


def test_reply_low_score(tmp_path):
    raw = (
        "From: contact@societe.example\n"
        "Reply-To: autre@gmail.example\n"
        "Subject: bonjour\n"
        "Content-Type: text/plain; charset=utf-8\n"
        "\n"
        "message simple.\n"
    )
    score, reasons = score_of_text(tmp_path, raw)
    assert score == 15
    assert len(reasons) == 1
    assert "Reply-To" in reasons[0]
    assert analyzer.risk_level(score) == "FAIBLE"


def test_mail_no_links(tmp_path):
    raw = (
        "From: contact@societe.example\n"
        "Subject: Info\n"
        "Content-Type: text/plain; charset=utf-8\n"
        "\n"
        "Pas de HTML ici, juste du texte.\n"
    )
    msg_path = tmp_path / "plain.eml"
    msg_path.write_text(raw, encoding="utf-8")
    msg = analyzer.parse_eml(str(msg_path))
    assert analyzer.extract_links(analyzer.get_html_body(msg)) == []
    score, reasons = analyzer.compute_score(msg)
    assert score == 0


def test_mail_without_headers(tmp_path):
    score, reasons = score_of_text(tmp_path, "Subject: x\n\ncorps\n")
    assert score == 0
    assert reasons == []


def test_analyze_returns():
    msg = analyzer.parse_eml(str(DATA / "phishing.eml"))
    result = analyzer.analyze(msg)
    assert result["score"] == 100
    assert result["risk_level"] == "ÉLEVÉ"
    assert result["authentication"]["spf"] == "fail"
    assert any(link["misleading"] for link in result["links"])


# tests for virustotal


def fake_VT(hits, total=70):  # fabrique une fausse reponse de virustotal, sans toucher au reseau

    return lambda sha, key: {
        "status": "detected", "malicious": hits, "suspicious": 0, "total": total}


def run_with_VT(monkeypatch, hits):
    monkeypatch.setenv("VT_API_KEY", "fausse-cle")
    monkeypatch.setattr(analyzer, "vt_lookup", fake_VT(hits))
    monkeypatch.setattr(analyzer.time, "sleep", lambda s: None)
    msg = analyzer.parse_eml(str(DATA / "attach.eml"))
    base = analyzer.analyze(msg)["score"]
    result = analyzer.apply_virustotal(analyzer.analyze(msg))
    return base, result


def test_VT_strong_consensus_adds_40(monkeypatch):

    base, result = run_with_VT(monkeypatch, hits=50)
    assert result["score"] == min(base + 40, 100)
    assert any("+40" in r and "VirusTotal" in r for r in result["reasons"])


def test_VT_medium_consensus_adds_25(monkeypatch):
    base, result = run_with_VT(monkeypatch, hits=5)
    assert result["score"] == min(base + 25, 100)


def test_VT_few_detection_adds_10(monkeypatch):
    base, result = run_with_VT(monkeypatch, hits=2)
    assert result["score"] == min(base + 10, 100)


def test_VT_unkown_adds_nothing(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "fake-key")
    monkeypatch.setattr(analyzer, "vt_lookup", lambda sha, key: {"status": "unknown"})
    msg = analyzer.parse_eml(str(DATA / "attach.eml"))
    base = analyzer.analyze(msg)["score"]
    result = analyzer.apply_virustotal(analyzer.analyze(msg))
    assert result["score"] == base


def test_VT_skipped_without_key(monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    msg = analyzer.parse_eml(str(DATA / "attach.eml"))
    result = analyzer.apply_virustotal(analyzer.analyze(msg))
    assert "virustotal" not in result["attachments"][0]

def run_with_dns(monkeypatch, records):
    monkeypatch.setattr(analyzer, "dns_txt", lambda name, timeout=5: records.get(name, []))
    msg = analyzer.parse_eml(str(DATA / "legit.eml"))
    base = analyzer.analyze(msg)["score"]
    result = analyzer.apply_dns(analyzer.analyze(msg), msg)
    return base, result


def test_dns_protected_domain_adds_nothing(monkeypatch):
    d = "entreprise-legit.example"
    base, result = run_with_dns(monkeypatch, {
        d: ["v=spf1 include:_spf.example.net -all"],
        "_dmarc." + d: ["v=DMARC1; p=reject"]})
    assert result["score"] == base


def test_dns_no_records_adds_20(monkeypatch):
    base, result = run_with_dns(monkeypatch, {})
    assert result["score"] == base + 20


def test_dns_dmarc_none_adds_5(monkeypatch):
    d = "entreprise-legit.example"
    base, result = run_with_dns(monkeypatch, {
        d: ["v=spf1 -all"], "_dmarc." + d: ["v=DMARC1; p=none"]})
    assert result["score"] == base + 5


def test_dns_error_adds_nothing(monkeypatch):
    monkeypatch.setattr(analyzer, "dns_txt", lambda name, timeout=5: None)
    msg = analyzer.parse_eml(str(DATA / "legit.eml"))
    base = analyzer.analyze(msg)["score"]
    result = analyzer.apply_dns(analyzer.analyze(msg), msg)
    assert result["score"] == base

def leet_variant(brand):
    #remplace o/l/e/s par 0/1/3/5 (None si la marque n'a aucun de ces caractères)
    swap = {"o": "0", "l": "1", "e": "3", "s": "5"}
    variant = "".join(swap.get(c, c) for c in brand)
    return variant if variant != brand else None


def rn_variant(brand):
    #remplace 'm' par 'rn' (None si la marque n'a pas de m)
    return brand.replace("m", "rn") if "m" in brand else None


def doubled_variant(brand):
    #double une lettre au milieu du nom (faute de frappe)
    mid = len(brand) // 2
    return brand[:mid] + brand[mid] + brand[mid:]


@pytest.mark.parametrize("brand", analyzer.BRANDS)
def test_real_brand_domain_is_not_flagged(brand):
    assert analyzer.typosquat_check(f"{brand}.com") is None
    assert analyzer.typosquat_check(f"mail.{brand}.fr") is None


@pytest.mark.parametrize("brand", analyzer.BRANDS)
def test_look_alike_characters_are_detected(brand):
    for variant in (leet_variant(brand), rn_variant(brand)):
        if variant is None:
            continue
        hit = analyzer.typosquat_check(f"{variant}.com")
        assert hit is not None, variant
        assert hit[0] == brand


@pytest.mark.parametrize("brand", [b for b in analyzer.BRANDS if len(b) >= 6])
def test_typo_is_detected_for_long_brands(brand):
    hit = analyzer.typosquat_check(f"{doubled_variant(brand)}.com")
    assert hit is not None
    assert hit[0] == brand


@pytest.mark.parametrize("brand", analyzer.BRANDS)
@pytest.mark.parametrize("pattern", ["{b}-secure.com", "secure-{b}.net", "mon-{b}-login.fr"])
def test_brand_plus_word_is_detected(brand, pattern):
    hit = analyzer.typosquat_check(pattern.format(b=brand))
    assert hit is not None
    assert hit[0] == brand


def test_random_domains_are_not_flagged():
    rng = random.Random(42)  # graine fixe : le test est reproductible
    letters = "bcdfghjkmnpqrtuvwxz"
    for _ in range(200):
        name = "".join(rng.choice(letters) for _ in range(10))
        assert analyzer.typosquat_check(f"{name}.com") is None, name


def test_rule_works_with_any_brand_list(monkeypatch):
    #la règle ne dépend pas des marques codées en dur : on lui en donne d'autres
    monkeypatch.setattr(analyzer, "BRANDS", ("macaisse", "monbanque"))
    assert analyzer.typosquat_check("macaiss3.fr")[0] == "macaisse"
    assert analyzer.typosquat_check("monbanque-secure.com")[0] == "monbanque"
    assert analyzer.typosquat_check("paypa1.com") is None  # plus dans la liste


def test_typosquat_adds_points_to_score(tmp_path):
    brand = analyzer.BRANDS[0]
    raw = (
        f"From: alerte@{leet_variant(brand) or brand + '-x'}.com\n"
        "Subject: Info\n"
        "Content-Type: text/plain; charset=utf-8\n"
        "\n"
        "Bonjour.\n"
    )
    score, reasons = score_of_text(tmp_path, raw)
    assert score >= 20
    assert any("imitant" in r for r in reasons)

@pytest.mark.parametrize("brand", analyzer.SHORT_BRANDS)
def test_short_brand_real_domain_not_flagged(brand):
    assert analyzer.typosquat_check(f"{brand}.com") is None


@pytest.mark.parametrize("brand", analyzer.SHORT_BRANDS)
def test_short_brand_look_alike_detected(brand):
    for variant in (leet_variant(brand), rn_variant(brand)):
        if variant is None:
            continue
        hit = analyzer.typosquat_check(f"{variant}.com")
        assert hit is not None and hit[0] == brand, variant


@pytest.mark.parametrize("name", ["free-games", "visa-voyage", "orange-vif",
                                  "target-practice", "box-office", "signal-forum"])
def test_common_words_are_not_flagged(name):
    assert analyzer.typosquat_check(f"{name}.com") is None

def test_brand_lists_do_not_overlap(): #on interdit les doublons entre les deux lists
    assert set(analyzer.BRANDS).isdisjoint(analyzer.SHORT_BRANDS)
    assert len(analyzer.BRANDS) == len(set(analyzer.BRANDS))
    assert len(analyzer.SHORT_BRANDS) == len(set(analyzer.SHORT_BRANDS))
