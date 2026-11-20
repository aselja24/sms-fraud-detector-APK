"""Тесты анализа ссылок (detector/links.py)."""
from detector.check import check
from detector.entities import find_urls
from detector.links import analyze_link, analyze_links, skeleton_variants

CYR_A = "а"


def test_cyrillic_letter_in_latin_domain():
    info = analyze_link(f"mb{CYR_A}nk.kg")
    assert "mixed_script" in info.spoof and "homoglyph" in info.spoof
    assert info.hint == "mbank.kg"
    assert any("кириллическая" in d for d in info.details)
    assert not info.official


def test_digit_and_capital_i_and_rn():
    assert analyze_link("0ptima-bank.info").spoof == ["homoglyph"]
    assert analyze_link("teIegram-security.net").spoof == ["homoglyph"]
    assert analyze_link("rnbank.kg").hint == "mbank.kg"
    assert analyze_link("bee1ine.kg").hint == "beeline.kg"


def test_skeleton_uses_original_case():
    # lower() стёр бы разницу между «I» и «l»: «teIegram» стал бы «teiegram».
    assert any("telegram" in s for s in skeleton_variants("teIegram.net"))
    assert not any("telegram" in s for s in skeleton_variants("teiegram.net"))


def test_punycode_is_decoded_and_flagged():
    puny = ("mb" + CYR_A + "nk.kg").encode("idna").decode("ascii")
    info = analyze_link(puny)
    assert "homoglyph" in info.spoof and info.hint == "mbank.kg"


def test_real_domains_are_not_spoofed():
    for host in ["mbank.kg", "my.beeline.kg", "optima24.kg", "megacom.kg", "google.com",
                 "taxi-namba.example", "kino-bishkek.example", "example.com"]:
        info = analyze_link(host)
        assert not info.spoof, host
    assert analyze_link("mbank.kg").official


def test_pure_cyrillic_domain_is_not_spoof():
    assert not analyze_link("ак-тилек.kg").spoof


def test_brand_in_domain_is_fake_but_not_spoof():
    info = analyze_link("mbank-support.net")
    assert info.fake and not info.spoof and info.hint == "mbank.kg"


def test_official_prefix_and_userinfo_tricks():
    assert not analyze_link("mbank.kg.secure-login.net").official
    assert analyze_link("mbank.kg.secure-login.net").fake
    assert not analyze_link("https://mbank.kg@evil-login.net/x").official


def test_find_urls_cyrillic_and_defanged():
    assert find_urls(f"Текшериңиз: mb{CYR_A}nk.kg") == [f"mb{CYR_A}nk.kg"]
    assert find_urls("hxxps://mbank.kg/x") == ["hxxps://mbank.kg/x"]
    assert find_urls("Оплатите до 09.12.2026") == []


def test_normalize_never_turns_spoof_into_official():
    from detector.normalize import normalize
    for text in [f"mb{CYR_A}nk.kg", "0ptima24.kg", "teIegram.org"]:
        urls = analyze_links(normalize(text))
        assert not any(link.official for link in urls), text


def test_check_names_the_real_site():
    result = check(f"Ваша карта заблокирована. Войдите: mb{CYR_A}nk.kg")
    assert result["risk"] == "high"
    assert "mbank.kg" in result["reasons"][0]
    assert "mbank.kg" in result["advice"][0]
    result = check("Ваш аккаунт требует проверки: mbank-support.net")
    assert result["risk"] == "high"
    assert any("mbank.kg" in a for a in result["advice"])


def test_cyrillic_tld_is_found_and_flagged():
    assert find_urls("Войдите: mbank.кг") == ["mbank.кг"]
    info = analyze_link("mbank.кг")
    assert info.spoof and info.hint == "mbank.kg" and not info.official


def test_hidden_zero_width_chars_do_not_split_the_link():
    text = "Войдите: mb\u200bank.kg"
    assert find_urls(text) == ["mbank.kg"]
    info = analyze_links(text)[0]
    assert "hidden_chars" in info.spoof and not info.official and info.hint == "mbank.kg"


def test_defanged_link_is_found_and_flagged():
    assert find_urls("Перейдите: mbank[.]kg/login") == ["mbank.kg/login"]
    assert find_urls("Перейдите: mbank(.)kg") == ["mbank.kg"]
    info = analyze_links("Перейдите: mbank[.]kg/login")[0]
    assert "hidden_chars" in info.spoof


def test_pure_cyrillic_brand_imitation():
    info = analyze_link("бакай.кг")
    assert info.spoof and info.hint == "bakai.kg"


def test_fullwidth_letters_are_spoofed():
    info = analyze_link("ｍbank.kg")
    assert info.spoof and not info.official and info.hint == "mbank.kg"


def test_user_reported_links_are_high():
    for text in [
        "Ваш аккаунт заблокирован. Войдите: mbank.кg",
        "Ваш аккаунт заблокирован. Войдите: mbаnk.кg",
        "Ваш аккаунт заблокирован. Войдите: mb\u200bank.kg",
        "Ваш аккаунт заблокирован. Войдите: mbank[.]kg",
        "Ваш аккаунт заблокирован. Войдите: бакай.кг",
    ]:
        assert check(text)["risk"] == "high", text
        assert check(text)["score"] >= 80, text


def test_hidden_chars_reason_names_real_site():
    result = check("Ваш аккаунт заблокирован. Войдите: mb\u200bank.kg")
    assert "mbank.kg" in result["reasons"][0] and "mbank.kg" in result["advice"][0]


def test_ordinary_cyrillic_domain_is_not_flagged():
    assert not analyze_link("кыргызстан.кг").spoof
    assert check("Посылка: https://кыргызстан.кг")["risk"] != "high"
