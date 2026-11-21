"""Тесты единого написания кыргызских букв и транслита корней."""
from detector.entities import find_urls, is_fake_brand, is_whitelisted
from detector.features import extract
from detector.normalize import normalize
from detector.translit import fold, latin_variants


def test_fold_kyrgyz_letters_cyrillic_and_latin():
    assert fold("жибериңиз бөгөттөлдү") == "жибериниз боготтолду"
    assert fold("kartaŋyz bögöttöldü") == "kartanyz bogottoldu"
    assert fold("jiberingiz") == "jiberiniz"


def test_normalize_makes_both_spellings_equal():
    assert normalize("Кодду жибериңиз") == normalize("Кодду жибериниз")


def test_latin_variants():
    assert set(latin_variants("жибериңиз")) == {"jiberiniz", "zhiberiniz"}
    # короткие корни не транслитерируются (pin, chal ловили бы чужие слова)
    assert latin_variants("пин") == []
    assert latin_variants("code") == []


def test_same_feature_in_all_spellings():
    for text in [
        "Картаңыз бөгөттөлдү",   # KG
        "Картаныз боготтолду",   # KG без раскладки
        "Kartaŋyz bögöttöldü",   # латиница с ö/ŋ
        "Kartanyz bogottoldu",   # латиница без них
    ]:
        assert extract(text)["block_threat"] == 1, text


def test_url_without_scheme():
    assert find_urls("Подтвердите: mbank-kg.com/verify.") == ["mbank-kg.com/verify"]
    assert find_urls("Получите: bit.ly/3xYzQ") == ["bit.ly/3xYzQ"]
    assert find_urls("Пишите на info@mbank.kg") == []
    assert find_urls("Оплатите до 09.12.2026, сумма 1.500 сом") == []
    assert is_whitelisted("my.beeline.kg")
    assert not is_whitelisted("mbank.kg-verify.example")
    assert is_fake_brand("www.optima-login.net")
    assert is_fake_brand("bit.ly/3xYzQ")
