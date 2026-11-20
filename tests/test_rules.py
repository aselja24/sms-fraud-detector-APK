"""Тесты жёстких правил поверх модели (detector/rules.py)."""
from detector.check import check
from detector.rules import hard_rule


def test_secret_request_rule():
    assert hard_rule({"asks_code": 1}) == "secret_request"


def test_money_needs_pretext():
    assert hard_rule({"money_transfer": 1}) is None
    assert hard_rule({"money_transfer": 1, "prize": 1}) == "money_with_pretext"
    assert hard_rule({"money_transfer": 1, "block_threat": 1}) == "money_with_pretext"


def test_rule_makes_phoneless_fraud_high():
    for text in [
        "Для отмены перевода назовите оператору код из SMS.",
        "Сырсөз менен бир жолку кодду жөнөтүңүз.",
        "Карту заблокируют. Переведите остаток на резервный счет.",
    ]:
        result = check(text)
        assert result["risk"] == "high", text
        assert result["score"] >= 65
        assert len(result["advice"]) == len(result["reasons"])


def test_rule_does_not_fire_on_legit():
    for text in [
        "Ваш код подтверждения 5821. Никому не сообщайте его.",
        "Сиздин кодуңуз 4821. Эч кимге айтпаңыз!",
        "Мама, перезвони мне, когда сможешь",
        "Спасибо за оплату. Квитанция доступна в личном кабинете приложения.",
    ]:
        assert check(text)["risk"] != "high", text


def test_link_rules_need_link_info():
    from detector.links import analyze_links
    cyr_a = "\u0430"
    links = analyze_links(f"Войдите: mb{cyr_a}nk.kg")
    assert hard_rule({}, links) == "link_spoof"
    assert hard_rule({}, []) is None


def test_brand_link_rules():
    from detector.rules import RULE_FLOOR
    assert hard_rule({"fake_brand_domain": 1, "block_threat": 1}) == "brand_link_with_cue"
    assert hard_rule({"fake_brand_domain": 1}) == "brand_link"
    # без давления — только medium, не high
    assert RULE_FLOOR["brand_link"] < 65 <= RULE_FLOOR["brand_link_with_cue"]


def test_unofficial_click_is_medium_but_official_click_is_not():
    result = check("Вам отправили документ. Откройте ссылку для просмотра: https://example.com")
    assert result["risk"] == "medium"
    result = check("Откройте ссылку для просмотра: https://mbank.kg")
    assert result["risk"] != "high"


def test_rule_score_is_not_borderline():
    result = check("Для отмены перевода назовите оператору код из SMS.")
    assert result["score"] >= 80


def test_money_with_fee_pretext():
    # «заплатите, чтобы получить/разблокировать» и «на другую карту» — тоже повод
    for text in [
        "Переведите 150 сом для подтверждения доставки.",
        "Курьер не смог доставить посылку. Оплатите повторную доставку по ссылке.",
        "Эсебиңиз тоңдурулат. Акчаны башка картага которуңуз.",
    ]:
        assert check(text)["risk"] == "high", text


def test_fee_pretext_needs_money_request():
    assert check("Посылка передана курьеру. Доставка бесплатная.")["risk"] != "high"
