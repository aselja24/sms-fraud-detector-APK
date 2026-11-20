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
