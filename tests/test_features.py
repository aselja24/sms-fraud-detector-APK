"""Тесты извлечения признаков."""
from detector.features import FEATURE_NAMES, extract


def test_feature_names_count_and_order():
    assert len(FEATURE_NAMES) == 13
    assert FEATURE_NAMES[:8] == [
        "has_link", "asks_code", "urgency", "block_threat", "prize",
        "bank_operator", "money_transfer", "call_back",
    ]


def test_safety_warning_on_do_not_share_code():
    f = extract("Ваш код подтверждения: 1234. Не сообщайте его никому")
    assert f["asks_code"] == 1
    assert f["safety_warning"] == 1


def test_lookalike_domain_is_not_whitelisted():
    f = extract("Куттуктайбыз! Шилтемеге өтүңүз: https://mbank.kg-verify.example")
    assert f["has_link"] == 1
    assert f["fake_brand_domain"] == 1


def test_official_domain_is_whitelisted():
    f = extract("Оплата: https://mbank.kg")
    assert f["has_link"] == 1
    assert f["fake_brand_domain"] == 0


def test_neutral_example_domain_is_not_fake_brand():
    f = extract("Расписание на неделю: https://univer.example/raspisanie")
    assert f["has_link"] == 1
    assert f["fake_brand_domain"] == 0


def test_block_threat_and_phone_and_urgency():
    f = extract("Срочно! Ваша SIM-карта будет заблокирована. Перезвоните на +996 770 835795")
    assert f["urgency"] == 1
    assert f["block_threat"] == 1
    assert f["call_back"] == 1
    assert f["has_phone"] == 1
    assert f["foreign_phone"] == 0


def test_foreign_phone_detected():
    f = extract("Срочно перезвоните на +44 7021520511")
    assert f["has_phone"] == 1
    assert f["foreign_phone"] == 1


def test_prize_kg_root_requires_double_t():
    # "утуш" (из предупреждения) не должен ловиться корнем "утт".
    f_warning = extract("Алдамчылардан сак болуңуз: утуш үчүн акча которбоңуз")
    assert f_warning["prize"] == 0
    assert f_warning["safety_warning"] == 1

    f_fraud = extract("Куттуктайбыз! Сиз 50 000 сом уттуңуз")
    assert f_fraud["prize"] == 1


def test_money_transfer_imperative_vs_warning():
    assert extract("срочно переведи 1500 сом на этот номер")["money_transfer"] == 1
    assert extract("Не переводите деньги незнакомым")["money_transfer"] == 0
