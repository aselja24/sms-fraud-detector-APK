"""Тесты извлечения признаков."""
from detector.features import FEATURE_NAMES, extract


def test_feature_names_count_and_order():
    assert len(FEATURE_NAMES) == 14
    assert FEATURE_NAMES[:8] == [
        "has_link", "asks_code", "urgency", "block_threat", "prize",
        "bank_operator", "money_transfer", "call_back",
    ]


def test_safety_warning_on_do_not_share_code():
    f = extract("Ваш код подтверждения: 1234. Не сообщайте его никому")
    # «код» есть, но просьбы его передать нет («не сообщайте» != «сообщите»).
    assert f["asks_code"] == 0
    assert f["safety_warning"] == 1


def test_asks_code_needs_request_verb():
    assert extract("Сообщите код из SMS")["asks_code"] == 1
    assert extract("Продиктуйте CVV оператору")["asks_code"] == 1
    assert extract("Картаңыз бөгөттөлдү, кодду жибериңиз")["asks_code"] == 1
    assert extract("Soobshite kod iz SMS")["asks_code"] == 1
    assert extract("Код для входа: 5521")["asks_code"] == 0


def test_phone_with_dashes_and_parentheses():
    assert extract("Звоните 0555-12-34-56")["has_phone"] == 1
    assert extract("Звоните +996 (555) 123456")["has_phone"] == 1
    assert extract("Оплатите до 09.12.2026")["has_phone"] == 0


def test_domain_imitating_kg_zone_is_fake():
    assert extract("Оплатите: https://post-kg.example/pay")["fake_brand_domain"] == 1
    assert extract("Оплата: https://my.beeline.kg")["fake_brand_domain"] == 0


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


def test_action_request_is_any_request():
    assert extract("Перезвоните нам")["action_request"] == 1
    assert extract("Сообщите код из SMS")["action_request"] == 1
    assert extract("Спасибо за оплату. Чек в приложении")["action_request"] == 0


def test_informal_imperative_but_not_passive():
    # «жибер» (отправь) — просьба; «жиберилди» (отправлен) — обычное SMS с кодом.
    assert extract("CVV кодду жана карта номерин жибер")["asks_code"] == 1
    assert extract("Сизге код жиберилди: 4410")["asks_code"] == 0


def test_deadline_in_digits_is_urgency():
    assert extract("Номер отключат через 30 минут")["urgency"] == 1
    assert extract("Бүгүн 10 мүнөт ичинде төлөңүз")["urgency"] == 1
    assert extract("Автобус 5 мүнөткө кечигип жатат")["urgency"] == 0


def test_real_kg_bank_domains_are_not_fake():
    # Настоящие домены банков/операторов — не подделка бренда...
    for text in ["Инфо: megacom.kg", "Подробнее на optima24.kg", "Маалымат bakai.kg сайтында"]:
        assert extract(text)["fake_brand_domain"] == 0, text
    # ...а бренд в чужом домене — подделка.
    for text in ["Войдите: optima24-security.com", "Утуш: beeline-utush.xyz", "odengi-bonus.top"]:
        assert extract(text)["fake_brand_domain"] == 1, text


def test_suspicious_tld_is_fake_domain():
    assert extract("Подробнее: http://promo-2026.xyz/a")["fake_brand_domain"] == 1
    assert extract("Кирүү: tunduk-login.info")["fake_brand_domain"] == 1
    assert extract("Меню: https://cafe-navat.example/menu")["fake_brand_domain"] == 0


def test_cancel_operation_pretext():
    f = extract("Балансыңыздан 8000 сом алынууда. Жокко чыгаруу үчүн кодду жибериңиз")
    assert f["block_threat"] == 1 and f["asks_code"] == 1
