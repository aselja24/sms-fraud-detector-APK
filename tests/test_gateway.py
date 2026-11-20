"""Тесты сетевого шлюза безопасных ссылок (Safe Links / SakBol)."""
from detector.gateway import SafeLinksRegistry, sanitize_sms


def test_whitelist_url_is_not_replaced():
    text = "Beeline: подключите пакет за 5000 сом. Подробнее: https://beeline.kg"
    res = sanitize_sms(text)
    assert not res["is_modified"]
    assert res["safe_text"] == text
    assert len(res["replaced_urls"]) == 0


def test_fake_brand_url_is_replaced():
    reg = SafeLinksRegistry()
    text = "Куттуктайбыз! Сиз iPhone 15 уттуңуз: https://my-beeline.kg.example"
    res = sanitize_sms(text, base_url="http://localhost:8000", link_registry=reg)

    assert res["is_modified"]
    assert "https://my-beeline.kg.example" not in res["safe_text"]
    assert "http://localhost:8000/x/" in res["safe_text"]
    assert len(res["replaced_urls"]) == 1

    rep = res["replaced_urls"][0]
    assert rep["original_url"] == "https://my-beeline.kg.example"
    assert rep["brand"] == "Beeline"

    # Проверяем запись в реестре
    info = reg.get(rep["token"])
    assert info is not None
    assert info["brand_name"] == "Beeline"
    assert info["original_url"] == "https://my-beeline.kg.example"
    assert info["clicks_count"] == 1


def test_multiple_clicks_increment_counter():
    reg = SafeLinksRegistry()
    token = reg.register(
        original_url="https://fraud.example",
        risk="high",
        reason="Фишинг",
        brand_key="mbank",
    )
    assert reg.get(token)["clicks_count"] == 1
    assert reg.get(token)["clicks_count"] == 2
