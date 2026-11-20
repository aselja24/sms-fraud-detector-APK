"""Тесты шлюза безопасных ссылок (detector/gateway.py, gateway_server.py)."""
import asyncio

import pytest
from aiohttp.test_utils import TestClient, TestServer

import gateway_server as server
from detector.gateway import SafeLinksRegistry, defang, sanitize_sms

BASE = "http://gw.test"


def run(text):
    reg = SafeLinksRegistry()
    return sanitize_sms(text, base_url=BASE, link_registry=reg), reg


def test_whitelist_url_is_not_replaced():
    text = "Beeline: подключите пакет за 500 сом. Подробнее: https://beeline.kg"
    res, reg = run(text)
    assert not res["is_modified"]
    assert res["safe_text"] == text
    assert res["links"][0]["action"] == "kept"
    assert reg.stats()["links_blocked"] == 0


def test_official_link_kept_even_in_fraud_sms():
    # Настоящий mbank.kg сеть не блокирует: опасность в тексте, а не в адресе.
    res, _ = run("Куттуктайбыз! Сиз Beeline'дан iPhone уттуңуз. Mbank.kg")
    assert res["risk"] == "high"
    assert not res["is_modified"]


def test_fake_brand_url_is_replaced():
    text = "Куттуктайбыз! Сиз iPhone 15 уттуңуз: https://my-beeline.kg.example"
    res, reg = run(text)
    assert res["is_modified"]
    assert "my-beeline" not in res["safe_text"]
    rep = res["replaced_urls"][0]
    assert res["safe_text"] == f"Куттуктайбыз! Сиз iPhone 15 уттуңуз: {rep['safe_url']}"
    assert rep["safe_url"].startswith(BASE + "/x/")
    assert rep["brand"] == "Beeline"
    assert rep["official_domain"] == "beeline.kg"
    record = reg.get(rep["token"])
    assert record.original_url == "https://my-beeline.kg.example"
    assert record.clicks_count == 0


@pytest.mark.parametrize("text, hidden", [
    ("MBANK: вход с нового устройства. Отмените: mb​ank.kg/cancel", "mb​ank.kg/cancel"),
    ("Сизге бонус! Алуу үчүн: mbank [.] kg-bonus.xyz бүгүн", "mbank [.] kg-bonus.xyz"),
    ("Срочно подтвердите карту: mbаnk.kg", "mbаnk.kg"),
    ("Бакай Банк: картаңыз бөгөттөлдү. Кириңиз: бакай.кг", "бакай.кг"),
])
def test_hidden_and_spoofed_links_really_disappear(text, hidden):
    # Раньше «заменённая» ссылка со спрятанными символами оставалась в тексте.
    res, _ = run(text)
    assert res["is_modified"]
    assert hidden not in res["safe_text"]
    assert "​" not in res["safe_text"]
    assert res["safe_text"].count(BASE + "/x/") == 1
    assert res["replaced_urls"][0]["official_domain"] in ("mbank.kg", "bakai.kg")


def test_lookalike_domain_is_replaced():
    res, _ = run("Privet, ty vyigral priz ot Beeline: bk-eline.kg")
    assert res["is_modified"]
    assert "почти как у «beeline»" in res["replaced_urls"][0]["reason"]


def test_same_url_gets_one_token_and_counts_sms():
    reg = SafeLinksRegistry()
    text = "Ваш пароль MBANK истекает: https://mbank.kg-verify.example"
    first = sanitize_sms(text, base_url=BASE, link_registry=reg)["replaced_urls"][0]["token"]
    second = sanitize_sms(text, base_url=BASE, link_registry=reg)["replaced_urls"][0]["token"]
    assert first == second
    assert reg.get(first).sms_count == 2
    assert reg.stats() == {"sms_checked": 2, "sms_modified": 2, "links_blocked": 1, "clicks_blocked": 0}


def test_click_counter_and_registry_limit():
    reg = SafeLinksRegistry(max_size=2)
    tokens = [reg.register(f"https://fraud{i}.xyz", "high", "фишинг").token for i in range(3)]
    assert reg.get(tokens[0]) is None          # самая старая вытеснена
    assert reg.click(tokens[2]).clicks_count == 1
    assert reg.click(tokens[2]).clicks_count == 2
    assert reg.get(tokens[2]).clicks_count == 2   # get() счётчик не трогает
    assert len(tokens[2]) >= 8


def test_sms_text_is_not_stored():
    reg = SafeLinksRegistry()
    sanitize_sms("Иван, ваш MBANK заблокирован: mbank-kg.xyz", base_url=BASE, link_registry=reg)
    assert "Иван" not in str(reg.all_records())


def test_segments_rebuild_safe_text():
    res, _ = run("Ваш MBANK заблокирован: mbаnk.kg и ещё https://mbank.kg-verify.example .")
    assert "".join(s["text"] for s in res["segments"]) == res["safe_text"]
    assert [s["kind"] for s in res["segments"]].count("blocked") == 2


def test_defang():
    assert defang("https://mbank.kg-verify.example") == "hxxps://mbank[.]kg-verify[.]example"


# --- веб-сервер ------------------------------------------------------------

async def _with_client(fn):
    server.registry.clear()
    client = TestClient(TestServer(server.create_app()))
    await client.start_server()
    try:
        return await fn(client)
    finally:
        await client.close()
        server.registry.clear()


def test_stop_page_works_and_counts_click():
    async def scenario(client):
        res = await client.post("/api/check", json={"text": "Срочно подтвердите карту: mbаnk.kg"})
        data = await res.json()
        token = data["replaced_urls"][0]["token"]
        page = await client.get(f"/x/{token}")
        body = await page.text()
        assert page.status == 200
        assert "Переход остановлен" in body
        assert "mbаnk[.]kg" in body                # адрес показан некликабельным
        assert 'href="https://mbank.kg"' in body   # и есть кнопка на настоящий сайт
        assert "default-src 'none'" in page.headers["Content-Security-Policy"]
        ky = await (await client.get(f"/x/{token}?lang=ky")).text()
        assert "Өтүү токтотулду" in ky
        stats = (await (await client.get("/api/records")).json())["stats"]
        assert stats["clicks_blocked"] == 2
    asyncio.run(_with_client(scenario))


def test_stop_page_escapes_html():
    async def scenario(client):
        evil = "Ваш MBANK заблокирован: https://mbank-kg.xyz/<script>alert(1)</script>"
        data = await (await client.post("/api/check", json={"text": evil})).json()
        body = await (await client.get(f"/x/{data['replaced_urls'][0]['token']}")).text()
        assert "<script>alert" not in body
        assert "&lt;script&gt;" in body
    asyncio.run(_with_client(scenario))


def test_unknown_token_and_bad_input():
    async def scenario(client):
        assert (await client.get("/x/nope")).status == 404
        assert (await client.post("/api/check", data="not json")).status == 400
        assert (await client.post("/api/check", json={"text": 5})).status == 400
        assert (await client.post("/api/check", json={"text": "a" * 5000})).status == 413
        assert (await client.get("/")).status == 200
    asyncio.run(_with_client(scenario))
