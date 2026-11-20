"""Тесты логики Telegram-бота без сети (bot/bot.py)."""
from types import SimpleNamespace
from urllib.parse import unquote

import bot.bot as b
from detector.check import check

SPOOF = "Ваш аккаунт заблокирован. Войдите: mbаnk.kg"


def test_language_defaults_and_choice():
    assert b.user_lang(SimpleNamespace(id=1, language_code="ky")) == "ky"
    assert b.user_lang(SimpleNamespace(id=2, language_code="en")) == "ru"
    b._user_lang[3] = "ky"
    assert b.user_lang(SimpleNamespace(id=3, language_code="ru")) == "ky"
    b._user_lang.pop(3)


def test_render_in_both_languages():
    result = check(SPOOF)
    assert b.render(result, "ru").startswith("🔴 Риск: высокий")
    ky = b.render(result, "ky")
    assert ky.startswith("🔴 Коркунуч: жогору") and "Себептери:" in ky


def test_share_only_for_risky_and_without_the_link():
    risky = check(SPOOF)
    url = b.share_url(risky, "ru")
    assert url and url.startswith("https://t.me/share/url?url=")
    assert "mbаnk.kg" not in unquote(url)   # саму ссылку мошенников не пересылаем
    assert b.share_url(check("Привет! Во сколько завтра встречаемся?"), "ru") is None


def test_keyboard_fits_telegram_limit():
    kb = b.result_keyboard("abcdef123456", "ky", "https://t.me/share/url?url=x")
    datas = [btn.callback_data for row in kb.inline_keyboard for btn in row if btn.callback_data]
    assert all(len(d.encode()) <= 64 for d in datas)
    assert kb.inline_keyboard[1][0].url


def test_shared_text_has_no_clickable_links():
    # find_urls здесь не подходит: он нарочно раскрывает «[.]» обратно.
    import re
    for lang in ("ru", "ky"):
        shared = unquote(b.share_url(check(SPOOF), lang)).split("url=", 1)[1]
        assert not re.search(r"\w\.(kg|com|net|ru)\b", shared), shared
        assert "[.]kg" in shared
