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


def test_main_menu_buttons_match_spec_and_omit_learning():
    for lang in ("ru", "ky"):
        kb = b.main_menu_inline(lang)
        button_texts = [btn.text for row in kb.inline_keyboard for btn in row]
        callbacks = [btn.callback_data for row in kb.inline_keyboard for btn in row if btn.callback_data]

        # 3 требуемые кнопки присутствуют
        assert "act:sms" in callbacks
        assert "act:link" in callbacks
        assert "act:sos" in callbacks

        # Кнопка «научиться распознавать мошенников» исключена по требованию
        for text in button_texts:
            assert "научиться" not in text.lower()
            assert "распознавать" not in text.lower()
            assert "үйрөнүү" not in text.lower()


def test_sos_options():
    for lang in ("ru", "ky"):
        kb = b.sos_inline(lang)
        callbacks = [btn.callback_data for row in kb.inline_keyboard for btn in row if btn.callback_data]
        assert "sos:banks" in callbacks
        assert "sos:apk" in callbacks
        assert "act:main" in callbacks


def test_format_link_analysis():
    # Поддельная ссылка с кириллической «а»
    spoof_body, res_spoof = b.format_link_analysis("mbаnk.kg", "ru")
    assert "ОПАСНАЯ ПОДДЕЛКА" in spoof_body
    assert "mbank.kg" in spoof_body
    assert res_spoof["risk"] == "high"

    # Официальная ссылка
    ok_body, res_ok = b.format_link_analysis("https://mbank.kg", "ru")
    assert "Официальный проверенный ресурс" in ok_body

