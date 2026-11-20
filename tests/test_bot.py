"""Тесты логики Telegram-бота без сети (bot/bot.py)."""
import re
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



def test_link_check_sees_hidden_characters():
    # Раньше адрес сначала очищался, и «mb<нулевой пробел>ank.kg» бот называл
    # официальным сайтом.
    body, result = b.format_link_analysis("mb​ank.kg/login", "ru")
    assert "ОПАСНАЯ ПОДДЕЛКА" in body
    assert "Официальный" not in body
    assert result["risk"] == "high"


def test_link_check_without_link():
    assert b.format_link_analysis("просто текст без адреса", "ru") is None


def test_render_escapes_html():
    result = {"risk": "high", "score": 90,
              "reasons": ["адрес «a<b>.xyz» & ко"], "advice": ["<i>не</i> открывайте"]}
    text = b.render(result, "ru")
    assert "<b>" not in text and "<i>" not in text
    assert "&lt;b&gt;" in text and "&amp;" in text


def test_reply_menu_buttons_have_handlers():
    # Текст кнопки нижнего меню должен совпадать с фильтром обработчика.
    for lang in ("ru", "ky"):
        texts = [btn.text for row in b.main_menu_reply(lang).keyboard for btn in row]
        for key in ("btn_check_sms", "btn_check_link", "btn_sos"):
            assert b.t(key, lang) in texts
            assert b.t(key, lang) in b._all_langs(key)
        assert b.BTN_LANG in texts and b.BTN_HELP in texts


def test_bank_contacts_have_no_made_up_numbers():
    # Номера горячих линий меняются, а неверный номер в экстренной помощи
    # опасен: бот отправляет к номеру на карте и в приложении банка.
    for lang in ("ru", "ky"):
        text = b.t("bank_contacts_text", lang)
        assert not re.search(r"\+996|\*\d{3,}|\d{2}-\d{2}-\d{2}", text)
        assert "102" in text
