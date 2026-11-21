"""Тесты логики Telegram-бота без сети (bot/bot.py)."""
from types import SimpleNamespace
from urllib.parse import unquote

import pytest

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
    assert kb is not None
    datas = [btn.callback_data for row in kb.inline_keyboard for btn in row if btn.callback_data]
    assert all(len(d.encode()) <= 64 for d in datas)
    assert kb.inline_keyboard[0][0].url

    # Проверяем, что кнопок «Это мошенничество» и «Не мошенничество» больше нет
    button_texts = [btn.text for row in kb.inline_keyboard for btn in row]
    assert not any("мошенничество" in t.lower() or "алдамчылык" in t.lower() for t in button_texts)


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

        # В меню нет кнопки «научиться распознавать мошенников»
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


def test_full_bot_flow_end_to_end():
    import asyncio
    from unittest.mock import AsyncMock, MagicMock
    from aiogram.types import User, Message, CallbackQuery
    from aiogram.fsm.context import FSMContext
    from aiogram.fsm.storage.memory import MemoryStorage, StorageKey

    async def _flow():
        user = User(id=999, is_bot=False, first_name="TestUser", language_code="ru")
        storage = MemoryStorage()
        key = StorageKey(bot_id=1, chat_id=999, user_id=999)
        state = FSMContext(storage=storage, key=key)

        def make_msg(text):
            m = MagicMock(spec=Message)
            m.from_user = user
            m.text = text
            m.answer = AsyncMock()
            return m

        # 1. /start
        msg = make_msg("/start")
        await b.on_start(msg, state)
        assert msg.answer.call_count == 1
        assert "SakBol" in msg.answer.call_args[0][0]
        # Проверяем, что в карточке ровно 3 кнопки
        kb = msg.answer.call_args[1]["reply_markup"]
        assert len(kb.inline_keyboard) == 3

        # 2. Переход к проверке SMS (работает)
        msg = make_msg("💬 Проверить подозрительное SMS")
        await b.on_text_btn_sms(msg, state)
        assert await state.get_state() == b.BotStates.waiting_for_sms.state

        # 3. Отправка SMS
        msg = make_msg("Ваша карта заблокирована, отправьте код на 0555123456")
        await b.on_text(msg, state)
        assert await state.get_state() is None
        assert "🔴" in msg.answer.call_args[0][0]

        # 4. Нажатие на кнопку ссылки (работает, запрашивает ссылку)
        msg = make_msg("🔗 Проверить ссылку")
        await b.on_text_btn_link(msg, state)
        assert await state.get_state() == b.BotStates.waiting_for_link.state
        assert "Проверка интернет-ссылки" in msg.answer.call_args[0][0]

        # 5. Отправка ссылки с омоглифом (mbаnk.kg с русской «а»)
        msg = make_msg("mbаnk.kg")
        await b.on_text(msg, state)
        assert await state.get_state() is None
        resp_spoof = msg.answer.call_args[0][0]
        assert "ОПАСНАЯ ПОДДЕЛКА" in resp_spoof
        assert "mbank.kg" in resp_spoof

        # 6. Отправка официальной ссылки (https://optima24.kg)
        await state.set_state(b.BotStates.waiting_for_link)
        msg = make_msg("https://optima24.kg")
        await b.on_text(msg, state)
        assert "Официальный проверенный ресурс" in msg.answer.call_args[0][0]

        # 7. Нажатие на кнопку SOS (интерактивный помощник)
        msg = make_msg("⚠️ Я уже попался на уловку")
        await b.on_text_btn_sos(msg, state)
        sos_ans = msg.answer.call_args[0][0]
        assert "Что делать" in sos_ans or "Эмне кылуу керек" in sos_ans
        sos_kb = msg.answer.call_args[1]["reply_markup"]
        sos_cbs = [btn.callback_data for row in sos_kb.inline_keyboard for btn in row]
        assert "sos:just_opened" in sos_cbs
        assert "sos:sent_money" in sos_cbs

        # 8. Инлайн колбэк для ссылки (активирует ввод) и SOS
        call = MagicMock(spec=CallbackQuery)
        call.from_user = user
        call.message = MagicMock()
        call.message.answer = AsyncMock()
        call.answer = AsyncMock()

        call.data = "act:link"
        await b.on_action_chosen(call, state)
        assert await state.get_state() == b.BotStates.waiting_for_link.state

        call.data = "act:sos"
        call.message.answer.reset_mock()
        await b.on_action_chosen(call, state)
        assert "Что делать" in call.message.answer.call_args[0][0]

        # 9. Проверка сценариев интерактивного помощника
        call.data = "sos:just_opened"
        call.message.answer.reset_mock()
        await b.on_sos_sub_chosen(call)
        assert "безопасности" in call.message.answer.call_args[0][0].lower()

        call.data = "sos:sent_money"
        call.message.answer.reset_mock()
        await b.on_sos_sub_chosen(call)
        assert "102" in call.message.answer.call_args[0][0]

    asyncio.run(_flow())


