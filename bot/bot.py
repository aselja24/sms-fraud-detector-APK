"""
Telegram-бот: присылает в ответ на SMS оценку риска мошенничества.

Что умеет:
  * текст SMS или скриншот SMS (распознаётся через Tesseract, bot/ocr.py);
  * два языка — кыргызча и русский (/lang); по умолчанию язык Telegram;
  * кнопки «🚨 Это мошенничество» / «✅ Не мошенничество»: отметки пишутся в
    data/feedback/feedback.csv (bot/feedback.py) для дообучения:
        python train.py --extra data/feedback/feedback.csv
  * «📤 Предупредить близких» — пользователь сам пересылает предупреждение
    (без самой ссылки из SMS) в любой свой чат через стандартное окно
    Telegram «Поделиться». Бот никому не пишет сам.

Запуск:
    python -m bot.bot
Токен берётся из переменной окружения BOT_TOKEN (файл bot/.env).
"""
import asyncio
import io
import logging
import os
import sys
import uuid
from collections import OrderedDict
from urllib.parse import quote

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aiogram import Bot, Dispatcher, F
from aiogram.filters import Command, CommandStart
from aiogram.types import CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup, Message
from dotenv import load_dotenv

from bot import ocr
from bot.feedback import save_feedback
from bot.i18n import LANGS, UI, t, translate
from detector.check import check
from detector.entities import find_urls

load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

LEVEL_EMOJI = {"low": "🟢", "medium": "🟡", "high": "🔴"}
_MAX_SHOWN_OCR = 400

# Тексты, по которым ещё ждём отметку. В callback_data Telegram помещается
# только 64 байта, поэтому сам текст храним здесь, а в кнопке — короткий ключ.
_pending: "OrderedDict[str, tuple[str, str]]" = OrderedDict()
_MAX_PENDING = 1000
# Выбранный язык — только в памяти процесса: id пользователей на диск не пишем.
_user_lang: dict[int, str] = {}
_ocr_ok: bool | None = None

dp = Dispatcher()


def user_lang(user) -> str:
    """Выбранный язык, иначе язык Telegram (ky -> кыргызча), иначе русский."""
    if user is None:
        return "ru"
    if user.id in _user_lang:
        return _user_lang[user.id]
    return "ky" if (user.language_code or "").lower().startswith("ky") else "ru"


def render(result: dict, lang: str) -> str:
    """Ответ check() текстом на нужном языке."""
    ui = UI[lang]
    lines = [ui["risk_line"].format(
        emoji=LEVEL_EMOJI.get(result["risk"], "❓"),
        level=ui["risk"][result["risk"]],
        score=result["score"],
    )]
    if result["reasons"]:
        lines.append("\n" + ui["reasons"])
        lines.extend(f"• {translate(r, lang)}" for r in result["reasons"])
    if result["advice"]:
        lines.append("\n" + ui["advice"])
        lines.extend(f"• {translate(a, lang)}" for a in result["advice"])
    return "\n".join(lines)


def share_url(result: dict, lang: str) -> str | None:
    """Ссылка «Поделиться» с предупреждением — только для medium/high.
    В текст не попадает сама подозрительная ссылка из SMS: пересылать её
    близким опасно."""
    if result["risk"] == "low" or not result["reasons"]:
        return None
    reason = translate(result["reasons"][0], lang)
    # Адреса в причине (в том числе адрес мошенников) делаем некликабельными:
    # «mbаnk[.]kg» — так их пишут в предупреждениях о фишинге.
    for url in sorted(set(find_urls(reason)), key=len, reverse=True):
        reason = reason.replace(url, url.replace(".", "[.]"))
    text = t("share_text", lang).format(reason=reason)
    return "https://t.me/share/url?url=" + quote(text)


def result_keyboard(key: str, lang: str, share: str | None) -> InlineKeyboardMarkup:
    rows = [[
        InlineKeyboardButton(text=t("btn_fraud", lang), callback_data=f"fb:fraud:{key}"),
        InlineKeyboardButton(text=t("btn_ok", lang), callback_data=f"fb:ok:{key}"),
    ]]
    if share:
        rows.append([InlineKeyboardButton(text=t("share_btn", lang), url=share)])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def lang_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text="Кыргызча 🇰🇬", callback_data="lang:ky"),
        InlineKeyboardButton(text="Русский 🇷🇺", callback_data="lang:ru"),
    ]])


async def reply_with_check(message: Message, text: str, lang: str, prefix: str = "") -> None:
    result = check(text)
    key = uuid.uuid4().hex[:12]
    _pending[key] = (text, result["risk"])
    while len(_pending) > _MAX_PENDING:
        _pending.popitem(last=False)
    body = render(result, lang)
    if prefix:
        body = prefix + "\n\n" + body
    await message.answer(body, reply_markup=result_keyboard(key, lang, share_url(result, lang)))


def _ocr_ready() -> bool:
    global _ocr_ok
    if _ocr_ok is None:
        _ocr_ok = ocr.available()
    return _ocr_ok


@dp.message(CommandStart())
async def on_start(message: Message):
    lang = user_lang(message.from_user)
    await message.answer(t("start", lang), reply_markup=lang_keyboard())


@dp.message(Command("help"))
async def on_help(message: Message):
    await message.answer(t("help", user_lang(message.from_user)))


@dp.message(Command("lang"))
async def on_lang(message: Message):
    await message.answer(t("choose_lang", user_lang(message.from_user)), reply_markup=lang_keyboard())


@dp.callback_query(F.data.startswith("lang:"))
async def on_lang_chosen(call: CallbackQuery):
    lang = call.data.split(":", 1)[1]
    if lang not in LANGS:
        await call.answer()
        return
    _user_lang[call.from_user.id] = lang
    await call.answer(t("lang_set", lang))
    if call.message:
        await call.message.answer(t("lang_set", lang))


@dp.callback_query(F.data.startswith("fb:"))
async def on_feedback(call: CallbackQuery):
    lang = user_lang(call.from_user)
    _, label, key = call.data.split(":", 2)
    item = _pending.pop(key, None)
    if item is None:
        await call.answer(t("fb_stale", lang))
        return
    text, risk = item
    save_feedback(text, label, risk)
    await call.answer(t("fb_thanks", lang))
    if call.message:
        # Убираем только кнопки отметки, «Поделиться» оставляем.
        keep = [row for row in (call.message.reply_markup.inline_keyboard if call.message.reply_markup else [])
                if all(button.url for button in row)]
        await call.message.edit_reply_markup(reply_markup=InlineKeyboardMarkup(inline_keyboard=keep) if keep else None)


@dp.message(F.photo | F.document.mime_type.startswith("image/"))
async def on_image(message: Message):
    lang = user_lang(message.from_user)
    if not _ocr_ready():
        await message.answer(t("ocr_unavailable", lang))
        return
    await message.answer(t("ocr_wait", lang))
    image = message.photo[-1] if message.photo else message.document
    buffer = io.BytesIO()
    await message.bot.download(image, destination=buffer)
    try:
        text = await asyncio.to_thread(ocr.image_to_text, buffer.getvalue())
    except ocr.OCRUnavailable:
        await message.answer(t("ocr_unavailable", lang))
        return
    if message.caption:
        text = f"{message.caption} {text}".strip()
    if len(text) < 5:
        await message.answer(t("ocr_empty", lang))
        return
    shown = text if len(text) <= _MAX_SHOWN_OCR else text[:_MAX_SHOWN_OCR] + "…"
    prefix = f"{t('ocr_text', lang)}\n«{shown}»"
    if find_urls(text):
        prefix += "\n\n" + t("ocr_note", lang)
    await reply_with_check(message, text, lang, prefix)


@dp.message(F.text)
async def on_text(message: Message):
    await reply_with_check(message, message.text, user_lang(message.from_user))


@dp.message()
async def on_other(message: Message):
    await message.answer(t("empty", user_lang(message.from_user)))


async def main():
    token = os.environ.get("BOT_TOKEN")
    if not token:
        raise SystemExit("Не задан BOT_TOKEN (файл bot/.env)")

    logging.basicConfig(level=logging.INFO)
    if not _ocr_ready():
        logging.warning("Tesseract не найден — скриншоты читаться не будут (см. bot/ocr.py)")
    bot = Bot(token=token)
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
