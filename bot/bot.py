"""
Telegram-бот: присылает в ответ на SMS оценку риска фишинга.

Под каждым ответом — кнопки «🚨 Это мошенничество» / «✅ Не мошенничество».
Отметка сохраняется в data/feedback/feedback.csv (bot/feedback.py), и на
этих данных модель можно дообучить:
    python train.py --extra data/feedback/feedback.csv

Запуск:
    python -m bot.bot
Токен берётся из переменной окружения BOT_TOKEN (файл bot/.env).
"""
import asyncio
import logging
import os
import sys
import uuid
from collections import OrderedDict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aiogram import Bot, Dispatcher, F
from aiogram.filters import CommandStart
from aiogram.types import CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup, Message
from dotenv import load_dotenv

from bot.feedback import save_feedback
from detector.check import check

load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

LEVEL_EMOJI = {"low": "🟢", "medium": "🟡", "high": "🔴"}

# Тексты, по которым ещё ждём отметку. В callback_data Telegram помещается
# только 64 байта, поэтому сам текст храним здесь, а в кнопке — короткий ключ.
# Ограничиваем размер, чтобы память не росла бесконечно.
_pending: "OrderedDict[str, tuple[str, str]]" = OrderedDict()
_MAX_PENDING = 1000

dp = Dispatcher()


def _feedback_keyboard(key: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text="🚨 Это мошенничество", callback_data=f"fb:fraud:{key}"),
        InlineKeyboardButton(text="✅ Не мошенничество", callback_data=f"fb:ok:{key}"),
    ]])


@dp.message(CommandStart())
async def on_start(message: Message):
    await message.answer(
        "Пришлите текст подозрительного SMS, и я оценю риск фишинга.\n"
        "Если я ошибся — нажмите кнопку под ответом: так я учусь."
    )


@dp.message()
async def on_text(message: Message):
    text = message.text or ""
    if not text:
        await message.answer("Пришлите текст SMS для проверки.")
        return

    result = check(text)
    emoji = LEVEL_EMOJI.get(result["risk"], "❓")
    lines = [f"{emoji} Риск: {result['risk']} (score {result['score']}/100)"]

    if result["reasons"]:
        lines.append("\nПричины:")
        lines.extend(f"• {reason}" for reason in result["reasons"])

    if result["advice"]:
        lines.append("\nЧто делать:")
        lines.extend(f"• {advice}" for advice in result["advice"])

    key = uuid.uuid4().hex[:12]
    _pending[key] = (text, result["risk"])
    while len(_pending) > _MAX_PENDING:
        _pending.popitem(last=False)

    await message.answer("\n".join(lines), reply_markup=_feedback_keyboard(key))


@dp.callback_query(F.data.startswith("fb:"))
async def on_feedback(call: CallbackQuery):
    _, label, key = call.data.split(":", 2)
    item = _pending.pop(key, None)
    if item is None:
        await call.answer("Отметка уже сохранена или устарела.")
        return
    text, risk = item
    save_feedback(text, label, risk)
    await call.answer("Спасибо! Учту при следующем обучении.")
    if call.message:
        await call.message.edit_reply_markup(reply_markup=None)


async def main():
    token = os.environ.get("BOT_TOKEN")
    if not token:
        raise SystemExit("Не задан BOT_TOKEN (файл bot/.env)")

    logging.basicConfig(level=logging.INFO)
    bot = Bot(token=token)
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
