"""
Telegram-бот: присылает в ответ на SMS оценку риска фишинга.

Запуск:
    python -m bot.bot
Токен берётся из переменной окружения BOT_TOKEN (см. bot/.env.example).
"""
import asyncio
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aiogram import Bot, Dispatcher
from aiogram.filters import CommandStart
from aiogram.types import Message
from dotenv import load_dotenv

from detector.check import check
from detector.gateway import sanitize_sms

load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

LEVEL_EMOJI = {"low": "🟢", "medium": "🟡", "high": "🔴"}

dp = Dispatcher()


@dp.message(CommandStart())
async def on_start(message: Message):
    await message.answer(
        "Пришлите текст подозрительного SMS, и я оценю риск фишинга."
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

    # Сетевой перехват опасных ссылок (Safe Links / SakBol)
    sanitized = sanitize_sms(text)
    if sanitized["is_modified"]:
        lines.append("\n🛡️ Сетевой перехват SakBol (Safe Links):")
        lines.append("Ссылка в SMS была бы нейтрализована оператором!")
        lines.append(f"Безопасный вид SMS для абонента:\n«{sanitized['safe_text']}»")
        lines.append("(Переход по ссылке ведёт на экран блокировки вместо фишинга)")

    await message.answer("\n".join(lines))



async def main():
    token = os.environ.get("BOT_TOKEN")
    if not token:
        raise SystemExit("Не задан BOT_TOKEN (см. bot/.env.example)")

    logging.basicConfig(level=logging.INFO)
    bot = Bot(token=token)
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
