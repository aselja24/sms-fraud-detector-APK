"""
Telegram-бот «Sakchi AI»: твой помощник по цифровой безопасности.
Функционал:
Запуск:
    python -m bot.bot
Токен берётся из переменной окружения BOT_TOKEN (файл bot/.env).
"""
import asyncio
import html
import io
import logging
import os
import sys
import uuid
from collections import OrderedDict
from urllib.parse import quote

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aiogram import Bot, Dispatcher, F
from aiogram.enums import ParseMode
from aiogram.filters import Command, CommandStart
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import (
    CallbackQuery,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    KeyboardButton,
    Message,
    ReplyKeyboardMarkup,
)
from dotenv import load_dotenv

try:
    from bot import ocr
    from bot.feedback import save_feedback
    from bot.i18n import LANGS, UI, t, translate
except ImportError:
    try:
        from . import ocr
        from .feedback import save_feedback
        from .i18n import LANGS, UI, t, translate
    except ImportError:
        import ocr  # type: ignore
        from feedback import save_feedback  # type: ignore
        from i18n import LANGS, UI, t, translate  # type: ignore
from detector.check import check
from detector.entities import find_urls
from detector.gateway import BRAND_DISPLAY_NAMES, _detect_brand
from detector.links import analyze_link

load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

LEVEL_EMOJI = {"low": "🟢", "medium": "🟡", "high": "🔴"}
_MAX_SHOWN_OCR = 400

# Тексты, по которым ещё ждём отметку. В callback_data Telegram помещается
# только 64 байта, поэтому сам текст храним здесь, а в кнопке — короткий ключ.
_pending: "OrderedDict[str, tuple[str, str]]" = OrderedDict()
_MAX_PENDING = 1000

# Выбранный язык — в памяти процесса (id пользователей на диск не пишем).
_user_lang: dict[int, str] = {}
_ocr_ok: bool | None = None


class BotStates(StatesGroup):
    waiting_for_sms = State()
    waiting_for_link = State()


__all__ = [
    "ocr",
    "user_lang",
    "_user_lang",
    "render",
    "share_url",
    "result_keyboard",
    "lang_keyboard",
    "main_menu_inline",
    "main_menu_reply",
    "sos_inline",
    "format_link_analysis",
    "dp",
]

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
        lines.extend(f"• {html.escape(translate(r, lang))}" for r in result["reasons"])
    elif result["risk"] == "low":
        lines.append(
            "\n" + (
                "✅ <b>Признаков мошенничества не обнаружено:</b>\n"
                "• Текст не содержит опасных ссылок, скрытых символов или омоглифов.\n"
                "• Нет признаков социальной инженерии и требований срочных переводов."
                if lang == "ru" else
                "✅ <b>Алдамчылыктын белгилери табылган жок:</b>\n"
                "• Билдирүүдө кооптуу шилтемелер, жашыруун же окшош тамгалар жок.\n"
                "• Эсептерди бөгөттөө же шашылыш акча которуу талаптары табылган жок."
            )
        )

    if result["advice"]:
        lines.append("\n" + ui["advice"])
        lines.extend(f"• {html.escape(translate(a, lang))}" for a in result["advice"])
    elif result["risk"] == "low":
        lines.append(
            "\n" + (
                "💡 <b>Совет по безопасности:</b>\n"
                "• Никогда и никому не сообщайте коды из SMS, пароли и CVC-код с карты."
                if lang == "ru" else
                "💡 <b>Коопсуздук кеңеши:</b>\n"
                "• SMS-коддорду, сырсөздөрдү жана картанын CVC-кодун эч кимге айтпаңыз."
            )
        )
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


def result_keyboard(
    key: str,
    lang: str,
    share: str | None,
    action_type: str = "sms",
) -> InlineKeyboardMarkup:
    """Клавиатура под результатом проверки (Поделиться + Меню / Проверить ещё)."""
    rows = []
    if share:
        rows.append([InlineKeyboardButton(text=t("share_btn", lang), url=share)])

    next_text = (
        "💬 Проверить ещё SMS" if lang == "ru" else "💬 Дагы SMS текшерүү"
    ) if action_type == "sms" else (
        "🔗 Проверить другую ссылку" if lang == "ru" else "🔗 Башка шилтеме"
    )
    next_callback = "act:sms" if action_type == "sms" else "act:link"

    rows.append([
        InlineKeyboardButton(text=next_text, callback_data=next_callback),
        InlineKeyboardButton(
            text="🏠 В главное меню" if lang == "ru" else "🏠 Башкы меню",
            callback_data="act:main",
        ),
    ])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def lang_keyboard() -> InlineKeyboardMarkup:
    """Кнопки выбора языка."""
    return InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text="Кыргызча 🇰🇬", callback_data="lang:ky"),
        InlineKeyboardButton(text="Русский 🇷🇺", callback_data="lang:ru"),
    ]])


def main_menu_inline(lang: str) -> InlineKeyboardMarkup:
    """Инлайн-карточка выбора действия («Что вас беспокоит?»)."""
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text=t("btn_check_sms", lang), callback_data="act:sms")],
        [InlineKeyboardButton(text=t("btn_check_link", lang), callback_data="act:link")],
        [InlineKeyboardButton(text=t("btn_sos", lang), callback_data="act:sos")],
    ])


def main_menu_reply(lang: str) -> ReplyKeyboardMarkup:
    """Постоянная нижняя клавиатура для быстрого доступа с мобильных устройств."""
    return ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text=t("btn_check_sms", lang))],
            [KeyboardButton(text=t("btn_check_link", lang))],
            [KeyboardButton(text=t("btn_sos", lang))],
        ],
        resize_keyboard=True,
    )


def sos_inline(lang: str) -> InlineKeyboardMarkup:
    """Инлайн-кнопки в разделе экстренной помощи."""
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text=t("btn_bank_contacts", lang), callback_data="sos:banks")],
        [InlineKeyboardButton(text=t("btn_apk_danger", lang), callback_data="sos:apk")],
        [InlineKeyboardButton(text=t("btn_back_menu", lang), callback_data="act:main")],
    ])


def sos_sub_inline(lang: str) -> InlineKeyboardMarkup:
    """Кнопки возврата из подразделов экстренной помощи."""
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text=t("btn_back_sos", lang), callback_data="act:sos")],
        [InlineKeyboardButton(text=t("btn_back_menu", lang), callback_data="act:main")],
    ])


def format_link_analysis(raw_url: str, lang: str) -> tuple[str, dict]:
    """Глубокий анализ ссылки и проверка подмен, аналогично симулятору SakBol Gateway."""
    info = analyze_link(raw_url)
    result = check(raw_url)
    brand_key = _detect_brand(raw_url, "")
    brand_display = info.hint or (BRAND_DISPLAY_NAMES.get(brand_key, brand_key) if brand_key else None)
    safe_url = html.escape(raw_url)

    lines = [
        f"🔗 <b>{'Результат проверки ссылки' if lang == 'ru' else 'Шилтемени текшерүүнүн жыйынтыгы'}:</b>",
        f"<code>{safe_url}</code>\n",
    ]

    if info.official:
        level_text = "НИЗКИЙ / БЕЗОПАСНО" if lang == "ru" else "ТӨМӨН / КООПСУЗ"
        lines.append(f"🟢 <b>{'Уровень риска:' if lang == 'ru' else 'Коркунуч деңгээли:'}</b> {level_text} ({result['score']}/100)")
        lines.append(f"✅ <b>{'Официальный проверенный ресурс' if lang == 'ru' else 'Расмий текшерилген ресурс'}</b>\n")
        desc = (
            "• Домен входит в официальный белый список доверенных сервисов Кыргызстана.\n"
            "• Подмены символов, омоглифов и скрытых знаков не обнаружено.\n\n"
            "💡 <i>Помните: даже на официальных сайтах сотрудники поддержки банков никогда не просят коды из SMS и CVC карты.</i>"
            if lang == "ru" else
            "• Домен Кыргызстандын расмий текшерилген ак тизмесине кирет.\n"
            "• Символдордун алмаштырылышы же жашыруун белгилер табылган жок.\n\n"
            "💡 <i>Эсиңизде болсун: расмий сайтта да банк кызматкерлери SMS-коддорду жана сырсөздөрдү сурабайт.</i>"
        )
        lines.append(desc)
    elif info.fake or info.spoof:
        level_text = "ВЫСОКИЙ (ОПАСНО)" if lang == "ru" else "ЖОГОРУ (КООПТУУ)"
        lines.append(f"🔴 <b>{'Уровень риска:' if lang == 'ru' else 'Коркунуч деңгээли:'}</b> {level_text} ({result['score']}/100)")
        lines.append(f"⚠️ <b>{'ВНИМАНИЕ: ОПАСНАЯ ПОДДЕЛКА (Фишинг / Спуфинг)!' if lang == 'ru' else 'КӨҢҮЛ БУРУҢУЗ: КООПТУУ ЖАСАЛМА (Фишинг / Спуфинг)!'}</b>\n")

        if info.details:
            details_str = "; ".join(translate(d, lang) for d in info.details)
            label = "• Обнаружена подмена символов:" if lang == "ru" else "• Белгилердин алмаштырылышы:"
            lines.append(f"{label} <b>{html.escape(details_str)}</b>")

        if brand_display:
            b_label = "• Маскируется под бренд:" if lang == "ru" else "• Бренддин атына жамынат:"
            lines.append(f"{b_label} <b>{html.escape(str(brand_display))}</b>")

        if info.hint:
            site_label = "• Настоящий официальный сайт:" if lang == "ru" else "• Расмий чыныгы сайт:"
            lines.append(f"{site_label} <code>https://{html.escape(info.hint)}</code>")

        lines.append("\n🛡 <b>" + ("Что делать:" if lang == "ru" else "Эмне кылуу керек:") + "</b>")
        lines.append("• " + ("Категорически не переходите по этой ссылке." if lang == "ru" else "Бул шилтемеге таптакыр өтпөңүз."))
        lines.append("• " + ("Не вводите логины, пароли, номера карт и SMS-коды." if lang == "ru" else "Логин, сырсөз, карта маалыматын жана SMS-коддорду жазбаңыз."))
        if info.hint:
            lines.append("• " + (f"Пользуйтесь только официальным сайтом: {info.hint}" if lang == "ru" else f"Расмий гана сайтты колдонуңуз: {info.hint}"))
    else:
        level_text = "СРЕДНИЙ / ПОДОЗРИТЕЛЬНЫЙ" if lang == "ru" else "ОРТОЧО / ШЕКТҮҮ"
        lines.append(f"🟡 <b>{'Уровень риска:' if lang == 'ru' else 'Коркунуч деңгээли:'}</b> {level_text} ({result['score']}/100)")
        lines.append(f"⚠️ <b>{'Неофициальный или сторонний ресурс' if lang == 'ru' else 'Расмий эмес же башка ресурс'}</b>\n")
        lines.append(
            "• Домен не найден в белом списке официальных сервисов Кыргызстана.\n"
            "• Будьте бдительны: не переходите по неизвестным ссылкам и не оставляйте личные данные."
            if lang == "ru" else
            "• Домен Кыргызстандын расмий кызматтарынын ак тизмесинен табылган жок.\n"
            "• Сак болуңуз: бейтааныш шилтемелерге өтпөңүз жана жеке маалыматыңызды калтырбаңыз."
        )

    return "\n".join(lines), result


async def reply_with_check(message: Message, text: str, lang: str, prefix: str = "") -> None:
    """Анализирует текст SMS и отправляет отчёт пользователю."""
    result = check(text)
    key = uuid.uuid4().hex[:12]
    _pending[key] = (text, result["risk"])
    while len(_pending) > _MAX_PENDING:
        _pending.popitem(last=False)

    body = render(result, lang)
    if prefix:
        body = prefix + "\n\n" + body

    await message.answer(
        body,
        reply_markup=result_keyboard(key, lang, share_url(result, lang), action_type="sms"),
        parse_mode=ParseMode.HTML,
    )


async def reply_with_link_check(message: Message, target_url: str, lang: str) -> None:
    """Анализирует интернет-ссылку и отправляет подробный отчёт."""
    body, result = format_link_analysis(target_url, lang)
    key = uuid.uuid4().hex[:12]
    _pending[key] = (target_url, result["risk"])
    while len(_pending) > _MAX_PENDING:
        _pending.popitem(last=False)

    await message.answer(
        body,
        reply_markup=result_keyboard(key, lang, share_url(result, lang), action_type="link"),
        parse_mode=ParseMode.HTML,
    )


def _ocr_ready() -> bool:
    global _ocr_ok
    if _ocr_ok is None:
        _ocr_ok = ocr.available()
    return _ocr_ok


# --- Хэндлеры команд ---


@dp.message(CommandStart())
@dp.message(Command("menu"))
@dp.message(F.text.lower().in_([
    "/start", "start", "старт", "баштоо",
    "/menu", "menu", "меню",
    "главное меню", "башкы меню",
    "привет", "салам", "здравствуйте", "саламатсызбы",
]))
async def on_start(message: Message, state: FSMContext):
    await state.clear()
    lang = user_lang(message.from_user)
    await message.answer(
        t("menu_title", lang),
        reply_markup=main_menu_inline(lang),
        parse_mode=ParseMode.HTML,
    )


@dp.message(Command("help"))
async def on_help(message: Message):
    lang = user_lang(message.from_user)
    await message.answer(t("help", lang))


@dp.message(Command("lang"))
async def on_lang(message: Message):
    lang = user_lang(message.from_user)
    await message.answer(t("choose_lang", lang), reply_markup=lang_keyboard())


# --- Хэндлеры текстовых кнопок из главного меню ---


@dp.message(F.text.in_([
    "💬 Проверить подозрительное SMS",
    "💬 Шектүү SMSти текшерүү",
    "Проверить подозрительное SMS",
    "Шектүү SMSти текшерүү",
    "Проверить SMS",
    "SMS текшерүү",
    "смс",
    "sms",
]))
async def on_text_btn_sms(message: Message, state: FSMContext):
    lang = user_lang(message.from_user)
    await state.set_state(BotStates.waiting_for_sms)
    await message.answer(t("prompt_sms", lang), parse_mode=ParseMode.HTML)


@dp.message(F.text.in_([
    "🔗 Проверить ссылку",
    "🔗 Шилтемени текшерүү",
    "Проверить ссылку",
    "Шилтемени текшерүү",
    "ссылка",
    "шилтеме",
]))
async def on_text_btn_link(message: Message, state: FSMContext):
    lang = user_lang(message.from_user)
    await state.set_state(BotStates.waiting_for_link)
    await message.answer(t("prompt_link", lang), parse_mode=ParseMode.HTML)


@dp.message(F.text.in_([
    "⚠️ Я уже попался на уловку",
    "⚠️ Мен алданып калдым",
    "Я уже попался на уловку",
    "Мен алданып калдым",
    "sos",
    "сос",
    "помощь",
    "жардам",
]))
async def on_text_btn_sos(message: Message, state: FSMContext):
    await state.clear()
    lang = user_lang(message.from_user)
    await message.answer(t("feature_in_dev_sos", lang), parse_mode=ParseMode.HTML)


@dp.message(F.text.in_([
    "🌐 Тил / Язык",
    "🌐 Тилди алмаштыруу / Сменить язык",
]))
async def on_text_btn_lang(message: Message):
    lang = user_lang(message.from_user)
    await message.answer(t("choose_lang", lang), reply_markup=lang_keyboard())


@dp.message(F.text.in_([
    "ℹ️ Помощь / Жардам",
    "ℹ️ Помощь",
    "ℹ️ Жардам",
]))
async def on_text_btn_help(message: Message):
    lang = user_lang(message.from_user)
    await message.answer(t("help", lang))


# --- Инлайн-хэндлеры главного меню и SOS ---


@dp.callback_query(F.data.startswith("act:"))
async def on_action_chosen(call: CallbackQuery, state: FSMContext):
    action = call.data.split(":", 1)[1]
    lang = user_lang(call.from_user)

    if action == "sms":
        await state.set_state(BotStates.waiting_for_sms)
        if call.message:
            await call.message.answer(t("prompt_sms", lang), parse_mode=ParseMode.HTML)
        await call.answer()
    elif action == "link":
        await state.set_state(BotStates.waiting_for_link)
        if call.message:
            await call.message.answer(t("prompt_link", lang), parse_mode=ParseMode.HTML)
        await call.answer()
    elif action == "sos":
        await state.clear()
        if call.message:
            await call.message.answer(t("feature_in_dev_sos", lang), parse_mode=ParseMode.HTML)
        await call.answer()
    elif action == "main":
        await state.clear()
        if call.message:
            await call.message.answer(
                t("menu_title", lang),
                reply_markup=main_menu_inline(lang),
                parse_mode=ParseMode.HTML,
            )
        await call.answer()
    elif action == "help":
        if call.message:
            await call.message.answer(t("help", lang))
        await call.answer()


@dp.callback_query(F.data.startswith("sos:"))
async def on_sos_sub_chosen(call: CallbackQuery):
    action = call.data.split(":", 1)[1]
    lang = user_lang(call.from_user)

    if action == "banks":
        await call.message.answer(
            t("bank_contacts_text", lang),
            reply_markup=sos_sub_inline(lang),
            parse_mode=ParseMode.HTML,
        )
        await call.answer()
    elif action == "apk":
        await call.message.answer(
            t("apk_guide", lang),
            reply_markup=sos_sub_inline(lang),
            parse_mode=ParseMode.HTML,
        )
        await call.answer()


@dp.callback_query(F.data.startswith("lang:"))
async def on_lang_chosen(call: CallbackQuery):
    lang = call.data.split(":", 1)[1]
    if lang not in LANGS:
        await call.answer()
        return
    _user_lang[call.from_user.id] = lang
    await call.answer(t("lang_set", lang))
    if call.message:
        await call.message.answer(
            t("lang_set", lang),
            reply_markup=main_menu_reply(lang),
        )
        await call.message.answer(
            t("menu_title", lang),
            reply_markup=main_menu_inline(lang),
            parse_mode=ParseMode.HTML,
        )


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
        keep = [
            row for row in (call.message.reply_markup.inline_keyboard if call.message.reply_markup else [])
            if all(button.url for button in row)
        ]
        await call.message.edit_reply_markup(
            reply_markup=InlineKeyboardMarkup(inline_keyboard=keep) if keep else None
        )


# --- Хэндлеры для скриншотов и изображений ---


@dp.message(F.photo | F.document.mime_type.startswith("image/"))
async def on_image(message: Message, state: FSMContext):
    await state.clear()
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
    prefix = f"{t('ocr_text', lang)}\n«{html.escape(shown)}»"
    if find_urls(text):
        prefix += "\n\n" + t("ocr_note", lang)
    await reply_with_check(message, text, lang, prefix)


# --- Хэндлер текстовых сообщений ---


@dp.message(F.text)
async def on_text(message: Message, state: FSMContext):
    lang = user_lang(message.from_user)
    raw = (message.text or "").strip()
    current_state = await state.get_state()

    # Если пользователь в режиме ожидания ссылки
    if current_state == BotStates.waiting_for_link:
        await state.clear()
        found_urls = find_urls(raw)
        target = found_urls[0] if found_urls else raw
        if not found_urls and "." not in raw:
            await message.answer(t("link_no_url", lang), parse_mode=ParseMode.HTML)
            return
        await reply_with_link_check(message, target, lang)
        return

    # Если пользователь в режиме ожидания SMS
    if current_state == BotStates.waiting_for_sms:
        await state.clear()
        await reply_with_check(message, raw, lang)
        return

    # Обычный ввод без предварительного нажатия кнопок:
    # Если введено только одно слово/URL (например: https://mbank.kg или mbank.kg)
    tokens = raw.split()
    if len(tokens) == 1 and (raw.startswith(("http://", "https://")) or ("." in raw and len(raw) < 100)):
        found = find_urls(raw)
        target = found[0] if found else raw
        await reply_with_link_check(message, target, lang)
        return

    # Иначе оцениваем как SMS
    await reply_with_check(message, raw, lang)


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
