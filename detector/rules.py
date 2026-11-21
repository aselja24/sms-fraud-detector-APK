"""Жёсткие правила поверх модели: поднимают нижнюю границу score (80 или 30)."""
import re

from detector.config import LOW, RULE_HIGH_SCORE
from detector.links import brand_mismatch
from detector.normalize import normalize
from detector.translit import expand_roots

# Поводы, при которых просьба о деньгах — мошенничество.
_MONEY_PRETEXTS = ("block_threat", "prize", "urgency")
# Любое давление или просьба рядом со ссылкой-имитацией бренда.
_LINK_CUES = ("action_request", "block_threat", "urgency", "prize")

# Сильные корни выигрыша. «Бонус» сюда не входит: официальные SMS о бонусах
# обычны. «Утуш» тоже не берём: им предупреждают («утуш үчүн акча которбоңуз»).
_STRONG_PRIZE_ROOTS = [
    "выиграл", "выигрыш", "победител", "розыгрыш", "приз", "белек", "байге",
    "сыйлык", "утуп ал", "уттуң", "куттукт",
    # транслит, которого нет в кириллице
    "yutdy",
]

# Повод «заплатите, чтобы получить/разблокировать» или «на другую карту».
_FEE_PRETEXT_ROOTS = [
    "для активац", "для подтвержден", "для получени", "для разблокир",
    "для доставк", "повторную доставку", "за доставку",
    "жеткирүү үчүн", "алуу үчүн", "ачуу үчүн",
    "башка эсеп", "башка карта", "частную карту", "другую карту", "другой счет",
]

# Сумма денег или объём «подарка» в тексте: «150 000 сом», «12000 som», «100 ГБ», «под 0%».
_AMOUNT_RE = re.compile(r"\d[\d\s.,]*\s?(?:сом|som|гб|gb|%)", re.IGNORECASE)

# «Лёгкий заработок» — только вместе со ссылкой на мессенджер или чужой сайт.
_EARN_ROOTS = [
    "заработ", "доход от", "в день", "удаленн", "без опыта", "требуются",
    "тайные покупател", "оценк товар", "онлайн жумуш", "үйдөн", "күнүнө",
    "тажрыйбасыз", "жумуш",
]
_MESSENGER_HOSTS = ("wa.me", "t.me", "api.whatsapp.com", "telegram.me")

# Корни в едином написании и с автоматическим транслитом.
_STRONG_PRIZE = expand_roots(_STRONG_PRIZE_ROOTS)
_EARN = expand_roots(_EARN_ROOTS)
_FEE_PRETEXT = expand_roots(_FEE_PRETEXT_ROOTS)
# «призыв» содержит «приз», но выигрышем не является.
_NOT_PRIZE_RE = re.compile(r"призыв\w*|prizyv\w*|priziv\w*")


def _has_root(normalized: str, roots: list[str]) -> bool:
    return any(root in normalized for root in roots)

# Нижняя граница score для каждого правила.
RULE_FLOOR = {
    "link_spoof": RULE_HIGH_SCORE,
    "secret_request": RULE_HIGH_SCORE,
    "money_with_pretext": RULE_HIGH_SCORE,
    "prize_with_link": RULE_HIGH_SCORE,
    "brand_link_with_cue": RULE_HIGH_SCORE,
    "easy_money": RULE_HIGH_SCORE,
    "brand_link": LOW,
    "unofficial_click": LOW,
    "brand_mismatch": LOW,
}

# Причина в ответе для правил со своим текстом ({brand} и {host} подставляет check()).
RULE_REASONS = {
    "secret_request": "просят передать код, пароль или данные карты — банки так никогда не делают",
    "money_with_pretext": "просят перевести или оплатить деньги под предлогом угрозы, выигрыша или срочности",
    "prize_with_link": "обещают выигрыш и присылают ссылку — призы по ссылке из SMS не выдают",
    "brand_link_with_cue": "ссылка ведёт на неофициальный адрес под видом известного бренда, и SMS при этом торопит, угрожает или просит действий",
    "brand_mismatch": "в SMS назван бренд {brand}, а ссылка ведёт на другой адрес: {host}",
    "easy_money": "обещают лёгкий заработок и зовут писать в мессенджер или на неофициальный сайт — так вербуют в мошеннические схемы",
}

RULE_ADVICE = {
    "secret_request": "Не отправляйте и не диктуйте коды, пароли и данные карты никому — это всегда мошенники.",
    "money_with_pretext": "Не переводите и не оплачивайте ничего по SMS — проверьте информацию в официальном приложении банка или у оператора.",
    "prize_with_link": "Не переходите по ссылке из SMS о выигрыше и не платите «за доставку» или «комиссию» — это мошенничество.",
    "brand_link_with_cue": "Не открывайте ссылку: адрес только похож на официальный. Зайдите на сайт вручную или через приложение.",
    "brand_mismatch": "Проверьте, от кого SMS: зайдите на сайт названной компании вручную, а не по ссылке из сообщения.",
    "easy_money": "Не отвечайте на «вакансии» с заработком за несколько часов: за ними стоят предоплата, кража данных карты или вовлечение в схемы с переводами.",
}


def _strong_prize(text: str) -> bool:
    return bool(text) and _has_root(_NOT_PRIZE_RE.sub(" ", normalize(text)), _STRONG_PRIZE)


def all_rules(features: dict[str, int], links=(), text: str = "") -> list[str]:
    """Все сработавшие правила по важности (links — analyze_links(), text — SMS)."""
    names = []
    normalized = normalize(text) if text else ""
    if any(link.spoof for link in links):
        names.append("link_spoof")
    if features.get("asks_code"):
        names.append("secret_request")
    if features.get("money_transfer") and (
        any(features.get(p) for p in _MONEY_PRETEXTS)
        or (text and _has_root(normalized, _FEE_PRETEXT))
    ):
        names.append("money_with_pretext")
    if links and _strong_prize(text):
        names.append("prize_with_link")
    # Давление, просьба, сумма денег или просьба о деньгах рядом со ссылкой.
    cue = (any(features.get(c) for c in _LINK_CUES) or features.get("money_transfer")
           or bool(text and _AMOUNT_RE.search(text)))
    mismatch = brand_mismatch(text, links) if text else None
    if features.get("fake_brand_domain"):
        names.append("brand_link_with_cue" if cue else "brand_link")
    elif features.get("link_action") and any(not link.official for link in links):
        names.append("unofficial_click")
    if mismatch:
        if cue and "brand_link_with_cue" not in names:
            names.append("brand_link_with_cue")
        names.append("brand_mismatch")
    unofficial = [link for link in links if not link.official]
    if unofficial and _has_root(normalized, _EARN) and (
        any(link.host.lower().startswith(_MESSENGER_HOSTS) for link in unofficial) or cue
    ):
        names.append("easy_money")
    return names


def hard_rule(features: dict[str, int], links=()) -> str | None:
    """Самое важное из сработавших правил или None (для совместимости)."""
    names = all_rules(features, links)
    return names[0] if names else None
