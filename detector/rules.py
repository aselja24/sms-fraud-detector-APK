"""
Жёсткие правила поверх логистической регрессии.

Зачем: в train почти у всех мошеннических SMS есть номер телефона или
ссылка с явным брендом, поэтому модель ставит "high" только при 3+
признаках. Мошенничество вида «повод + просьба» без телефона («Для отмены
перевода назовите код из SMS») и ссылки-подделки, где улика — сам адрес
(«mbаnk.kg» с кириллической «а»), она оценивает слишком низко: таких
примеров в train просто нет.

Правила не меняют обученные веса, а только поднимают нижнюю границу score.
Официальность ссылки на них не влияет: правила смотрят на текст SMS и на
то, как устроен адрес, но не снижают риск за то, что домен из белого списка.

  "high" (score не ниже RULE_HIGH_SCORE):
    link_spoof          — в адресе ссылки подменены символы или спрятаны (links.py);
    secret_request      — просят код/пароль/CVV/данные карты;
    money_with_pretext  — просят деньги + угроза, выигрыш, срочность или
                          «заплатите, чтобы получить/разблокировать», «на другую карту»;
    prize_with_link     — «вы выиграли» (сильные корни) + любая ссылка;
    brand_link_with_cue — ссылка под видом бренда + любое давление/просьба.
  "medium" (score не ниже LOW):
    brand_link          — ссылка под видом бренда, но без другого давления;
    unofficial_click    — неофициальная ссылка + «откройте/нажмите/перейдите»;
    brand_mismatch      — в SMS назван бренд, а ссылка ведёт на другой адрес.
Так же устроен белый список доменов: экспертное знание, которое из 200
обучающих SMS не выучить.
"""
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

# Повод «заплатите, чтобы получить/разблокировать/доставить» или «переведите
# на другой счёт/карту». С просьбой о деньгах это классическая схема.
# (Текст после normalize: кыргызские ө/ү/ң уже сведены к о/у/н.)
_FEE_PRETEXT_ROOTS = [
    "для активац", "для подтвержден", "для получени", "для разблокир",
    "для доставк", "повторную доставку", "за доставку",
    "жеткирүү үчүн", "алуу үчүн", "ачуу үчүн",
    "башка эсеп", "башка карта", "частную карту", "другую карту", "другой счет",
]

# Корни сравниваются так же, как в словаре (features.py): в едином написании
# (ө/ү/ң -> о/у/н) и с автоматическим транслитом — «выиграл» ловит и
# «vyigral», «приз» — «priz». Раньше здесь были регулярки только на
# кириллице, и «Privet, ty vyigral priz» проходило мимо правила.
_STRONG_PRIZE = expand_roots(_STRONG_PRIZE_ROOTS)
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
    "brand_link": LOW,
    "unofficial_click": LOW,
    "brand_mismatch": LOW,
}

# Текст в ответе — у правил, которые добавляют свою причину. Признаки уже
# дают причины сами, поэтому у brand_link и unofficial_click текста нет.
# {brand} и {host} подставляет check().
RULE_REASONS = {
    "secret_request": "просят передать код, пароль или данные карты — банки так никогда не делают",
    "money_with_pretext": "просят перевести или оплатить деньги под предлогом угрозы, выигрыша или срочности",
    "prize_with_link": "обещают выигрыш и присылают ссылку — призы по ссылке из SMS не выдают",
    "brand_link_with_cue": "ссылка ведёт на неофициальный адрес под видом известного бренда, и SMS при этом торопит, угрожает или просит действий",
    "brand_mismatch": "в SMS назван бренд {brand}, а ссылка ведёт на другой адрес: {host}",
}

RULE_ADVICE = {
    "secret_request": "Не отправляйте и не диктуйте коды, пароли и данные карты никому — это всегда мошенники.",
    "money_with_pretext": "Не переводите и не оплачивайте ничего по SMS — проверьте информацию в официальном приложении банка или у оператора.",
    "prize_with_link": "Не переходите по ссылке из SMS о выигрыше и не платите «за доставку» или «комиссию» — это мошенничество.",
    "brand_link_with_cue": "Не открывайте ссылку: адрес только похож на официальный. Зайдите на сайт вручную или через приложение.",
    "brand_mismatch": "Проверьте, от кого SMS: зайдите на сайт названной компании вручную, а не по ссылке из сообщения.",
}


def _strong_prize(text: str) -> bool:
    return bool(text) and _has_root(_NOT_PRIZE_RE.sub(" ", normalize(text)), _STRONG_PRIZE)


def all_rules(features: dict[str, int], links=(), text: str = "") -> list[str]:
    """Все сработавшие правила в порядке важности (первое — самое весомое).

    links — результат links.analyze_links(); text — исходный текст SMS.
    Без них правила, которые смотрят на ссылки или текст, не проверяются.
    """
    names = []
    if any(link.spoof for link in links):
        names.append("link_spoof")
    if features.get("asks_code"):
        names.append("secret_request")
    if features.get("money_transfer") and (
        any(features.get(p) for p in _MONEY_PRETEXTS)
        or (text and _has_root(normalize(text), _FEE_PRETEXT))
    ):
        names.append("money_with_pretext")
    if links and _strong_prize(text):
        names.append("prize_with_link")
    if features.get("fake_brand_domain"):
        if any(features.get(c) for c in _LINK_CUES):
            names.append("brand_link_with_cue")
        else:
            names.append("brand_link")
    elif features.get("link_action") and any(not link.official for link in links):
        names.append("unofficial_click")
    if text and brand_mismatch(text, links):
        names.append("brand_mismatch")
    return names


def hard_rule(features: dict[str, int], links=()) -> str | None:
    """Самое важное из сработавших правил или None (для совместимости)."""
    names = all_rules(features, links)
    return names[0] if names else None
