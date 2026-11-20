"""Извлечение признаков из текста SMS для модели логистической регрессии."""
import re

from detector.entities import find_phones, is_foreign_phone
from detector.lexicon import CHECK_REQUEST, CODE_REQUEST_VERBS, NO_TRANSLIT, PATTERNS
from detector.links import analyze_links
from detector.normalize import normalize
from detector.translit import expand_roots

# Фиксированный порядок признаков — важен для model.py (веса обучены в этом порядке).
FEATURE_NAMES = [
    # обязательные по ТЗ
    "has_link",
    "asks_code",
    "urgency",
    "block_threat",
    "prize",
    "bank_operator",
    "money_transfer",
    "call_back",
    # дополнительные
    "fake_brand_domain",
    "has_phone",
    "foreign_phone",
    "link_action",
    "safety_warning",
    "action_request",
]

# Признаки из PATTERNS — ищутся подстрокой в нормализованном тексте.
_LEXICON_FEATURES = [
    "asks_code",
    "urgency",
    "block_threat",
    "prize",
    "bank_operator",
    "money_transfer",
    "call_back",
    "link_action",
    "safety_warning",
]


# Корни в том же написании, что и нормализованный текст, плюс латинские
# варианты: один кириллический корень ловит RU/KG, KG без раскладки и транслит.
_ROOTS = {name: expand_roots(PATTERNS[name], NO_TRANSLIT) for name in _LEXICON_FEATURES}
_CODE_VERBS = expand_roots(CODE_REQUEST_VERBS, NO_TRANSLIT)
_CHECK_ROOTS = expand_roots(CHECK_REQUEST, NO_TRANSLIT)


# Короткий срок в цифрах — давление срочностью: «через 30 минут», «за 5 минут»,
# «в течение 2 часов», «10 мүнөт ичинде», «20 мүнөттөн кийин».
_DEADLINE_RE = re.compile(
    r"(?:через|в течение|за) \d+ (?:мин|час)"
    r"|\d+ (?:мунот|саат)\w* (?:ичинде|кийин)"
    r"|\d+ (?:minut|munot|saat)\w* (?:ichinde|kiyin|kiin)"
)


# Разговорный императив отдельным словом: «жибер», «айт», «отправь».
# Подстрокой их искать нельзя: «жибер» есть в «код жиберилди» («код
# отправлен» — обычное SMS с кодом).
_INFORMAL_VERB_RE = re.compile(
    r"(?<!\w)(?:жибер|жонот|айт|скажи|отправь|пришли|назови|скинь|jiber|aity?)(?!\w)"
)


def _lexicon_hit(normalized_text: str, feature: str) -> int:
    return int(any(root in normalized_text for root in _ROOTS[feature]))


def extract(text: str) -> dict[str, int]:
    """Возвращает словарь признак -> 0/1 в порядке FEATURE_NAMES.

    Ссылки и телефоны извлекаются из СЫРОГО текста (до нормализации), а
    текстовые признаки — из нормализованного (без обфускации) текста.
    """
    links = analyze_links(text)
    phones = find_phones(text)
    normalized = normalize(text)

    features = {
        "has_link": int(bool(links)),
        # подделка (подмена символов) или имитация бренда — см. links.py
        "fake_brand_domain": int(any(link.fake for link in links)),
        "has_phone": int(bool(phones)),
        "foreign_phone": int(any(is_foreign_phone(p) for p in phones)),
    }
    for name in _LEXICON_FEATURES:
        features[name] = _lexicon_hit(normalized, name)
    if _DEADLINE_RE.search(normalized):
        features["urgency"] = 1
    # «код» сам по себе есть и в легитимных SMS — нужна ещё просьба его передать.
    asks_verb = (
        any(verb in normalized for verb in _CODE_VERBS)
        or bool(_INFORMAL_VERB_RE.search(normalized))
    )
    features["asks_code"] = int(features["asks_code"] and asks_verb)
    # Общий признак «SMS просит что-то сделать»: передать код/данные,
    # перевести/оплатить, позвонить или перейти по ссылке. Почти у любого
    # мошенничества есть такая просьба, у обычных уведомлений — редко.
    # Отдельный признак нужен, чтобы модель училась на него целиком, а не
    # делила вес между четырьмя частными просьбами.
    # «Проверьте/текшериңиз» — тоже просьба, но без перехода по ссылке
    # (поэтому не в link_action: иначе она считалась бы дважды).
    asks_check = any(root in normalized for root in _CHECK_ROOTS)
    features["action_request"] = int(
        features["asks_code"] or features["money_transfer"]
        or features["call_back"] or features["link_action"] or asks_check
    )

    return {name: features[name] for name in FEATURE_NAMES}
