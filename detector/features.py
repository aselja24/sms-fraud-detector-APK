"""Извлечение признаков из текста SMS для модели логистической регрессии."""
from detector.entities import find_phones, find_urls, is_fake_brand, is_foreign_phone
from detector.lexicon import CODE_REQUEST_VERBS, PATTERNS
from detector.normalize import normalize

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


def _lexicon_hit(normalized_text: str, feature: str) -> int:
    return int(any(root in normalized_text for root in PATTERNS[feature]))


def extract(text: str) -> dict[str, int]:
    """Возвращает словарь признак -> 0/1 в порядке FEATURE_NAMES.

    Ссылки и телефоны извлекаются из СЫРОГО текста (до нормализации), а
    текстовые признаки — из нормализованного (без обфускации) текста.
    """
    urls = find_urls(text)
    phones = find_phones(text)
    normalized = normalize(text)

    features = {
        "has_link": int(bool(urls)),
        "fake_brand_domain": int(any(is_fake_brand(u) for u in urls)),
        "has_phone": int(bool(phones)),
        "foreign_phone": int(any(is_foreign_phone(p) for p in phones)),
    }
    for name in _LEXICON_FEATURES:
        features[name] = _lexicon_hit(normalized, name)
    # «код» сам по себе есть и в легитимных SMS — нужна ещё просьба его передать.
    asks_verb = any(verb in normalized for verb in CODE_REQUEST_VERBS)
    features["asks_code"] = int(features["asks_code"] and asks_verb)

    return {name: features[name] for name in FEATURE_NAMES}
