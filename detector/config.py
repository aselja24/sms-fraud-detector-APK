"""Константы и настройки детектора."""
import os

# Официальные домены (ТЗ, data/CLARIFICATIONS_RU.md). Поддомены (my.beeline.kg)
# считаются доверенными, похожие по написанию домены (mbank.kg-verify.example) — нет.
WHITELIST = [
    "beeline.kg",
    "balance.kg",
    "nbkr.kg",
    "mbank.kg",
]

# Названия брендов (банки, операторы), которыми маскируются фишинговые домены.
BRANDS = [
    "beeline",
    "megacom",
    "mbank",
    "kicb",
    "optima",
    "nbkr",
    "balance",
    "bakai",
    "demir",
    "rsk",
]

# Слова в домене, типичные для фишинговых ссылок (включая известные сокращатели ссылок).
SUSPICIOUS_DOMAIN_WORDS = [
    "secure",
    "verify",
    "login",
    "bonus",
    "gift",
    "prize",
    "check",
    "online",
    "bit-ly",
    "bitly",
    "tinyurl",
    "goo-gl",
]

# Границы уровней риска (0-100).
LOW = 30
HIGH = 65

# Путь к обученным весам модели.
WEIGHTS_PATH = os.path.join(os.path.dirname(__file__), "..", "weights.json")
