"""Константы и настройки детектора."""
import os

# Официальные домены (ТЗ, data/CLARIFICATIONS_RU.md). Поддомены (my.beeline.kg)
# тоже считаются официальными, похожие суффиксы (mbank.kg-verify) — нет.
WHITELIST = [
    "beeline.kg",
    "balance.kg",
    "nbkr.kg",
    "mbank.kg",
    # Настоящие домены банков, операторов и госсервисов КР. В учебных
    # данных их нет (там чужие ссылки только .example), но в реальных SMS
    # они встречаются, и без этого списка «megacom.kg» считался бы
    # подделкой бренда megacom.
    "megacom.kg",
    "o.kg",
    "optima24.kg",
    "optimabank.kg",
    "bakai.kg",
    "demirbank.kg",
    "kicb.kg",
    "rsk.kg",
    "ab.kg",
    "keremetbank.kg",
    "elcart.kg",
    "odengi.kg",
    "tunduk.kg",
    "salyk.kg",
    # Крупные международные сервисы, под которые часто маскируются ссылки
    # (бренды — в GLOBAL_BRANDS ниже; без этого их настоящие сайты считались
    # бы подделкой).
    "telegram.org",
    "whatsapp.com",
    "instagram.com",
    "google.com",
    "binance.com",
]

# Международные бренды: под них подделывают адреса так же, как под местные банки.
GLOBAL_BRANDS = ["telegram", "whatsapp", "instagram", "google", "binance"]

# Названия брендов (банки, операторы), которыми маскируются фишинговые домены.
_LOCAL_BRANDS = [
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
    "odengi",
    "elkart",
    "elcart",
    "keremet",
    "ayil",
    "tunduk",
    "salyk",
    "kyrgyzpost",
]
BRANDS = _LOCAL_BRANDS + GLOBAL_BRANDS

# Настоящий сайт бренда — для подсказки «Официальный сайт: ...» в совете.
# Только домены, в которых уверены (список ТЗ и настоящие домены из учебных
# SMS); для остальных брендов подсказки нет, чтобы не назвать чужой адрес.
BRAND_OFFICIAL = {
    "mbank": "mbank.kg",
    "beeline": "beeline.kg",
    "balance": "balance.kg",
    "nbkr": "nbkr.kg",
    "megacom": "megacom.kg",
    "optima": "optima24.kg",
    "bakai": "bakai.kg",
    "demir": "demirbank.kg",
    "tunduk": "tunduk.kg",
    "keremet": "keremetbank.kg",
    "telegram": "telegram.org",
    "whatsapp": "whatsapp.com",
    "instagram": "instagram.com",
    "google": "google.com",
    "binance": "binance.com",
}

# Слова в домене, типичные для фишинговых ссылок (включая известные сокращатели ссылок).
SUSPICIOUS_DOMAIN_WORDS = [
    "secure",
    "verify",
    "login",
    "bonus",
    "gift",
    "prize",
    "check",
    "confirm",
    "support",
    "help",
    "update",
    "unlock",
    "recover",
    "online",
    "cashback",
    "bit-ly",
    "bitly",
    "bit.ly",
    "tinyurl",
    "goo-gl",
    "goo.gl",
    "cutt.ly",
    "clck.ru",
    "is.gd",
    # Имитация национальной зоны .kg в чужом домене: "balance-kg.example",
    # "mbank.kg-verify.example", "my-beeline.kg.example". Официальные
    # *.kg-домены сюда не доходят — их раньше пропускает белый список.
    "-kg",
    "kg-",
    ".kg.",
]

# Доменные зоны, которые почти не используют банки и операторы, но любят
# фишинговые сайты (дёшево и без проверки владельца). Ссылка в такой зоне
# считается подозрительной даже без бренда в имени.
SUSPICIOUS_TLDS = ["xyz", "top", "info", "site", "pw", "click", "icu", "buzz", "live"]

# Границы уровней риска (0-100).
LOW = 30
HIGH = 65

# Нижняя граница score, когда сработало жёсткое правило "high" (rules.py).
# Выше HIGH, чтобы ответ не выглядел «на грани».
RULE_HIGH_SCORE = 80

# Путь к обученным весам модели.
WEIGHTS_PATH = os.path.join(os.path.dirname(__file__), "..", "weights.json")
