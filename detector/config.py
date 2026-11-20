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
    "odengi",
    "elkart",
    "elcart",
    "keremet",
    "ayil",
    "tunduk",
    "salyk",
    "kyrgyzpost",
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

# Путь к обученным весам модели.
WEIGHTS_PATH = os.path.join(os.path.dirname(__file__), "..", "weights.json")
