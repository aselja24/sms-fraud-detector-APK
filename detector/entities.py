import re
from urllib.parse import urlparse

from detector.config import BRANDS, SUSPICIOUS_DOMAIN_WORDS, SUSPICIOUS_TLDS, WHITELIST
from detector.homoglyphs import INVISIBLE_RE, tld_key

# Известные доменные зоны. Адрес без протокола считаем ссылкой, только если
# его зона есть в этом списке: так не ловим даты ("09.12.2026"), суммы и
# обычные слова с точкой.
_TLDS = (
    "kg|ru|kz|uz|su|com|net|org|info|biz|xyz|top|site|online|click|link|"
    "live|shop|store|cfd|pro|vip|work|club|fun|cyou|rest|icu|pw|buzz|tk|ml|"
    "ga|cf|gq|app|io|me|cc|co|ly|gl|gd|to|example"
)
KNOWN_TLDS = set(_TLDS.split("|"))

# Ссылка: с протоколом ("https://...", "hxxps://...") или без него
# ("mbank-kg.com/verify", "www.optima-login.net", "bit.ly/3xYz").
# В названии домена допускаются любые буквы, в том числе кириллица: на
# подмене символов ("mbаnk.kg" с кириллической «а») держится целая схема.
# Зона проверяется отдельно (_is_known_tld), потому что она тоже может быть
# написана кириллицей ("mbank.кг").
_URL_RE = re.compile(
    r"(?:https?|hxxps?)://\S+"
    r"|(?<![\w@.\-])(?:www\.)?(?:[^\W_](?:[\w\-]*[^\W_])?\.)+[^\W\d_]{2,10}(?![\w\-])(?:/\S*)?",
    re.IGNORECASE,
)

# Обход фильтров: «mbank[.]kg», «mbank(.)kg», «mbank{.}kg» — точка спрятана.
DEFANG_RE = re.compile(r"\s*(?:\[\.\]|\(\.\)|\{\.\})\s*")

# Телефон: + и/или цифры; между группами цифр допускаются пробелы, дефисы
# и скобки ("0555-12-34-56", "+996 (555) 123456"). Точки нет — это даты.
PHONE_RE = re.compile(r"(?<!\d)\+?\d[\d\s\-()]{6,}\d(?!\d)")


def clean_link_text(text: str) -> str:
    """Текст, в котором спрятанное снято: без невидимых символов, «[.]» -> «.»."""
    text = INVISIBLE_RE.sub("", text)
    return DEFANG_RE.sub(".", text)


def _is_known_tld(url: str) -> bool:
    host = url.split("://", 1)[-1].split("/", 1)[0]
    tld = host.rsplit(".", 1)[-1]
    return tld_key(tld) in KNOWN_TLDS


def find_urls(text: str) -> list[str]:
    """Находит все ссылки в тексте (без хвостовой пунктуации типа запятой).

    Поиск идёт по тексту, очищенному от невидимых символов и «[.]»: иначе
    «mb<нулевой пробел>ank.kg» нашлось бы как «ank.kg».
    """
    found = []
    for match in _URL_RE.finditer(clean_link_text(text)):
        url = match.group(0)
        if "://" in url or _is_known_tld(url):
            found.append(url.rstrip(",.!?:;)"))
    return found


def find_phones(text: str) -> list[str]:
    """Находит номера телефонов (по ТЗ — не короче 9 цифр без учёта пробелов)."""
    found = []
    for match in PHONE_RE.findall(text):
        digits = re.sub(r"\D", "", match)
        if len(digits) >= 9:
            found.append(match.strip())
    return found


def _hostname(url: str) -> str:
    """hostname ссылки; для адреса без протокола добавляем "http://"."""
    if "://" not in url:
        url = "http://" + url
    return (urlparse(url).hostname or "").lower()


def is_whitelisted(url: str) -> bool:
    """Проверка официального домена по hostname (а не подстрокой!).

    "mbank.kg-verify.example" содержит подстроку "mbank.kg", но его hostname
    не равен "mbank.kg" и не заканчивается на ".mbank.kg" — поэтому белый
    список не проходит.
    """
    host = _hostname(url)
    for domain in WHITELIST:
        if host == domain or host.endswith("." + domain):
            return True
    return False


def is_fake_brand(url: str) -> bool:
    """Домен не из белого списка, но маскируется под бренд, похож на фишинг
    или находится в подозрительной зоне (.xyz, .top, .info...)."""
    if is_whitelisted(url):
        return False
    host = _hostname(url)
    if host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
        return True
    for word in BRANDS + SUSPICIOUS_DOMAIN_WORDS:
        if word in host:
            return True
    return False


def is_foreign_phone(phone: str) -> bool:
    """Иностранный номер: явный код страны (+), отличный от +996."""
    digits_only = re.sub(r"[^\d+]", "", phone)
    if digits_only.startswith("+"):
        return not digits_only.startswith("+996")
    return False
