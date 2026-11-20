import re
from urllib.parse import urlparse

from detector.config import WHITELIST, BRANDS, SUSPICIOUS_DOMAIN_WORDS

URL_RE = re.compile(r"https?://\S+", re.IGNORECASE)
# Телефон: + и/или цифры; между группами цифр допускаются пробелы, дефисы
# и скобки ("0555-12-34-56", "+996 (555) 123456"). Точки нет — это даты.
PHONE_RE = re.compile(r"(?<!\d)\+?\d[\d\s\-()]{6,}\d(?!\d)")


def find_urls(text: str) -> list[str]:
    """Находит все ссылки в тексте (без хвостовой пунктуации типа запятой)."""
    return [url.rstrip(",.!?:;)") for url in URL_RE.findall(text)]


def find_phones(text: str) -> list[str]:
    """Находит номера телефонов (по ТЗ — не короче 9 цифр без учёта пробелов)."""
    found = []
    for match in PHONE_RE.findall(text):
        digits = re.sub(r"\D", "", match)
        if len(digits) >= 9:
            found.append(match.strip())
    return found


def is_whitelisted(url: str) -> bool:
    """Проверка официального домена по hostname (а не подстрокой!).

    "mbank.kg-verify.example" содержит подстроку "mbank.kg", но его hostname
    не равен "mbank.kg" и не заканчивается на ".mbank.kg" — поэтому белый
    список не проходит.
    """
    host = urlparse(url).hostname or ""
    host = host.lower()
    for domain in WHITELIST:
        if host == domain or host.endswith("." + domain):
            return True
    return False


def is_fake_brand(url: str) -> bool:
    """Домен не из белого списка, но маскируется под бренд или похож на фишинг."""
    if is_whitelisted(url):
        return False
    host = (urlparse(url).hostname or "").lower()
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
