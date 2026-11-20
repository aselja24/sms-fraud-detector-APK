"""
Модуль безопасных ссылок (Safe Links / сетевой шлюз перехвата SakBol).

Реализует концепцию защиты на уровне оператора связи:
1. Опасные и подозрительные ссылки в SMS не доставляются как есть.
2. Сеть заменяет их на защищенный URL вида: {base_url}/x/{token}.
3. При переходе абонент видит официальную страницу-стоп с предупреждением
   и блокировкой перехода на фишинговый сайт.
4. Ссылки из официального белого списка (beeline.kg, mbank.kg и др.) НЕ подменяются.
"""
import hashlib
import time
from urllib.parse import urlparse

from detector.check import check
from detector.config import BRANDS, WHITELIST
from detector.entities import find_urls, is_fake_brand, is_whitelisted

# Официальные домены брендов для предложения безопасного перехода
BRAND_OFFICIAL_DOMAINS = {
    "beeline": "beeline.kg",
    "balance": "balance.kg",
    "mbank": "mbank.kg",
    "nbkr": "nbkr.kg",
    "megacom": "megacom.kg",
    "kicb": "kicb.net",
    "optima": "optimabank.kg",
    "bakai": "bakai.kg",
    "demir": "demirbank.kg",
    "rsk": "rskbank.kg",
}

BRAND_DISPLAY_NAMES = {
    "beeline": "Beeline",
    "balance": "Balance.kg",
    "mbank": "MBANK",
    "nbkr": "Национальный банк КР (НБКР)",
    "megacom": "MegaCom (MEGA)",
    "kicb": "KICB",
    "optima": "Оптима Банк",
    "bakai": "Бакай Банк",
    "demir": "Демир Банк",
    "rsk": "РСК Банк (Элдик Банк)",
}


class SafeLinksRegistry:
    """Реестр перехваченных опасных ссылок (in-memory с поддержкой выгрузки)."""

    def __init__(self):
        self._storage: dict[str, dict] = {}

    def register(
        self,
        original_url: str,
        risk: str,
        reason: str,
        brand_key: str | None = None,
        sms_text: str = "",
    ) -> str:
        """Регистрирует опасную ссылку и возвращает короткий токен (хэш)."""
        raw_token = hashlib.sha256(f"{original_url}_{time.time()}".encode()).hexdigest()[:6]
        token = raw_token

        host = (urlparse(original_url).hostname or "").lower()
        brand_name = BRAND_DISPLAY_NAMES.get(brand_key, "") if brand_key else ""
        official_domain = BRAND_OFFICIAL_DOMAINS.get(brand_key, "") if brand_key else ""

        self._storage[token] = {
            "token": token,
            "original_url": original_url,
            "host": host,
            "risk": risk,
            "reason": reason,
            "brand_key": brand_key,
            "brand_name": brand_name,
            "official_domain": official_domain,
            "official_url": f"https://{official_domain}" if official_domain else None,
            "sms_text": sms_text,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "clicks_count": 0,
        }
        return token

    def get(self, token: str) -> dict | None:
        """Возвращает данные о ссылке и увеличивает счётчик переходов."""
        item = self._storage.get(token)
        if item:
            item["clicks_count"] += 1
        return item

    def all_records(self) -> list[dict]:
        return list(self._storage.values())

    def clear(self):
        self._storage.clear()


# Глобальный реестр ссылок шлюза
registry = SafeLinksRegistry()


def _detect_brand(url: str, text: str) -> str | None:
    """Определяет, под какой бренд маскируется фишинг."""
    url_lower = url.lower()
    text_lower = text.lower()
    for brand in BRANDS:
        if brand in url_lower or brand in text_lower:
            return brand
    return None


def sanitize_sms(
    text: str,
    base_url: str = "http://localhost:8000",
    link_registry: SafeLinksRegistry | None = None,
) -> dict:
    """Анализирует SMS и заменяет опасные ссылки на ссылки безопасного шлюза SakBol.

    Правила:
    - Официальные ссылки (из белого списка) остаются без изменений.
    - Фишинговые ссылки и ссылки при высоком/среднем риске подменяются на:
      {base_url}/x/{token}
    - При клике абонент попадает на экран-стоп с разъяснением угрозы.
    """
    reg = link_registry if link_registry is not None else registry
    analysis = check(text)
    risk = analysis["risk"]
    urls = find_urls(text)

    safe_text = text
    replaced_urls = []

    for url in urls:
        # Официальный домен — оставляем нетронутым
        if is_whitelisted(url):
            continue

        fake_brand = is_fake_brand(url)
        # Подменяем, если есть риск или домен маскируется под бренд
        if risk in ("high", "medium") or fake_brand:
            brand_key = _detect_brand(url, text)
            if brand_key:
                brand_display = BRAND_DISPLAY_NAMES.get(brand_key, brand_key)
                reason = f"Ссылка ведёт на поддельный ресурс, маскирующийся под {brand_display}"
            else:
                reason = "Ссылка ведёт на подозрительный неофициальный сайт"

            token = reg.register(
                original_url=url,
                risk=risk,
                reason=reason,
                brand_key=brand_key,
                sms_text=text,
            )
            safe_url = f"{base_url}/x/{token}"
            safe_text = safe_text.replace(url, safe_url)

            replaced_urls.append({
                "original_url": url,
                "safe_url": safe_url,
                "token": token,
                "brand": BRAND_DISPLAY_NAMES.get(brand_key, "Неизвестный бренд"),
                "risk": risk,
                "reason": reason,
            })

    return {
        "original_text": text,
        "safe_text": safe_text,
        "is_modified": safe_text != text,
        "risk": risk,
        "score": analysis["score"],
        "reasons": analysis["reasons"],
        "advice": analysis["advice"],
        "replaced_urls": replaced_urls,
    }
