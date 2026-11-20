"""
Безопасные ссылки (Safe Links): симуляция защиты SMS на стороне оператора.

Идея: опасная ссылка не доходит до абонента как есть. Сеть заменяет её на
адрес шлюза {base_url}/x/{token}; при переходе человек видит страницу-стоп
с объяснением, а сайт мошенников не открывается.

Что подменяется:
  * ссылка с подменой символов или спрятанными символами («mbаnk.kg» с
    кириллической «а», «mb<нулевой пробел>ank.kg», «mbank[.]kg-bonus.xyz»);
  * ссылка под видом бренда, на подозрительной зоне, «почти как у бренда»;
  * любая неофициальная ссылка в SMS с риском medium/high.
Официальные ссылки из белого списка остаются как есть.

Ссылки ищутся теми же функциями, что и в check() (links.analyze_links), а
заменяются по позициям в исходном тексте. Это важно: в find_urls() адрес
уже очищен от невидимых символов и «[.]», и простой str.replace() его в
исходном SMS не находил — «заменённая» ссылка оставалась в тексте.

Реестр хранит только адрес и причины — сам текст SMS не сохраняется.
"""
import secrets
import time
from collections import OrderedDict
from dataclasses import dataclass, field

from detector.check import check
from detector.config import BRAND_OFFICIAL, BRANDS
from detector.entities import DEFANG_RE, is_whitelisted
from detector.homoglyphs import INVISIBLE_RE
from detector.links import LinkInfo, analyze_link, analyze_links, spoof_reason_advice

# Как бренд называть на странице-стоп.
BRAND_DISPLAY_NAMES = {
    "beeline": "Beeline",
    "balance": "Balance.kg",
    "mbank": "MBANK",
    "nbkr": "НБКР",
    "megacom": "MegaCom",
    "kicb": "KICB",
    "optima": "Оптима Банк",
    "bakai": "Бакай Банк",
    "demir": "Демир Банк",
    "rsk": "РСК Банк",
    "tunduk": "Түндүк",
    "keremet": "Керемет Банк",
    "telegram": "Telegram",
    "whatsapp": "WhatsApp",
    "instagram": "Instagram",
    "google": "Google",
    "binance": "Binance",
}

_BRAND_BY_DOMAIN = {domain: brand for brand, domain in BRAND_OFFICIAL.items()}
_MAX_REASONS = 3


def defang(url: str) -> str:
    """Некликабельный вид адреса для показа: «mbank[.]kg», «hxxps://»."""
    return url.replace("http", "hxxp", 1).replace(".", "[.]")


@dataclass
class LinkRecord:
    """Перехваченная ссылка в реестре шлюза."""
    token: str
    original_url: str
    host: str
    risk: str
    reason: str
    reasons: list = field(default_factory=list)   # причины check() для всего SMS
    brand_key: str | None = None
    brand_name: str = ""
    official_domain: str | None = None
    created_at: str = ""
    sms_count: int = 1      # сколько SMS с этой ссылкой прошло через шлюз
    clicks_count: int = 0   # сколько переходов остановлено

    @property
    def official_url(self) -> str | None:
        return f"https://{self.official_domain}" if self.official_domain else None

    def as_dict(self) -> dict:
        return {
            "token": self.token,
            "original_url": self.original_url,
            "defanged_url": defang(self.original_url),
            "host": self.host,
            "risk": self.risk,
            "reason": self.reason,
            "reasons": list(self.reasons),
            "brand_key": self.brand_key,
            "brand_name": self.brand_name,
            "official_domain": self.official_domain,
            "official_url": self.official_url,
            "created_at": self.created_at,
            "sms_count": self.sms_count,
            "clicks_count": self.clicks_count,
        }


class SafeLinksRegistry:
    """Реестр перехваченных ссылок в памяти процесса.

    Одна и та же ссылка получает один токен: массовая рассылка не раздувает
    реестр, а счётчики показывают, сколько SMS и переходов было по ней.
    Размер ограничен: старые записи вытесняются.
    """

    def __init__(self, max_size: int = 5000):
        self.max_size = max_size
        self._records: "OrderedDict[str, LinkRecord]" = OrderedDict()
        self._by_url: dict[str, str] = {}
        self.sms_checked = 0
        self.sms_modified = 0

    def register(self, original_url: str, risk: str, reason: str, reasons=(),
                 brand_key: str | None = None, official_domain: str | None = None,
                 host: str = "") -> LinkRecord:
        token = self._by_url.get(original_url)
        if token in self._records:
            record = self._records[token]
            record.sms_count += 1
            self._records.move_to_end(token)
            return record

        token = secrets.token_urlsafe(6)   # 8 символов, не угадывается
        while token in self._records:
            token = secrets.token_urlsafe(6)
        record = LinkRecord(
            token=token,
            original_url=original_url,
            host=host,
            risk=risk,
            reason=reason,
            reasons=list(reasons)[:_MAX_REASONS],
            brand_key=brand_key,
            brand_name=BRAND_DISPLAY_NAMES.get(brand_key, "") if brand_key else "",
            official_domain=official_domain,
            created_at=time.strftime("%Y-%m-%d %H:%M:%S"),
        )
        self._records[token] = record
        self._by_url[original_url] = token
        while len(self._records) > self.max_size:
            _, old = self._records.popitem(last=False)
            self._by_url.pop(old.original_url, None)
        return record

    def get(self, token: str) -> LinkRecord | None:
        """Запись по токену (счётчики не меняет)."""
        return self._records.get(token)

    def click(self, token: str) -> LinkRecord | None:
        """Переход по ссылке шлюза: возвращает запись и считает остановленный переход."""
        record = self._records.get(token)
        if record is not None:
            record.clicks_count += 1
        return record

    def all_records(self) -> list[dict]:
        """Записи от новых к старым."""
        return [r.as_dict() for r in reversed(self._records.values())]

    def stats(self) -> dict:
        return {
            "sms_checked": self.sms_checked,
            "sms_modified": self.sms_modified,
            "links_blocked": len(self._records),
            "clicks_blocked": sum(r.clicks_count for r in self._records.values()),
        }

    def clear(self) -> None:
        self._records.clear()
        self._by_url.clear()
        self.sms_checked = 0
        self.sms_modified = 0


# Общий реестр шлюза (для gateway_server.py).
registry = SafeLinksRegistry()


def _clean_with_map(text: str) -> tuple[str, list[int], list[int]]:
    """То же, что entities.clean_link_text(), плюс карта позиций: для каждого
    символа очищенного текста — где он начинается и кончается в исходном."""
    out, starts, ends = [], [], []
    i = 0
    while i < len(text):
        if INVISIBLE_RE.match(text, i):
            i += 1
            continue
        m = DEFANG_RE.match(text, i)
        if m:
            out.append(".")
            starts.append(i)
            ends.append(m.end())
            i = m.end()
            continue
        out.append(text[i])
        starts.append(i)
        ends.append(i + 1)
        i += 1
    return "".join(out), starts, ends


def _spans(text: str, links: list[LinkInfo]) -> list[tuple[int, int] | None]:
    """Где каждая ссылка записана в исходном тексте (с невидимыми символами и «[.]»)."""
    cleaned, starts, ends = _clean_with_map(text)
    spans, cursor = [], 0
    for info in links:
        pos = cleaned.find(info.url, cursor)
        if pos < 0 or not info.url:
            spans.append(None)
            continue
        end = pos + len(info.url)
        spans.append((starts[pos], ends[end - 1]))
        cursor = end
    return spans


def _brand_of(info: LinkInfo, text: str) -> str | None:
    """Под какой бренд маскируется ссылка: по настоящему сайту, по адресу, по тексту."""
    if info.hint in _BRAND_BY_DOMAIN:
        return _BRAND_BY_DOMAIN[info.hint]
    if info.lookalike:
        return info.lookalike
    host = info.host.lower()
    for brand in BRANDS:
        if brand in host:
            return brand
    low = text.lower()
    for brand in BRANDS:
        if brand in low:
            return brand
    return None


def _detect_brand(url: str, text: str = "") -> str | None:
    """Определяет, под какой бренд маскируется ссылка/текст."""
    info = analyze_link(url)
    return _brand_of(info, text)


def _link_reason(info: LinkInfo, brand: str | None, analysis: dict) -> str:
    """Почему именно эта ссылка опасна — одна фраза для страницы-стоп."""
    if info.spoof:
        return spoof_reason_advice(info)[0]
    name = BRAND_DISPLAY_NAMES.get(brand, brand) if brand else None
    if info.lookalike:
        # Та же фраза, что в check(): её уже переводит bot/i18n.py.
        return f"адрес «{info.host}» почти как у «{info.lookalike}», но отличается на пару букв"
    if info.brand_fake and name:
        return f"ссылка ведёт на неофициальный адрес под видом {name}"
    if info.brand_fake:
        return "адрес в подозрительной доменной зоне или со словами, типичными для фишинга"
    if analysis["reasons"]:
        return "ссылка пришла в SMS с признаками мошенничества: " + analysis["reasons"][0]
    return "ссылка пришла в SMS с признаками мошенничества"


def should_block(info: LinkInfo, risk: str) -> bool:
    """Подменять ли ссылку. Официальная без подмены символов — никогда."""
    if info.spoof or info.brand_fake:
        return True
    if info.official:
        return False
    return risk in ("medium", "high")


def sanitize_sms(text: str, base_url: str = "http://localhost:8000",
                 link_registry: SafeLinksRegistry | None = None) -> dict:
    """Проверяет SMS и заменяет опасные ссылки на ссылки шлюза.

    Возвращает результат check() (risk, score, reasons, advice) и:
      safe_text     — SMS, каким его увидит абонент;
      is_modified   — была ли подмена;
      links         — решение по каждой ссылке (blocked / kept);
      replaced_urls — только подменённые ссылки;
      segments      — safe_text по кускам (plain / blocked) для показа без HTML-вставок.
    """
    reg = link_registry if link_registry is not None else registry
    base_url = base_url.rstrip("/")
    analysis = check(text)
    risk = analysis["risk"]
    links = analyze_links(text)

    decisions = []
    for info, span in zip(links, _spans(text, links)):
        blocked = span is not None and should_block(info, risk)
        brand = _brand_of(info, text) if blocked else None
        item = {
            "original_url": info.url,
            "defanged_url": defang(info.url),
            "action": "blocked" if blocked else "kept",
            "official": info.official,
            "span": span,
        }
        if blocked:
            official = info.hint if info.hint and is_whitelisted(info.hint) else None
            record = reg.register(
                original_url=info.url,
                risk=risk,
                reason=_link_reason(info, brand, analysis),
                reasons=analysis["reasons"],
                brand_key=brand,
                official_domain=official,
                host=info.host,
            )
            item.update({
                "token": record.token,
                "safe_url": f"{base_url}/x/{record.token}",
                "brand": record.brand_name or "неизвестный сервис",
                "reason": record.reason,
                "official_domain": official,
            })
        else:
            item["reason"] = "официальный адрес из белого списка" if info.official else \
                "явных признаков подделки нет, а SMS не выглядит мошенническим"
        decisions.append(item)

    # Собираем SMS заново: куски исходного текста и ссылки шлюза вместо опасных.
    segments, cursor = [], 0
    for item in sorted((d for d in decisions if d["action"] == "blocked"), key=lambda d: d["span"][0]):
        start, end = item["span"]
        if start < cursor:   # пересечение (на всякий случай) — пропускаем
            continue
        if start > cursor:
            segments.append({"kind": "plain", "text": text[cursor:start]})
        segments.append({"kind": "blocked", "text": item["safe_url"],
                         "original_url": item["original_url"], "token": item["token"]})
        cursor = end
    if cursor < len(text):
        segments.append({"kind": "plain", "text": text[cursor:]})
    safe_text = "".join(s["text"] for s in segments)

    for item in decisions:
        item.pop("span")
    replaced = [d for d in decisions if d["action"] == "blocked"]

    reg.sms_checked += 1
    if replaced:
        reg.sms_modified += 1

    return {
        "original_text": text,
        "safe_text": safe_text,
        "is_modified": bool(replaced),
        "risk": risk,
        "score": analysis["score"],
        "reasons": analysis["reasons"],
        "advice": analysis["advice"],
        "links": decisions,
        "replaced_urls": replaced,
        "segments": segments,
    }
