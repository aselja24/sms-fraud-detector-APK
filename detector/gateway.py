"""Шлюз безопасных ссылок: подмена опасных ссылок в SMS и проверка отправителя."""
import re
import secrets
import time
from collections import OrderedDict
from dataclasses import dataclass, field

from detector.check import check
from detector.config import BRAND_OFFICIAL, BRANDS, LOW, RULE_HIGH_SCORE
from detector.entities import DEFANG_RE, is_foreign_phone, is_whitelisted
from detector.features import extract
from detector.homoglyphs import INVISIBLE_RE
from detector.links import LinkInfo, analyze_link, analyze_links, spoof_reason_advice
from detector.model import to_level

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

# Как бренды пишут кириллицей — чтобы назвать бренд в причине про отправителя.
_BRAND_CYR = {
    "мбанк": "mbank", "билайн": "beeline", "мегаком": "megacom", "оптима": "optima",
    "бакай": "bakai", "демир": "demir", "керемет": "keremet", "түндүк": "tunduk",
    "элдик": "rsk", "рск": "rsk", "кикб": "kicb",
}
# Короткий номер (сервисные SMS): до 6 цифр.
_SHORT_CODE_LEN = 6


def _brand_in_text(text: str) -> str | None:
    low = text.lower()
    for brand in BRANDS:
        if brand in low:
            return brand
    for word, brand in _BRAND_CYR.items():
        if word in low:
            return brand
    return None


def classify_sender(sender: str) -> str:
    """alpha — буквенное имя (MBANK), short — короткий номер (4444), phone — обычный номер."""
    compact = re.sub(r"[\s\-()]", "", sender)
    if re.fullmatch(r"\+?\d+", compact):
        return "short" if len(compact.lstrip("+")) <= _SHORT_CODE_LEN else "phone"
    return "alpha"


def check_sender(sender: str | None, text: str, links=()) -> dict | None:
    """Оценка отправителя SMS: {sender, kind, verdict, floor, reason} или None."""
    if not sender or not sender.strip():
        return None
    sender = sender.strip()
    kind = classify_sender(sender)
    out = {"sender": sender, "kind": kind, "verdict": "ok", "floor": 0, "reason": None}

    if kind == "alpha":
        has_latin = any(ch.isascii() and ch.isalpha() for ch in sender)
        has_other = any(not ch.isascii() and ch.isalpha() for ch in sender)
        if has_latin and has_other:
            out.update(verdict="suspicious", floor=RULE_HIGH_SCORE, reason=(
                f"в имени отправителя «{sender}» смешаны буквы разных алфавитов — "
                "так подделывают имя, под которым пишет банк или оператор"))
        return out

    if kind == "phone":
        brand = _brand_in_text(text)
        if brand or extract(text)["bank_operator"]:
            name = BRAND_DISPLAY_NAMES.get(brand, "банка или оператора") if brand else "банка или оператора"
            out.update(verdict="suspicious", floor=RULE_HIGH_SCORE, reason=(
                f"SMS от имени {name} пришло с обычного номера {sender} — банки и операторы "
                "пишут с буквенного имени (MBANK, Beeline) или короткого номера"))
        elif is_foreign_phone(sender) and links:
            out.update(verdict="suspicious", floor=LOW, reason=(
                f"SMS со ссылкой пришло с иностранного номера {sender}"))
    return out


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
    """Реестр перехваченных ссылок в памяти: один токен на адрес, размер ограничен."""

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
    """Под какой бренд маскируется ссылка (нужна боту: bot/bot.py)."""
    return _brand_of(analyze_link(url), text)


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
    if analysis.get("gateway_reasons"):
        return "ссылка пришла в SMS с признаками мошенничества: " + analysis["gateway_reasons"][0]
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
                 link_registry: SafeLinksRegistry | None = None,
                 sender: str | None = None) -> dict:
    """Проверяет SMS и заменяет опасные ссылки ссылками шлюза.
    Возвращает результат check() и итог шлюза (safe_text, links, segments и т.д.)."""
    reg = link_registry if link_registry is not None else registry
    base_url = base_url.rstrip("/")
    analysis = check(text)
    links = analyze_links(text)
    sender_info = check_sender(sender, text, links)
    gateway_score = analysis["score"]
    gateway_reasons = list(analysis["reasons"])
    if sender_info and sender_info["reason"]:
        gateway_score = max(gateway_score, sender_info["floor"])
        gateway_reasons.insert(0, sender_info["reason"])
    risk = to_level(gateway_score)   # ссылки подменяем по итогу шлюза

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
                reason=_link_reason(info, brand, {**analysis, "gateway_reasons": gateway_reasons}),
                reasons=gateway_reasons,
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
        "risk": analysis["risk"],
        "score": analysis["score"],
        "sender": sender_info,
        "gateway_risk": risk,
        "gateway_score": gateway_score,
        "gateway_reasons": gateway_reasons,
        "reasons": analysis["reasons"],
        "advice": analysis["advice"],
        "links": decisions,
        "replaced_urls": replaced,
        "segments": segments,
    }


def run_stream(rows, base_url: str = "http://localhost:8000",
               link_registry: SafeLinksRegistry | None = None, max_examples: int = 5) -> dict:
    """Прогон размеченных SMS через шлюз: сводка по ссылкам и примеры ошибок."""
    summary = {
        "total": 0, "fraud": 0, "ok": 0, "sms_modified": 0,
        "fraud_high": 0, "ok_high": 0,
        "fraud_links": 0, "fraud_links_blocked": 0, "fraud_links_official": 0, "fraud_links_missed": 0,
        "ok_links": 0, "ok_links_broken": 0,
    }
    broken, missed, items = [], [], []
    for row in rows:
        text = row.get("text") or ""
        label = (row.get("label") or "").strip()
        res = sanitize_sms(text, base_url=base_url, link_registry=link_registry,
                           sender=row.get("sender"))
        is_fraud = label == "fraud"
        summary["total"] += 1
        summary["fraud" if is_fraud else "ok"] += 1
        summary["sms_modified"] += res["is_modified"]
        if res["gateway_risk"] == "high":
            summary["fraud_high" if is_fraud else "ok_high"] += 1
        for link in res["links"]:
            blocked = link["action"] == "blocked"
            if is_fraud:
                summary["fraud_links"] += 1
                if blocked:
                    summary["fraud_links_blocked"] += 1
                elif link["official"]:
                    summary["fraud_links_official"] += 1
                else:
                    summary["fraud_links_missed"] += 1
                    missed.append({"id": row.get("id"), "text": text, "url": link["defanged_url"]})
            else:
                summary["ok_links"] += 1
                if blocked:
                    summary["ok_links_broken"] += 1
                    broken.append({"id": row.get("id"), "text": text, "url": link["defanged_url"]})
        items.append({
            "id": row.get("id"),
            "label": label,
            "risk": res["gateway_risk"],
            "score": res["gateway_score"],
            "is_modified": res["is_modified"],
            "links": len(res["links"]),
            "blocked": len(res["replaced_urls"]),
            "segments": res["segments"],
        })
    return {"summary": summary, "broken": broken[:max_examples],
            "missed": missed[:max_examples], "items": items}
