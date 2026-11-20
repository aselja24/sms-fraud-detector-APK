"""
Анализ ссылок в SMS: подмена символов в адресе, смешанные алфавиты, скрытые
символы, полноширинные буквы, punycode, имитация бренда.

Главная идея — «скелет» адреса: все символы, которые глазом не отличить от
латинских букв, заменяются на эти буквы, и скелет сравнивается с белым
списком и брендами.
    mbаnk.kg  (кириллическая «а») -> mbank.kg          — совпал с белым списком
    mbank.кг  (кириллическая зона) -> mbank.kg         — совпал с белым списком
    бакай.кг  (кириллица целиком)  -> bakai.kg         — совпал с белым списком
    0ptima-bank.info (цифра 0)     -> optima-bank.info — бренд optima
    teIegram-security.net (I)      -> telegram-security.net
    rnbank.kg (rn)                 -> mbank.kg
Настоящий адрес с таким же скелетом уже в белом списке, поэтому «скелет
совпал, а буквы другие» — это почти наверняка подделка, и у легитимных
отправителей так не бывает.

Скрытые символы (нулевой пробел внутри адреса, «mbank[.]kg») снимаются в
entities.find_urls; здесь они отмечаются отдельным признаком hidden_chars,
потому что настоящее SMS их не использует.

ВАЖНО: адрес разбирается с исходным регистром. normalize() здесь не
используется: он переводит латиницу в кириллицу (для словарей), а скелету
нужно наоборот; а lower() стёр бы разницу I/l.
"""
import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import urlparse

from detector.config import BRAND_OFFICIAL, BRANDS, WHITELIST
from detector.entities import DEFANG_RE, clean_link_text, find_urls, is_fake_brand, is_whitelisted
from detector.homoglyphs import CONFUSABLE, INVISIBLE_RE, transliterate

# Цифры/символы, которыми подменяют буквы. "1" — это и «l», и «i».
_DIGITS = {"0": "o", "3": "e", "5": "s", "$": "s", "@": "a"}
# Короткие бренды дают случайные совпадения в скелете.
_MIN_BRAND_LEN = 4


def _is_cyrillic(ch: str) -> bool:
    return "Ѐ" <= ch <= "ӿ"


def _has_ascii_letter(s: str) -> bool:
    return any(ch.isascii() and ch.isalpha() for ch in s)


def _has_non_ascii_letter(s: str) -> bool:
    return any(not ch.isascii() and ch.isalpha() for ch in s)


def raw_host(url: str) -> str:
    """Адрес сайта с исходным регистром (urlparse().hostname делает lower())."""
    if "://" not in url:
        url = "http://" + url
    host = urlparse(url).netloc.rsplit("@", 1)[-1]
    return re.sub(r":\d+$", "", host)


def _to_unicode(host: str) -> tuple[str, bool]:
    """punycode ("xn--...") -> настоящие буквы. Второе значение — удалось ли."""
    if "xn--" not in host.lower():
        return host, True
    try:
        return host.encode("ascii").decode("idna"), True
    except (UnicodeError, ValueError):
        return host, False


def _label_skeleton(label: str, one_as: str) -> str:
    # Слово целиком из кириллицы: читаем его как транслитерацию («бакай» -> «bakai»).
    if _has_non_ascii_letter(label) and not _has_ascii_letter(label):
        return transliterate(label)
    label = label.replace("I", "l").replace("|", "l")   # до lower()!
    label = "".join(CONFUSABLE.get(ch.lower(), ch) for ch in label)
    label = label.lower().translate(str.maketrans({**_DIGITS, "1": one_as}))
    return label.replace("rn", "m").replace("vv", "w")


def skeleton_variants(host: str) -> list[str]:
    """Скелеты адреса (два — потому что «1» может быть и «l», и «i»)."""
    return [
        ".".join(_label_skeleton(label, one) for label in host.split("."))
        for one in ("l", "i")
    ]


def _substitutions(host: str) -> list[str]:
    """Человеческое описание подменённых символов."""
    found = []
    if _has_non_ascii_letter(host) and not _has_ascii_letter(host):
        found.append("адрес написан кириллицей вместо латиницы")
    for ch in host:
        if ch.lower() in CONFUSABLE and not ch.isascii():
            kind = "кириллическая" if _is_cyrillic(ch) else "похожая не-латинская"
            found.append(f"{kind} «{ch}» вместо латинской «{CONFUSABLE[ch.lower()]}»")
        elif ch in _DIGITS and ch.isdigit():
            found.append(f"цифра «{ch}» вместо буквы «{_DIGITS[ch]}»")
        elif ch == "1":
            found.append("цифра «1» вместо буквы «l» или «i»")
        elif ch == "I":
            found.append("заглавная «I» вместо строчной «l»")
    if "rn" in host.lower():
        found.append("«rn» вместо «m»")
    if "vv" in host.lower():
        found.append("«vv» вместо «w»")
    return list(dict.fromkeys(found))[:3]


def _brand_hint(low: str) -> str | None:
    """Настоящий сайт бренда, если бренд назван в адресе."""
    for brand in BRANDS:
        if brand in low:
            return BRAND_OFFICIAL.get(brand)
    return None


def _match_official(sk: str, low: str) -> tuple[bool, str | None]:
    """Скелет совпал с белым списком или брендом, а буквы адреса другие?"""
    for domain in WHITELIST:
        if (sk == domain or sk.endswith("." + domain)) and low != sk:
            return True, domain
    for brand in BRANDS:
        if len(brand) >= _MIN_BRAND_LEN and brand in sk and brand not in low:
            return True, BRAND_OFFICIAL.get(brand)
    return False, None


@dataclass
class LinkInfo:
    url: str
    host: str                       # как в тексте, с регистром (punycode раскрыт)
    official: bool                  # домен из белого списка
    spoof: list = field(default_factory=list)   # mixed_script / punycode / homoglyph / hidden_chars
    brand_fake: bool = False        # бренд/фишинговое слово/зона в чужом домене
    hint: str | None = None         # настоящий сайт бренда
    details: list = field(default_factory=list)  # что именно подменено
    lookalike: str | None = None    # бренд, на 1–2 буквы отличающийся от имени домена

    @property
    def fake(self) -> bool:
        """Для признака fake_brand_domain: подделка или имитация бренда."""
        return self.brand_fake or bool(self.spoof)


def analyze_link(url: str) -> LinkInfo:
    host, decoded = _to_unicode(raw_host(url))
    # Полноширинные и составные символы («ｍbank») приводим к обычным, но
    # сам факт замены — признак подделки.
    nfkc = unicodedata.normalize("NFKC", host)
    info = LinkInfo(url=url, host=nfkc, official=is_whitelisted(url) and nfkc == host)
    if nfkc != host:
        info.spoof.append("homoglyph")
        info.details.append("полноширинные или составные символы вместо обычных")
    if not decoded:
        info.spoof.append("punycode")
    if info.official:
        return info

    host = nfkc
    low = host.lower()
    labels = host.split(".")
    body = ".".join(labels[:-1])

    # 1. Буквы двух алфавитов в одном слове адреса: «mbаnk». Кириллическая
    #    зона на латинском домене («mbank.кг») — тоже смешение.
    if any(_has_ascii_letter(lb) and _has_non_ascii_letter(lb) for lb in labels) or (
        _has_non_ascii_letter(labels[-1]) and _has_ascii_letter(body)
    ):
        info.spoof.append("mixed_script")

    # 2. Скелет совпал с белым списком или брендом, а буквы другие.
    for sk in skeleton_variants(host):
        matched, hint = _match_official(sk, low)
        if matched:
            info.spoof.append("homoglyph")
            info.hint = hint
            break

    # 3. Бренд, фишинговое слово или зона в чужом домене (прежняя проверка).
    info.brand_fake = is_fake_brand(url)
    if info.hint is None:
        info.hint = _brand_hint(low)

    # 4. Имя домена почти как у бренда: «eline» вместо «beeline» (2 буквы
    #    разницы). Не из белого списка — значит, имитация бренда.
    label = labels[-2] if len(labels) >= 2 else ""
    near = _lookalike_brand(label) if label else None
    if near:
        info.brand_fake = True
        info.lookalike = near
        if not info.spoof:   # при подмене символов причина уже объяснена точнее
            info.details.append(f"имя домена «{label}» почти как у «{near}»")
        if info.hint is None:
            info.hint = BRAND_OFFICIAL[near]

    if info.spoof:
        info.spoof = list(dict.fromkeys(info.spoof))
        info.details = list(dict.fromkeys(info.details + _substitutions(host)))
    return info


def _mark_hidden(info: LinkInfo) -> None:
    """Адрес записан с невидимыми символами или «[.]» — признак обхода фильтров."""
    if "hidden_chars" in info.spoof:
        return
    was_official = info.official
    info.spoof.append("hidden_chars")
    info.official = False
    info.details.insert(0, "в адресе спрятаны символы: невидимые или «[.]» вместо точки")
    if info.hint is None:
        info.hint = info.host if was_official else _brand_hint(info.host.lower())


def analyze_links(text: str) -> list[LinkInfo]:
    """Все ссылки текста с результатом анализа."""
    # Токены с невидимыми символами или «[.]»: адрес в них записан «спрятанным».
    hidden_bits = [
        INVISIBLE_RE.sub("", tok)
        for tok in text.split()
        if INVISIBLE_RE.search(tok) or DEFANG_RE.search(tok)
    ]
    result = []
    for url in find_urls(text):
        info = analyze_link(url)
        if any(url in clean_link_text(bit) for bit in hidden_bits):
            _mark_hidden(info)
        result.append(info)
    return result


def spoof_reason_advice(info: LinkInfo) -> tuple[str, str]:
    """Причина и совет для ссылки с подменой или спрятанными символами."""
    if "hidden_chars" in info.spoof and info.hint:
        reason = (
            f"в адресе ссылки спрятаны символы: она выглядит как «{info.hint}», "
            "но это не он"
        )
        advice = f"Не переходите по ссылке. Настоящий сайт — {info.hint}."
        return reason, advice
    if info.hint:
        reason = f"адрес ссылки «{info.host}» выдаёт себя за {info.hint}"
        if info.details:
            reason += ": подменены символы — " + "; ".join(info.details)
        advice = f"Не переходите по ссылке. Настоящий сайт — {info.hint}."
    else:
        reason = (
            f"в адресе ссылки «{info.host}» подменены или смешаны символы разных "
            "алфавитов — так подделывают настоящие сайты"
        )
        if info.details:
            reason += ": " + "; ".join(info.details)
        advice = "Не переходите по ссылке: такие адреса создают, чтобы выдать себя за настоящий сайт."
    return reason, advice


def _levenshtein(a: str, b: str) -> int:
    """Расстояние Левенштейна: сколько правок нужно, чтобы превратить a в b."""
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _lookalike_brand(label: str) -> str | None:
    """Бренд, от которого имя домена отличается на 1–2 символа (бренды короче
    5 символов не сравниваем: их слишком легко совпасть случайно)."""
    for brand in BRAND_OFFICIAL:
        if len(brand) < 5 or label == brand:
            continue
        if 1 <= _levenshtein(label, brand) <= 2:
            return brand
    return None


# Бренды, которые часто называют в SMS и у которых известен настоящий сайт.
NAMED_BRANDS = [
    "mbank", "beeline", "megacom", "optima", "bakai", "demir",
    "telegram", "whatsapp", "instagram", "google", "binance",
]


def _related(brand: str, host: str) -> bool:
    """Относится ли адрес к бренду: в нём есть название или он сам настоящий."""
    if brand in host:
        return True
    official = BRAND_OFFICIAL.get(brand)
    return bool(official) and (host == official or host.endswith("." + official))


def brand_mismatch(text: str, links, include_official: bool = False) -> tuple[str, str] | None:
    """(бренд, адрес), если в тексте назван бренд, а ни одна ссылка к нему
    не относится. По умолчанию нужен неофициальный адрес; include_official=True
    разрешает и официальный (для пояснения причины, без повышения риска).

    Официальные домены другой компании не считаем: операторы и банки
    ссылаются друг на друга (MegaCom -> beeline.kg, Beeline -> balance.kg),
    и в учебных данных такие SMS помечены как обычные. Неофициальный адрес
    с чужим брендом — уже подозрительно."""
    unofficial = [link for link in links if include_official or not link.official]
    if not unofficial:
        return None
    low = text.lower()
    for brand in NAMED_BRANDS:
        if brand in low and not any(_related(brand, link.host.lower()) for link in links):
            return brand, unofficial[0].host
    return None
