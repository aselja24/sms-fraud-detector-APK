"""
Нормализация текста SMS перед анализом признаков.

Снимает типичную обфускацию мошенников:
  1. "Разбитые" пробелами слова: "з а б л о к и р о в а н а" -> "заблокирована".
  2. Символы-двойники вместо букв: латиница вместо кириллицы ("Bаnк"),
     цифры и "@" вместо букв ("б@нк", "с00бщите").
  3. Разное написание кыргызских букв: "ө/ү/ң" и "о/у/н" (без раскладки),
     "ö/ü/ŋ" в латинице — всё сводится к одному виду.

ВАЖНО: замена латиницы/цифр на кириллицу делается только внутри слова, где
уже есть хотя бы одна "настоящая" кириллическая буква — иначе чистый
транслит ("kartanyz bogottoldu") был бы сломан. Цифра "1" не заменяется
никогда (суммы, даты, "10до").
"""

import re

from detector.homoglyphs import INVISIBLE_RE
from detector.translit import fold

# Цифры/символы -> кириллица (похожие по написанию).
_DIGIT_SYMBOL_MAP = {
    "0": "о",
    "3": "з",
    "6": "б",
    "@": "а",
    "u": "и",
}

# Латинские буквы-двойники кириллических букв.
_LATIN_LOOKALIKE_MAP = {
    "a": "а",
    "e": "е",
    "o": "о",
    "p": "р",
    "c": "с",
    "x": "х",
    "k": "к",
    "m": "м",
    "h": "н",
    "t": "т",
    "y": "у",
    "B": "В",
    "H": "Н",
    # латинские ö/ü внутри кыргызского слова = ө/ү
    "ö": "ө",
    "ü": "ү",
}

HOMOGLYPH_MAP = {**_DIGIT_SYMBOL_MAP, **_LATIN_LOOKALIKE_MAP}


def _is_cyrillic(ch: str) -> bool:
    return "Ѐ" <= ch <= "ӿ"


def _has_cyrillic(token: str) -> bool:
    return any(_is_cyrillic(ch) for ch in token)


# Настоящие однобуквенные слова русского языка, которые могут случайно
# оказаться соседями разбитого пробелами слова ("...т е в пункте", "я с
# нового номера"). Гласные-окончания ("и","а","о","у") намеренно не
# включены — они слишком часто являются ПОСЛЕДНЕЙ буквой самого
# обфусцированного слова ("в ы и г р а л и" -> "выиграли").
_COMMON_SHORT_WORDS = {"в", "с", "я"}


def _despace_words(text: str) -> str:
    """Склеивает последовательности из 2+ "однобуквенных" токенов подряд:
    "к о д" -> "код". Одиночные однобуквенные слова (предлоги "в", "и"
    и т.п.) не трогает, а настоящие соседние короткие слова ("я", "с")
    не склеивает между собой и не "прилипает" ими к обфусцированному слову.
    """
    tokens = text.split(" ")
    result = []
    i = 0
    n = len(tokens)

    def is_single_char_token(tok: str) -> bool:
        return len(tok) == 1 and (tok.isalnum() or tok == "@")

    def is_real_word(tok: str) -> bool:
        return len(tok) > 1 and tok[0].isalnum()

    while i < n:
        if is_single_char_token(tokens[i]):
            j = i
            while j < n and is_single_char_token(tokens[j]):
                j += 1
            run = tokens[i:j]

            # Короткая цепочка из настоящих отдельных слов ("я", "с") -
            # это не обфускация, не склеивать вообще.
            if len(run) <= 2 and all(t.lower() in _COMMON_SHORT_WORDS for t in run):
                result.extend(run)
                i = j
                continue

            # К длинной обфусцированной последовательности мог "прилипнуть"
            # настоящий предлог на конце ("...т е в пункте" -> "...те" + "в").
            while (
                len(run) >= 3
                and run[-1].lower() in _COMMON_SHORT_WORDS
                and j < n
                and is_real_word(tokens[j])
            ):
                j -= 1
                run = tokens[i:j]

            if len(run) >= 2:
                result.append("".join(run))
            else:
                result.append(tokens[i])
            i = j
        else:
            result.append(tokens[i])
            i += 1
    return " ".join(result)


# Слово, разбитое дефисами/точками/подчёркиваниями на 3+ коротких куска:
# "за-бло-ки-ро-ва-на", "к.о.д", "к_о_д". "SIM-карта" (2 куска), даты и
# ссылки сюда не попадают. [^\W_] — буква или цифра (без "_").
_SPLIT_WORD_RE = re.compile(r"^(?:(?:[^\W_]|@){1,3}[-._]){2,}(?:[^\W_]|@){1,3}$")


def _join_split_letters(text: str) -> str:
    words = []
    for word in text.split(" "):
        core = word.rstrip(",.!?:;")
        tail = word[len(core):]
        if _SPLIT_WORD_RE.match(core) and any(ch.isalpha() for ch in core):
            word = re.sub(r"[-._]", "", core) + tail
        words.append(word)
    return " ".join(words)


def _apply_map(word: str) -> str:
    """Заменяет символы-двойники на кириллицу внутри слова.

    Ведущая цифровая группа защищена от замены, если после неё идёт
    "чистое" кириллическое слово — это настоящее число ("10до", "14до"),
    а не обфускация (где после первой цифры сразу шла бы латиница/символ,
    как в "3aблokиpoвaн@")."""
    lead = 0
    while lead < len(word) and word[lead].isdigit():
        lead += 1
    if lead > 0:
        remainder = word[lead:]
        if remainder and all(_is_cyrillic(ch) for ch in remainder):
            return word
    return "".join(HOMOGLYPH_MAP.get(ch, ch) for ch in word)


def _fix_homoglyphs(text: str) -> str:
    """Заменяет цифры/латиницу-двойники на кириллицу, но только внутри
    слов, где уже есть кириллическая буква — иначе чистый транслит
    («kartanyz», «kodduu») был бы испорчен.

    Отдельное исключение: очень короткие (1-2 символа) служебные слова
    («He» вместо «Не», «u3» вместо «из») иногда целиком состоят из
    двойников и не имеют "якоря" из настоящей кириллицы. Их тоже
    чинят, но только если где-то в сообщении кириллица уже есть —
    так чисто-латинские SMS («kartanyz bogottoldu») не трогаются.
    """
    message_has_cyrillic = _has_cyrillic(text)
    words = text.split(" ")
    fixed_words = []
    for word in words:
        if _has_cyrillic(word):
            word = _apply_map(word)
        elif message_has_cyrillic and len(word) <= 2 and any(ch.isalpha() for ch in word):
            word = _apply_map(word)
        fixed_words.append(word)
    return " ".join(fixed_words)


def normalize(text: str) -> str:
    """Приводит текст SMS к виду, пригодному для поиска признаков по словарю."""
    # Невидимые символы внутри слов («мо\u200bшенник») мешают словарю.
    text = INVISIBLE_RE.sub("", text)
    text = _join_split_letters(text)
    text = _despace_words(text)
    text = _fix_homoglyphs(text)
    # Единое написание кыргызских букв: «жибериңиз» = «жибериниз»,
    # «Kartaŋyz» = «kartanyz» (см. translit.py).
    return fold(text.lower())
