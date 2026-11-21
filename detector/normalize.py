"""Нормализация текста SMS: склейка разбитых слов, двойники букв, единое написание ө/ү/ң."""

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


# Настоящие однобуквенные слова, которые не склеиваются с разбитым словом.
_COMMON_SHORT_WORDS = {"в", "с", "я"}


def _despace_words(text: str) -> str:
    """Склеивает 2+ однобуквенных токена подряд: «к о д» -> «код»."""
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


# Слово, разбитое дефисами, точками или подчёркиваниями: «за-бло-ки», «к.о.д».
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
    """Заменяет символы-двойники на кириллицу внутри слова (числа в начале не трогает)."""
    lead = 0
    while lead < len(word) and word[lead].isdigit():
        lead += 1
    if lead > 0:
        remainder = word[lead:]
        if remainder and all(_is_cyrillic(ch) for ch in remainder):
            return word
    return "".join(HOMOGLYPH_MAP.get(ch, ch) for ch in word)


def _fix_homoglyphs(text: str) -> str:
    """Заменяет двойники на кириллицу в словах, где уже есть кириллическая буква."""
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
