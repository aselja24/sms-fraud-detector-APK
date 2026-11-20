"""
Единое написание кыргызских букв и автоматический транслит корней словаря.

Зачем:
  1. Многие пишут по-кыргызски без кыргызской раскладки: «бөгөттөлдү» ->
     «боготтолду», «жибериңиз» -> «жибериниз». fold() сводит оба варианта
     к одному («ө»->«о», «ү»->«у», «ң»->«н»), и словарь, и текст проходят
     через неё, поэтому корень «бөгөт» ловит обе записи.
  2. Те же сообщения пишут латиницей: «Kartaŋyz bögöttöldü», «jiberiniz»,
     «zhiberiniz». latin_variants() по каждому кириллическому корню строит
     его латинские написания, чтобы не вписывать транслит вручную.
"""

import re

# Кыргызские/русские буквы -> «упрощённое» написание (как без раскладки).
_CYR_FOLD = str.maketrans({"ө": "о", "ү": "у", "ң": "н", "ё": "е"})
# То же для латиницы (турецкая/кыргызская латиница, ñ, ŋ).
_LAT_FOLD = str.maketrans({"ö": "o", "ü": "u", "ŋ": "n", "ñ": "n", "ı": "i", "ç": "ch", "ş": "sh"})
# «ng» перед гласной в транслите = «ң»: «jiberingiz» -> «jiberiniz».
_NG_RE = re.compile(r"ng(?=[aeiouy])")


def fold(text: str) -> str:
    """Сводит варианты написания к одному (текст уже в нижнем регистре)."""
    text = text.translate(_CYR_FOLD).translate(_LAT_FOLD)
    return _NG_RE.sub("n", text)


# Кириллица -> латиница. Для букв с несколькими привычными записями —
# список вариантов (ж = j/zh, ы = y/i и т.д.).
_TRANSLIT = {
    "а": "a", "б": "b", "в": "v", "г": "g", "д": "d", "е": "e", "ж": ["j", "zh"],
    "з": "z", "и": "i", "й": ["i", "y"], "к": "k", "л": "l", "м": "m", "н": "n",
    "о": "o", "п": "p", "р": "r", "с": "s", "т": "t", "у": "u", "ф": "f",
    "х": ["h", "kh"], "ц": ["ts", "c"], "ч": "ch", "ш": "sh", "щ": ["sh", "sch"],
    "ъ": "", "ы": ["y", "i"], "ь": "", "э": "e", "ю": ["yu", "iu"], "я": ["ya", "ia"],
}

# Не больше стольких вариантов на корень — чтобы словарь не разрастался.
_MAX_VARIANTS = 16
# Короткие корни («пин», «чал») в латинице ловят чужие слова (pink, chalk) —
# для них транслит пишется вручную в lexicon.py.
_MIN_LEN = 4


def latin_variants(root: str) -> list[str]:
    """Латинские написания кириллического корня: «жибериниз» ->
    ["jiberiniz", "zhiberiniz"]. Для некириллических и коротких корней — []."""
    root = fold(root)
    if not any("а" <= ch <= "я" for ch in root):
        return []
    variants = [""]
    for ch in root:
        options = _TRANSLIT.get(ch, ch)
        if isinstance(options, str):
            options = [options]
        variants = [v + o for v in variants for o in options][:_MAX_VARIANTS]
    return [v for v in variants if len(v.replace(" ", "")) >= _MIN_LEN]


def expand_roots(roots: list[str], skip: set[str] = frozenset()) -> list[str]:
    """Корни в едином написании + их латинские варианты, без повторов."""
    result = []
    for root in roots:
        result.append(fold(root))
        if root not in skip:
            result.extend(latin_variants(root))
    return list(dict.fromkeys(result))
