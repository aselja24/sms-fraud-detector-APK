"""
Чтение текста со скриншота SMS (Tesseract OCR).

Нужны:
  * программа Tesseract с языками rus, kir, eng
    (macOS: brew install tesseract tesseract-lang;
     Ubuntu: apt install tesseract-ocr tesseract-ocr-rus tesseract-ocr-kir);
  * Python-пакеты Pillow и pytesseract (requirements.txt).
Если чего-то нет, available() возвращает False, и бот просит прислать текст.

Важно про ссылки. По картинке нельзя отличить кириллическую «а» от
латинской «a» — OCR угадывает. Из-за этого в распознанной ссылке легко
появляется «смесь алфавитов», которой в SMS не было, и детектор поднял бы
ложную тревогу «подмена символов». Поэтому fix_ocr_links() приводит
похожие буквы в ссылках к латинице: подмену по скриншоту мы не ловим
(бот честно об этом пишет), зато и не выдумываем её.
"""
import io
import re

from detector.homoglyphs import CONFUSABLE

# Похоже на адрес: слово с точкой внутри и буквами после неё («mbank.kg», «bit.ly/x»).
_LINKISH_RE = re.compile(r"\S+\.[^\W\d_]{2,}\S*")


class OCRUnavailable(Exception):
    """Tesseract или нужные Python-пакеты не установлены."""


def _modules():
    try:
        import pytesseract
        from PIL import Image, ImageOps
    except ImportError as exc:
        raise OCRUnavailable(str(exc)) from exc
    return pytesseract, Image, ImageOps


def _languages(pytesseract) -> str:
    try:
        installed = set(pytesseract.get_languages(config=""))
    except Exception as exc:   # программа tesseract не найдена
        raise OCRUnavailable(str(exc)) from exc
    # Кыргызский первым: с порядком rus+kir Tesseract теряет ө/ү/ң
    # («бөгөттөлдү» -> «бегеттелду»), а русский текст kir+rus читает так же.
    langs = [lang for lang in ("kir", "rus", "eng") if lang in installed]
    if not langs:
        raise OCRUnavailable("в tesseract нет языков rus/kir/eng")
    return "+".join(langs)


def available() -> bool:
    try:
        pytesseract, _, _ = _modules()
        _languages(pytesseract)
        return True
    except OCRUnavailable:
        return False


def fix_ocr_links(text: str) -> str:
    """В словах, похожих на адрес и уже содержащих латиницу, заменяет
    кириллические двойники на латинские буквы («mbаnk.kg» -> «mbank.kg»)."""
    def fix(match: re.Match) -> str:
        word = match.group(0)
        if not any(ch.isascii() and ch.isalpha() for ch in word):
            return word   # целиком кириллический адрес не трогаем
        return "".join(CONFUSABLE.get(ch, ch) if not ch.isascii() else ch for ch in word)
    return _LINKISH_RE.sub(fix, text)


def clean_text(raw: str) -> str:
    """Строки скриншота -> одна строка текста SMS."""
    lines = [" ".join(line.split()) for line in raw.splitlines()]
    return " ".join(line for line in lines if line)


def image_to_text(data: bytes) -> str:
    """Текст со скриншота. Бросает OCRUnavailable, если OCR не установлен."""
    pytesseract, Image, ImageOps = _modules()
    langs = _languages(pytesseract)
    image = Image.open(io.BytesIO(data))
    image = ImageOps.exif_transpose(image).convert("L")
    # Мелкий текст скриншота OCR читает лучше, если картинку увеличить.
    if image.width < 1200:
        scale = 1200 / image.width
        image = image.resize((int(image.width * scale), int(image.height * scale)))
    raw = pytesseract.image_to_string(image, lang=langs)
    return fix_ocr_links(clean_text(raw))
