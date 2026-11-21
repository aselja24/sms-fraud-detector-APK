"""Тесты чтения скриншотов (bot/ocr.py) — без самого Tesseract."""
import pytest

from bot import ocr


def test_clean_text_joins_lines():
    assert ocr.clean_text("MBANK\n\n  Ваша карта   заблокирована.\nmbank.kg  ") == "MBANK Ваша карта заблокирована. mbank.kg"


def test_ocr_lookalikes_in_links_become_latin():
    # OCR мог прочитать латинскую «a» как кириллическую — это не подмена в SMS.
    assert ocr.fix_ocr_links("Войдите: mbаnk.kg") == "Войдите: mbank.kg"
    # обычный текст не трогаем
    assert ocr.fix_ocr_links("Ваша карта заблокирована") == "Ваша карта заблокирована"
    # целиком кириллический адрес не трогаем
    assert ocr.fix_ocr_links("Сайт: кыргызстан.кг") == "Сайт: кыргызстан.кг"


def test_missing_tesseract_is_reported(monkeypatch):
    def fail():
        raise ocr.OCRUnavailable("нет")
    monkeypatch.setattr(ocr, "_modules", fail)
    assert ocr.available() is False
    with pytest.raises(ocr.OCRUnavailable):
        ocr.image_to_text(b"...")


FONT = "/System/Library/Fonts/Supplemental/Arial Unicode.ttf"


def _screenshot(lines):
    import io
    import os
    from PIL import Image, ImageDraw, ImageFont
    if not os.path.exists(FONT):
        pytest.skip("нет шрифта с кириллицей")
    img = Image.new("RGB", (720, 70 + 60 * len(lines)), "white")
    draw = ImageDraw.Draw(img)
    font = ImageFont.truetype(FONT, 34)
    for i, line in enumerate(lines):
        draw.text((30, 30 + 60 * i), line, fill="black", font=font)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


@pytest.mark.skipif(not ocr.available(), reason="Tesseract не установлен")
def test_real_ocr_keeps_kyrgyz_letters_and_finds_fraud():
    from detector.check import check
    text = ocr.image_to_text(_screenshot(["Картаңыз бөгөттөлдү.", "Кодду жибериңиз 0555 123456"]))
    assert "бөгөттөлдү" in text and "жибериңиз" in text
    assert check(text)["risk"] == "high"


@pytest.mark.skipif(not ocr.available(), reason="Tesseract не установлен")
def test_real_ocr_legit_sms_stays_low():
    from detector.check import check
    text = ocr.image_to_text(_screenshot(["Beeline", "Ваш баланс пополнен на 300 сом.", "Спасибо!"]))
    assert check(text)["risk"] == "low"
