"""Тесты нормализации (снятие обфускации)."""
from detector.normalize import normalize


def test_latin_lookalikes_inside_cyrillic_word():
    assert "заблокирована" in normalize("Ваша карта 3aблokиpoвaн@")


def test_digit_lookalikes():
    assert "сообщайте" in normalize("не с00бщайте коды")


def test_despaced_word():
    text = "Срочно! Ваша SIM-карта будет з а б л о к и р о в а н а"
    assert "заблокирована" in normalize(text)


def test_word_split_by_dashes_or_dots():
    assert "заблокирована" in normalize("Карта за-бло-ки-ро-ва-на")
    assert "сообщите код" in normalize("сообщите к.о.д по номеру")
    assert "отправьте код" in normalize("Отправьте к_о_д подтверждения")
    # Два куска и даты не склеиваются.
    assert "sim-карта" in normalize("Ваша SIM-карта")
    assert "09.12.2026" in normalize("до 09.12.2026")


def test_real_number_not_corrupted():
    # "10до" — это число 10, а не обфускация буквы "о".
    assert "10до" in normalize("Эртең саат 10до жолугалы")


def test_pure_translit_not_converted_to_cyrillic():
    text = "Apa tez arada 300 som kotorup jiberchi"
    normalized = normalize(text)
    assert "kotorup" in normalized
    assert "которуп" not in normalized


def test_short_word_without_cyrillic_anchor():
    # "He" и "u3" целиком состоят из латиницы-двойника, но сообщение в целом
    # кириллическое — поэтому их всё равно нужно починить.
    text = "He переводите деньги и не сообщайте коды u3 SMS"
    normalized = normalize(text)
    assert "не переводите" in normalized
    assert "коды из sms" in normalized


def test_real_adjacent_short_words_not_merged():
    # "заберите" + "в" не должны склеиваться в "заберитев".
    assert "заберите в пункте" in normalize("з а б е р и т е в пункте выдачи")
    # "я" + "с" не должны склеиваться в "яс".
    assert "это я с нового номера" in normalize("это я с нового номера")


def test_despaced_word_ending_in_common_short_word_letter():
    # Последняя буква обфусцированного слова совпадает с коротким словом
    # ("и" = "и"), но склеивать всё равно нужно полностью.
    text = "Поздравляем! Вы в ы и г р а л и iPhone 15"
    assert "выиграли" in normalize(text)
