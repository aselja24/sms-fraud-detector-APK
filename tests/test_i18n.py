"""Тесты перевода ответа на кыргызский (bot/i18n.py)."""
import csv
import os

from bot.i18n import KY_ADVICE, KY_REASONS, KY_RULE_ADVICE, KY_RULE_REASONS, UI, translate
from detector.check import check
from detector.lexicon import ADVICE, REASONS
from detector.rules import RULE_ADVICE, RULE_REASONS

ROOT = os.path.join(os.path.dirname(__file__), "..")


def test_every_feature_and_rule_has_kyrgyz_text():
    # Добавили признак или правило — добавьте и перевод.
    assert set(KY_REASONS) == set(REASONS)
    assert set(KY_ADVICE) == set(ADVICE)
    assert set(KY_RULE_REASONS) == set(RULE_REASONS)
    assert set(KY_RULE_ADVICE) == set(RULE_ADVICE)


def test_ui_has_same_keys_in_both_languages():
    assert set(UI["ru"]) == set(UI["ky"])


def test_russian_is_unchanged():
    assert translate("в сообщении есть ссылка", "ru") == "в сообщении есть ссылка"


def test_all_model_outputs_are_translated():
    """Каждая причина и совет, которые выдаёт check() на наших наборах,
    переводится (а не остаётся по-русски)."""
    texts = []
    for path in ["data/sms_train.csv", "data/sms_dev.csv", "tests/sms_hard.csv"]:
        with open(os.path.join(ROOT, path), encoding="utf-8-sig") as f:
            texts += [r["text"] for r in csv.DictReader(f)]
    missing = set()
    for text in texts:
        result = check(text)
        for line in result["reasons"] + result["advice"]:
            if translate(line, "ky") == line:
                missing.add(line)
    assert not missing, missing


def test_dynamic_parts_keep_addresses():
    line = "в SMS назван бренд Beeline, а ссылка ведёт на другой адрес: mbank.kg"
    ky = translate(line, "ky")
    assert "Beeline" in ky and "mbank.kg" in ky and ky != line
    advice = "Проверяйте домен внимательно: мошенники используют похожие на официальные адреса. Настоящий сайт — beeline.kg."
    assert translate(advice, "ky").endswith("Чыныгы сайт — beeline.kg.")
