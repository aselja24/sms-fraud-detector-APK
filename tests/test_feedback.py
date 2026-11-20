"""Тесты сохранения отметок из бота (bot/feedback.py)."""
import csv

import pytest

from bot.feedback import FIELDS, save_feedback
from train import load_rows


def test_feedback_is_appended_with_header(tmp_path):
    path = str(tmp_path / "feedback" / "feedback.csv")
    save_feedback("Вы выиграли приз! https://prize.example", "fraud", "high", path)
    save_feedback("Мама, перезвони", "ok", "low", path)
    with open(path, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert list(rows[0].keys()) == FIELDS
    assert [r["label"] for r in rows] == ["fraud", "ok"]


def test_feedback_file_is_valid_training_data(tmp_path):
    path = str(tmp_path / "feedback.csv")
    save_feedback("Сырсөздү жибериңиз", "fraud", "high", path)
    assert load_rows(path) == [("Сырсөздү жибериңиз", 1)]


def test_bad_label_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        save_feedback("текст", "maybe", "low", str(tmp_path / "f.csv"))
