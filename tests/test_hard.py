"""Регрессионный набор трудных случаев tests/sms_hard.csv (expected_risk, known_gap)."""
import csv
import os

import pytest

from detector.check import check

PATH = os.path.join(os.path.dirname(__file__), "sms_hard.csv")


def _load():
    with open(PATH, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def _params():
    for row in _load():
        marks = []
        if row["status"] == "known_gap":
            marks.append(pytest.mark.xfail(strict=True, reason="известный пробел"))
        yield pytest.param(row, id=f"{row['id']}-{row['category']}", marks=marks)


@pytest.mark.parametrize("row", list(_params()))
def test_hard_case(row):
    result = check(row["text"])
    allowed = row["expected_risk"].split("|")
    assert result["risk"] in allowed, (result["risk"], result["score"], row["text"])
    assert len(result["advice"]) == len(result["reasons"])


def test_spoofed_links_are_always_high_with_explanation():
    """Подмена символов — самый опасный случай: человек видит 'низкий риск' и
    открывает ссылку. Ответ должен быть high и объяснять, что подменено."""
    spoofed = [r for r in _load() if r["category"].startswith("spoof_")]
    assert len(spoofed) >= 10
    for row in spoofed:
        result = check(row["text"])
        assert result["risk"] == "high", row["text"]
        assert result["score"] >= 80, row["text"]
        first = result["reasons"][0]
        assert "ссылки" in first and ("подмен" in first or "смешан" in first), (row["text"], first)


def test_hard_set_has_both_classes():
    rows = _load()
    assert {r["label"] for r in rows} == {"fraud", "ok"}
    assert len({r["id"] for r in rows}) == len(rows)
