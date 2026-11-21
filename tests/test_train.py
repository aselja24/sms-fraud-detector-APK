"""Тесты обучения (train.py): новые данные, утечка, ТЗ."""
import csv
import json
import sys

import train


def _write(path, rows):
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["id", "text", "label"])
        for i, (text, label) in enumerate(rows):
            w.writerow([i, text, label])


def test_load_rows_skips_unlabeled(tmp_path):
    path = tmp_path / "x.csv"
    _write(path, [("a", "fraud"), ("b", "ok"), ("c", ""), ("", "fraud")])
    assert train.load_rows(str(path)) == [("a", 1), ("b", 0)]


def test_extra_goes_only_to_text_layer(tmp_path, monkeypatch):
    extra = tmp_path / "extra.csv"
    dev_text = train.load_rows("data/sms_dev.csv")[0][0]
    _write(extra, [
        ("Акчаны башка картага которуңуз, тез арада", "fraud"),
        ("Эртең сабак саат 9да башталат", "ok"),
        (dev_text, "fraud"),   # такая строка есть в dev — должна быть выброшена
    ])
    out, text_out = tmp_path / "w.json", tmp_path / "t.json"
    monkeypatch.setattr(sys, "argv", ["train.py", "--extra", str(extra),
                                      "--out", str(out), "--text-out", str(text_out), "--force"])
    train.main()
    weights = json.loads(out.read_text(encoding="utf-8"))
    text = json.loads(text_out.read_text(encoding="utf-8"))
    # признаки — только train (ТЗ), текстовый слой — train + новые
    assert weights["trained_on"] == ["data/sms_train.csv"]
    assert weights["n_examples"] == 200
    assert text["trained_on"] == ["data/sms_train.csv", str(extra)]
    assert text["n_examples"] == 202   # строка из dev выброшена
