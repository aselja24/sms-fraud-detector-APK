"""Тесты обучаемого текстового слоя (detector/text_model.py)."""
import csv
import importlib
import os

import pytest

from detector import text_model as tm
from detector.normalize import normalize

check_module = importlib.import_module("detector.check")
ROOT = os.path.join(os.path.dirname(__file__), "..")


def _train_rows():
    with open(os.path.join(ROOT, "data", "sms_train.csv"), encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    return [r["text"] for r in rows], [int(r["label"] == "fraud") for r in rows]


@pytest.fixture(scope="module")
def model():
    texts, labels = _train_rows()
    return tm.fit(texts, labels)


def test_char_ngrams_match_sklearn():
    from sklearn.feature_extraction.text import CountVectorizer
    # lowercase=False: в text_model текст уже нормализован (и в нижнем регистре)
    analyzer = CountVectorizer(analyzer="char_wb", ngram_range=(2, 5), lowercase=False).build_analyzer()
    for text in ["мбанк  kg", "Сиздин картаңыз", "a", "к.о.д 1234"]:
        assert tm.char_wb_ngrams(text) == analyzer(text)


def test_pure_python_proba_matches_sklearn(model):
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    texts, labels = _train_rows()
    vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), sublinear_tf=True, preprocessor=normalize)
    clf = LogisticRegression(C=model["C"], max_iter=5000).fit(vec.fit_transform(texts), labels)
    for text in ["Акчаны башка картага которуңуз", "Привет, как дела?", "Вы выиграли приз!"]:
        assert abs(tm.predict_proba(model, text) - clf.predict_proba(vec.transform([text]))[0, 1]) < 1e-4


def test_top_words_show_original_spelling(model):
    words = tm.top_words(model, "Эсебиңизди коргоо үчүн акчаны башка эсепке которуңуз")
    assert words and all(w in "Эсебиңизди коргоо үчүн акчаны башка эсепке которуңуз" for w in words)


def test_missing_model_file_disables_layer(tmp_path):
    assert tm.load(str(tmp_path / "нет.json")) is None


def test_save_and_load_roundtrip(model, tmp_path):
    path = str(tmp_path / "m.json")
    tm.save(model, path)
    loaded = tm.load(path)
    assert abs(tm.predict_proba(loaded, "Срочно переведите деньги") - tm.predict_proba(model, "Срочно переведите деньги")) < 1e-5


def _always_fraud_model():
    # Модель, которая на любой текст отвечает «мошенничество» с вероятностью ~1.
    return {"ngram_range": [2, 5], "threshold": 0.6, "intercept": 50.0, "vocab": {}}


def test_layer_only_lifts_medium_without_links():
    saved = check_module._text_model
    try:
        check_module._text_model = _always_fraud_model()
        # medium без ссылки -> слой поднимает до high и объясняет почему
        medium = "Срочно перезвони, когда освободишься, по поводу дачи"
        result = check_module.check(medium)
        assert result["risk"] == "high"
        assert result["reasons"][0].startswith("текст похож на мошеннические SMS")
        assert len(result["reasons"]) == len(result["advice"])
        # low не трогаем
        assert check_module.check("Привет! Во сколько завтра встречаемся?")["risk"] == "low"
        # SMS со ссылкой не трогаем — ссылки разбирает links.py
        with_link = "Вам отправили документ. Откройте ссылку для просмотра: https://example.com"
        assert check_module.check(with_link)["risk"] == "medium"
    finally:
        check_module._text_model = saved
