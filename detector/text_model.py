"""
Обучаемый текстовый слой: символьные n-граммы + логистическая регрессия.

Зачем: основная модель (features.py) — 14 признаков по словарю. Новые
данные могут только перевесить эти признаки, но не научить модель новым
словам: каждую новую формулировку мошенников приходится вписывать в
lexicon.py вручную. Текстовый слой учится формулировкам прямо из
размеченных SMS: дали ему примеры «акчаны башка эсепке которуңуз» — он
сам запомнил, что «башка эсепке» характерно для мошенничества.

Как устроен:
  * текст проходит normalize() (снятие обфускации, ө/ү/ң и т.п.);
  * из каждого слова берутся куски по 2–5 символов (как TfidfVectorizer
    с analyzer="char_wb" в sklearn) — так ловятся и словоформы, и транслит;
  * TF-IDF + логистическая регрессия обучаются в train.py (sklearn);
  * модель сохраняется в text_model.json — словарь n-грамм с их idf и
    весом. Применение (predict) — чистый Python, без sklearn: бот и
    check() его не требуют.

Как используется (check.py): только как «второе мнение» для SMS без
ссылок, которое основная модель оценила как medium. Если слой уверен
(вероятность ≥ threshold), риск поднимается до high. Ссылки лучше
разбирает links.py, а одному текстовому слою на 200 шаблонных SMS из
train доверять нельзя — он поднимает только пограничные случаи.
"""
import json
import math
import os
import re
from collections import Counter

from detector.normalize import normalize

TEXT_MODEL_PATH = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "text_model.json"))
NGRAM_RANGE = (2, 5)
_WHITESPACE_RE = re.compile(r"\s\s+")


def char_wb_ngrams(text: str, min_n: int = NGRAM_RANGE[0], max_n: int = NGRAM_RANGE[1]) -> list[str]:
    """n-граммы символов внутри слов, с пробелом по краям слова.
    Точная копия sklearn CountVectorizer(analyzer="char_wb")."""
    text = _WHITESPACE_RE.sub(" ", text)
    ngrams = []
    for word in text.split():
        word = " " + word + " "
        length = len(word)
        for n in range(min_n, max_n + 1):
            offset = 0
            ngrams.append(word[offset:offset + n])
            while offset + n < length:
                offset += 1
                ngrams.append(word[offset:offset + n])
            if offset == 0:   # слово короче n — считаем один раз
                break
    return ngrams


def fit(texts: list[str], labels: list[int], C: float = 10.0, threshold: float = 0.6,
        trained_on: list[str] | None = None) -> dict:
    """Обучает слой и возвращает его в виде словаря для text_model.json."""
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression

    vec = TfidfVectorizer(analyzer="char_wb", ngram_range=NGRAM_RANGE,
                          sublinear_tf=True, preprocessor=normalize)
    X = vec.fit_transform(texts)
    clf = LogisticRegression(C=C, max_iter=5000).fit(X, labels)
    coef = clf.coef_[0]
    vocab = {
        term: [round(float(vec.idf_[j]), 6), round(float(coef[j]), 6)]
        for term, j in vec.vocabulary_.items()
    }
    return {
        "ngram_range": list(NGRAM_RANGE),
        "C": C,
        "threshold": threshold,
        "intercept": float(clf.intercept_[0]),
        "trained_on": trained_on or [],
        "n_examples": len(texts),
        "vocab": vocab,
    }


def _vector(model: dict, text: str) -> dict[str, float]:
    """TF-IDF вектор текста (sublinear tf, l2-норма) — как в sklearn."""
    lo, hi = model["ngram_range"]
    counts = Counter(g for g in char_wb_ngrams(normalize(text), lo, hi) if g in model["vocab"])
    weights = {g: (1 + math.log(c)) * model["vocab"][g][0] for g, c in counts.items()}
    norm = math.sqrt(sum(w * w for w in weights.values()))
    return {g: w / norm for g, w in weights.items()} if norm else {}


def predict_proba(model: dict, text: str) -> float:
    """Вероятность мошенничества по тексту (0..1)."""
    vec = _vector(model, text)
    z = model["intercept"] + sum(x * model["vocab"][g][1] for g, x in vec.items())
    return 1 / (1 + math.exp(-z))


def top_words(model: dict, text: str, k: int = 3) -> list[str]:
    """Слова SMS, которые сильнее всего тянут к «мошенничеству» — для причины."""
    vec = _vector(model, text)
    contrib = sorted(((x * model["vocab"][g][1], g) for g, x in vec.items()), reverse=True)
    norm_words = normalize(text).split()
    raw_words = text.split()
    # Показываем слово как в SMS («эсебиңизди»), если нормализация не
    # склеивала и не разбивала слова; иначе — нормализованное.
    shown = raw_words if len(raw_words) == len(norm_words) else norm_words
    strip = ".,!?:;«»\"'()"
    found = []
    for value, gram in contrib:
        if value <= 0 or len(found) >= k:
            break
        piece = gram.strip()
        if len(piece) < 3:
            continue
        for norm, word in zip(norm_words, shown):
            if piece in norm.strip(strip):
                word = word.strip(strip)
                if word not in found and len(word) > 2:
                    found.append(word)
                break
    return found


def save(model: dict, path: str = TEXT_MODEL_PATH) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(model, f, ensure_ascii=False, separators=(",", ":"))


def load(path: str = TEXT_MODEL_PATH) -> dict | None:
    """Модель из файла или None, если её нет (тогда слой выключен)."""
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)
