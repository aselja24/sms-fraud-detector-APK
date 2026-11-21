"""Применение обученной логистической регрессии к признакам SMS."""
import json
import math

from detector.config import HIGH, LOW, WEIGHTS_PATH
from detector.lexicon import REASONS


def load_weights(path: str = WEIGHTS_PATH) -> dict:
    """Загружает веса модели: {"features": [...], "coef": [...], "intercept": float}."""
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def predict_score(features: dict[str, int], weights: dict) -> int:
    """sigmoid(w . x + b) * 100, округлённое до целого 0..100."""
    names = weights["features"]
    coef = weights["coef"]
    intercept = weights["intercept"]

    z = intercept
    for name, w in zip(names, coef):
        z += w * features.get(name, 0)

    probability = 1 / (1 + math.exp(-z))
    return int(round(probability * 100))


def to_level(score: int) -> str:
    """0..100 -> "low" / "medium" / "high"."""
    if score < LOW:
        return "low"
    if score < HIGH:
        return "medium"
    return "high"


def top_reasons(features: dict[str, int], weights: dict) -> list[str]:
    """Человеко-читаемые причины: сработавшие признаки с положительным
    весом, от самого весомого к наименее весомому."""
    names = weights["features"]
    coef_by_name = dict(zip(names, weights["coef"]))

    hit_features = [
        name for name in names
        if features.get(name, 0) and coef_by_name.get(name, 0) > 0
    ]
    hit_features.sort(key=lambda name: coef_by_name[name], reverse=True)
    return [REASONS[name] for name in hit_features]
