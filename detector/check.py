import json
import sys

from detector.config import HIGH
from detector.features import extract
from detector.lexicon import ADVICE, REASONS
from detector.model import load_weights, predict_score, to_level, top_reasons
from detector.rules import RULE_ADVICE, RULE_REASONS, hard_rule

_weights = None


def _get_weights():
    global _weights
    if _weights is None:
        _weights = load_weights()
    return _weights


def check(text: str) -> dict:
    """Оценивает SMS и возвращает {"risk", "score", "reasons", "advice"}."""
    weights = _get_weights()
    features = extract(text)
    score = predict_score(features, weights)
    reasons = top_reasons(features, weights)

    # Жёсткое правило (rules.py) поднимает риск до "high" для просьбы
    # передать код/данные карты и для просьбы о деньгах с поводом.
    rule = hard_rule(features)
    if rule:
        score = max(score, HIGH)
    level = to_level(score)

    names = weights["features"]
    coef_by_name = dict(zip(names, weights["coef"]))
    hit_features = [
        name for name in names
        if features.get(name, 0) and coef_by_name.get(name, 0) > 0
    ]
    hit_features.sort(key=lambda name: coef_by_name[name], reverse=True)
    advice = [ADVICE[name] for name in hit_features]
    if rule:
        # Правило «просят код» повторяет признак asks_code — убираем дубль.
        if rule == "secret_request" and REASONS["asks_code"] in reasons:
            reasons.remove(REASONS["asks_code"])
            advice.remove(ADVICE["asks_code"])
        reasons.insert(0, RULE_REASONS[rule])
        advice.insert(0, RULE_ADVICE[rule])

    return {
        "risk": level,
        "score": score,
        "reasons": reasons,
        "advice": advice,
    }


def main():
    if len(sys.argv) < 2:
        print("Использование: python -m detector.check \"текст SMS\"", file=sys.stderr)
        sys.exit(1)
    text = sys.argv[1]
    result = check(text)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
