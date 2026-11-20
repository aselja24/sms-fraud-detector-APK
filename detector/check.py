import json
import sys

from detector.features import extract
from detector.lexicon import ADVICE
from detector.model import load_weights, predict_score, to_level, top_reasons

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
    level = to_level(score)
    reasons = top_reasons(features, weights)

    names = weights["features"]
    coef_by_name = dict(zip(names, weights["coef"]))
    hit_features = [
        name for name in names
        if features.get(name, 0) and coef_by_name.get(name, 0) > 0
    ]
    hit_features.sort(key=lambda name: coef_by_name[name], reverse=True)
    advice = [ADVICE[name] for name in hit_features]

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
