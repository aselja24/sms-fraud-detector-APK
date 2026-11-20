"""
Обучение логистической регрессии на признаках SMS.

Запуск:
    python train.py [data/sms_train.csv] [--dev data/sms_dev.csv]

Веса обучаются ТОЛЬКО на train, параметр регуляризации C подбирается по
accuracy на dev. Результат сохраняется в weights.json.
"""
import argparse
import csv
import json

from sklearn.linear_model import LogisticRegression

from detector.features import FEATURE_NAMES, extract
from detector.model import predict_score, to_level

C_CANDIDATES = [0.03, 0.1, 0.3, 1.0, 3.0, 10.0, 30.0, 100.0]


def load_dataset(path: str):
    with open(path, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    X = [[extract(r["text"])[name] for name in FEATURE_NAMES] for r in rows]
    y = [1 if r["label"] == "fraud" else 0 for r in rows]
    return X, y


def risk_accuracy(model, X, y, feature_names) -> float:
    """Точность по реальному критерию жюри: fraud <=> risk == "high"
    (не по внутреннему порогу sklearn 0.5, а по нашим LOW/HIGH)."""
    weights = {
        "features": feature_names,
        "coef": model.coef_[0].tolist(),
        "intercept": float(model.intercept_[0]),
    }
    correct = 0
    for xi, yi in zip(X, y):
        features = dict(zip(feature_names, xi))
        score = predict_score(features, weights)
        predicted_fraud = to_level(score) == "high"
        correct += int(predicted_fraud == bool(yi))
    return correct / len(y)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("train_path", nargs="?", default="data/sms_train.csv")
    parser.add_argument("--dev", default="data/sms_dev.csv")
    parser.add_argument("--out", default="weights.json")
    args = parser.parse_args()

    X_train, y_train = load_dataset(args.train_path)
    X_dev, y_dev = load_dataset(args.dev)

    best_c = None
    best_key = (-1.0, -1.0)
    for c in C_CANDIDATES:
        model = LogisticRegression(C=c, max_iter=1000)
        model.fit(X_train, y_train)
        dev_acc = risk_accuracy(model, X_dev, y_dev, FEATURE_NAMES)
        train_acc = risk_accuracy(model, X_train, y_train, FEATURE_NAMES)
        print(
            f"C={c:>6}: dev accuracy (по уровню risk) = {dev_acc:.3f}, "
            f"train accuracy = {train_acc:.3f}"
        )
        # Главный критерий — accuracy на dev; при равенстве выбираем C с
        # лучшей accuracy на train (меньше недообучения на простых случаях).
        key = (dev_acc, train_acc)
        if key > best_key:
            best_key = key
            best_c = c

    print(f"\nЛучший C = {best_c} (dev accuracy = {best_key[0]:.3f}, train accuracy = {best_key[1]:.3f})")

    final_model = LogisticRegression(C=best_c, max_iter=1000)
    final_model.fit(X_train, y_train)

    weights = {
        "features": FEATURE_NAMES,
        "coef": final_model.coef_[0].tolist(),
        "intercept": float(final_model.intercept_[0]),
        "C": best_c,
    }
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(weights, f, ensure_ascii=False, indent=2)
    print(f"Веса сохранены в {args.out}\n")

    print(f"{'признак':<18} вес")
    for name, w in sorted(
        zip(weights["features"], weights["coef"]), key=lambda nw: -nw[1]
    ):
        print(f"{name:<18} {w:+.3f}")
    print(f"{'intercept':<18} {weights['intercept']:+.3f}")


if __name__ == "__main__":
    main()
