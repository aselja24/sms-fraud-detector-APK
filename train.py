"""
Обучение детектора.

Запуск:
    python train.py                                   # по ТЗ: только data/sms_train.csv
    python train.py --extra data/extra/*.csv          # + новые размеченные SMS
    python train.py --extra data/feedback/feedback.csv   # + отметки из Telegram-бота

Что обучается:
  1. weights.json    — логистическая регрессия на 14 признаках (features.py),
                       ВСЕГДА только на train (требование ТЗ); C подбирается
                       по accuracy на dev (критерий жюри: fraud <=> risk == "high");
  2. text_model.json — текстовый слой (text_model.py): символьные n-граммы +
                       логистическая регрессия на train + новых данных (--extra).
                       Учит формулировки прямо из данных, поэтому с каждым
                       новым набором SMS становится точнее без правки словаря.

Почему новые данные идут только в текстовый слой: проверка показала, что
перевешивание 14 признаков на внешних SMS ломает трудные случаи
(официальная ссылка + угроза становится high), а дообучение одного
текстового слоя — нет. Флаг --retrain-features всё же добавляет новые
данные и в признаки (под присмотром проверки качества).

Новые данные (--extra) — CSV с колонками text,label (label = fraud / ok),
как data/sms_train.csv. Строки, совпадающие с dev или data/sms_hard.csv,
выбрасываются: иначе проверка качества ниже была бы нечестной.

Проверка качества: новые модели прогоняются через весь check() (признаки +
правила + текстовый слой) на dev и на data/sms_hard.csv и сравниваются с
текущими weights.json / text_model.json. Если хоть где-то стало хуже,
файлы НЕ перезаписываются (--force — сохранить всё равно).

ВАЖНО (ТЗ): weights.json по умолчанию обучается только на sms_train.csv
даже с --extra. Для сдачи «в чистом виде» запускайте без --extra — тогда и
текстовый слой обучен только на train. В обоих файлах записано, на чём они
обучены (поле trained_on).
"""
import argparse
import csv
import importlib
import json
import os

from sklearn.linear_model import LogisticRegression

from detector import text_model
from detector.config import WEIGHTS_PATH
from detector.features import FEATURE_NAMES, extract
from detector.model import load_weights, predict_score, to_level

C_CANDIDATES = [0.03, 0.1, 0.3, 1.0, 3.0, 10.0, 30.0, 100.0]
# Сам модуль detector/check.py (detector.check в пакете — это функция check()).
check_module = importlib.import_module("detector.check")
HARD_PATH = "data/sms_hard.csv"


def _key(text: str) -> str:
    return " ".join(text.lower().split())


def load_rows(path: str) -> list[tuple[str, int]]:
    """(текст, 1 — fraud / 0 — ok). Строки с другой меткой пропускаются."""
    with open(path, encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    out = []
    for r in rows:
        label = (r.get("label") or "").strip().lower()
        if label in ("fraud", "ok") and (r.get("text") or "").strip():
            out.append((r["text"], int(label == "fraud")))
    return out


def load_dataset(path: str):
    """X (признаки) и y для одного CSV — для совместимости со старыми скриптами."""
    rows = load_rows(path)
    return [[extract(t)[n] for n in FEATURE_NAMES] for t, _ in rows], [y for _, y in rows]


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
        score = predict_score(dict(zip(feature_names, xi)), weights)
        correct += int((to_level(score) == "high") == bool(yi))
    return correct / len(y)


def fit_feature_model(rows, dev_rows, trained_on) -> dict:
    """Логистическая регрессия на признаках; C — по accuracy на dev."""
    X = [[extract(t)[n] for n in FEATURE_NAMES] for t, _ in rows]
    y = [lab for _, lab in rows]
    X_dev = [[extract(t)[n] for n in FEATURE_NAMES] for t, _ in dev_rows]
    y_dev = [lab for _, lab in dev_rows]

    best_c, best_key = None, (-1.0, -1.0)
    for c in C_CANDIDATES:
        model = LogisticRegression(C=c, max_iter=1000).fit(X, y)
        dev_acc = risk_accuracy(model, X_dev, y_dev, FEATURE_NAMES)
        train_acc = risk_accuracy(model, X, y, FEATURE_NAMES)
        print(f"  C={c:>6}: dev accuracy = {dev_acc:.3f}, train accuracy = {train_acc:.3f}")
        # Главный критерий — dev; при равенстве — train (меньше недообучения).
        if (dev_acc, train_acc) > best_key:
            best_c, best_key = c, (dev_acc, train_acc)
    print(f"  Лучший C = {best_c}")

    final = LogisticRegression(C=best_c, max_iter=1000).fit(X, y)
    return {
        "features": FEATURE_NAMES,
        "coef": final.coef_[0].tolist(),
        "intercept": float(final.intercept_[0]),
        "C": best_c,
        "trained_on": trained_on,
        "n_examples": len(rows),
    }


def pipeline_quality(weights, tmodel, dev_rows, hard_rows) -> tuple[float, float]:
    """Accuracy всего check() на dev и доля пройденных трудных случаев.
    Модели подменяются в check() только на время замера."""
    saved = check_module._weights, check_module._text_model
    try:
        check_module._weights, check_module._text_model = weights, tmodel
        dev = sum((check_module.check(t)["risk"] == "high") == bool(y) for t, y in dev_rows) / len(dev_rows)
        hard = sum(check_module.check(t)["risk"] in allowed for t, allowed in hard_rows) / max(len(hard_rows), 1)
    finally:
        check_module._weights, check_module._text_model = saved
    return dev, hard


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("train_path", nargs="?", default="data/sms_train.csv")
    parser.add_argument("--dev", default="data/sms_dev.csv")
    parser.add_argument("--extra", nargs="*", default=[], help="CSV с новыми размеченными SMS (text,label)")
    parser.add_argument("--out", default="weights.json")
    parser.add_argument("--text-out", default=text_model.TEXT_MODEL_PATH)
    parser.add_argument("--no-text", action="store_true", help="не обучать текстовый слой")
    parser.add_argument("--retrain-features", action="store_true",
                        help="добавить --extra и в обучение 14 признаков (по умолчанию — только train)")
    parser.add_argument("--force", action="store_true", help="сохранить, даже если качество упало")
    args = parser.parse_args()

    dev_rows = load_rows(args.dev)
    hard_rows = []
    if os.path.exists(HARD_PATH):
        with open(HARD_PATH, encoding="utf-8", newline="") as f:
            hard_rows = [(r["text"], r["expected_risk"].split("|")) for r in csv.DictReader(f)]

    # Обучающие данные: train + новые, без повторов и без утечки из dev/hard.
    blocked = {_key(t) for t, _ in dev_rows} | {_key(t) for t, _ in hard_rows}
    seen, dropped = set(), 0

    def collect(paths):
        nonlocal dropped
        out = []
        for path in paths:
            for text, label in load_rows(path):
                k = _key(text)
                if k in seen:
                    continue
                if k in blocked:
                    dropped += 1
                    continue
                seen.add(k)
                out.append((text, label))
        return out

    train_rows = collect([args.train_path])
    extra_rows = collect(args.extra)
    all_rows = train_rows + extra_rows
    fraud = sum(y for _, y in all_rows)
    print(f"Обучающих SMS: train {len(train_rows)} + новых {len(extra_rows)} "
          f"(всего fraud {fraud}, ok {len(all_rows) - fraud})")
    if dropped:
        print(f"  выброшено {dropped} строк, совпадающих с dev или {HARD_PATH}")

    feature_rows = all_rows if args.retrain_features else train_rows
    feature_src = [args.train_path] + (args.extra if args.retrain_features else [])
    print(f"\n1) Логистическая регрессия на признаках — обучение на {feature_src}")
    if args.retrain_features and args.extra:
        print("  ВНИМАНИЕ: признаки обучены не только на train — для сдачи по ТЗ так не делать.")
    weights = fit_feature_model(feature_rows, dev_rows, feature_src)

    tmodel = text_model.load()
    if not args.no_text:
        text_src = [args.train_path] + args.extra
        print(f"\n2) Текстовый слой (символьные n-граммы) — обучение на {text_src}")
        tmodel = text_model.fit([t for t, _ in all_rows], [y for _, y in all_rows], trained_on=text_src)
        print(f"  словарь n-грамм: {len(tmodel['vocab'])}, порог: {tmodel['threshold']}")

    print("\n3) Проверка качества всего check() (признаки + правила + текстовый слой)")
    old_weights = load_weights(WEIGHTS_PATH) if os.path.exists(WEIGHTS_PATH) else None
    old_text = text_model.load()
    new_q = pipeline_quality(weights, tmodel, dev_rows, hard_rows)
    print(f"  новые модели:   dev {new_q[0]:.3f}, {HARD_PATH} {new_q[1]:.3f}")
    worse = False
    if old_weights is not None:
        old_q = pipeline_quality(old_weights, old_text, dev_rows, hard_rows)
        print(f"  текущие модели: dev {old_q[0]:.3f}, {HARD_PATH} {old_q[1]:.3f}")
        worse = new_q[0] < old_q[0] or new_q[1] < old_q[1]
    if worse and not args.force:
        print("\nКачество упало — файлы НЕ перезаписаны (--force, чтобы сохранить всё равно).")
        raise SystemExit(1)

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(weights, f, ensure_ascii=False, indent=2)
    print(f"\nВеса сохранены в {args.out}")
    if not args.no_text:
        text_model.save(tmodel, args.text_out)
        print(f"Текстовый слой сохранён в {args.text_out}")

    print(f"\n{'признак':<18} вес")
    for name, w in sorted(zip(weights["features"], weights["coef"]), key=lambda nw: -nw[1]):
        print(f"{name:<18} {w:+.3f}")
    print(f"{'intercept':<18} {weights['intercept']:+.3f}")


if __name__ == "__main__":
    main()
