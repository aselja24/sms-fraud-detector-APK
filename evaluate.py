"""
Оценка детектора на размеченном CSV.
Запуск: python evaluate.py data/sms_dev.csv

fraud считается тогда, когда risk == "high" (low и medium == ok, как в
data/CLARIFICATIONS_RU.md).
"""
import argparse
import csv

from detector.check import check


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv_path")
    args = parser.parse_args()

    with open(args.csv_path, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    tp = fp = tn = fn = 0
    errors = []

    for row in rows:
        result = check(row["text"])
        predicted_fraud = result["risk"] == "high"
        actual_fraud = row["label"] == "fraud"

        if predicted_fraud and actual_fraud:
            tp += 1
        elif predicted_fraud and not actual_fraud:
            fp += 1
        elif not predicted_fraud and not actual_fraud:
            tn += 1
        else:
            fn += 1

        if predicted_fraud != actual_fraud:
            errors.append((row["id"], row["label"], result["risk"], result["score"], row["text"]))

    total = len(rows)
    accuracy = (tp + tn) / total if total else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0

    print(f"Всего примеров: {total}")
    print(f"Accuracy:  {accuracy:.3f}")
    print(f"Precision (fraud): {precision:.3f}")
    print(f"Recall (fraud):    {recall:.3f}")
    print()
    print("Матрица ошибок (строки — факт, столбцы — прогноз):")
    print(f"{'':15}{'pred ok':>10}{'pred fraud':>12}")
    print(f"{'actual ok':15}{tn:>10}{fp:>12}")
    print(f"{'actual fraud':15}{fn:>10}{tp:>12}")

    if errors:
        print(f"\nОшибки ({len(errors)}):")
        for id_, label, risk, score, text in errors:
            print(f"  {id_}  label={label:<6} risk={risk:<6} score={score:<4} {text}")
    else:
        print("\nОшибок нет.")


if __name__ == "__main__":
    main()
