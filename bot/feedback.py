"""
Сохранение отметок пользователей бота («это мошенничество» / «нет»).

Файл data/feedback/feedback.csv в формате обучающих данных (text,label)
можно сразу передать в обучение:
    python train.py --extra data/feedback/feedback.csv

Сохраняются только текст SMS, отметка, оценка бота и время — без имени и
id пользователя. В SMS бывают личные данные, поэтому папка data/feedback/
в .gitignore и в репозиторий не попадает. Перед обучением отметки стоит
просмотреть: одна случайная или ошибочная отметка — уже шум в данных.
"""
import csv
import os
import uuid
from datetime import datetime, timezone

FEEDBACK_PATH = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "data", "feedback", "feedback.csv")
)
FIELDS = ["id", "text", "label", "predicted_risk", "created_at"]


def save_feedback(text: str, label: str, predicted_risk: str, path: str = FEEDBACK_PATH) -> None:
    """Дописывает одну отметку в CSV (создаёт файл с заголовком, если его нет)."""
    if label not in ("fraud", "ok"):
        raise ValueError(f"label должен быть fraud или ok, а не {label!r}")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    is_new = not os.path.exists(path)
    with open(path, "a", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        if is_new:
            writer.writeheader()
        writer.writerow({
            "id": uuid.uuid4().hex[:12],
            "text": text,
            "label": label,
            "predicted_risk": predicted_risk,
            "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        })
