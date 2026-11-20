"""Тесты сквозной функции check()."""
from detector.check import check


def test_fraud_example_is_high():
    result = check(
        "Ваша к@рт@ з а б л о к и р о в а н а, сообщите код по номеру "
        "+996 555 123456"
    )
    assert result["risk"] == "high"
    assert result["score"] >= 65
    assert "reasons" in result and len(result["reasons"]) > 0
    assert len(result["advice"]) == len(result["reasons"])


def test_ok_example_with_safety_warning_is_low():
    result = check("Ваш код подтверждения: 1234. Никому не сообщайте его")
    assert result["risk"] == "low"
    assert result["score"] < 30


def test_result_shape():
    result = check("Привет! Во сколько завтра встречаемся?")
    assert set(result.keys()) == {"risk", "score", "reasons", "advice"}
    assert isinstance(result["score"], int)
    assert result["risk"] in {"low", "medium", "high"}
