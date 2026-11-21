def check(text: str) -> dict:
    from detector.check import check as _check
    return _check(text)

__all__ = ["check"]

