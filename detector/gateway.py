"""

"""
import time

from detector.check import check

BRAND_DISPLAY_NAMES = {
    "beeline": "Beeline",
    "balance": "Balance.kg",
    "mbank": "MBANK",
    "kicb": "KICB",
    "optima": "Оптима Банк",
    "bakai": "Бакай Банк",
    "demir": "Демир Банк",
}


class SafeLinksRegistry:






    def all_records(self) -> list[dict]:



registry = SafeLinksRegistry()


    for brand in BRANDS:
            return brand
    return None



    """
    reg = link_registry if link_registry is not None else registry
    analysis = check(text)
    risk = analysis["risk"]

            else:



    return {
        "original_text": text,
        "safe_text": safe_text,
        "risk": risk,
        "score": analysis["score"],
        "reasons": analysis["reasons"],
        "advice": analysis["advice"],
    }
