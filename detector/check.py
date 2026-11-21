import json
import sys

from detector.features import extract
from detector.lexicon import ADVICE, REASONS
from detector.links import analyze_links, brand_mismatch, spoof_reason_advice
from detector.model import load_weights, predict_score, to_level, top_reasons
from detector.config import HIGH
from detector.rules import RULE_ADVICE, RULE_FLOOR, RULE_REASONS, all_rules
from detector import text_model

_weights = None
_text_model = False   # False — ещё не загружали; None — файла нет (слой выключен)


def _get_weights():
    global _weights
    if _weights is None:
        _weights = load_weights()
    return _weights


def _get_text_model():
    global _text_model
    if _text_model is False:
        _text_model = text_model.load()
    return _text_model


def check(text: str) -> dict:
    """Оценивает SMS и возвращает {"risk", "score", "reasons", "advice"}."""
    weights = _get_weights()
    features = extract(text)
    score = predict_score(features, weights)
    reasons = top_reasons(features, weights)

    # Жёсткие правила (rules.py) поднимают нижнюю границу score. Официальный
    # домен в ссылке риск текста не снижает.
    links = analyze_links(text)
    rules = all_rules(features, links, text)
    for name in rules:
        score = max(score, RULE_FLOOR[name])
    level = to_level(score)

    # Текстовый слой поднимает medium до high для SMS без ссылок, если уверен.
    tm = _get_text_model()
    text_hit = None
    if tm and level == "medium" and not links:
        proba = text_model.predict_proba(tm, text)
        if proba >= tm["threshold"]:
            score = max(score, HIGH, round(proba * 100))
            level = to_level(score)
            text_hit = text_model.top_words(tm, text)

    names = weights["features"]
    coef_by_name = dict(zip(names, weights["coef"]))
    hit_features = [
        name for name in names
        if features.get(name, 0) and coef_by_name.get(name, 0) > 0
    ]
    hit_features.sort(key=lambda name: coef_by_name[name], reverse=True)
    advice = [ADVICE[name] for name in hit_features]

    # Причины правил — в начало списка; самое весомое правило оказывается первым.
    mismatch = brand_mismatch(text, links)
    for name in reversed(rules):
        if name == "link_spoof":
            spoofed = next(link for link in links if link.spoof)
            reason, tip = spoof_reason_advice(spoofed)
            reasons.insert(0, reason)
            advice.insert(0, tip)
        elif name in RULE_REASONS:
            # Правило «просят код» повторяет признак asks_code — убираем дубль.
            if name == "secret_request" and REASONS["asks_code"] in reasons:
                reasons.remove(REASONS["asks_code"])
                advice.remove(ADVICE["asks_code"])
            ctx = {"brand": mismatch[0].capitalize(), "host": mismatch[1]} if mismatch else {}
            reasons.insert(0, RULE_REASONS[name].format(**ctx))
            advice.insert(0, RULE_ADVICE[name])

    # Бренд в тексте не совпадает с адресом ссылки: пишем это первой причиной.
    note = None if mismatch else brand_mismatch(text, links, include_official=True)
    if rules and note:
        reasons.insert(0, RULE_REASONS["brand_mismatch"].format(brand=note[0].capitalize(), host=note[1]))
        advice.insert(0, RULE_ADVICE["brand_mismatch"])

    # Домен почти как у бренда («eline» вместо «beeline») — своя причина.
    # Если ссылка уже помечена как подделка символов, своя причина не нужна.
    look = next((link for link in links if link.lookalike and not link.spoof), None)
    if look:
        reasons.insert(0, f"адрес «{look.host}» почти как у «{look.hint}», но отличается на пару букв")
        advice.insert(0, "Не переходите по ссылке: адрес похож на настоящий, но это другой сайт.")

    if text_hit is not None:
        words = ", ".join(f"«{w}»" for w in text_hit) or "формулировки"
        reasons.insert(0, f"текст похож на мошеннические SMS из обучающих данных: {words}")
        advice.insert(0, "Такие формулировки типичны для мошенников — не выполняйте просьбу из SMS, проверьте её через официальное приложение или горячую линию.")

    # Подсказка настоящего адреса к совету про подделку бренда в домене.
    hint = next((link.hint for link in links if link.fake and link.hint), None)
    if hint and "link_spoof" not in rules and ADVICE["fake_brand_domain"] in advice:
        i = advice.index(ADVICE["fake_brand_domain"])
        advice[i] = f"{advice[i]} Настоящий сайт — {hint}."

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
