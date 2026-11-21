"""Веб-демо шлюза SakBol: пульт оператора, страница-стоп и API.
Запуск: python gateway_server.py (http://127.0.0.1:8000)."""
import argparse
import csv
import html
import logging
import os
import re
import sys

from aiohttp import web

from bot.i18n import translate as translate_check
from detector.gateway import defang, registry, run_stream, sanitize_sms

MAX_TEXT_LEN = 2000
MAX_SENDER_LEN = 40
_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
# Наборы для потока — размеченные CSV из data/ (кроме финальной проверки).
_EXCLUDED_DATASETS = {"sms_phishing_test_150.csv"}
_MAX_STREAM_ROWS = 2000


def _read_csv(path: str) -> list[dict]:
    # utf-8-sig: у части CSV в начале BOM.
    with open(path, encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def discover_datasets(data_dir: str | None = None) -> dict[str, tuple[str, str]]:
    """{ключ: (путь, подпись)} для размеченных CSV в data/."""
    data_dir = data_dir or _DATA_DIR
    found = {}
    try:
        names = sorted(os.listdir(data_dir))
    except OSError:
        return found
    for name in names:
        path = os.path.join(data_dir, name)
        if not name.endswith(".csv") or name in _EXCLUDED_DATASETS or not os.path.isfile(path):
            continue
        try:
            rows = _read_csv(path)
        except (OSError, UnicodeDecodeError, csv.Error):
            continue
        if not rows or not {"text", "label"} <= set(rows[0]):
            continue
        fraud = sum((r.get("label") or "").strip() == "fraud" for r in rows)
        title = f"{name[:-4]} — {len(rows)} SMS ({fraud} мошеннических)"
        found[name[:-4]] = (path, title)
    return found


LANGS = ("ru", "ky")

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
        "connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; "
        "frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}

# --- Тексты страницы-стоп --------------------------------------------------

STOP_TEXT = {
    "ru": {
        "badge": "Опасная ссылка",
        "title": "Переход остановлен",
        "subtitle": "Защитный шлюз оператора SakBol не открыл эту ссылку из SMS. Сайт мошенников не загрузился — ваши данные в безопасности.",
        "why": "Почему ссылка опасна",
        "also": "Что ещё насторожило в SMS",
        "fake_url": "Адрес из SMS (не открывайте и не пересылайте):",
        "todo": "Что делать",
        "todo_items": [
            "Не вводите коды из SMS, пароли и данные карты на сайтах из сообщений.",
            "Если уже ввели данные — сразу позвоните в банк и заблокируйте карту.",
            "Заходите в банк и к оператору только через официальное приложение или сайт, набранный вручную.",
        ],
        "official": "Открыть настоящий сайт {brand}: {domain}",
        "close": "Закрыть страницу",
        "unknown_brand": "известного сервиса",
        "footer": "Шлюз безопасных ссылок SakBol. Демо для хакатона INAI 2026.",
        "not_found_badge": "Ссылка шлюза",
        "not_found_title": "Ссылка не найдена",
        "not_found": "Такой защищённой ссылки нет или она устарела. Не возвращайтесь к исходному SMS и не открывайте адрес из него.",
    },
    "ky": {
        "badge": "Коркунучтуу шилтеме",
        "title": "Өтүү токтотулду",
        "subtitle": "SakBol оператордук коргоо шлюзу SMSтеги бул шилтемени ачкан жок. Алдамчылардын сайты жүктөлгөн жок — маалыматыңыз коопсуз.",
        "why": "Шилтеме эмне үчүн коркунучтуу",
        "also": "SMSте дагы эмне шектүү",
        "fake_url": "SMSтеги дарек (ачпаңыз жана эч кимге жибербеңиз):",
        "todo": "Эмне кылуу керек",
        "todo_items": [
            "Билдирүүдөгү сайттарга SMS коддорду, сырсөздөрдү жана карта маалыматын киргизбеңиз.",
            "Эгер маалыматты киргизип алсаңыз — дароо банкка чалып, картаны бөгөттөңүз.",
            "Банкка жана операторго расмий тиркеме же колго терилген сайт аркылуу гана кириңиз.",
        ],
        "official": "Чыныгы {brand} сайтын ачуу: {domain}",
        "close": "Баракты жабуу",
        "unknown_brand": "белгилүү кызмат",
        "footer": "SakBol коопсуз шилтемелер шлюзу. INAI 2026 хакатону үчүн демо.",
        "not_found_badge": "Шлюз шилтемеси",
        "not_found_title": "Шилтеме табылган жок",
        "not_found": "Мындай корголгон шилтеме жок же анын мөөнөтү бүткөн. Баштапкы SMSке кайтпаңыз жана андагы даректи ачпаңыз.",
    },
}

# Фразы шлюза, которых нет в check() (их переводит bot/i18n.py).
_KY_GATEWAY = [
    (re.compile(r"ссылка ведёт на неофициальный адрес под видом (?P<b>.+)"),
     lambda m: f"шилтеме {m['b']} атынан расмий эмес дарекке алып барат"),
    (re.compile(r"адрес в подозрительной доменной зоне или со словами, типичными для фишинга"),
     lambda m: "дарек шектүү домен зонасында же фишингге мүнөздүү сөздөр менен жазылган"),
    (re.compile(r"ссылка пришла в SMS с признаками мошенничества(?:: (?P<r>.+))?"),
     lambda m: "шилтеме алдамчылык белгилери бар SMS менен келди"
               + (f": {translate_check(m['r'], 'ky')}" if m["r"] else "")),
]


def tr(text: str, lang: str) -> str:
    if lang != "ky":
        return text
    for pattern, render in _KY_GATEWAY:
        m = pattern.fullmatch(text)
        if m:
            return render(m)
    return translate_check(text, "ky")


def _cap(text: str) -> str:
    return text[:1].upper() + text[1:]


def fill(template: str, **values: str) -> str:
    """Подставляет {{name}}. Значения уже должны быть безопасным HTML."""
    return re.sub(r"\{\{(\w+)\}\}", lambda m: values[m.group(1)], template)


STOP_PAGE_HTML = """<!DOCTYPE html>
<html lang="{{lang}}">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>{{title}} — SakBol</title>
<style>
  :root {
    --bg:#F4F4F0; --panel:#FFFFFF; --soft:#F4F4F0; --ink:#1D1E20; --muted:#6E6E68; --line:#E4E3DC;
    --nav:#1E1F21; --nav-ink:#F4F4F0; --nav-muted:#A9A9A2;
    --accent:#FFDF4A; --accent-ink:#1D1E20; --accent-soft:#FFF7D1; --accent-line:#F2D35B;
    --red:#B0392C; --red-soft:#F8EBE8; --green:#2C7A4B; --green-soft:#EBF4EE; --amber:#8A5B00; --amber-soft:#FCF2DC;
    --phone:#2A2B2D; --screen:#E9EFE0;
    --sans:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
    --mono:ui-monospace,"SF Mono",Menlo,Consolas,"Liberation Mono",monospace;
    color-scheme: light dark;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg:#151617; --panel:#1F2022; --soft:#28292B; --ink:#ECECE8; --muted:#A3A39C; --line:#36373A;
      --nav:#0E0F10; --accent-soft:#3A3416; --accent-line:#6B5C1C;
      --red:#F08A7C; --red-soft:#3A2522; --green:#7CCB98; --green-soft:#1E3125; --amber:#E6B04E; --amber-soft:#3A2F17;
      --phone:#0E0F10; --screen:#2B3326;
    }
  }
  * { box-sizing:border-box; margin:0; padding:0; }
  body { background:var(--bg); color:var(--ink); font:16px/1.55 var(--sans); min-height:100vh; }
  .wrap { max-width:760px; margin:0 auto; padding:0 20px; }
  .nav { background:var(--nav); color:var(--nav-ink); }
  .nav-in { display:flex; align-items:center; justify-content:space-between; gap:16px; height:72px; }
  .brand { font-size:19px; font-weight:600; }
  .lang a { color:var(--nav-muted); text-decoration:none; margin-left:18px; font-size:15px; }
  .lang a.on { color:var(--accent); }
  :focus-visible { outline:2px solid var(--ink); outline-offset:2px; }
  .nav :focus-visible { outline-color:var(--accent); }
  main.wrap { padding-top:32px; padding-bottom:40px; }
  .card { background:var(--panel); border-radius:20px; padding:32px 28px; }
  .badge { display:inline-block; background:var(--red-soft); color:var(--red); font-size:11px; font-weight:700; letter-spacing:.04em;
           text-transform:uppercase; padding:7px 14px; border-radius:999px; margin-bottom:16px; }
  h1 { font-size:clamp(28px,5vw,38px); line-height:1.15; font-weight:700; letter-spacing:-.01em; margin-bottom:10px; }
  .lead { color:var(--muted); font-size:17px; margin-bottom:26px; }
  .box { background:var(--soft); border-radius:12px; padding:18px; margin-bottom:12px; }
  .box.red { background:var(--red-soft); }
  .box h2 { font-size:11px; font-weight:600; letter-spacing:.04em; text-transform:uppercase; color:var(--muted); margin-bottom:8px; }
  .box.red h2 { color:var(--red); }
  .label { font-size:14px; color:var(--muted); margin-top:12px; }
  .addr { display:inline-block; margin-top:4px; font:500 15px/1.5 var(--mono); color:var(--red); background:var(--panel);
          padding:4px 10px; border-radius:6px; word-break:break-all; text-decoration:line-through; text-decoration-thickness:2px; }
  ul { padding-left:20px; }
  li + li { margin-top:6px; }
  .actions { display:flex; flex-wrap:wrap; gap:12px; margin-top:24px; }
  .btn { display:inline-flex; align-items:center; justify-content:center; min-height:50px; border-radius:12px; padding:0 22px;
         font:600 16px/1.3 var(--sans); text-decoration:none; cursor:pointer; border:0; }
  .primary { background:var(--accent); color:var(--accent-ink); }
  .quiet { background:var(--soft); color:var(--ink); }
  footer { color:var(--muted); font-size:13px; margin-top:20px; }
  @media (max-width:560px) { .card { padding:24px 18px; } .btn { width:100%; } }
</style>
</head>
<body>
<header class="nav">
  <div class="wrap nav-in"><span class="brand">SakBol</span><nav class="lang" aria-label="Язык / Тил">{{lang_links}}</nav></div>
</header>
<main class="wrap">
  <div class="card">
    <span class="badge">{{badge}}</span>
    <h1>{{title}}</h1>
    <p class="lead">{{subtitle}}</p>
    {{body}}
    <div class="actions">
      {{official_button}}
      <button class="btn quiet" type="button" onclick="window.close()">{{close}}</button>
    </div>
  </div>
  <footer>{{footer}}</footer>
</main>
</body>
</html>
"""


def _lang(request: web.Request) -> str:
    lang = request.query.get("lang", "")
    if lang in LANGS:
        return lang
    accept = request.headers.get("Accept-Language", "").lower()
    return "ky" if accept.startswith("ky") else "ru"


def _lang_links(path: str, lang: str) -> str:
    names = {"ky": "Кыргызча", "ru": "Русский"}
    links = []
    for code in ("ky", "ru"):
        cls = ' class="on"' if code == lang else ""
        links.append(f'<a href="{html.escape(path)}?lang={code}"{cls}>{names[code]}</a>')
    return "".join(links)


def render_stop_page(record, lang: str, path: str) -> str:
    s = STOP_TEXT[lang]
    esc = html.escape
    reason = _cap(tr(record.reason, lang))
    others = [r for r in record.reasons if r != record.reason]
    body = (
        f'<section class="box red"><h2>{esc(s["why"])}</h2><p>{esc(reason)}.</p>'
        f'<p class="label">{esc(s["fake_url"])}</p>'
        f'<span class="addr">{esc(defang(record.original_url))}</span></section>'
    )
    if others:
        items = "".join(f"<li>{esc(_cap(tr(r, lang)))}</li>" for r in others)
        body += f'<section class="box"><h2>{esc(s["also"])}</h2><ul>{items}</ul></section>'
    todo = "".join(f"<li>{esc(item)}</li>" for item in s["todo_items"])
    body += f'<section class="box"><h2>{esc(s["todo"])}</h2><ul>{todo}</ul></section>'

    official = ""
    if record.official_url:
        label = s["official"].format(brand=record.brand_name or record.official_domain, domain=record.official_domain)
        official = (f'<a class="btn primary" href="{esc(record.official_url)}" target="_blank" '
                    f'rel="noopener noreferrer">{esc(label)}</a>')

    return fill(
        STOP_PAGE_HTML,
        lang=lang,
        lang_links=_lang_links(path, lang),
        badge=esc(s["badge"]),
        title=esc(s["title"]),
        subtitle=esc(s["subtitle"]),
        body=body,
        official_button=official,
        close=esc(s["close"]),
        footer=esc(s["footer"]),
    )


def render_not_found(lang: str, path: str) -> str:
    s = STOP_TEXT[lang]
    return fill(
        STOP_PAGE_HTML,
        lang=lang,
        lang_links=_lang_links(path, lang),
        badge=html.escape(s["not_found_badge"]),
        title=html.escape(s["not_found_title"]),
        subtitle=html.escape(s["not_found"]),
        body="",
        official_button="",
        close=html.escape(s["close"]),
        footer=html.escape(s["footer"]),
    )


# --- Пульт оператора --------------------------------------------------------

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SakBol — шлюз безопасных ссылок</title>
<style>
  :root {
    --bg:#F4F4F0; --panel:#FFFFFF; --soft:#F4F4F0; --ink:#1D1E20; --muted:#6E6E68; --line:#E4E3DC;
    --nav:#1E1F21; --nav-ink:#F4F4F0; --nav-muted:#A9A9A2;
    --accent:#FFDF4A; --accent-ink:#1D1E20; --accent-soft:#FFF7D1; --accent-line:#F2D35B;
    --red:#B0392C; --red-soft:#F8EBE8; --green:#2C7A4B; --green-soft:#EBF4EE; --amber:#8A5B00; --amber-soft:#FCF2DC;
    --phone:#2A2B2D; --screen:#E9EFE0;
    --sans:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
    --mono:ui-monospace,"SF Mono",Menlo,Consolas,"Liberation Mono",monospace;
    color-scheme: light dark;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg:#151617; --panel:#1F2022; --soft:#28292B; --ink:#ECECE8; --muted:#A3A39C; --line:#36373A;
      --nav:#0E0F10; --accent-soft:#3A3416; --accent-line:#6B5C1C;
      --red:#F08A7C; --red-soft:#3A2522; --green:#7CCB98; --green-soft:#1E3125; --amber:#E6B04E; --amber-soft:#3A2F17;
      --phone:#0E0F10; --screen:#2B3326;
    }
  }
  * { box-sizing:border-box; margin:0; padding:0; }
  html { scroll-behavior:smooth; }
  @media (prefers-reduced-motion: reduce) { html { scroll-behavior:auto; } }
  body { background:var(--bg); color:var(--ink); font:15px/1.5 var(--sans); }
  .wrap { max-width:1200px; margin:0 auto; padding:0 32px; }
  .sr-only { position:absolute; width:1px; height:1px; overflow:hidden; clip:rect(0 0 0 0); }
  [hidden] { display:none !important; }
  button, input, select, textarea { font:inherit; color:inherit; }
  :focus-visible { outline:2px solid var(--ink); outline-offset:2px; }
  code { font-family:var(--mono); font-size:.9em; }
  .label { display:block; font-size:11px; font-weight:600; letter-spacing:.04em; text-transform:uppercase; color:var(--muted); margin-bottom:8px; }
  .muted { color:var(--muted); }

  /* верхняя панель */
  .nav { background:var(--nav); color:var(--nav-ink); }
  .nav-in { display:flex; align-items:center; gap:32px; height:76px; }
  .brand { font-size:20px; font-weight:600; margin-right:40px; }
  .nav a { color:var(--nav-muted); text-decoration:none; }
  .nav a:hover { color:var(--nav-ink); }
  .nav a.on { color:var(--accent); }
  .nav :focus-visible { outline-color:var(--accent); }
  .nav-pill { margin-left:auto; background:#3A3B3D; font-size:11px; font-weight:600; letter-spacing:.04em; text-transform:uppercase;
              padding:9px 16px; border-radius:999px; white-space:nowrap; }

  /* заголовок со счётчиками */
  .hero { display:grid; grid-template-columns:minmax(0,1fr) auto; align-items:end; gap:20px 40px; padding:28px 0 24px; }
  .hero h1 { font-size:32px; line-height:1.15; font-weight:700; letter-spacing:-.01em; margin-bottom:8px; }
  .hero p { color:var(--muted); font-size:16px; }
  .counters { display:grid; grid-template-columns:repeat(4, auto); gap:4px 28px; }
  .counters div { display:flex; flex-direction:column-reverse; justify-content:flex-end; }
  .counters dd { font-size:24px; font-weight:700; line-height:1.15; font-variant-numeric:tabular-nums; }
  .counters dt { font-size:12px; color:var(--muted); }

  /* карточки-разделы */
  main { display:grid; gap:24px; padding-bottom:56px; }
  .card { background:var(--panel); border-radius:20px; padding:28px; min-width:0; scroll-margin-top:16px; }
  .card-head { display:flex; justify-content:space-between; align-items:baseline; gap:16px; margin-bottom:20px; }
  .card h2 { font-size:20px; font-weight:600; line-height:1.3; }
  .card > h2 { margin-bottom:20px; }
  .note { color:var(--muted); max-width:72ch; margin-bottom:16px; }

  /* 1. Проверить SMS */
  .check { display:grid; grid-template-columns:minmax(0,3fr) minmax(0,2fr); gap:36px; }
  .field { display:block; margin-bottom:18px; }
  input[type=text], textarea, select { width:100%; background:var(--soft); border:1px solid var(--line); border-radius:10px; padding:12px 14px; font-size:16px; }
  textarea { display:block; resize:vertical; min-height:112px; line-height:1.45; }
  .btn-main { display:inline-flex; align-items:center; gap:8px; background:var(--accent); color:var(--accent-ink); border:0; border-radius:12px;
              height:50px; padding:0 26px; font-weight:600; font-size:16px; cursor:pointer; }
  .btn-main:hover { filter:brightness(.97); }
  .btn-main:disabled { opacity:.6; cursor:progress; }
  .examples { display:grid; gap:18px; align-content:start; }
  .chips { display:flex; flex-wrap:wrap; gap:8px; }
  .example { background:var(--soft); border:1px solid transparent; border-radius:10px; padding:8px 12px; font-size:13px; cursor:pointer; text-align:left; }
  .example:hover { border-color:var(--line); }
  .example.on { background:var(--accent-soft); border-color:var(--accent-line); }

  /* 2. Путь SMS через шлюз */
  .transit { display:grid; grid-template-columns:minmax(0,1fr) 220px minmax(0,1fr); }
  .side { display:flex; flex-direction:column; min-width:0; }
  .side-head { height:44px; }
  .side-head .label { margin-bottom:2px; }
  .from { font-size:13px; color:var(--muted); }
  .bubble { flex:1; min-height:104px; padding:16px 18px; border-radius:16px 16px 16px 4px; white-space:pre-wrap; overflow-wrap:anywhere; font-size:16px; line-height:1.5; }
  .bubble.before { background:var(--soft); }
  .bubble.after { background:var(--screen); }
  .bubble del { color:var(--red); background:var(--red-soft); text-decoration-thickness:2px; font-family:var(--mono); font-size:.86em; padding:1px 4px; border-radius:4px; }
  .bubble a { color:var(--green); font-weight:600; text-underline-offset:3px; }
  .gate { position:relative; margin-top:44px; display:flex; flex-direction:column; align-items:center; justify-content:center; gap:4px; text-align:center; padding:0 14px; }
  .gate::before { content:""; position:absolute; left:10px; right:10px; top:50%; height:2px; background:var(--gate, var(--line)); }
  .gate::after { content:""; position:absolute; right:6px; top:calc(50% - 5px); border:6px solid transparent; border-left-color:var(--gate, var(--line)); border-right:0; }
  .gate > * { position:relative; background:var(--panel); padding:0 8px; }
  .gate small { font-size:11px; font-weight:600; letter-spacing:.04em; text-transform:uppercase; color:var(--muted); }
  .gate strong { font-size:16px; font-weight:600; white-space:nowrap; }
  .badge { font-size:11px; font-weight:700; letter-spacing:.04em; text-transform:uppercase; padding:6px 12px; border-radius:999px; white-space:nowrap; }
  .b-low { background:var(--green-soft); color:var(--green); } .b-medium { background:var(--amber-soft); color:var(--amber); } .b-high { background:var(--red-soft); color:var(--red); }
  .t-low { color:var(--green); } .t-medium { color:var(--amber); } .t-high { color:var(--red); }

  .decision { display:grid; grid-template-columns:minmax(0,1fr) minmax(0,1fr); gap:24px; margin-top:24px; }
  .box { background:var(--soft); border-radius:12px; padding:18px; min-width:0; }
  .sender-line { padding:10px 12px; border-radius:10px; background:var(--green-soft); margin-bottom:14px; font-size:14px; }
  .sender-line.bad { background:var(--red-soft); }
  .sender-line small { display:block; color:var(--muted); font-size:13px; margin-top:2px; }
  .links { list-style:none; display:grid; gap:10px; }
  .links li { display:grid; grid-template-columns:92px minmax(0,1fr); gap:2px 12px; font-size:14px; }
  .links li + li { padding-top:10px; border-top:1px solid var(--line); }
  .status { font-weight:600; font-size:13px; }
  .status.blocked { color:var(--red); } .status.kept { color:var(--green); }
  .links code { overflow-wrap:anywhere; }
  .links .why { grid-column:2; color:var(--muted); font-size:13px; }
  .reasons { padding-left:18px; font-size:14px; }
  .reasons li + li { margin-top:4px; }
  .raised { font-size:13px; color:var(--muted); margin-bottom:10px; }

  /* 3. Поток */
  .stream-ctl { display:flex; flex-wrap:wrap; gap:10px; }
  .stream-ctl select { flex:1 1 300px; width:auto; }
  .btn-dark { background:var(--ink); color:var(--panel); border:0; border-radius:10px; padding:0 22px; min-height:48px; font-weight:600; cursor:pointer; }
  .btn-dark:disabled { opacity:.6; cursor:progress; }
  .progress { color:var(--muted); font-size:14px; margin:16px 0 8px; font-variant-numeric:tabular-nums; }
  .feed { max-height:360px; overflow-y:auto; border:1px solid var(--line); border-radius:12px; }
  .feed-row { display:grid; grid-template-columns:52px minmax(0,1fr) 130px; gap:12px; padding:9px 14px; border-bottom:1px solid var(--line); font-size:14px; }
  .feed-row:last-child { border-bottom:0; }
  .feed-row b { font-variant-numeric:tabular-nums; }
  .feed-row .txt { overflow-wrap:anywhere; }
  .feed-row .txt a { color:var(--green); }
  .feed-row .truth { color:var(--muted); font-size:13px; text-align:right; }
  .summary { display:grid; grid-template-columns:repeat(3, minmax(0,1fr)); gap:16px; margin-top:18px; }
  .summary div { border-radius:12px; padding:16px 18px; }
  .summary .good { background:var(--green-soft); } .summary .bad { background:var(--red-soft); }
  .summary dd { font-size:26px; font-weight:700; font-variant-numeric:tabular-nums; }
  .summary .good dd { color:var(--green); } .summary .bad dd { color:var(--red); }
  .summary dt { font-size:14px; }
  .remarks { margin-top:14px; padding-left:18px; color:var(--muted); font-size:14px; }
  .remarks li + li { margin-top:4px; }
  .remarks code { color:var(--red); }

  /* 4. Реестр */
  .quiet { background:none; border:0; color:var(--muted); text-decoration:underline; text-underline-offset:3px; cursor:pointer; font-size:14px; }
  .table { overflow-x:auto; }
  table { width:100%; border-collapse:collapse; font-size:14px; }
  th, td { text-align:left; padding:10px 16px 10px 0; border-bottom:1px solid var(--line); vertical-align:top; }
  th:last-child, td:last-child { padding-right:0; }
  th { font-size:11px; font-weight:600; letter-spacing:.04em; text-transform:uppercase; color:var(--muted); white-space:nowrap; }
  td code { color:var(--red); overflow-wrap:anywhere; }
  td:nth-child(3) { min-width:240px; }
  td:nth-child(1), td:nth-child(5) { white-space:nowrap; }
  td a { color:var(--ink); }
  .num { text-align:right; font-variant-numeric:tabular-nums; }
  .empty { color:var(--muted); }

  @media (max-width:860px) {
    .wrap { padding:0 16px; }
    .nav-in { height:64px; gap:16px; }
    .brand { margin-right:0; }
    .nav a { display:none; }
    .nav-pill { font-size:10px; padding:8px 12px; }
    .hero { grid-template-columns:minmax(0,1fr); }
    .hero h1 { font-size:26px; }
    .counters { grid-template-columns:repeat(2, minmax(0,1fr)); }
    .card { padding:22px 16px; }
    .check, .decision, .summary { grid-template-columns:minmax(0,1fr); }
    .transit { grid-template-columns:minmax(0,1fr); }
    .side-head { height:auto; margin-bottom:8px; }
    .gate { margin:0; padding:18px 0; }
    .gate::after { display:none; }
    .feed-row { grid-template-columns:40px minmax(0,1fr); }
    .feed-row .truth { grid-column:2; text-align:left; }
  }
</style>
</head>
<body>
<header class="nav">
  <div class="wrap nav-in">
    <span class="brand">SakBol</span>
    <a href="#check" class="on">Проверка SMS</a>
    <a href="#stream">Поток SMS</a>
    <a href="#records">Реестр</a>
    <span class="nav-pill">Демонстрация · не реальная сеть</span>
  </div>
</header>

<div class="wrap">
  <div class="hero">
    <div>
      <span class="label">Защита до того, как SMS прочитали</span>
      <h1>SakBol — шлюз безопасных ссылок</h1>
      <p>Опасные ссылки подменяются в сети оператора до доставки SMS абоненту.</p>
    </div>
    <dl class="counters" id="stats" aria-label="Счётчики шлюза"></dl>
  </div>
</div>

<main class="wrap">
  <section class="card" id="check" aria-labelledby="check-h">
    <h2 id="check-h">Проверить SMS</h2>
    <div class="check">
      <div>
        <label class="field"><span class="label">Отправитель — видит только оператор, можно не указывать</span>
          <input type="text" id="sender" maxlength="40" placeholder="MBANK, 4444 или +996 555 123456" autocomplete="off"></label>
        <label class="field"><span class="label">Текст SMS</span>
          <textarea id="sms" maxlength="2000" rows="4">Куттуктайбыз! Сиз 50 000 сом уттуңуз. Алуу үчүн шилтемеге өтүңүз: https://my-beeline.kg.example</textarea></label>
        <button class="btn-main" id="run" type="button">Пропустить через шлюз <span aria-hidden="true">→</span></button>
      </div>
      <div class="examples" id="presets" aria-label="Примеры SMS"></div>
    </div>
  </section>

  <section class="card" aria-labelledby="transit-h" aria-live="polite">
    <h2 id="transit-h">Путь SMS через шлюз</h2>
    <div class="transit">
      <div class="side">
        <div class="side-head"><span class="label">Пришло в сеть</span><p class="from" id="fromBefore"></p></div>
        <div class="bubble before" id="before"></div>
      </div>
      <div class="gate" id="gate">
        <small>шлюз</small>
        <strong id="gateVerdict">ждёт SMS</strong>
        <span class="badge" id="gateRisk"></span>
      </div>
      <div class="side">
        <div class="side-head"><span class="label">Доставлено абоненту</span><p class="from" id="fromAfter"></p></div>
        <div class="bubble after" id="after"></div>
      </div>
    </div>
    <div class="decision" id="decision" hidden>
      <div class="box"><span class="label">Ссылки в SMS</span><div id="decisionLinks"></div></div>
      <div class="box"><span class="label">Что насторожило</span><div id="decisionReasons"></div></div>
    </div>
  </section>

  <section class="card" id="stream" aria-labelledby="stream-h">
    <h2 id="stream-h">Поток SMS</h2>
    <p class="note">Прогон целого набора через шлюз. Для оператора главное — не испортить честные SMS, поэтому сводка начинается с них.</p>
    <div class="stream-ctl">
      <label class="sr-only" for="dataset">Набор SMS</label>
      <select id="dataset"></select>
      <button class="btn-dark" id="streamBtn" type="button">Запустить поток</button>
    </div>
    <div id="streamOut"></div>
  </section>

  <section class="card" id="records" aria-labelledby="records-h">
    <div class="card-head">
      <h2 id="records-h">Реестр перехватов</h2>
      <button class="quiet" id="reset" type="button">Очистить реестр и счётчики</button>
    </div>
    <div id="recordsBox" class="table"></div>
  </section>
</main>

<script>
const GROUPS = [
  ["Подмена в ссылке", [
    ["Фейк Beeline", "Куттуктайбыз! Сиз 50 000 сом уттуңуз. Алуу үчүн шилтемеге өтүңүз: https://my-beeline.kg.example"],
    ["Фейк MBANK", "Ваш пароль от MBANK Online истекает. Обновите его по ссылке https://mbank.kg-verify.example"],
    ["Кириллическая «а»", "MBANK: ваша карта заблокирована. Срочно подтвердите данные: mbаnk.kg/verify"],
    ["Невидимый символ", "MBANK: вход с нового устройства. Если это не вы, отмените: mb​ank.kg/cancel"],
    ["Адрес кириллицей", "Бакай Банк: картаңыз бөгөттөлдү. Ачуу үчүн кириңиз: бакай.кг"],
    ["Похожий домен", "Privet, ty vyigral priz ot Beeline! Zaberi tut: bk-eline.kg"],
    ["«[.]» вместо точки", "Сизге бонус! Алуу үчүн: mbank[.]kg-bonus.xyz"],
  ]],
  ["Отправитель", [
    ["Банк с обычного номера", "Мбанк: вход в приложение с нового устройства. Если это не вы, позвоните нам.", "+996 555 123456"],
    ["Имя «MBАNK» с кириллицей", "MBANK: ваш перевод 15 000 сом отклонён. Повторите в приложении.", "MBАNK"],
  ]],
  ["Честные SMS", [
    ["Настоящий MBANK", "MBANK: вход в приложение с нового устройства.", "MBANK"],
    ["Официальный Beeline", "Beeline: подключите пакет «Безлимит» за 500 сом в месяц. Подробнее: https://beeline.kg", "Beeline"],
  ]],
];
const RISK = { low: "низкий", medium: "средний", high: "высокий" };
const KIND = { alpha: "буквенное имя", short: "короткий номер", phone: "обычный номер" };
const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
const $ = id => document.getElementById(id);

function el(tag, attrs, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "class") node.className = v; else node.setAttribute(k, v);
  }
  for (const c of children) if (c !== null && c !== undefined && c !== false) node.append(c);
  return node;
}
const gateLink = s => el("a", { href: "/x/" + encodeURIComponent(s.token), target: "_blank", rel: "noopener" }, s.text);
const plural = (n, one, few, many) => {
  const m10 = n % 10, m100 = n % 100;
  return m10 === 1 && m100 !== 11 ? one : (m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14) ? few : many);
};

function renderTransit(d) {
  const before = $("before"), after = $("after");
  before.replaceChildren(); after.replaceChildren();
  for (const s of d.segments) {
    if (s.kind === "blocked") { before.append(el("del", {}, s.original_url)); after.append(gateLink(s)); }
    else { before.append(s.text); after.append(s.text); }
  }
  const from = d.sender ? "от " + d.sender.sender : "отправитель не указан";
  $("fromBefore").textContent = from; $("fromAfter").textContent = from;

  const n = d.replaced_urls.length, risk = d.gateway_risk;
  $("gateVerdict").textContent = n
    ? `${plural(n, "подменена", "подменены", "подменено")} ${n} ${plural(n, "ссылка", "ссылки", "ссылок")}`
    : d.links.length ? "ссылки пропущены" : "ссылок нет";
  $("gateVerdict").className = n ? "t-high" : "";
  $("gateRisk").textContent = `${RISK[risk]} риск · ${d.gateway_score}`;
  $("gateRisk").className = "badge b-" + risk;
  // Цвет стрелки — по итоговому риску: опасное SMS без ссылок не должно выглядеть «зелёным».
  const color = { low: "var(--green)", medium: "var(--amber)", high: "var(--red)" }[risk];
  $("gate").style.setProperty("--gate", n ? "var(--red)" : color);
}

function renderDecision(d) {
  const left = $("decisionLinks"), right = $("decisionReasons");
  left.replaceChildren(); right.replaceChildren();
  if (d.sender) {
    const bad = d.sender.verdict === "suspicious";
    left.append(el("p", { class: "sender-line" + (bad ? " bad" : "") },
      `Отправитель ${d.sender.sender}: ${KIND[d.sender.kind]}${bad ? "" : ", вопросов нет"}.`,
      bad ? el("small", {}, d.sender.reason) : null));
  }
  if (d.links.length) {
    left.append(el("ul", { class: "links" }, ...d.links.map(l => el("li", {},
      el("span", { class: "status " + l.action }, l.action === "blocked" ? "подменена" : "пропущена"),
      el("code", {}, l.defanged_url),
      el("span", { class: "why" }, l.reason)))));
  } else {
    left.append(el("p", { class: "muted" }, "Ссылок в SMS нет."));
  }
  // Причина про отправителя уже показана слева — справа её не повторяем.
  const reasons = d.gateway_reasons.filter(r => !(d.sender && r === d.sender.reason));
  if (d.gateway_score !== d.score) {
    right.append(el("p", { class: "raised" }, `По тексту риск ${d.score} из 100, шлюз поднял его до ${d.gateway_score} из-за отправителя.`));
  }
  if (reasons.length) right.append(el("ul", { class: "reasons" }, ...reasons.map(r => el("li", {}, r))));
  else if (!d.gateway_reasons.length) right.append(el("p", { class: "muted" }, "Ничего: SMS доставлено без изменений."));
  $("decision").hidden = false;
}

function renderStats(s) {
  const items = [[s.sms_checked, "SMS проверено"], [s.sms_modified, "с подменой ссылки"],
                 [s.links_blocked, "адресов в реестре"], [s.clicks_blocked, "переходов остановлено"]];
  $("stats").replaceChildren(...items.map(([n, label]) => el("div", {}, el("dt", {}, label), el("dd", {}, String(n)))));
}

function renderRecords(records) {
  const box = $("recordsBox");
  box.replaceChildren();
  if (!records.length) {
    box.append(el("p", { class: "empty" }, "Перехватов пока нет. Пропустите через шлюз SMS со ссылкой — адрес появится здесь."));
    return;
  }
  const head = el("tr", {}, ...["Время", "Бренд", "Адрес мошенников", "Почему", "Ссылка шлюза"].map(h => el("th", {}, h)),
    el("th", { class: "num" }, "SMS"), el("th", { class: "num" }, "Переходы"));
  const rows = records.slice(0, 50).map(r => el("tr", {},
    el("td", {}, r.created_at.slice(11)),
    el("td", {}, r.brand_name || "—"),
    el("td", {}, el("code", {}, r.defanged_url)),
    el("td", {}, r.reason),
    el("td", {}, el("a", { href: "/x/" + encodeURIComponent(r.token), target: "_blank", rel: "noopener" }, "/x/" + r.token)),
    el("td", { class: "num" }, String(r.sms_count)),
    el("td", { class: "num" }, String(r.clicks_count))));
  box.append(el("table", {}, el("thead", {}, head), el("tbody", {}, ...rows)));
}

async function loadRecords() {
  try {
    const data = await (await fetch("/api/records")).json();
    renderStats(data.stats);
    renderRecords(data.records);
  } catch (e) { /* шлюз недоступен — оставляем прошлые данные */ }
}

async function run() {
  const btn = $("run");
  btn.disabled = true;
  try {
    const res = await fetch("/api/check", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: $("sms").value, sender: $("sender").value.trim() }) });
    const data = await res.json();
    if (!res.ok) { $("gateVerdict").textContent = data.error || "Шлюз отклонил запрос"; return; }
    renderTransit(data);
    renderDecision(data);
    await loadRecords();
  } catch (e) {
    $("gateVerdict").textContent = "Шлюз не отвечает";
  } finally {
    btn.disabled = false;
  }
}

function selectExample(button) {
  for (const b of document.querySelectorAll(".example")) b.classList.toggle("on", b === button);
}
for (const [title, items] of GROUPS) {
  const chips = el("div", { class: "chips" });
  for (const [label, text, sender] of items) {
    const b = el("button", { class: "example", type: "button" }, label);
    b.addEventListener("click", () => { $("sms").value = text; $("sender").value = sender || ""; selectExample(b); run(); });
    chips.append(b);
  }
  $("presets").append(el("div", {}, el("span", { class: "label" }, title), chips));
}
document.querySelector(".example").classList.add("on");
$("run").addEventListener("click", () => { selectExample(null); run(); });
$("sms").addEventListener("keydown", e => { if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) { selectExample(null); run(); } });
$("reset").addEventListener("click", async () => { await fetch("/api/reset", { method: "POST" }); loadRecords(); });

// --- поток ---
const sleep = ms => new Promise(r => setTimeout(r, ms));

function feedRow(it) {
  const txt = el("div", { class: "txt" });
  for (const s of it.segments) txt.append(s.kind === "blocked" ? gateLink(s) : s.text);
  return el("div", { class: "feed-row" },
    el("b", { class: "t-" + it.risk, title: "риск " + RISK[it.risk] }, String(it.score)),
    txt,
    el("span", { class: "truth" }, it.label === "fraud" ? "мошенничество" : "честное"));
}

function renderSummary(box, r) {
  const s = r.summary;
  const lines = [
    [`${s.ok_links_broken} из ${s.ok_links}`, "ссылок в честных SMS тронуто зря", s.ok_links_broken === 0],
    [`${s.fraud_links_blocked} из ${s.fraud_links - s.fraud_links_official}`, "ссылок мошенников обезврежено", s.fraud_links_missed === 0],
    [`${s.fraud_high} из ${s.fraud}`, "мошеннических SMS с высоким риском", s.fraud_high === s.fraud],
  ];
  box.append(el("dl", { class: "summary" }, ...lines.map(([v, label, good]) =>
    el("div", { class: good ? "good" : "bad" }, el("dd", {}, v), el("dt", {}, label)))));
  const remarks = [];
  if (s.fraud_links_official) remarks.push(el("li", {}, `${s.fraud_links_official} официальных адресов в мошеннических SMS шлюз пропустил намеренно: настоящий сайт банка не блокируется, опасен там текст.`));
  if (s.ok_high) remarks.push(el("li", {}, `${s.ok_high} честных SMS получили высокий риск.`));
  for (const x of r.broken) remarks.push(el("li", {}, "Тронута зря: ", el("code", {}, x.url), " в SMS «", x.text, "»"));
  for (const x of r.missed) remarks.push(el("li", {}, "Пропущена: ", el("code", {}, x.url), " в SMS «", x.text, "»"));
  if (remarks.length) box.append(el("ul", { class: "remarks" }, ...remarks));
}

async function runStream() {
  const btn = $("streamBtn"), box = $("streamOut");
  btn.disabled = true;
  box.replaceChildren(el("p", { class: "progress" }, "Шлюз обрабатывает набор…"));
  try {
    const res = await fetch("/api/stream", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ dataset: $("dataset").value }) });
    const r = await res.json();
    if (!res.ok) { box.replaceChildren(el("p", { class: "progress" }, r.error || "Шлюз отклонил запрос")); return; }
    const progress = el("p", { class: "progress" }), feed = el("div", { class: "feed" });
    box.replaceChildren(progress, feed);
    const delay = reduceMotion ? 0 : Math.max(15, Math.min(90, 4000 / r.items.length));
    let done = 0, modified = 0;
    for (const it of r.items) {
      feed.prepend(feedRow(it));
      done += 1; modified += it.is_modified ? 1 : 0;
      progress.textContent = `Обработано ${done} из ${r.items.length}. Ссылка подменена в ${modified} SMS.`;
      if (delay) await sleep(delay);
    }
    renderSummary(box, r);
    loadRecords();
  } catch (e) {
    box.replaceChildren(el("p", { class: "progress" }, "Шлюз не отвечает. Проверьте, что сервер запущен."));
  } finally {
    btn.disabled = false;
  }
}

(async () => {
  const sets = await (await fetch("/api/datasets")).json();
  for (const d of sets) $("dataset").append(el("option", { value: d.key }, d.title));
  if (!sets.length) { $("dataset").append(el("option", {}, "В папке data нет наборов")); $("streamBtn").disabled = true; }
})();
$("streamBtn").addEventListener("click", runStream);

// Подсветка пункта меню по разделу на экране.
const navLinks = [...document.querySelectorAll(".nav a")];
const observer = new IntersectionObserver(entries => {
  for (const e of entries) if (e.isIntersecting) navLinks.forEach(a => a.classList.toggle("on", a.getAttribute("href") === "#" + e.target.id));
}, { rootMargin: "-40% 0px -55% 0px" });
["check", "stream", "records"].forEach(id => observer.observe($(id)));

// Переход по ссылке шлюза в другой вкладке — обновим счётчики при возврате.
window.addEventListener("focus", loadRecords);
loadRecords();
run();
</script>
</body>
</html>
"""


# --- Обработчики -------------------------------------------------------------

@web.middleware
async def security_headers(request: web.Request, handler):
    response = await handler(request)
    for name, value in SECURITY_HEADERS.items():
        response.headers.setdefault(name, value)
    return response


async def handle_dashboard(request: web.Request) -> web.Response:
    return web.Response(text=DASHBOARD_HTML, content_type="text/html")


async def handle_stop(request: web.Request) -> web.Response:
    lang = _lang(request)
    record = registry.click(request.match_info["token"])
    if record is None:
        return web.Response(text=render_not_found(lang, request.path), content_type="text/html", status=404)
    return web.Response(text=render_stop_page(record, lang, request.path), content_type="text/html")


def _base_url(request: web.Request) -> str:
    return request.app.get("public_url") or f"{request.scheme}://{request.host}"


async def handle_api_check(request: web.Request) -> web.Response:
    try:
        data = await request.json()
    except Exception:
        return web.json_response({"error": "Нужен JSON: {\"text\": \"...\"}"}, status=400)
    text = data.get("text") if isinstance(data, dict) else None
    if not isinstance(text, str):
        return web.json_response({"error": "Поле text должно быть строкой"}, status=400)
    if len(text) > MAX_TEXT_LEN:
        return web.json_response({"error": f"SMS длиннее {MAX_TEXT_LEN} символов"}, status=413)
    sender = data.get("sender") or None
    if sender is not None and (not isinstance(sender, str) or len(sender) > MAX_SENDER_LEN):
        return web.json_response({"error": f"Поле sender — строка до {MAX_SENDER_LEN} символов"}, status=400)
    return web.json_response(sanitize_sms(text, base_url=_base_url(request), sender=sender))


async def handle_api_datasets(request: web.Request) -> web.Response:
    return web.json_response([{"key": key, "title": title}
                              for key, (_, title) in discover_datasets().items()])


async def handle_api_stream(request: web.Request) -> web.Response:
    try:
        data = await request.json()
    except Exception:
        return web.json_response({"error": "Нужен JSON: {\"dataset\": \"sms_dev\"}"}, status=400)
    key = data.get("dataset") if isinstance(data, dict) else None
    datasets = discover_datasets()
    if not isinstance(key, str) or key not in datasets:
        return web.json_response({"error": "Такого набора нет в папке data"}, status=404)
    path, title = datasets[key]
    rows = _read_csv(path)[:_MAX_STREAM_ROWS]
    result = run_stream(rows, base_url=_base_url(request), link_registry=registry)
    result["dataset"] = {"key": key, "title": title}
    return web.json_response(result)


async def handle_api_records(request: web.Request) -> web.Response:
    return web.json_response({"stats": registry.stats(), "records": registry.all_records()})


async def handle_api_reset(request: web.Request) -> web.Response:
    registry.clear()
    return web.json_response({"ok": True})


def create_app(public_url: str | None = None) -> web.Application:
    app = web.Application(middlewares=[security_headers], client_max_size=64 * 1024)
    if public_url:
        app["public_url"] = public_url.rstrip("/")
    app.router.add_get("/", handle_dashboard)
    app.router.add_get("/x/{token}", handle_stop)
    app.router.add_post("/api/check", handle_api_check)
    app.router.add_get("/api/records", handle_api_records)
    app.router.add_get("/api/datasets", handle_api_datasets)
    app.router.add_post("/api/stream", handle_api_stream)
    app.router.add_post("/api/reset", handle_api_reset)
    return app


def main(argv=None):
    parser = argparse.ArgumentParser(description="SakBol Safe Links Gateway — веб-демо")
    parser.add_argument("--port", type=int, default=8000, help="порт (по умолчанию 8000)")
    parser.add_argument("--host", default="127.0.0.1",
                        help="адрес (по умолчанию только этот компьютер; 0.0.0.0 — вся локальная сеть)")
    parser.add_argument("--public-url", help="адрес шлюза в подменённых ссылках, например http://192.168.1.5:8000")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO)
    shown = args.public_url or f"http://{'localhost' if args.host in ('127.0.0.1', '0.0.0.0') else args.host}:{args.port}"
    print(f"\nSakBol: пульт шлюза — {shown}\n", file=sys.stderr)
    web.run_app(create_app(args.public_url), host=args.host, port=args.port, print=None)


if __name__ == "__main__":
    main()
