"""
Веб-демо «SakBol Gateway»: безопасные ссылки в SMS на уровне оператора.

Запуск:
    python gateway_server.py                       # http://127.0.0.1:8000
    python gateway_server.py --host 0.0.0.0 --public-url http://192.168.1.5:8000
        (чтобы открыть ссылку шлюза с телефона в той же Wi-Fi сети)

Маршруты:
    GET  /              — пульт оператора: симулятор SMS и реестр перехватов
    GET  /x/{token}     — страница-стоп (?lang=ky|ru)
    POST /api/check     — {"text": "..."} -> результат sanitize_sms()
    GET  /api/records   — статистика и реестр перехваченных ссылок
    POST /api/reset     — очистить реестр (для показа с нуля)

Всё, что пришло из SMS (адреса, причины), вставляется в HTML только
экранированным: адрес мошенников может содержать «<script>».
"""
import argparse
import html
import logging
import re
import sys

from aiohttp import web

from bot.i18n import translate as translate_check
from detector.gateway import defang, registry, sanitize_sms

MAX_TEXT_LEN = 2000
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
        "footer": "Защищено SakBol Anti-Fraud Gateway • INAI 2026",
        "not_found_title": "Ссылка не найдена",
        "not_found": "Такой защищённой ссылки нет или она устарела. Не возвращайтесь к исходному SMS и не открывайте адрес из него.",
    },
    "ky": {
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
        "footer": "SakBol Anti-Fraud Gateway коргойт • INAI 2026",
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
  :root { --bg:#0d1117; --card:#161b22; --line:#30363d; --red:#f85149; --text:#f0f6fc; --muted:#8b949e; --green:#2ea043; }
  * { box-sizing:border-box; margin:0; padding:0; }
  body { background:var(--bg); color:var(--text); min-height:100vh; display:flex; align-items:center; justify-content:center;
         padding:16px; font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }
  .card { max-width:620px; width:100%; background:var(--card); border:1px solid var(--line); border-top:5px solid var(--red);
          border-radius:12px; padding:28px 22px; box-shadow:0 16px 36px rgba(248,81,73,.2); }
  .lang { text-align:right; font-size:13px; margin-bottom:8px; }
  .lang a { color:var(--muted); margin-left:10px; text-decoration:none; }
  .lang a.on { color:var(--text); font-weight:600; }
  .icon { width:68px; height:68px; margin:0 auto 14px; border-radius:50%; border:2px solid var(--red); background:rgba(248,81,73,.15);
          display:flex; align-items:center; justify-content:center; font-size:34px; }
  h1 { text-align:center; color:var(--red); font-size:24px; margin-bottom:8px; }
  .sub { text-align:center; color:var(--muted); margin-bottom:22px; }
  h2 { font-size:14px; margin-bottom:6px; }
  .box { border-radius:8px; padding:14px 16px; margin-bottom:14px; }
  .danger { background:rgba(248,81,73,.08); border:1px dashed var(--red); }
  .plain { background:#21262d; }
  ul { margin-left:20px; color:var(--muted); }
  li + li { margin-top:4px; }
  .url { display:inline-block; margin-top:6px; padding:4px 8px; border-radius:4px; background:rgba(0,0,0,.35); color:var(--red);
         font:13px/1.4 ui-monospace,Menlo,monospace; word-break:break-all; }
  .actions { display:flex; flex-direction:column; gap:10px; margin-top:18px; }
  .btn { display:block; text-align:center; padding:12px 16px; border-radius:6px; font-weight:600; font-size:14px; text-decoration:none;
         cursor:pointer; border:1px solid var(--line); }
  .ok { background:var(--green); border-color:var(--green); color:#fff; }
  .ghost { background:#21262d; color:var(--muted); }
  .foot { margin-top:20px; padding-top:12px; border-top:1px solid var(--line); text-align:center; font-size:12px; color:var(--muted); }
</style>
</head>
<body>
<main class="card">
  <div class="lang">{{lang_links}}</div>
  <div class="icon" aria-hidden="true">🛑</div>
  <h1>{{title}}</h1>
  <p class="sub">{{subtitle}}</p>
  {{body}}
  <div class="actions">
    {{official_button}}
    <button class="btn ghost" type="button" onclick="window.close()">{{close}}</button>
  </div>
  <p class="foot">{{footer}}</p>
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
        f'<section class="box danger"><h2>{esc(s["why"])}</h2><p>{esc(reason)}.</p>'
        f'<p style="margin-top:10px">{esc(s["fake_url"])}<br>'
        f'<span class="url">{esc(defang(record.original_url))}</span></p></section>'
    )
    if others:
        items = "".join(f"<li>{esc(_cap(tr(r, lang)))}</li>" for r in others)
        body += f'<section class="box plain"><h2>{esc(s["also"])}</h2><ul>{items}</ul></section>'
    todo = "".join(f"<li>{esc(item)}</li>" for item in s["todo_items"])
    body += f'<section class="box plain"><h2>{esc(s["todo"])}</h2><ul>{todo}</ul></section>'

    official = ""
    if record.official_url:
        label = s["official"].format(brand=record.brand_name or record.official_domain, domain=record.official_domain)
        official = (f'<a class="btn ok" href="{esc(record.official_url)}" target="_blank" '
                    f'rel="noopener noreferrer">{esc(label)}</a>')

    return fill(
        STOP_PAGE_HTML,
        lang=lang,
        lang_links=_lang_links(path, lang),
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
<title>SakBol Gateway</title>
<style>
  :root { --bg:#0d1117; --panel:#161b22; --line:#30363d; --text:#f0f6fc; --muted:#8b949e; --blue:#58a6ff;
          --green:#3fb950; --yellow:#d29922; --red:#f85149; }
  * { box-sizing:border-box; margin:0; padding:0; }
  body { background:var(--bg); color:var(--text); padding:24px 16px; font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; }
  .wrap { max-width:1040px; margin:0 auto; }
  header { display:flex; flex-wrap:wrap; gap:10px; justify-content:space-between; align-items:center; padding-bottom:14px;
           margin-bottom:18px; border-bottom:1px solid var(--line); }
  h1 { font-size:21px; }
  .live { background:#238636; color:#fff; padding:3px 9px; border-radius:20px; font-size:12px; font-weight:600; }
  .how { display:grid; grid-template-columns:repeat(3,1fr); gap:12px; margin-bottom:18px; }
  .how div { background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:12px; color:var(--muted); font-size:13px; }
  .how b { color:var(--text); display:block; margin-bottom:2px; }
  .grid { display:grid; grid-template-columns:1fr 1fr; gap:18px; }
  @media (max-width:800px) { .grid, .how, .stats { grid-template-columns:1fr !important; } }
  .card { background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:18px; min-width:0; }
  .card h2 { font-size:15px; color:var(--blue); margin-bottom:12px; }
  textarea { width:100%; height:120px; background:var(--bg); color:var(--text); border:1px solid var(--line); border-radius:6px;
             padding:10px; font:inherit; resize:vertical; }
  .row { display:flex; gap:8px; margin-top:10px; flex-wrap:wrap; }
  button { cursor:pointer; font:inherit; }
  .main-btn { background:var(--blue); color:#0d1117; border:0; padding:9px 16px; border-radius:6px; font-weight:600; }
  .main-btn:disabled { opacity:.6; cursor:wait; }
  .ghost-btn { background:transparent; color:var(--muted); border:1px solid var(--line); padding:9px 12px; border-radius:6px; }
  .presets { display:flex; flex-wrap:wrap; gap:6px; margin-top:12px; }
  .chip { background:#21262d; color:var(--muted); border:1px solid var(--line); padding:4px 9px; border-radius:14px; font-size:12px; }
  .chip:hover { color:var(--text); border-color:var(--blue); }
  .phone { background:#0b0f14; border:1px solid var(--line); border-radius:18px; padding:14px; }
  .phone .from { color:var(--muted); font-size:12px; margin-bottom:6px; }
  .bubble { background:#21262d; border-radius:14px 14px 14px 4px; padding:10px 12px; white-space:pre-wrap; word-break:break-word; }
  .bubble a { color:var(--green); font-weight:600; }
  .orig { margin-top:8px; font-size:12px; color:var(--muted); word-break:break-word; }
  .orig s { color:var(--red); }
  .risk { display:inline-block; padding:2px 8px; border-radius:4px; font-weight:600; font-size:12px; }
  .risk-low { background:rgba(63,185,80,.18); color:var(--green); }
  .risk-medium { background:rgba(210,153,34,.2); color:var(--yellow); }
  .risk-high { background:rgba(248,81,73,.2); color:var(--red); }
  .muted { color:var(--muted); }
  .section { margin-top:14px; }
  .section h3 { font-size:13px; margin-bottom:4px; }
  .section ul { margin-left:18px; color:var(--muted); }
  .link { border:1px solid var(--line); border-radius:6px; padding:8px 10px; margin-top:6px; font-size:13px; }
  .link code { font:12px ui-monospace,Menlo,monospace; word-break:break-all; }
  .tag { font-size:11px; font-weight:600; padding:1px 6px; border-radius:4px; margin-right:6px; }
  .tag-blocked { background:rgba(248,81,73,.2); color:var(--red); }
  .tag-kept { background:rgba(63,185,80,.18); color:var(--green); }
  .stats { display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin-top:18px; }
  .stat { background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:12px 14px; }
  .stat b { display:block; font-size:24px; }
  .stat span { color:var(--muted); font-size:12px; }
  .table { overflow-x:auto; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th, td { text-align:left; padding:8px 10px; border-bottom:1px solid var(--line); vertical-align:top; }
  th { color:var(--muted); font-weight:500; white-space:nowrap; }
  td code { font:12px ui-monospace,Menlo,monospace; color:var(--red); word-break:break-all; }
  td a { color:var(--blue); }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>🛡️ SakBol Safe Links Gateway</h1>
    <span class="live">Шлюз активен</span>
  </header>

  <div class="how">
    <div><b>1. SMS приходит в сеть</b>Шлюз проверяет текст и каждую ссылку тем же детектором, что и бот.</div>
    <div><b>2. Опасная ссылка подменяется</b>Абонент получает SMS, где вместо фишинга — защищённая ссылка шлюза.</div>
    <div><b>3. Клик → страница-стоп</b>Сайт мошенников не открывается; человек видит, почему, и ссылку на настоящий сайт.</div>
  </div>

  <div class="grid">
    <section class="card">
      <h2>Входящее SMS (до шлюза)</h2>
      <textarea id="sms" maxlength="2000" aria-label="Текст SMS">Куттуктайбыз! Сиз 50 000 сом уттуңуз. Алуу үчүн шилтемеге өтүңүз: https://my-beeline.kg.example</textarea>
      <div class="row">
        <button class="main-btn" id="run">Пропустить через шлюз</button>
        <button class="ghost-btn" id="reset" title="Очистить реестр и счётчики">Сбросить реестр</button>
      </div>
      <div class="presets" id="presets"><span class="muted" style="font-size:12px;align-self:center">Примеры:</span></div>
    </section>

    <section class="card">
      <h2>Что получит абонент (после шлюза)</h2>
      <div id="out" class="muted">Нажмите «Пропустить через шлюз».</div>
    </section>
  </div>

  <div class="stats" id="stats"></div>

  <section class="card" style="margin-top:18px">
    <h2>Реестр перехваченных ссылок</h2>
    <div id="records" class="table muted">Загрузка…</div>
  </section>
</div>

<script>
const PRESETS = [
  ["Фейк Beeline (KG)", "Куттуктайбыз! Сиз 50 000 сом уттуңуз. Алуу үчүн шилтемеге өтүңүз: https://my-beeline.kg.example"],
  ["Фейк MBANK", "Ваш пароль от MBANK Online истекает. Обновите его по ссылке https://mbank.kg-verify.example"],
  ["Кириллическая «а»", "MBANK: ваша карта заблокирована. Срочно подтвердите данные: mbаnk.kg/verify"],
  ["Невидимый символ", "MBANK: вход с нового устройства. Если это не вы, отмените: mb​ank.kg/cancel"],
  ["Адрес кириллицей", "Бакай Банк: картаңыз бөгөттөлдү. Ачуу үчүн кириңиз: бакай.кг"],
  ["Похожий домен", "Privet, ty vyigral priz ot Beeline! Zaberi tut: bk-eline.kg"],
  ["«[.]» вместо точки", "Сизге бонус! Алуу үчүн: mbank[.]kg-bonus.xyz"],
  ["Официальный Beeline", "Beeline: подключите пакет «Безлимит» за 500 сом в месяц. Подробнее: https://beeline.kg"],
];
const RISK = { low: "Низкий", medium: "Средний", high: "Высокий" };

function el(tag, attrs, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "class") node.className = v; else node.setAttribute(k, v);
  }
  for (const c of children) if (c !== null && c !== undefined) node.append(c);
  return node;
}

function renderResult(d) {
  const out = document.getElementById("out");
  out.className = "";
  out.replaceChildren();

  const bubble = el("div", { class: "bubble" });
  for (const s of d.segments) {
    if (s.kind === "blocked") {
      bubble.append(el("a", { href: "/x/" + encodeURIComponent(s.token), target: "_blank", rel: "noopener" }, s.text));
    } else {
      bubble.append(s.text);
    }
  }
  const phone = el("div", { class: "phone" }, el("div", { class: "from" }, "📱 Входящее SMS"), bubble);
  if (d.is_modified) {
    const orig = el("div", { class: "orig" }, "Было: ");
    d.replaced_urls.forEach((u, i) => { if (i) orig.append(", "); orig.append(el("s", {}, u.defanged_url)); });
    phone.append(orig);
  }
  out.append(phone);

  const head = el("div", { class: "section" },
    el("span", { class: "risk risk-" + d.risk }, `${RISK[d.risk] || d.risk} риск · ${d.score}/100`), " ",
    el("span", { class: "muted" }, d.is_modified
      ? `ссылок обезврежено: ${d.replaced_urls.length}`
      : (d.links.length ? "ссылки оставлены без изменений" : "ссылок в SMS нет")));
  out.append(head);

  if (d.links.length) {
    const box = el("div", { class: "section" }, el("h3", {}, "Решение по ссылкам"));
    for (const l of d.links) {
      box.append(el("div", { class: "link" },
        el("span", { class: "tag tag-" + l.action }, l.action === "blocked" ? "ПОДМЕНЕНА" : "ОСТАВЛЕНА"),
        el("code", {}, l.defanged_url),
        el("div", { class: "muted" }, l.reason)));
    }
    out.append(box);
  }
  if (d.reasons.length) {
    out.append(el("div", { class: "section" }, el("h3", {}, "Почему SMS подозрительное"),
      el("ul", {}, ...d.reasons.map(r => el("li", {}, r)))));
  }
}

function renderStats(s) {
  const items = [
    [s.sms_checked, "SMS проверено"],
    [s.sms_modified, "SMS с подменой"],
    [s.links_blocked, "опасных ссылок в реестре"],
    [s.clicks_blocked, "переходов остановлено"],
  ];
  document.getElementById("stats").replaceChildren(
    ...items.map(([n, label]) => el("div", { class: "stat" }, el("b", {}, String(n)), el("span", {}, label))));
}

function renderRecords(records) {
  const box = document.getElementById("records");
  box.replaceChildren();
  if (!records.length) { box.className = "table muted"; box.append("Пока ничего не перехвачено."); return; }
  box.className = "table";
  const tbody = el("tbody");
  for (const r of records) {
    tbody.append(el("tr", {},
      el("td", {}, r.created_at.slice(11)),
      el("td", {}, el("strong", {}, r.brand_name || "—")),
      el("td", {}, el("code", {}, r.defanged_url)),
      el("td", {}, r.reason),
      el("td", {}, el("a", { href: "/x/" + encodeURIComponent(r.token), target: "_blank", rel: "noopener" }, "/x/" + r.token)),
      el("td", {}, String(r.sms_count)),
      el("td", {}, String(r.clicks_count))));
  }
  const head = el("tr", {}, ...["Время", "Бренд", "Адрес мошенников", "Почему", "Ссылка шлюза", "SMS", "Кликов"].map(h => el("th", {}, h)));
  box.append(el("table", {}, el("thead", {}, head), tbody));
}

async function loadRecords() {
  const res = await fetch("/api/records");
  const data = await res.json();
  renderStats(data.stats);
  renderRecords(data.records);
}

async function run() {
  const btn = document.getElementById("run");
  const text = document.getElementById("sms").value;
  btn.disabled = true;
  try {
    const res = await fetch("/api/check", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ text }) });
    const data = await res.json();
    if (!res.ok) { document.getElementById("out").textContent = data.error || "Ошибка"; return; }
    renderResult(data);
    await loadRecords();
  } catch (e) {
    document.getElementById("out").textContent = "Шлюз не ответил: " + e;
  } finally {
    btn.disabled = false;
  }
}

const presetBox = document.getElementById("presets");
for (const [label, text] of PRESETS) {
  const b = el("button", { class: "chip", type: "button" }, label);
  b.addEventListener("click", () => { document.getElementById("sms").value = text; run(); });
  presetBox.append(b);
}
document.getElementById("run").addEventListener("click", run);
document.getElementById("reset").addEventListener("click", async () => {
  await fetch("/api/reset", { method: "POST" });
  document.getElementById("out").className = "muted";
  document.getElementById("out").textContent = "Реестр очищен.";
  loadRecords();
});
// Клик по ссылке шлюза в другой вкладке — обновим счётчики, когда вернутся.
window.addEventListener("focus", loadRecords);
loadRecords();
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
    return web.json_response(sanitize_sms(text, base_url=_base_url(request)))


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
    print(f"\n🛡️ SakBol Safe Links Gateway: {shown}\n", file=sys.stderr)
    web.run_app(create_app(args.public_url), host=args.host, port=args.port, print=None)


if __name__ == "__main__":
    main()
