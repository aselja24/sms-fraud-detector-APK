"""
Веб-сервер системы «SakBol Gateway» (Безопасные ссылки на уровне сети).

Запуск:
    python gateway_server.py [--port 8000]

Маршруты:
    GET  /           — Интерактивный дашборд оператора и симулятор перехвата
    GET  /x/{token}  — Страница-стоп при клике по перехваченной фишинговой ссылке
    POST /api/check  — JSON API для проверки и санитизации SMS
"""
import argparse
import json
import logging
from aiohttp import web

from detector.gateway import registry, sanitize_sms

STOP_PAGE_HTML = """<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛑 Доступ заблокирован — SakBol Защита</title>
    <style>
        :root {
            --bg-color: #0d1117;
            --card-bg: #161b22;
            --border-color: #30363d;
            --danger-color: #f85149;
            --danger-glow: rgba(248, 81, 73, 0.25);
            --text-main: #f0f6fc;
            --text-muted: #8b949e;
            --accent-green: #2ea043;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; }
        body {
            background-color: var(--bg-color);
            color: var(--text-main);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container {
            max-width: 620px;
            width: 100%;
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-top: 5px solid var(--danger-color);
            border-radius: 12px;
            box-shadow: 0 16px 36px var(--danger-glow);
            padding: 36px 30px;
            text-align: center;
        }
        .shield-icon {
            width: 76px;
            height: 76px;
            background: rgba(248, 81, 73, 0.15);
            border-radius: 50%;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            font-size: 38px;
            margin-bottom: 20px;
            border: 2px solid var(--danger-color);
        }
        h1 {
            font-size: 24px;
            font-weight: 700;
            color: var(--danger-color);
            margin-bottom: 12px;
        }
        .subtitle {
            font-size: 15px;
            color: var(--text-muted);
            margin-bottom: 24px;
            line-height: 1.5;
        }
        .warning-card {
            background: rgba(248, 81, 73, 0.08);
            border: 1px dashed var(--danger-color);
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 24px;
            text-align: left;
        }
        .warning-card strong {
            color: var(--text-main);
            display: block;
            margin-bottom: 6px;
            font-size: 14px;
        }
        .fake-url {
            color: var(--danger-color);
            text-decoration: line-through;
            word-break: break-all;
            font-family: monospace;
            background: rgba(0,0,0,0.3);
            padding: 4px 8px;
            border-radius: 4px;
            display: inline-block;
            margin: 6px 0;
            font-size: 13px;
        }
        .explanation {
            font-size: 14px;
            line-height: 1.6;
            color: var(--text-main);
            margin-bottom: 24px;
            text-align: left;
            background: #21262d;
            padding: 16px;
            border-radius: 8px;
        }
        .explanation li {
            margin-left: 20px;
            margin-top: 6px;
            color: var(--text-muted);
        }
        .actions {
            display: flex;
            flex-direction: column;
            gap: 12px;
        }
        .btn {
            display: inline-block;
            padding: 12px 20px;
            border-radius: 6px;
            font-size: 14px;
            font-weight: 600;
            text-decoration: none;
            cursor: pointer;
            transition: 0.2s;
            border: none;
        }
        .btn-official {
            background-color: var(--accent-green);
            color: #ffffff;
        }
        .btn-official:hover { background-color: #3fb950; }
        .btn-close {
            background-color: #21262d;
            color: var(--text-muted);
            border: 1px solid var(--border-color);
        }
        .btn-close:hover { background-color: #30363d; color: var(--text-main); }
        .footer {
            margin-top: 24px;
            font-size: 12px;
            color: var(--text-muted);
            border-top: 1px solid var(--border-color);
            padding-top: 14px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="shield-icon">🛑</div>
        <h1>Переход заблокирован</h1>
        <p class="subtitle">Сетевой защитный шлюз <strong>SakBol</strong> остановил опасное соединение.</p>

        <div class="warning-card">
            <strong>Обнаружена угроза фишинга:</strong>
            {reason_text}
            <div>Обезвреженный адрес: <span class="fake-url">{original_url}</span></div>
        </div>

        <div class="explanation">
            <strong>Что это значит?</strong>
            <ul>
                <li>Мошенники скопировали оформление {brand_name}, чтобы украсть ваши коды из SMS, пароли или деньги.</li>
                <li>Благодаря защите оператора ссылка была нейтрализована до того, как вы могли ввести данные.</li>
                <li>Ваши данные в безопасности — сайт мошенников не смог открыться.</li>
            </ul>
        </div>

        <div class="actions">
            {official_button}
            <button class="btn btn-close" onclick="window.close(); alert('Вы можете безопасно закрыть эту вкладку.');">Закрыть страницу</button>
        </div>

        <div class="footer">
            Защищено сервисом <strong>SakBol Anti-Fraud Gateway</strong> • Осенний хакатон INAI 2026
        </div>
    </div>
</body>
</html>
"""

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛡️ SakBol Gateway — Сетевой шлюз защиты SMS</title>
    <style>
        :root {
            --bg: #0d1117;
            --panel: #161b22;
            --border: #30363d;
            --text: #f0f6fc;
            --muted: #8b949e;
            --brand: #58a6ff;
            --success: #3fb950;
            --danger: #f85149;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
        body { background: var(--bg); color: var(--text); padding: 24px; }
        .wrapper { max-width: 960px; margin: 0 auto; }
        header { margin-bottom: 24px; border-bottom: 1px solid var(--border); padding-bottom: 16px; display: flex; justify-content: space-between; align-items: center; }
        h1 { font-size: 22px; display: flex; align-items: center; gap: 10px; }
        .badge { background: #238636; color: #fff; padding: 4px 8px; border-radius: 20px; font-size: 12px; font-weight: 600; }
        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        @media(max-width: 768px) { .grid { grid-template-columns: 1fr; } }
        .card { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 20px; }
        .card h2 { font-size: 16px; margin-bottom: 14px; color: var(--brand); }
        textarea { width: 100%; height: 110px; background: #0d1117; border: 1px solid var(--border); border-radius: 6px; color: var(--text); padding: 12px; font-size: 14px; resize: vertical; }
        button { background: var(--brand); color: #0d1117; border: none; padding: 10px 16px; border-radius: 6px; font-weight: 600; cursor: pointer; margin-top: 10px; }
        button:hover { opacity: 0.9; }
        .presets { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 10px; }
        .preset-btn { background: #21262d; color: var(--muted); border: 1px solid var(--border); padding: 4px 8px; font-size: 12px; border-radius: 4px; cursor: pointer; }
        .preset-btn:hover { color: var(--text); border-color: var(--brand); }
        .output-box { background: #0d1117; border: 1px solid var(--border); border-radius: 6px; padding: 14px; margin-top: 10px; min-height: 120px; font-size: 13px; line-height: 1.5; }
        .url-highlight { color: #f85149; text-decoration: line-through; }
        .safe-highlight { color: #3fb950; font-weight: 600; text-decoration: underline; }
        .table-wrap { margin-top: 24px; }
        table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 13px; }
        th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid var(--border); }
        th { color: var(--muted); background: #0d1117; }
        .tag-high { background: rgba(248, 81, 73, 0.2); color: #f85149; padding: 2px 6px; border-radius: 4px; font-size: 11px; }
        .tag-low { background: rgba(63, 185, 80, 0.2); color: #3fb950; padding: 2px 6px; border-radius: 4px; font-size: 11px; }
    </style>
</head>
<body>
    <div class="wrapper">
        <header>
            <h1>🛡️ SakBol Safe Links Gateway</h1>
            <span class="badge">Активен (Защита сети)</span>
        </header>

        <div class="grid">
            <div class="card">
                <h2>Симулятор отправки SMS оператором</h2>
                <textarea id="smsInput" placeholder="Введите текст входящего SMS со ссылкой...">Куттуктайбыз! Сиз iPhone 15 уттуңуз. Алуу үчүн шилтемеге өтүңүз: https://my-beeline.kg.example</textarea>
                <button onclick="processSms()">Пропустить через шлюз SakBol</button>

                <div class="presets">
                    <span style="font-size:12px; color:var(--muted); align-self:center;">Тестовые примеры:</span>
                    <button class="preset-btn" onclick="setPreset(1)">Фейк Beeline</button>
                    <button class="preset-btn" onclick="setPreset(2)">Фейк MBANK</button>
                    <button class="preset-btn" onclick="setPreset(3)">Официальный Beeline (белый список)</button>
                </div>
            </div>

            <div class="card">
                <h2>Результат сетевой фильтрации</h2>
                <div id="output" class="output-box">Нажмите «Пропустить через шлюз SakBol», чтобы протестировать перехват ссылки.</div>
            </div>
        </div>

        <div class="card table-wrap">
            <h2>Реестр перехваченных опасных ссылок</h2>
            <div id="recordsTable">Загрузка реестра...</div>
        </div>
    </div>

    <script>
        const presets = {
            1: "Куттуктайбыз! Сиз 50 000 сом уттуңуз. Алуу үчүн шилтемеге өтүңүз: https://my-beeline.kg.example",
            2: "Ваш пароль от MBANK Online истекает. Обновите его по ссылке https://mbank.kg-verify.example",
            3: "Beeline: подключите пакет «Безлимит» за 5000 сом в месяц. Подробнее: https://beeline.kg"
        };

        function setPreset(id) {
            document.getElementById('smsInput').value = presets[id];
            processSms();
        }

        async function processSms() {
            const text = document.getElementById('smsInput').value;
            const res = await fetch('/api/check', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({text})
            });
            const data = await res.json();
            
            let html = `<strong>Уровень риска:</strong> <span class="${data.risk === 'high' ? 'tag-high' : 'tag-low'}">${data.risk.toUpperCase()} (Скор: ${data.score}/100)</span><br><br>`;
            
            if (data.is_modified) {
                html += `<strong>⚠️ Сеть оператора заменила ссылку:</strong><br>`;
                html += `<div style="margin: 8px 0; background: #21262d; padding: 10px; border-radius: 4px;">${data.safe_text}</div>`;
                html += `<small style="color:var(--muted)">Кликните по безопасной ссылке в тексте выше, чтобы увидеть страницу-стоп.</small><br><br>`;
                html += `<strong>Перехваченные ссылки:</strong><br>`;
                data.replaced_urls.forEach(u => {
                    html += `• Было: <span class="url-highlight">${u.original_url}</span><br>`;
                    html += `  Стало: <a href="${u.safe_url}" target="_blank" class="safe-highlight">${u.safe_url}</a> (${u.brand})<br>`;
                });
            } else {
                html += `<strong>✅ Ссылка безопасна (белый список):</strong><br>`;
                html += `<div style="margin: 8px 0; background: #21262d; padding: 10px; border-radius: 4px;">${data.safe_text}</div>`;
                html += `<span style="color:var(--success)">Ссылка не изменялась, так как домен доверенный.</span>`;
            }

            document.getElementById('output').innerHTML = html;
            loadRecords();
        }

        async function loadRecords() {
            const res = await fetch('/api/records');
            const records = await res.json();
            if (!records.length) {
                document.getElementById('recordsTable').innerHTML = '<span style="color:var(--muted)">В реестре пока нет перехваченных ссылок.</span>';
                return;
            }
            let html = '<table><thead><tr><th>Время</th><th>Бренд</th><th>Оригинальный URL</th><th>Защитная ссылка</th><th>Кликов</th></tr></thead><tbody>';
            records.forEach(r => {
                html += `<tr>
                    <td>${r.created_at}</td>
                    <td><strong>${r.brand_name || 'Неизвестно'}</strong></td>
                    <td><span class="url-highlight">${r.original_url}</span></td>
                    <td><a href="/x/${r.token}" target="_blank" style="color:var(--brand)">/x/${r.token}</a></td>
                    <td>${r.clicks_count}</td>
                </tr>`;
            });
            html += '</tbody></table>';
            document.getElementById('recordsTable').innerHTML = html;
        }

        loadRecords();
    </script>
</body>
</html>
"""


async def handle_dashboard(request: web.Request) -> web.Response:
    return web.Response(text=DASHBOARD_HTML, content_type="text/html")


async def handle_redirect(request: web.Request) -> web.Response:
    token = request.match_info.get("token", "")
    info = registry.get(token)

    if not info:
        return web.Response(
            text="<h1>404: Ссылка не найдена или срок действия истек</h1>",
            content_type="text/html",
            status=404,
        )

    official_button = ""
    if info.get("official_url"):
        official_button = (
            f'<a class="btn btn-official" href="{info["official_url"]}" target="_blank">'
            f'Перейти на настоящий сайт {info["brand_name"]} ({info["official_domain"]})</a>'
        )

    page = STOP_PAGE_HTML.format(
        brand_name=info["brand_name"] or "известного сервиса",
        reason_text=info["reason"],
        original_url=info["original_url"],
        official_button=official_button,
    )
    return web.Response(text=page, content_type="text/html")


async def handle_api_check(request: web.Request) -> web.Response:
    try:
        data = await request.json()
    except Exception:
        return web.json_response({"error": "Invalid JSON"}, status=400)

    text = data.get("text", "")
    host = request.host
    scheme = request.scheme
    base_url = f"{scheme}://{host}"

    result = sanitize_sms(text, base_url=base_url)
    return web.json_response(result)


async def handle_api_records(request: web.Request) -> web.Response:
    records = registry.all_records()
    return web.json_response(records)


def create_app() -> web.Application:
    app = web.Application()
    app.router.add_get("/", handle_dashboard)
    app.router.add_get("/x/{token}", handle_redirect)
    app.router.add_post("/api/check", handle_api_check)
    app.router.add_get("/api/records", handle_api_records)
    return app


def main():
    parser = argparse.ArgumentParser(description="SakBol Safe Links Gateway Server")
    parser.add_argument("--port", type=int, default=8000, help="Порт веб-сервера (по умолчанию 8000)")
    parser.add_argument("--host", default="0.0.0.0", help="Хост (по умолчанию 0.0.0.0)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    app = create_app()
    print(f"\n🛡️ SakBol Safe Links Gateway запущен на http://localhost:{args.port}\n")
    web.run_app(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
