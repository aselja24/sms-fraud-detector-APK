"""

Запуск:

Маршруты:
"""
import argparse
import logging
from aiohttp import web


STOP_PAGE_HTML = """<!DOCTYPE html>
<head>
    <meta charset="UTF-8">
    <style>
    </style>
</head>
<body>
        <div class="actions">
        </div>
</body>
</html>
"""

<html lang="ru">
<head>
    <meta charset="UTF-8">
    <style>
    </style>
</head>
<body>
        <header>
            <h1>🛡️ SakBol Safe Links Gateway</h1>
        </header>

            </div>
        </div>

        </div>
    </div>

    <script>

        }

            const data = await res.json();
            
            }

            loadRecords();
            });
        loadRecords();
    </script>
</body>
</html>
"""


async def handle_dashboard(request: web.Request) -> web.Response:
    return web.Response(text=DASHBOARD_HTML, content_type="text/html")






async def handle_api_check(request: web.Request) -> web.Response:
    try:
        data = await request.json()
    except Exception:


async def handle_api_records(request: web.Request) -> web.Response:


    app.router.add_get("/", handle_dashboard)
    app.router.add_post("/api/check", handle_api_check)
    app.router.add_get("/api/records", handle_api_records)
    return app



    logging.basicConfig(level=logging.INFO)


if __name__ == "__main__":
    main()
