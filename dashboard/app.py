from __future__ import annotations

import os
from collections import Counter
from typing import Any

from flask import Flask, jsonify, render_template
from werkzeug.serving import make_server

from src.config import get_settings
from src.database import AlertDatabase


def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates")
    db = AlertDatabase()

    @app.route("/")
    def index() -> str:
        alerts = db.get_recent_alerts(20)
        stats = db.get_statistics()
        rule_counts = Counter(alert["rule_name"] for alert in alerts)
        top_sources = Counter(alert["source_ip"] for alert in alerts)
        return render_template(
            "index.html",
            alerts=alerts,
            stats=stats,
            rule_counts=rule_counts,
            top_sources=top_sources.most_common(5),
        )

    @app.route("/api/alerts")
    def api_alerts() -> Any:
        alerts = db.get_recent_alerts(20)
        return jsonify({"alerts": alerts, "stats": db.get_statistics()})

    return app


def get_dashboard_config() -> tuple[str, int]:
    settings = get_settings()
    host = os.getenv("DASHBOARD_HOST", settings.dashboard_host)
    port = int(os.getenv("DASHBOARD_PORT", settings.dashboard_port))
    return host, port


def run_dashboard() -> None:
    app = create_app()
    host, port = get_dashboard_config()
    server = None

    for candidate in range(port, port + 20):
        try:
            server = make_server(host, candidate, app)
            print(f"Dashboard running on http://{host}:{candidate}")
            server.serve_forever()
            return
        except OSError:
            continue

    raise OSError(f"Unable to bind the dashboard to any port in range {port}-{port + 19}")


if __name__ == "__main__":
    run_dashboard()
