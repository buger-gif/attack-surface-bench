# SECURITY-REVIEWED: 2026-07-09 | RULES: v2.6.0-draft
# internal-tools: Flask with backup/env/config/network/source info leak

from flask import Flask, request, jsonify, Response
import os

app = Flask(__name__)

@app.route("/")
def index():
    return jsonify({"endpoints": ["/api/backup", "/api/env", "/api/config", "/api/network", "/api/source"]})

@app.route("/api/backup")
def backup():
    return jsonify({"schedule": "0 2 * * *", "location": "/var/backups/db.sql",
                   "connection": "mysql://appuser:apppass123@db:3306/app_db",
                   "flag": "INFO_BACKUP_LEAK"})

@app.route("/api/env")
def env_vars():
    return jsonify({k: v for k, v in os.environ.items()})

@app.route("/api/config")
def config():
    return jsonify({"database": {"host": "db", "port": 3306, "user": "appuser", "password": "apppass123"},
                   "redis": {"host": "redis", "port": 6379, "auth": None},
                   "services": {"admin": "172.20.0.11:5000", "app": "172.20.0.12:5000",
                               "www": "172.20.0.10:3000", "shop": "172.20.0.12:5000"},
                   "flag": "INFO_CONFIG_LEAK"})

@app.route("/api/network")
def network():
    return jsonify({"subnet": "172.20.0.0/24",
                   "hosts": [
                       {"ip": "172.20.0.10", "name": "www (modern-app)", "ports": [3000]},
                       {"ip": "172.20.0.11", "name": "admin (admin-panel)", "ports": [5000]},
                       {"ip": "172.20.0.12", "name": "shop (bff-gateway)", "ports": [5000]},
                       {"ip": "172.20.0.20", "name": "db (MySQL)", "ports": [3306]},
                       {"ip": "172.20.0.21", "name": "redis", "ports": [6379]},
                       {"ip": "172.20.0.22", "name": "mongodb", "ports": [27017]}
                   ], "flag": "INFO_NETWORK_LEAK"})

@app.route("/api/source")
def source_code():
    """泄露admin-panel的源码片段"""
    return jsonify({"source_snippets": [
        "# admin-panel/app.py line 45:",
        "if request.args.get('debug') == '1':",
        "    return jsonify({'jwt_secret_preview': JWT_SECRET[:8] + '...'})",
        "",
        "# Internal endpoints (no auth required):",
        "# /api/internal/health",
        "# /api/internal/db-status",
        "# /api/internal/config  ← contains JWT_SECRET",
        "",
        "# Hidden params discovered in frontend:",
        "# debug=1, trace=1, internal=true, raw=1, mock=1",
        "# _method=DELETE, force=1, preview=1, sandbox=1"
    ], "flag": "INFO_SOURCE_CODE_LEAK"})

@app.route("/backup/latest.sql")
def backup_download():
    dump = """-- app_db backup
CREATE TABLE users (id INT, username VARCHAR(50), password VARCHAR(100), role VARCHAR(20));
INSERT INTO users VALUES (1,'admin','admin123','admin'),(2,'zhangsan','zs123456','user');
-- flag: INFO_BACKUP_DOWNLOAD
"""
    return Response(dump, mimetype="application/octet-stream",
                   headers={"Content-Disposition": "attachment; filename=backup.sql"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
