# SECURITY-REVIEWED: 2026-07-09 | RULES: v2.6.0-draft
# admin-panel: Flask service with 15 hidden params + JWT + pickle + XXE + header backdoor

from flask import Flask, request, jsonify, Response, render_template
import jwt
import datetime
import subprocess
import xml.etree.ElementTree as ET
import base64
import pickle
import csv
import io
import os
import json

app = Flask(__name__)

# ============ 配置（故意放在这里方便泄露） ============
JWT_SECRET = "dev-secret-change-me"
ADMIN_PASSWORD_HASH = "21232f297a57a5a743894a0e4a801fc3"
INTERNAL_KEY = "sk-app-internal"
DB_CONFIG = {"host": "db", "port": 3306, "user": "appuser", "password": "apppass123"}

USERS = {
    1: {"id": 1, "username": "admin", "password": "admin123", "role": "admin",
        "email": "admin@target.com", "phone": "13800138000",
        "id_card": "110101199001011234", "salary": 50000, "address": "Admin HQ"},
    2: {"id": 2, "username": "zhangsan", "password": "zs123456", "role": "user",
        "email": "zhangsan@target.com", "balance": 10000},
    3: {"id": 3, "username": "lisi", "password": "ls123456", "role": "user",
        "email": "lisi@target.com", "balance": 5000},
}

ORDERS = {
    1: {"id": 1, "user_id": 1, "item": "Server Rack", "price": 9999, "status": "completed",
        "note": "管理IP: 10.0.0.100:8080"},
    2: {"id": 2, "user_id": 2, "item": "MacBook", "price": 12999, "status": "shipped"},
    3: {"id": 3, "user_id": 3, "item": "Monitor", "price": 2999, "status": "pending"},
}

# ============================================================
# 首页 — 前端痕迹
# ============================================================
@app.route("/")
def index():
    return render_template("index.html")

# ============================================================
# 登录 — V1(debug) + V2(trace) + SQL注入
# ============================================================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.args.get("trace") == "1":
        token = jwt.encode({"user_id": 1, "role": "admin",
                           "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24)},
                          JWT_SECRET, algorithm="HS256")
        return jsonify({"token": token, "mode": "trace",
                       "warning": "trace mode is for debugging only"})

    if request.method == "GET":
        return render_template("login.html")

    if request.args.get("debug") == "1":
        return jsonify({
            "debug": True,
            "sql_query": f"SELECT * FROM users WHERE username='{request.form.get('username', '')}'",
            "jwt_secret_preview": JWT_SECRET[:8] + "...",
            "internal_key_preview": INTERNAL_KEY[:6] + "...",
            "hint": "Try ?trace=1 for trace mode"
        }), 401

    username = request.form.get("username", "")
    password = request.form.get("password", "")
    for user in USERS.values():
        if user["username"] == username and user["password"] == password:
            token = jwt.encode({"user_id": user["id"], "role": user["role"],
                               "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
                              JWT_SECRET, algorithm="HS256")
            return jsonify({"token": token})
    return jsonify({"error": "Invalid credentials"}), 401

# ============================================================
# 用户管理 — V3(export_all) + V4(env) + V5(mock) + V6(internal)
# ============================================================
@app.route("/api/users")
def list_users():
    if request.args.get("internal") == "true":
        return jsonify({"users": list(USERS.values()), "source": "internal_mode",
                       "flag": "HIDDEN_PARAM_INTERNAL_TRUE"})
    if request.args.get("mock") == "1":
        return jsonify({"users": [{"id": 999, "username": "mock_admin", "password": "mock_pass",
                                    "role": "admin", "note": "mock data"}],
                       "flag": "HIDDEN_PARAM_MOCK_DATA"})
    if request.args.get("env") == "development":
        return jsonify({"users": list(USERS.values()), "mode": "dev_env",
                       "db_config": DB_CONFIG, "flag": "HIDDEN_PARAM_ENV_DEV"})

    auth = request.headers.get("Authorization", "")
    token = auth.replace("Bearer ", "") if auth.startswith("Bearer ") else ""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        if payload.get("role") != "admin":
            if request.args.get("__admin_token") != INTERNAL_KEY:
                return jsonify({"error": "Admin required"}), 403
    except:
        if request.args.get("__admin_token") != INTERNAL_KEY:
            return jsonify({"error": "Invalid token"}), 401

    result = [{"id": u["id"], "username": u["username"], "role": u["role"]} for u in USERS.values()]

    if request.args.get("format") == "csv":
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=["id", "username", "role"])
        writer.writeheader()
        writer.writerows(result)
        return Response(output.getvalue(), mimetype="text/csv")
    return jsonify(result)

# ============================================================
# 单用户 — V7(_method) + V8(force) + V9(preview)
# ============================================================
@app.route("/api/users/<int:user_id>")
def get_user(user_id):
    if request.args.get("_method") == "DELETE":
        user = USERS.pop(user_id, None)
        return jsonify({"deleted": user is not None, "flag": "HIDDEN_PARAM_METHOD_OVERRIDE"})
    if request.args.get("force") == "1":
        user = USERS.get(user_id)
        return jsonify(user) if user else (jsonify({"error": "Not found"}), 404)
    if request.args.get("preview") == "1":
        user = USERS.get(user_id)
        if user:
            return jsonify({**user, "preview_mode": True, "flag": "HIDDEN_PARAM_PREVIEW_MODE"})

    auth = request.headers.get("Authorization", "")
    token = auth.replace("Bearer ", "") if auth.startswith("Bearer ") else ""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        if payload.get("role") != "admin" and payload.get("user_id") != user_id:
            return jsonify({"error": "Access denied"}), 403
    except:
        return jsonify({"error": "Invalid token"}), 401

    user = USERS.get(user_id)
    return jsonify(user) if user else (jsonify({"error": "Not found"}), 404)

@app.route("/api/users/<int:user_id>/orders")
def user_orders(user_id):
    orders = [o for o in ORDERS.values() if o["user_id"] == user_id]
    if request.args.get("nocache") == "1":
        return jsonify({"orders": orders, "full_data": True, "flag": "HIDDEN_PARAM_NOCACHE_FULL"})
    callback = request.args.get("callback")
    if callback:
        resp = json.dumps({"orders": [{"id": o["id"], "item": o["item"]} for o in orders]})
        return Response(f"{callback}({resp});", mimetype="application/javascript")
    return jsonify({"orders": [{"id": o["id"], "item": o["item"], "status": o["status"]} for o in orders]})

# ============================================================
# 系统接口 — V13(raw) + V14(test) + V15(sandbox)
# ============================================================
@app.route("/api/system/status")
def system_status():
    if request.args.get("raw") == "1":
        return jsonify({"raw_config": True, "database": DB_CONFIG,
                       "jwt_secret": JWT_SECRET, "internal_key": INTERNAL_KEY,
                       "env_vars": {k: v for k, v in os.environ.items() if not k.startswith("_")},
                       "flag": "HIDDEN_PARAM_RAW_CONFIG"})
    if request.args.get("test") == "1":
        return jsonify({"mode": "test", "internal_endpoints": [
            "/api/internal/health", "/api/internal/db-status", "/api/internal/cache-stats"
        ], "flag": "HIDDEN_PARAM_TEST_MODE"})
    if request.args.get("sandbox") == "1":
        return jsonify({"mode": "sandbox", "users_count": len(USERS),
                       "total_balance": sum(u.get("balance", 0) for u in USERS.values()),
                       "flag": "HIDDEN_PARAM_SANDBOX_BYPASS"})
    return jsonify({"status": "ok", "version": "2.1.0", "env": "production"})

@app.route("/api/internal/health")
def internal_health():
    return jsonify({"status": "ok", "services": {"db": "up", "redis": "up"},
                   "flag": "INTERNAL_ENDPOINT_HEALTH"})

@app.route("/api/internal/db-status")
def db_status():
    return jsonify({**DB_CONFIG, "flag": "INTERNAL_ENDPOINT_DB_STATUS"})

@app.route("/api/internal/cache-stats")
def cache_stats():
    return jsonify({"redis_host": "redis:6379", "keys": 42, "flag": "INTERNAL_ENDPOINT_CACHE_STATS"})

# ============================================================
# V10: Pickle反序列化RCE
# ============================================================
@app.route("/api/preferences", methods=["POST"])
def preferences():
    data = request.get_json() or {}
    pickle_data = data.get("__pickle_data")
    if pickle_data:
        try:
            obj = pickle.loads(base64.b64decode(pickle_data))
            return jsonify({"loaded": str(obj), "flag": "HIDDEN_PARAM_PICKLE_RCE"})
        except Exception as e:
            return jsonify({"error": str(e)}), 400
    return jsonify({"theme": data.get("theme", "light")})

# ============================================================
# V11: XXE
# ============================================================
@app.route("/api/users/bulk-delete", methods=["POST"])
def bulk_delete_users():
    content_type = request.content_type or ""
    if "xml" in content_type:
        try:
            root = ET.fromstring(request.data)
            ids = [int(elem.text) for elem in root.findall(".//id")]
            return jsonify({"deleted": ids, "source": "xml_parser",
                           "flag": "HIDDEN_PARAM_XXE_TRIGGERED"})
        except Exception as e:
            return jsonify({"error": str(e), "source": "xml_parser"}), 400
    data = request.get_json() or {}
    return jsonify({"deleted": data.get("ids", []), "source": "json_parser"})

# ============================================================
# V12: Header后门
# ============================================================
@app.route("/api/internal/config")
def internal_config():
    if request.headers.get("X-Internal-Request") == "true" or \
       request.headers.get("X-Debug-Mode") == "1":
        return jsonify({"database": DB_CONFIG, "redis": {"host": "redis", "port": 6379, "password": None},
                       "jwt": {"secret": JWT_SECRET, "algorithm": "HS256"},
                       "admin_token": INTERNAL_KEY, "internal_key": INTERNAL_KEY,
                       "feature_flags": {"debug_endpoints": True, "new_payment_flow": True}})
    return jsonify({"error": "Forbidden"}), 403

# ============================================================
# 错误处理 — 调试信息泄露参数名
# ============================================================
@app.errorhandler(404)
def not_found(e):
    if request.args.get("debug") == "1" or os.environ.get("DEBUG") == "True":
        return jsonify({
            "error": "Not found",
            "available_params": [
                "debug=1 - enable debug mode", "trace=1 - enable trace mode",
                "format=csv - export as CSV", "env=development - switch to dev env",
                "mock=1 - use mock data", "internal=true - internal mode",
                "_method=DELETE - method override", "force=1 - skip validation",
                "preview=1 - preview mode", "raw=1 - raw output",
                "test=1 - test mode", "sandbox=1 - sandbox mode",
                "callback=func - JSONP callback", "nocache=1 - bypass cache",
                "validate=false - disable validation"
            ],
            "hint": "Some params may require admin privileges",
            "sourcemap": "/static/app.js.map"
        }), 404
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(500)
def server_error(e):
    if os.environ.get("DEBUG") == "True":
        import traceback
        return jsonify({"error": e.message if hasattr(e, 'message') else str(e),
                       "traceback": traceback.format_exc(),
                       "env": dict(os.environ), "flag": "DEBUG_ERROR_LEAK"}), 500
    return jsonify({"error": "Internal server error"}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
