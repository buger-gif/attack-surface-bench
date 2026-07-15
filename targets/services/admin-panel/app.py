# admin-panel: Flask service with 15 hidden params + JWT + pickle + XXE + header backdoor

from flask import Flask, request, jsonify, Response, render_template, make_response
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
import re
import uuid

app = Flask(__name__)

# ============ 配置（故意放在这里方便泄露） ============
JWT_SECRET = "dev-secret-change-me"
ADMIN_PASSWORD_HASH = "21232f297a57a5a743894a0e4a801fc3"
INTERNAL_KEY = "sk-app-internal"
DB_CONFIG = {"host": "db", "port": 3306, "user": "appuser", "password": "apppass123"}

USERS = {
    1: {"id": 1, "username": "admin", "password": "admin123", "role": "admin",
        "email": "admin@target.bench", "phone": "13800138000",
        "id_card": "110101199001011234", "salary": 50000, "address": "Admin HQ"},
    2: {"id": 2, "username": "zhangsan", "password": "zs123456", "role": "user",
        "email": "zhangsan@target.bench", "balance": 10000},
    3: {"id": 3, "username": "lisi", "password": "ls123456", "role": "user",
        "email": "lisi@target.bench", "balance": 5000},
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
            "internal_key_preview": INTERNAL_KEY[:6] + "..."
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
# 系统接口 — hidden params (raw/test/sandbox)
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
    # CLUE_API_HEADER: leaks internal API domain in error response
    if request.args.get("debug") == "1" or os.environ.get("DEBUG") == "True":
        resp = jsonify({"error": "Not found", "sourcemap": "/static/app.js.map"})
    else:
        resp = jsonify({"error": "Not found"})
    resp.headers["X-Internal-Api"] = "api.target.bench"
    return resp, 404

@app.errorhandler(500)
def server_error(e):
    if os.environ.get("DEBUG") == "True":
        import traceback
        resp = jsonify({"error": e.message if hasattr(e, 'message') else str(e),
                       "traceback": traceback.format_exc(),
                       "env": dict(os.environ), "flag": "DEBUG_ERROR_LEAK"})
        resp.headers["X-Internal-Api"] = "api.target.bench"
        return resp, 500
    resp = jsonify({"error": "Internal server error"})
    resp.headers["X-Internal-Api"] = "api.target.bench"
    return resp, 500

# ============================================================
# Safe endpoints: MySQL connection helper
# ============================================================
try:
    import pymysql
    MYSQL_AVAILABLE = True
except ImportError:
    MYSQL_AVAILABLE = False

def get_db_connection():
    """Create a new MySQL connection using config from environment variables.
    D-001: No hardcoded credential fallbacks — fail closed if env vars are missing."""
    if not MYSQL_AVAILABLE:
        return None
    db_host = os.environ.get("DB_HOST")
    db_user = os.environ.get("DB_USER")
    db_password = os.environ.get("DB_PASSWORD")
    db_name = os.environ.get("DB_NAME")
    # D-001: require all connection params from env, no hardcoded defaults
    if not all([db_host, db_user, db_password, db_name]):
        return None
    try:
        conn = pymysql.connect(
            host=db_host,
            port=3306,
            user=db_user,
            password=db_password,
            database=db_name,
            charset="utf8mb4",
            cursorclass=pymysql.cursors.DictCursor
        )
        return conn
    except Exception:
        return None

# ============================================================
# Audit log — safe in-memory store for demo
# ============================================================
AUDIT_LOG = []

def write_audit_log(operator_id, action, target, detail, result):
    """M-003: Audit log with desensitization — no passwords/tokens logged."""
    entry = {
        "id": str(uuid.uuid4()),
        "operator_id": operator_id,
        "action": action,
        "target": str(target)[:50],
        "detail": str(detail)[:100],
        "result": result,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "ip": request.remote_addr
    }
    AUDIT_LOG.append(entry)

# ============================================================
# Auth helper for safe endpoints — uses INTERNAL_KEY defined above
# ============================================================

def require_auth():
    """Verify JWT or __admin_token. Returns (payload_dict, error_response).
    Follows M-001: strict type/range check on token fields."""
    auth_header = request.headers.get("Authorization", "")
    admin_token = request.args.get("__admin_token", "") or request.headers.get("X-Admin-Token", "")

    # __admin_token path — must match exactly
    if admin_token:
        if admin_token == INTERNAL_KEY:
            return {"user_id": 0, "role": "admin", "source": "admin_token"}, None
        # M-001: reject invalid tokens immediately
        return None, (jsonify({"error": "ERR_AUTH_INVALID_TOKEN"}), 401)

    # JWT path
    if auth_header.startswith("Bearer "):
        token_str = auth_header[7:]
        try:
            payload = jwt.decode(token_str, JWT_SECRET, algorithms=["HS256"])
            # M-001: validate expected fields and types
            if not isinstance(payload.get("user_id"), int) or payload.get("user_id", 0) <= 0:
                return None, (jsonify({"error": "ERR_AUTH_INVALID_PAYLOAD"}), 401)
            if payload.get("role") not in ("admin", "user", "manager"):
                return None, (jsonify({"error": "ERR_AUTH_INVALID_ROLE"}), 401)
            return payload, None
        except jwt.ExpiredSignatureError:
            return None, (jsonify({"error": "ERR_AUTH_TOKEN_EXPIRED"}), 401)
        except jwt.InvalidTokenError:
            return None, (jsonify({"error": "ERR_AUTH_INVALID_TOKEN"}), 401)

    return None, (jsonify({"error": "ERR_AUTH_REQUIRED"}), 401)

def require_role(payload, allowed_roles):
    """Check that payload role is in allowed_roles."""
    if payload.get("role") not in allowed_roles:
        return jsonify({"error": "ERR_FORBIDDEN_ROLE"}), 403
    return None

def validate_input(value, field_name, max_len=50, pattern=None, allowed_values=None):
    """M-001: Input validation — type, length, pattern, allowed values."""
    if value is None:
        return None
    if not isinstance(value, str):
        return f"ERR_INVALID_TYPE_{field_name.upper()}"
    if len(value) > max_len:
        return f"ERR_LENGTH_EXCEEDED_{field_name.upper()}"
    if len(value) == 0:
        return f"ERR_EMPTY_{field_name.upper()}"
    if pattern and not re.match(pattern, value):
        return f"ERR_PATTERN_MISMATCH_{field_name.upper()}"
    if allowed_values and value not in allowed_values:
        return f"ERR_DISALLOWED_VALUE_{field_name.upper()}"
    return None

def sanitize_for_csv(value):
    """M-008: CSV injection protection — prefix dangerous chars with single quote."""
    if not isinstance(value, str):
        value = str(value)
    if value and value[0] in ('=', '+', '-', '@', '\t', '\r'):
        value = "'" + value
    return value

def desensitize_phone(phone):
    """Desensitize phone: show only last 4 digits."""
    if not phone or len(phone) < 4:
        return "***"
    return "****" + phone[-4:]

def desensitize_id_card(id_card):
    """Desensitize ID card: show only first 3 and last 4."""
    if not id_card or len(id_card) < 7:
        return "***"
    return id_card[:3] + "****" + id_card[-4:]

# ============================================================
# Sample data for safe endpoints
# ============================================================
REPORT_SALES = [
    {"date": "2026-07-01", "total_orders": 120, "total_amount": 58000, "avg_order": 483},
    {"date": "2026-07-02", "total_orders": 135, "total_amount": 62000, "avg_order": 467},
    {"date": "2026-07-03", "total_orders": 98, "total_amount": 45000, "avg_order": 460},
    {"date": "2026-07-04", "total_orders": 142, "total_amount": 71000, "avg_order": 504},
    {"date": "2026-07-05", "total_orders": 110, "total_amount": 53000, "avg_order": 486},
    {"date": "2026-07-06", "total_orders": 128, "total_amount": 60000, "avg_order": 470},
    {"date": "2026-07-07", "total_orders": 156, "total_amount": 78000, "avg_order": 500},
    {"date": "2026-07-08", "total_orders": 115, "total_amount": 55000, "avg_order": 479},
    {"date": "2026-07-09", "total_orders": 130, "total_amount": 63000, "avg_order": 485},
    {"date": "2026-07-10", "total_orders": 145, "total_amount": 72000, "avg_order": 498},
    {"date": "2026-07-11", "total_orders": 162, "total_amount": 81000, "avg_order": 500},
    {"date": "2026-07-12", "total_orders": 118, "total_amount": 56000, "avg_order": 475},
    {"date": "2026-07-13", "total_orders": 155, "total_amount": 77000, "avg_order": 497},
    {"date": "2026-07-14", "total_orders": 140, "total_amount": 69000, "avg_order": 493},
]

REPORT_PRODUCTS = [
    {"product_id": 1, "name": "Server Rack", "category": "hardware", "total_sales": 45, "total_amount": 449955},
    {"product_id": 2, "name": "MacBook Pro", "category": "hardware", "total_sales": 32, "total_amount": 415968},
    {"product_id": 3, "name": "Monitor 27\"", "category": "hardware", "total_sales": 28, "total_amount": 83972},
    {"product_id": 4, "name": "Cloud Storage 1TB", "category": "service", "total_sales": 56, "total_amount": 5600},
    {"product_id": 5, "name": "VPN Service", "category": "service", "total_sales": 40, "total_amount": 4000},
    {"product_id": 6, "name": "Office Suite", "category": "software", "total_sales": 65, "total_amount": 32500},
    {"product_id": 7, "name": "Antivirus Pro", "category": "software", "total_sales": 38, "total_amount": 19000},
]

REPORT_REGIONS = [
    {"region": "华东", "user_count": 5200, "active_rate": 0.72},
    {"region": "华南", "user_count": 3800, "active_rate": 0.68},
    {"region": "华北", "user_count": 4100, "active_rate": 0.75},
    {"region": "西南", "user_count": 2200, "active_rate": 0.60},
    {"region": "华中", "user_count": 2900, "active_rate": 0.65},
    {"region": "东北", "user_count": 1800, "active_rate": 0.55},
]

REPORT_SCHEDULES = []

HR_EMPLOYEES = [
    {"id": 1, "name": "王明", "department": "技术部", "position": "高级工程师", "gender": "男",
     "phone": "13800138001", "id_card": "110101199001011235", "salary": 35000,
     "hire_date": "2023-03-15", "status": "active"},
    {"id": 2, "name": "李芳", "department": "产品部", "position": "产品经理", "gender": "女",
     "phone": "13900139002", "id_card": "310101199203021236", "salary": 28000,
     "hire_date": "2023-06-01", "status": "active"},
    {"id": 3, "name": "张伟", "department": "运营部", "position": "运营专员", "gender": "男",
     "phone": "13700137003", "id_card": "440101199505031237", "salary": 15000,
     "hire_date": "2024-01-10", "status": "active"},
    {"id": 4, "name": "赵丽", "department": "技术部", "position": "前端工程师", "gender": "女",
     "phone": "13600136004", "id_card": "320101199707041238", "salary": 22000,
     "hire_date": "2024-04-20", "status": "active"},
    {"id": 5, "name": "陈刚", "department": "财务部", "position": "财务主管", "gender": "男",
     "phone": "13500135005", "id_card": "510101199108051239", "salary": 30000,
     "hire_date": "2022-09-01", "status": "active"},
    {"id": 6, "name": "刘洋", "department": "市场部", "position": "市场经理", "gender": "男",
     "phone": "13400134006", "id_card": "210101199310061240", "salary": 25000,
     "hire_date": "2023-08-15", "status": "active"},
    {"id": 7, "name": "孙娜", "department": "人事部", "position": "HR专员", "gender": "女",
     "phone": "13300133007", "id_card": "120101199412071241", "salary": 16000,
     "hire_date": "2024-02-28", "status": "active"},
    {"id": 8, "name": "周磊", "department": "技术部", "position": "后端工程师", "gender": "男",
     "phone": "13200132008", "id_card": "330101199603081242", "salary": 26000,
     "hire_date": "2024-03-01", "status": "active"},
]

HR_DEPARTMENTS = [
    {"id": 1, "name": "技术部", "head_count": 3, "avg_salary_range": "22k-35k"},
    {"id": 2, "name": "产品部", "head_count": 1, "avg_salary_range": "28k"},
    {"id": 3, "name": "运营部", "head_count": 1, "avg_salary_range": "15k"},
    {"id": 4, "name": "财务部", "head_count": 1, "avg_salary_range": "30k"},
    {"id": 5, "name": "市场部", "head_count": 1, "avg_salary_range": "25k"},
    {"id": 6, "name": "人事部", "head_count": 1, "avg_salary_range": "16k"},
]

HR_ATTENDANCE = [
    {"id": 1, "employee_id": 1, "date": "2026-07-01", "check_in": "09:00", "check_out": "18:00", "status": "normal"},
    {"id": 2, "employee_id": 1, "date": "2026-07-02", "check_in": "09:15", "check_out": "18:30", "status": "normal"},
    {"id": 3, "employee_id": 1, "date": "2026-07-03", "check_in": "08:45", "check_out": "17:45", "status": "normal"},
    {"id": 4, "employee_id": 2, "date": "2026-07-01", "check_in": "09:30", "check_out": "18:00", "status": "late"},
    {"id": 5, "employee_id": 2, "date": "2026-07-02", "check_in": "09:00", "check_out": "18:00", "status": "normal"},
    {"id": 6, "employee_id": 3, "date": "2026-07-01", "check_in": "09:00", "check_out": "18:00", "status": "normal"},
    {"id": 7, "employee_id": 3, "date": "2026-07-03", "check_in": None, "check_out": None, "status": "absent"},
    {"id": 8, "employee_id": 4, "date": "2026-07-01", "check_in": "08:50", "check_out": "18:10", "status": "normal"},
    {"id": 9, "employee_id": 5, "date": "2026-07-01", "check_in": "09:00", "check_out": "18:00", "status": "normal"},
    {"id": 10, "employee_id": 5, "date": "2026-07-02", "check_in": "09:00", "check_out": "17:30", "status": "early_leave"},
]

HR_LEAVE_REQUESTS = [
    {"id": 1, "employee_id": 1, "type": "年假", "start_date": "2026-07-15", "end_date": "2026-07-17",
     "days": 3, "reason": "家庭事务", "status": "pending", "approver_id": None},
    {"id": 2, "employee_id": 2, "type": "病假", "start_date": "2026-07-10", "end_date": "2026-07-11",
     "days": 2, "reason": "身体不适", "status": "approved", "approver_id": 5},
    {"id": 3, "employee_id": 3, "type": "事假", "start_date": "2026-07-08", "end_date": "2026-07-08",
     "days": 1, "reason": "个人原因", "status": "rejected", "approver_id": 6},
]

REPORT_NOTIFICATIONS = [
    {"id": 1, "title": "月度销售报告已生成", "type": "report_ready", "created_at": "2026-07-10T08:00:00Z",
     "status": "unread"},
    {"id": 2, "title": "异常订单预警", "type": "alert", "created_at": "2026-07-12T14:30:00Z",
     "status": "read"},
]

# ============================================================
# /reports — 运营报告区 (15 safe endpoints)
# ============================================================

@app.route("/reports")
def reports_page():
    """GET /reports — HTML dashboard page."""
    return render_template("reports.html")

@app.route("/reports/api/dashboard")
def reports_dashboard():
    """GET /reports/api/dashboard — Dashboard data, desensitized, auth required."""
    payload, err = require_auth()
    if err:
        return err
    is_admin = payload.get("role") == "admin"

    # Aggregated counts only, no PII
    total_sales_amount = sum(r["total_amount"] for r in REPORT_SALES)
    total_orders = sum(r["total_orders"] for r in REPORT_SALES)
    avg_order = round(total_sales_amount / max(total_orders, 1), 2)

    result = {
        "summary": {
            "total_orders": total_orders,
            "avg_order_amount": avg_order,
            "total_users": sum(r["user_count"] for r in REPORT_REGIONS),
            "total_products": len(REPORT_PRODUCTS),
        }
    }
    # Revenue details only visible to admin role
    if is_admin:
        result["summary"]["total_revenue"] = total_sales_amount
    else:
        result["summary"]["total_revenue"] = "REDACTED_NON_ADMIN"

    # M-007: Limit top products to 5
    result["top_products"] = sorted(
        [{"name": p["name"], "total_sales": p["total_sales"]} for p in REPORT_PRODUCTS],
        key=lambda x: x["total_sales"], reverse=True
    )[:5]

    return jsonify(result)

@app.route("/reports/api/sales")
def reports_sales():
    """GET /reports/api/sales — Sales summary with pagination and desensitization."""
    payload, err = require_auth()
    if err:
        return err
    is_admin = payload.get("role") == "admin"

    # M-001: validate pagination params
    page = request.args.get("page", "1")
    page_size = request.args.get("page_size", "10")
    try:
        page = max(1, int(page))
        page_size = max(1, min(100, int(page_size)))  # M-007: max 100 per page
    except (ValueError, TypeError):
        return jsonify({"error": "ERR_INVALID_PAGINATION"}), 400

    total = len(REPORT_SALES)
    start = (page - 1) * page_size
    end = start + page_size
    items = REPORT_SALES[start:end]

    # Desensitize: non-admin sees no revenue details
    if not is_admin:
        items = [{"date": r["date"], "total_orders": r["total_orders"],
                  "avg_order": r["avg_order"]} for r in items]

    return jsonify({"total": total, "page": page, "page_size": page_size, "items": items})

@app.route("/reports/api/sales/daily")
def reports_sales_daily():
    """GET /reports/api/sales/daily — Daily breakdown with date range validation.
    Uses parameterized query when MySQL is available; falls back to in-memory data.
    M-007: pagination with max page_size 100; M-005: no source disclosure."""
    payload, err = require_auth()
    if err:
        return err

    start_date = request.args.get("start_date", "")
    end_date = request.args.get("end_date", "")

    # M-001: validate date format YYYY-MM-DD
    date_pattern = r"^\d{4}-\d{2}-\d{2}$"
    if start_date:
        err_v = validate_input(start_date, "start_date", max_len=10, pattern=date_pattern)
        if err_v:
            return jsonify({"error": err_v}), 400
    if end_date:
        err_v = validate_input(end_date, "end_date", max_len=10, pattern=date_pattern)
        if err_v:
            return jsonify({"error": err_v}), 400

    # M-007: pagination params
    page = request.args.get("page", "1")
    page_size = request.args.get("page_size", "20")
    try:
        page = max(1, int(page))
        page_size = max(1, min(100, int(page_size)))
    except (ValueError, TypeError):
        return jsonify({"error": "ERR_INVALID_PAGINATION"}), 400

    # Attempt parameterized MySQL query — M-007: LIMIT capped at 100
    conn = get_db_connection()
    if conn:
        try:
            offset = (page - 1) * page_size
            with conn.cursor() as cursor:
                query = "SELECT date, total_orders, total_amount, avg_order FROM report_sales WHERE date BETWEEN %s AND %s ORDER BY date LIMIT %s OFFSET %s"
                cursor.execute(query, (start_date or "2026-01-01", end_date or "2099-12-31", page_size, offset))
                rows = cursor.fetchall()
            conn.close()
            # M-005: no source disclosure
            return jsonify({"items": rows, "page": page, "page_size": page_size})
        except Exception:
            # M-005: Do not leak exception details
            try:
                conn.close()
            except Exception:
                pass

    # Fallback: in-memory filter
    items = REPORT_SALES
    if start_date:
        items = [r for r in items if r["date"] >= start_date]
    if end_date:
        items = [r for r in items if r["date"] <= end_date]

    total = len(items)
    start_idx = (page - 1) * page_size
    end_idx = start_idx + page_size
    page_items = items[start_idx:end_idx]

    is_admin = payload.get("role") == "admin"
    if not is_admin:
        page_items = [{"date": r["date"], "total_orders": r["total_orders"],
                  "avg_order": r["avg_order"]} for r in page_items]

    # M-005: no source disclosure
    return jsonify({"items": page_items, "page": page, "page_size": page_size, "total": total})

@app.route("/reports/api/sales/export")
def reports_sales_export():
    """GET /reports/api/sales/export — CSV export with CSV injection protection.
    M-003: audit log for data export."""
    payload, err = require_auth()
    if err:
        return err
    role_err = require_role(payload, ["admin"])
    if role_err:
        return role_err

    # M-003: audit log
    write_audit_log(payload.get("user_id"), "EXPORT_SALES", "sales_export", "csv", "success")

    output = io.StringIO()
    writer = csv.writer(output)
    # M-008: CSV injection — sanitize each field
    writer.writerow([sanitize_for_csv("日期"), sanitize_for_csv("订单数"),
                     sanitize_for_csv("总金额"), sanitize_for_csv("平均单价")])
    for r in REPORT_SALES:
        writer.writerow([sanitize_for_csv(r["date"]), sanitize_for_csv(r["total_orders"]),
                         sanitize_for_csv(r["total_amount"]), sanitize_for_csv(r["avg_order"])])

    resp = make_response(output.getvalue())
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = "attachment; filename=sales_export.csv"
    return resp

@app.route("/reports/api/users/active")
def reports_users_active():
    """GET /reports/api/users/active — Active user stats, counts only, no PII."""
    payload, err = require_auth()
    if err:
        return err

    total_users = sum(r["user_count"] for r in REPORT_REGIONS)
    active_users = sum(int(r["user_count"] * r["active_rate"]) for r in REPORT_REGIONS)

    return jsonify({
        "total_users": total_users,
        "active_users": active_users,
        "active_rate": round(active_users / max(total_users, 1), 4),
        "detail": "COUNTS_ONLY_NO_PII"
    })

@app.route("/reports/api/users/regions")
def reports_users_regions():
    """GET /reports/api/users/regions — User distribution by region, aggregated counts."""
    payload, err = require_auth()
    if err:
        return err

    result = [{"region": r["region"], "user_count": r["user_count"],
               "active_rate": round(r["active_rate"], 2)} for r in REPORT_REGIONS]
    return jsonify({"items": result})

@app.route("/reports/api/products/ranking")
def reports_products_ranking():
    """GET /reports/api/products/ranking — Product ranking, aggregated data only."""
    payload, err = require_auth()
    if err:
        return err

    is_admin = payload.get("role") == "admin"
    ranked = sorted(REPORT_PRODUCTS, key=lambda p: p["total_sales"], reverse=True)

    # Non-admin: aggregated data only, no amounts
    if not is_admin:
        result = [{"product_id": p["product_id"], "name": p["name"],
                   "category": p["category"], "total_sales": p["total_sales"]} for p in ranked[:10]]
    else:
        result = [{"product_id": p["product_id"], "name": p["name"],
                   "category": p["category"], "total_sales": p["total_sales"],
                   "total_amount": p["total_amount"]} for p in ranked[:10]]

    return jsonify({"items": result})

@app.route("/reports/api/orders/stats")
def reports_orders_stats():
    """GET /reports/api/orders/stats — Order statistics, aggregated, no PII."""
    payload, err = require_auth()
    if err:
        return err

    total_orders = sum(r["total_orders"] for r in REPORT_SALES)
    total_amount = sum(r["total_amount"] for r in REPORT_SALES)

    result = {
        "total_orders": total_orders,
        "avg_order_value": round(total_amount / max(total_orders, 1), 2),
        "completed_rate": 0.85,
        "cancelled_rate": 0.05,
        "note": "AGGREGATED_STATS_NO_PII"
    }

    is_admin = payload.get("role") == "admin"
    if is_admin:
        result["total_amount"] = total_amount
    else:
        result["total_amount"] = "REDACTED"

    return jsonify(result)

@app.route("/reports/api/charts/sales")
def reports_charts_sales():
    """GET /reports/api/charts/sales — Chart data, aggregated and sanitized."""
    payload, err = require_auth()
    if err:
        return err

    is_admin = payload.get("role") == "admin"
    chart_data = [{"date": r["date"], "orders": r["total_orders"],
                   "avg": r["avg_order"]} for r in REPORT_SALES]
    if is_admin:
        for item, r in zip(chart_data, REPORT_SALES):
            item["amount"] = r["total_amount"]

    return jsonify({"chart_type": "line", "data": chart_data})

@app.route("/reports/api/charts/users")
def reports_charts_users():
    """GET /reports/api/charts/users — User growth chart data, aggregated."""
    payload, err = require_auth()
    if err:
        return err

    # Simulated growth data — counts only, no PII
    growth_data = [
        {"month": "2026-01", "new_users": 320, "total_users": 12000},
        {"month": "2026-02", "new_users": 450, "total_users": 12450},
        {"month": "2026-03", "new_users": 380, "total_users": 12830},
        {"month": "2026-04", "new_users": 520, "total_users": 13350},
        {"month": "2026-05", "new_users": 410, "total_users": 13760},
        {"month": "2026-06", "new_users": 560, "total_users": 14320},
        {"month": "2026-07", "new_users": 490, "total_users": 14810},
    ]
    return jsonify({"chart_type": "bar", "data": growth_data})

@app.route("/reports/api/schedules", methods=["POST"])
def reports_create_schedule():
    """POST /reports/api/schedules — Schedule report generation, input validation, auth required."""
    payload, err = require_auth()
    if err:
        return err

    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({"error": "ERR_INVALID_REQUEST_BODY"}), 400

    # M-001: Validate required fields
    report_type = data.get("report_type", "")
    schedule_date = data.get("schedule_date", "")
    format_type = data.get("format", "json")

    err_v = validate_input(report_type, "report_type", max_len=20,
                           allowed_values=["sales", "users", "products", "orders"])
    if err_v:
        return jsonify({"error": err_v}), 400

    err_v = validate_input(schedule_date, "schedule_date", max_len=10,
                           pattern=r"^\d{4}-\d{2}-\d{2}$")
    if err_v:
        return jsonify({"error": err_v}), 400

    err_v = validate_input(format_type, "format", max_len=10,
                           allowed_values=["json", "csv", "pdf"])
    if err_v:
        return jsonify({"error": err_v}), 400

    # M-003: Audit log
    write_audit_log(payload.get("user_id"), "CREATE_SCHEDULE",
                    report_type, f"format={format_type}, date={schedule_date}", "success")

    new_schedule = {
        "id": len(REPORT_SCHEDULES) + 1,
        "owner_id": payload.get("user_id"),
        "report_type": report_type,
        "schedule_date": schedule_date,
        "format": format_type,
        "status": "pending",
        "created_at": datetime.datetime.utcnow().isoformat() + "Z",
    }
    REPORT_SCHEDULES.append(new_schedule)

    return jsonify({"id": new_schedule["id"], "status": "pending"}), 201

@app.route("/reports/api/schedules", methods=["GET"])
def reports_list_schedules():
    """GET /reports/api/schedules — List own scheduled reports, auth required."""
    payload, err = require_auth()
    if err:
        return err

    owner_id = payload.get("user_id")
    own_schedules = [s for s in REPORT_SCHEDULES if s["owner_id"] == owner_id]

    return jsonify({"items": own_schedules, "total": len(own_schedules)})

@app.route("/reports/api/schedules/<int:schedule_id>", methods=["DELETE"])
def reports_cancel_schedule(schedule_id):
    """DELETE /reports/api/schedules/:id — Cancel schedule, only own, audit log."""
    payload, err = require_auth()
    if err:
        return err

    # M-001: validate schedule_id is positive integer (Flask <int:> already enforces)
    if schedule_id <= 0:
        return jsonify({"error": "ERR_INVALID_SCHEDULE_ID"}), 400

    schedule = None
    for s in REPORT_SCHEDULES:
        if s["id"] == schedule_id:
            schedule = s
            break

    if not schedule:
        return jsonify({"error": "ERR_SCHEDULE_NOT_FOUND"}), 404

    # Only owner or admin can cancel
    if schedule["owner_id"] != payload.get("user_id") and payload.get("role") != "admin":
        return jsonify({"error": "ERR_FORBIDDEN_NOT_OWNER"}), 403

    # M-003: Audit log
    write_audit_log(payload.get("user_id"), "CANCEL_SCHEDULE",
                    schedule_id, schedule.get("report_type", ""), "success")

    REPORT_SCHEDULES.remove(schedule)
    return jsonify({"id": schedule_id, "status": "cancelled"})

@app.route("/reports/api/notifications")
def reports_notifications():
    """GET /reports/api/notifications — Report notifications, desensitization, auth required."""
    payload, err = require_auth()
    if err:
        return err

    # Desensitize: only title and type, no internal details
    items = [{"id": n["id"], "title": n["title"], "type": n["type"],
              "status": n["status"], "created_at": n["created_at"]} for n in REPORT_NOTIFICATIONS]

    return jsonify({"items": items, "total": len(items)})

# ============================================================
# /hr — HR人事管理区 (12 safe endpoints)
# ============================================================

@app.route("/hr")
def hr_page():
    """GET /hr — HTML employee management page."""
    return render_template("hr.html")

@app.route("/hr/api/employees")
def hr_employees_list():
    """GET /hr/api/employees — Employee list, desensitized, pagination, auth required."""
    payload, err = require_auth()
    if err:
        return err

    # M-001: validate pagination params
    page = request.args.get("page", "1")
    page_size = request.args.get("page_size", "10")
    try:
        page = max(1, int(page))
        page_size = max(1, min(100, int(page_size)))  # M-007
    except (ValueError, TypeError):
        return jsonify({"error": "ERR_INVALID_PAGINATION"}), 400

    total = len(HR_EMPLOYEES)
    start = (page - 1) * page_size
    end = start + page_size
    items = HR_EMPLOYEES[start:end]

    # Desensitize: no id_card, no phone, no salary
    result = [{"id": e["id"], "name": e["name"], "department": e["department"],
               "position": e["position"], "gender": e["gender"],
               "hire_date": e["hire_date"], "status": e["status"]} for e in items]

    return jsonify({"total": total, "page": page, "page_size": page_size, "items": result})

@app.route("/hr/api/employees/<int:emp_id>")
def hr_employee_detail(emp_id):
    """GET /hr/api/employees/:id — Limited fields: name, department, position only."""
    payload, err = require_auth()
    if err:
        return err

    # M-001: emp_id must be positive (Flask <int:> enforces integer)
    if emp_id <= 0:
        return jsonify({"error": "ERR_INVALID_EMPLOYEE_ID"}), 400

    employee = None
    for e in HR_EMPLOYEES:
        if e["id"] == emp_id:
            employee = e
            break

    if not employee:
        return jsonify({"error": "ERR_EMPLOYEE_NOT_FOUND"}), 404

    # Limited fields only — no id_card, no phone, no salary
    result = {
        "id": employee["id"],
        "name": employee["name"],
        "department": employee["department"],
        "position": employee["position"],
        "status": employee["status"],
    }

    # Admin can see desensitized phone (last 4 digits)
    if payload.get("role") == "admin":
        result["phone_desensitized"] = desensitize_phone(employee.get("phone", ""))

    return jsonify(result)

@app.route("/hr/api/employees", methods=["POST"])
def hr_add_employee():
    """POST /hr/api/employees — Add employee, input validation, auth, audit log."""
    payload, err = require_auth()
    if err:
        return err
    role_err = require_role(payload, ["admin", "manager"])
    if role_err:
        return role_err

    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({"error": "ERR_INVALID_REQUEST_BODY"}), 400

    # M-001: Validate each field
    name = data.get("name", "")
    department = data.get("department", "")
    position = data.get("position", "")
    gender = data.get("gender", "")

    err_v = validate_input(name, "name", max_len=20, pattern=r"^[a-zA-Z一-龥]+$")
    if err_v:
        return jsonify({"error": err_v}), 400
    err_v = validate_input(department, "department", max_len=30,
                           allowed_values=["技术部", "产品部", "运营部", "财务部", "市场部", "人事部"])
    if err_v:
        return jsonify({"error": err_v}), 400
    err_v = validate_input(position, "position", max_len=30, pattern=r"^[a-zA-Z一-龥]+$")
    if err_v:
        return jsonify({"error": err_v}), 400
    err_v = validate_input(gender, "gender", max_len=5, allowed_values=["男", "女"])
    if err_v:
        return jsonify({"error": err_v}), 400

    # M-003: Audit log
    write_audit_log(payload.get("user_id"), "ADD_EMPLOYEE",
                    name, f"dept={department}, pos={position}", "success")

    new_id = max(e["id"] for e in HR_EMPLOYEES) + 1 if HR_EMPLOYEES else 1
    new_employee = {
        "id": new_id,
        "name": name,
        "department": department,
        "position": position,
        "gender": gender,
        "phone": None,
        "id_card": None,
        "salary": None,
        "hire_date": datetime.datetime.utcnow().strftime("%Y-%m-%d"),
        "status": "active",
    }
    HR_EMPLOYEES.append(new_employee)

    # Return only safe fields
    return jsonify({"id": new_id, "name": name, "department": department,
                    "position": position, "status": "active"}), 201

@app.route("/hr/api/employees/<int:emp_id>", methods=["PUT"])
def hr_update_employee(emp_id):
    """PUT /hr/api/employees/:id — Update employee, limited fields, auth, audit log."""
    payload, err = require_auth()
    if err:
        return err
    role_err = require_role(payload, ["admin", "manager"])
    if role_err:
        return role_err

    if emp_id <= 0:
        return jsonify({"error": "ERR_INVALID_EMPLOYEE_ID"}), 400

    employee = None
    for e in HR_EMPLOYEES:
        if e["id"] == emp_id:
            employee = e
            break

    if not employee:
        return jsonify({"error": "ERR_EMPLOYEE_NOT_FOUND"}), 404

    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({"error": "ERR_INVALID_REQUEST_BODY"}), 400

    # Only allow updating limited safe fields
    ALLOWED_UPDATE_FIELDS = {"department", "position", "status"}
    for key in data:
        if key not in ALLOWED_UPDATE_FIELDS:
            # M-005: static error code, no user input reflection
            return jsonify({"error": "ERR_FIELD_NOT_ALLOWED"}), 400

    # M-001: validate each allowed field
    if "department" in data:
        err_v = validate_input(data["department"], "department", max_len=30,
                               allowed_values=["技术部", "产品部", "运营部", "财务部", "市场部", "人事部"])
        if err_v:
            return jsonify({"error": err_v}), 400
        employee["department"] = data["department"]

    if "position" in data:
        err_v = validate_input(data["position"], "position", max_len=30,
                               pattern=r"^[a-zA-Z一-龥]+$")
        if err_v:
            return jsonify({"error": err_v}), 400
        employee["position"] = data["position"]

    if "status" in data:
        err_v = validate_input(data["status"], "status", max_len=10,
                               allowed_values=["active", "inactive", "resigned"])
        if err_v:
            return jsonify({"error": err_v}), 400
        employee["status"] = data["status"]

    # M-003: Audit log
    write_audit_log(payload.get("user_id"), "UPDATE_EMPLOYEE",
                    emp_id, str(list(data.keys())), "success")

    # Return only safe fields
    result = {"id": employee["id"], "name": employee["name"],
              "department": employee["department"], "position": employee["position"],
              "status": employee["status"]}
    return jsonify(result)

@app.route("/hr/api/attendance")
def hr_attendance_list():
    """GET /hr/api/attendance — Attendance records, only own or aggregated, auth, pagination."""
    payload, err = require_auth()
    if err:
        return err

    # M-001: validate pagination
    page = request.args.get("page", "1")
    page_size = request.args.get("page_size", "10")
    try:
        page = max(1, int(page))
        page_size = max(1, min(100, int(page_size)))  # M-007
    except (ValueError, TypeError):
        return jsonify({"error": "ERR_INVALID_PAGINATION"}), 400

    user_id = payload.get("user_id")
    is_admin = payload.get("role") == "admin"

    # Non-admin: only own records
    if not is_admin:
        items = [a for a in HR_ATTENDANCE if a["employee_id"] == user_id]
    else:
        items = HR_ATTENDANCE

    total = len(items)
    start = (page - 1) * page_size
    end = start + page_size
    page_items = items[start:end]

    # Desensitize: no employee names for non-admin
    result = []
    for a in page_items:
        entry = {"id": a["id"], "date": a["date"], "status": a["status"]}
        if is_admin:
            entry["employee_id"] = a["employee_id"]
            entry["check_in"] = a.get("check_in", "")
            entry["check_out"] = a.get("check_out", "")
        else:
            entry["check_in"] = a.get("check_in", "")
            entry["check_out"] = a.get("check_out", "")
        result.append(entry)

    return jsonify({"total": total, "page": page, "page_size": page_size, "items": result})

@app.route("/hr/api/attendance", methods=["POST"])
def hr_submit_attendance():
    """POST /hr/api/attendance — Submit attendance, input validation, auth, no SQL injection."""
    payload, err = require_auth()
    if err:
        return err

    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({"error": "ERR_INVALID_REQUEST_BODY"}), 400

    # M-001: validate fields
    check_in = data.get("check_in", "")
    check_out = data.get("check_out", "")
    date_str = data.get("date", "")

    err_v = validate_input(date_str, "date", max_len=10, pattern=r"^\d{4}-\d{2}-\d{2}$")
    if err_v:
        return jsonify({"error": err_v}), 400
    # M-001: strict time validation — hours 00-23, minutes 00-59
    time_pattern = r"^([01]\d|2[0-3]):[0-5]\d$"
    err_v = validate_input(check_in, "check_in", max_len=5, pattern=time_pattern)
    if err_v:
        return jsonify({"error": err_v}), 400
    err_v = validate_input(check_out, "check_out", max_len=5, pattern=time_pattern)
    if err_v:
        return jsonify({"error": err_v}), 400

    new_id = max(a["id"] for a in HR_ATTENDANCE) + 1 if HR_ATTENDANCE else 1
    new_attendance = {
        "id": new_id,
        "employee_id": payload.get("user_id"),
        "date": date_str,
        "check_in": check_in,
        "check_out": check_out,
        "status": "normal",
    }
    HR_ATTENDANCE.append(new_attendance)

    # M-003: Audit log
    write_audit_log(payload.get("user_id"), "SUBMIT_ATTENDANCE",
                    date_str, f"in={check_in}, out={check_out}", "success")

    return jsonify({"id": new_id, "date": date_str, "status": "normal"}), 201

@app.route("/hr/api/attendance/export")
def hr_attendance_export():
    """GET /hr/api/attendance/export — CSV export with CSV injection protection, auth.
    M-003: audit log for data export."""
    payload, err = require_auth()
    if err:
        return err
    role_err = require_role(payload, ["admin", "manager"])
    if role_err:
        return role_err

    # M-003: audit log
    write_audit_log(payload.get("user_id"), "EXPORT_ATTENDANCE", "attendance_export", "csv", "success")

    output = io.StringIO()
    writer = csv.writer(output)
    # M-008: CSV injection protection
    writer.writerow([sanitize_for_csv("ID"), sanitize_for_csv("员工ID"),
                     sanitize_for_csv("日期"), sanitize_for_csv("签到"),
                     sanitize_for_csv("签退"), sanitize_for_csv("状态")])

    for a in HR_ATTENDANCE:
        writer.writerow([
            sanitize_for_csv(a["id"]),
            sanitize_for_csv(a["employee_id"]),
            sanitize_for_csv(a["date"]),
            sanitize_for_csv(a.get("check_in", "") or ""),
            sanitize_for_csv(a.get("check_out", "") or ""),
            sanitize_for_csv(a["status"]),
        ])

    resp = make_response(output.getvalue())
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = "attachment; filename=attendance_export.csv"
    return resp

@app.route("/hr/api/departments")
def hr_departments():
    """GET /hr/api/departments — Department list, aggregated stats only."""
    payload, err = require_auth()
    if err:
        return err

    # Aggregated stats only — no individual employee info
    result = [{"id": d["id"], "name": d["name"], "head_count": d["head_count"],
               "avg_salary_range": d["avg_salary_range"]} for d in HR_DEPARTMENTS]

    return jsonify({"items": result})

@app.route("/hr/api/leave")
def hr_leave_list():
    """GET /hr/api/leave — Leave requests, only own, auth, pagination."""
    payload, err = require_auth()
    if err:
        return err

    # M-001: validate pagination
    page = request.args.get("page", "1")
    page_size = request.args.get("page_size", "10")
    try:
        page = max(1, int(page))
        page_size = max(1, min(100, int(page_size)))  # M-007
    except (ValueError, TypeError):
        return jsonify({"error": "ERR_INVALID_PAGINATION"}), 400

    user_id = payload.get("user_id")
    is_admin = payload.get("role") == "admin"

    # Non-admin: only own leave requests
    if not is_admin:
        items = [l for l in HR_LEAVE_REQUESTS if l["employee_id"] == user_id]
    else:
        items = HR_LEAVE_REQUESTS

    total = len(items)
    start = (page - 1) * page_size
    end = start + page_size
    page_items = items[start:end]

    # Desensitize reason for non-owner
    result = []
    for l in page_items:
        entry = {
            "id": l["id"],
            "type": l["type"],
            "start_date": l["start_date"],
            "end_date": l["end_date"],
            "days": l["days"],
            "status": l["status"],
        }
        if is_admin or l["employee_id"] == user_id:
            entry["employee_id"] = l["employee_id"]
            entry["reason"] = l["reason"][:10] + "..." if len(l["reason"]) > 10 else l["reason"]
        else:
            entry["employee_id"] = l["employee_id"]
            entry["reason"] = "REDACTED"
        result.append(entry)

    return jsonify({"total": total, "page": page, "page_size": page_size, "items": result})

@app.route("/hr/api/leave", methods=["POST"])
def hr_apply_leave():
    """POST /hr/api/leave — Apply for leave, input validation, auth."""
    payload, err = require_auth()
    if err:
        return err

    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({"error": "ERR_INVALID_REQUEST_BODY"}), 400

    # M-001: validate fields
    leave_type = data.get("type", "")
    start_date = data.get("start_date", "")
    end_date = data.get("end_date", "")
    reason = data.get("reason", "")

    err_v = validate_input(leave_type, "type", max_len=10,
                           allowed_values=["年假", "病假", "事假", "婚假", "产假"])
    if err_v:
        return jsonify({"error": err_v}), 400
    err_v = validate_input(start_date, "start_date", max_len=10,
                           pattern=r"^\d{4}-\d{2}-\d{2}$")
    if err_v:
        return jsonify({"error": err_v}), 400
    err_v = validate_input(end_date, "end_date", max_len=10,
                           pattern=r"^\d{4}-\d{2}-\d{2}$")
    if err_v:
        return jsonify({"error": err_v}), 400
    err_v = validate_input(reason, "reason", max_len=100)
    if err_v:
        return jsonify({"error": err_v}), 400

    # Validate date range
    if end_date < start_date:
        return jsonify({"error": "ERR_END_DATE_BEFORE_START"}), 400

    # M-003: Audit log
    write_audit_log(payload.get("user_id"), "APPLY_LEAVE",
                    leave_type, f"{start_date}~{end_date}", "success")

    new_id = max(l["id"] for l in HR_LEAVE_REQUESTS) + 1 if HR_LEAVE_REQUESTS else 1
    new_leave = {
        "id": new_id,
        "employee_id": payload.get("user_id"),
        "type": leave_type,
        "start_date": start_date,
        "end_date": end_date,
        "days": 1,  # Simplified
        "reason": reason,
        "status": "pending",
        "approver_id": None,
    }
    HR_LEAVE_REQUESTS.append(new_leave)

    return jsonify({"id": new_id, "status": "pending", "type": leave_type}), 201

@app.route("/hr/api/leave/<int:leave_id>/approve", methods=["PUT"])
def hr_approve_leave(leave_id):
    """PUT /hr/api/leave/:id/approve — Approve leave, manager role only, audit."""
    payload, err = require_auth()
    if err:
        return err
    role_err = require_role(payload, ["admin", "manager"])
    if role_err:
        return role_err

    if leave_id <= 0:
        return jsonify({"error": "ERR_INVALID_LEAVE_ID"}), 400

    data = request.get_json(silent=True) or {}
    action = data.get("action", "")

    # M-001: validate action
    err_v = validate_input(action, "action", max_len=10,
                           allowed_values=["approve", "reject"])
    if err_v:
        return jsonify({"error": err_v}), 400

    leave = None
    for l in HR_LEAVE_REQUESTS:
        if l["id"] == leave_id:
            leave = l
            break

    if not leave:
        return jsonify({"error": "ERR_LEAVE_NOT_FOUND"}), 404

    if leave["status"] != "pending":
        return jsonify({"error": "ERR_LEAVE_ALREADY_PROCESSED"}), 400

    # M-003: Audit log
    write_audit_log(payload.get("user_id"), "APPROVE_LEAVE",
                    leave_id, f"action={action}, type={leave['type']}", "success")

    leave["status"] = "approved" if action == "approve" else "rejected"
    leave["approver_id"] = payload.get("user_id")

    return jsonify({"id": leave_id, "status": leave["status"],
                    "approver_id": leave["approver_id"]})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
