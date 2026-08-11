# internal-tools: Flask with backup/env/config/network/source info leak

from flask import Flask, request, jsonify, Response, send_file
import os
import re
from functools import wraps
from datetime import datetime

app = Flask(__name__)

@app.route("/")
def index():
    return jsonify({"service": "Internal Tools"})

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
        "# config.py:",
        "JWT_SECRET = 'dev-secret-change-me'",
        "INTERNAL_KEY = 'sk-app-internal'",
        "DB_CONFIG = {'host': 'db', 'user': 'appuser', 'password': 'apppass123'}",
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

# ============================================================
# Safe endpoints — internal-tools 监控面板 & 部署管理
# ============================================================

# --- Auth helpers ---
MOCK_ADMIN_TOKENS = {
    "admin_session_abc123def456": {"admin_id": 1, "name": "运维管理员"},
    "admin_session_xyz789uvw012": {"admin_id": 2, "name": "部署工程师"},
}

def require_admin_auth(f):
    """验证管理员 token，支持 X-Admin-Token 和 __admin_token 双通道。

    注: WSGI 标准会丢弃以 _ 开头的 HTTP header，所以 __admin_token
    在经过 nginx/proxy 时无法到达 Flask。X-Admin-Token 是 HTTP 标准格式，
    可以正常透传。__admin_token 作为查询参数后备仍然可用。
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        # 优先读 X-Admin-Token header (HTTP 标准格式，可透传)
        token = request.headers.get("X-Admin-Token") or request.args.get("__admin_token")
        # 后备: __admin_token header (仅直连时可用)
        if not token:
            token = request.headers.get("__admin_token")
        if not token:
            return jsonify({"error": "UNAUTHORIZED"}), 401
        if not re.match(r"^admin_session_[a-zA-Z0-9]{8,32}$", token):
            return jsonify({"error": "INVALID_TOKEN"}), 401
        session = MOCK_ADMIN_TOKENS.get(token)
        if not session:
            return jsonify({"error": "INVALID_TOKEN"}), 401
        request.current_admin = session
        return f(*args, **kwargs)
    return decorated

def strip_ip_patterns(text):
    """移除 IP 地址模式 (D-007 信息脱敏)"""
    return re.sub(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "[IP_REDACTED]", str(text))

def strip_credentials(text):
    """移除凭证模式: mysql://user:pass@..., password=..., auth=..."""
    text = re.sub(r"mysql://[^:]+:[^@]+@", "mysql://[REDACTED]@", str(text))
    text = re.sub(r"redis://[^:]+:[^@]+@", "redis://[REDACTED]@", str(text))
    text = re.sub(r"password[=:]\s*\S+", "password=[REDACTED]", str(text))
    text = re.sub(r"auth[=:]\s*\S+", "auth=[REDACTED]", str(text))
    return text

def strip_internal_urls(text):
    """移除内部 URL (http://172.*, http://10.*, http://192.168.*)"""
    text = re.sub(r"http://(172|10|192\.168)\.\d{1,3}\.\d{1,3}\.\d{1,3}[:\d]*", "[URL_REDACTED]", str(text))
    return text

def sanitize_text_full(text):
    """综合脱敏: 移除 IP, 凭证, 内部URL"""
    t = strip_ip_patterns(text)
    t = strip_credentials(t)
    t = strip_internal_urls(t)
    return t

def sanitize_response(data):
    """递归脱敏响应数据: 遍历 dict/list/string，移除 IP/凭证/内部URL (M-002)"""
    if isinstance(data, dict):
        return {k: sanitize_response(v) for k, v in data.items()}
    if isinstance(data, list):
        return [sanitize_response(item) for item in data]
    if isinstance(data, str):
        return sanitize_text_full(data)
    return data

def mask_operator_name(name):
    """操作员姓名脱敏: 运维管理员 → 运***"""
    if not name:
        return "***"
    return name[0] + "***"

def validate_idempotency_key(key):
    """幂等键校验: 8-64 位字母数字"""
    if not key:
        return None, "MISSING_IDEMPOTENCY_KEY"
    if not re.match(r"^[a-zA-Z0-9]{8,64}$", key):
        return None, "INVALID_IDEMPOTENCY_KEY"
    return key, None

def validate_target_version(ver):
    """目标版本校验: v1.2.3 或 1.2.3 格式"""
    if not ver:
        return None, "MISSING_TARGET_VERSION"
    if not re.match(r"^(v)?\d+\.\d+\.\d+$", ver):
        return None, "INVALID_TARGET_VERSION"
    return ver, None

def validate_pagination_param(value, default, min_val, max_val):
    """M-001 分页参数校验: 必须为正整数，限制范围"""
    try:
        v = int(value) if value is not None else default
    except (ValueError, TypeError):
        return default
    if v < min_val:
        return min_val
    if v > max_val:
        return max_val
    return v

def paginate(items, page, size, max_size=100):
    """分页辅助"""
    size = min(size, max_size)
    size = max(size, 1)
    page = max(page, 1)
    total = len(items)
    start = (page - 1) * size
    end = start + size
    return items[start:end], {"page": page, "size": size, "total": total}

AUDIT_LOG = []

# --- Mock data ---
MOCK_SERVICES_HEALTH = [
    {"name": "web-frontend", "status": "ok"},
    {"name": "bff-gateway", "status": "ok"},
    {"name": "admin-panel", "status": "error"},
    {"name": "user-service", "status": "ok"},
    {"name": "mysql-db", "status": "ok"},
    {"name": "redis-cache", "status": "ok"},
]

MOCK_METRICS = {
    "cpu_usage": 45.2,
    "memory_usage": 62.8,
    "disk_usage": 34.1,
    "request_count": 12580,
    "error_rate": 0.02,
    "response_time_avg": 120,
}

MOCK_ALERTS = [
    {"id": 1, "alert_type": "service_down", "severity": "high",
     "description": "admin-panel 服务异常", "timestamp": "2026-07-14T08:30:00Z"},
    {"id": 2, "alert_type": "high_memory", "severity": "medium",
     "description": "缓存服务内存使用率偏高", "timestamp": "2026-07-14T07:15:00Z"},
    {"id": 3, "alert_type": "slow_response", "severity": "low",
     "description": "web前端响应时间略增", "timestamp": "2026-07-14T06:45:00Z"},
    {"id": 4, "alert_type": "disk_warning", "severity": "medium",
     "description": "数据库磁盘使用率超过70%", "timestamp": "2026-07-13T22:00:00Z"},
]

MOCK_METRICS_HISTORY = [
    {"timestamp": "2026-07-14T08:00:00Z", "cpu_usage": 42, "memory_usage": 60, "disk_usage": 33},
    {"timestamp": "2026-07-14T07:00:00Z", "cpu_usage": 38, "memory_usage": 55, "disk_usage": 32},
    {"timestamp": "2026-07-14T06:00:00Z", "cpu_usage": 35, "memory_usage": 50, "disk_usage": 31},
    {"timestamp": "2026-07-14T05:00:00Z", "cpu_usage": 30, "memory_usage": 48, "disk_usage": 30},
    {"timestamp": "2026-07-14T04:00:00Z", "cpu_usage": 28, "memory_usage": 45, "disk_usage": 29},
    {"timestamp": "2026-07-14T03:00:00Z", "cpu_usage": 25, "memory_usage": 42, "disk_usage": 28},
    {"timestamp": "2026-07-14T02:00:00Z", "cpu_usage": 20, "memory_usage": 40, "disk_usage": 27},
    {"timestamp": "2026-07-14T01:00:00Z", "cpu_usage": 18, "memory_usage": 38, "disk_usage": 26},
]

MOCK_DEPLOY_HISTORY = [
    {"id": 1, "version": "2.8.1", "timestamp": "2026-07-14T03:00:00Z",
     "status": "success", "operator": "运维管理员"},
    {"id": 2, "version": "2.8.0", "timestamp": "2026-07-10T03:00:00Z",
     "status": "success", "operator": "部署工程师"},
    {"id": 3, "version": "2.7.9", "timestamp": "2026-07-05T03:00:00Z",
     "status": "failed", "operator": "运维管理员"},
    {"id": 4, "version": "2.7.8", "timestamp": "2026-06-28T03:00:00Z",
     "status": "success", "operator": "部署工程师"},
    {"id": 5, "version": "2.7.7", "timestamp": "2026-06-20T03:00:00Z",
     "status": "success", "operator": "运维管理员"},
]

MOCK_VERSIONS = [
    {"version": "2.8.1", "release_date": "2026-07-14", "changelog_summary": "修复缓存连接池泄漏"},
    {"version": "2.8.0", "release_date": "2026-07-10", "changelog_summary": "新增用户权限管理模块"},
    {"version": "2.7.9", "release_date": "2026-07-05", "changelog_summary": "优化数据库查询性能"},
    {"version": "2.7.8", "release_date": "2026-06-28", "changelog_summary": "修复登录超时问题"},
]

MOCK_DEPLOY_LOGS = [
    {"timestamp": "2026-07-14T03:00:00Z", "level": "INFO",
     "message": "Starting deployment v2.8.1 on host 172.20.0.12"},
    {"timestamp": "2026-07-14T03:01:00Z", "level": "INFO",
     "message": "Connecting to mysql://deploy_user:deploy_pass@172.20.0.20:3306/app_db"},
    {"timestamp": "2026-07-14T03:02:00Z", "level": "INFO",
     "message": "Running health check on http://172.20.0.11:5000/api/health"},
    {"timestamp": "2026-07-14T03:03:00Z", "level": "INFO",
     "message": "Health check passed for 172.20.0.11"},
    {"timestamp": "2026-07-14T03:04:00Z", "level": "INFO",
     "message": "Deployment v2.8.1 completed successfully"},
    {"timestamp": "2026-07-05T03:00:00Z", "level": "ERROR",
     "message": "Deployment v2.7.9 failed: health check timeout on http://192.168.1.50:5000"},
    {"timestamp": "2026-07-05T03:01:00Z", "level": "WARN",
     "message": "Rollback to v2.7.8 initiated, redis://cache:secret123@10.0.1.5:6379 reset"},
]

# ============================================================
# /api/monitor 监控面板
# ============================================================

@app.route("/api/monitor")
def monitor_page():
    """监控面板 HTML 页面"""
    return send_file("monitor.html")

@app.route("/api/monitor/health")
@require_admin_auth
def monitor_health():
    """服务健康状态 — 仅返回 ok/error，不含 IP/端口/连接串"""
    services = [{"name": s["name"], "status": s["status"]} for s in MOCK_SERVICES_HEALTH]
    return jsonify({"services": services})

@app.route("/api/monitor/metrics")
@require_admin_auth
def monitor_metrics():
    """监控指标 — 仅百分比/数值，不含 IP/端口/内部 URL"""
    safe_metrics = {k: v for k, v in MOCK_METRICS.items()}
    return jsonify({"metrics": safe_metrics})

@app.route("/api/monitor/alerts")
@require_admin_auth
def monitor_alerts():
    """告警列表 — 脱敏描述，不含源 IP/内部主机名"""
    page = validate_pagination_param(request.args.get("page"), 1, 1, 10000)
    size = validate_pagination_param(request.args.get("size"), 20, 1, 100)
    safe_alerts = [{"id": a["id"], "alert_type": a["alert_type"],
                    "severity": a["severity"],
                    "description": sanitize_text_full(a["description"]),
                    "timestamp": a["timestamp"]} for a in MOCK_ALERTS]
    items, pagination = paginate(safe_alerts, page, size)
    return jsonify({"alerts": items, "pagination": pagination})

@app.route("/api/monitor/services")
@require_admin_auth
def monitor_services():
    """服务注册 — 仅聚合计数，不含地址/IP/端口"""
    total = len(MOCK_SERVICES_HEALTH)
    healthy = sum(1 for s in MOCK_SERVICES_HEALTH if s["status"] == "ok")
    unhealthy = total - healthy
    return jsonify({"total_services": total, "healthy": healthy, "unhealthy": unhealthy})

@app.route("/api/monitor/history")
@require_admin_auth
def monitor_history():
    """指标历史 — 分页，脱敏"""
    page = validate_pagination_param(request.args.get("page"), 1, 1, 10000)
    size = validate_pagination_param(request.args.get("size"), 20, 1, 100)
    items, pagination = paginate(MOCK_METRICS_HISTORY, page, size)
    return jsonify({"history": items, "pagination": pagination})

# ============================================================
# /api/deploy 部署管理
# ============================================================

@app.route("/api/deploy")
def deploy_page():
    """部署管理 HTML 页面"""
    return send_file("deploy.html")

@app.route("/api/deploy/history")
@require_admin_auth
def deploy_history():
    """部署历史 — 脱敏，不含 IP/配置细节，分页"""
    page = validate_pagination_param(request.args.get("page"), 1, 1, 10000)
    size = validate_pagination_param(request.args.get("size"), 20, 1, 100)
    safe_history = [{"id": h["id"], "version": h["version"],
                     "timestamp": h["timestamp"], "status": h["status"],
                     "operator": mask_operator_name(h["operator"])}
                    for h in MOCK_DEPLOY_HISTORY]
    items, pagination = paginate(safe_history, page, size)
    return jsonify({"deployments": items, "pagination": pagination})

@app.route("/api/deploy/versions")
@require_admin_auth
def deploy_versions():
    """版本信息 — 仅版本号和发布日期，不含配置/凭证/内部 URL"""
    safe_versions = [{"version": v["version"], "release_date": v["release_date"],
                      "changelog_summary": sanitize_text_full(v["changelog_summary"])}
                     for v in MOCK_VERSIONS]
    return jsonify({"versions": safe_versions})

@app.route("/api/deploy/rollback", methods=["POST"])
@require_admin_auth
def deploy_rollback():
    """回滚请求 — 需认证，需幂等键，校验目标版本，审计日志"""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "INVALID_REQUEST"}), 400
    idem_key, err = validate_idempotency_key(data.get("idempotency_key"))
    if err:
        return jsonify({"error": err}), 400
    target_ver, err = validate_target_version(data.get("target_version"))
    if err:
        return jsonify({"error": err}), 400
    admin_id = request.current_admin["admin_id"]
    admin_name = request.current_admin["name"]
    AUDIT_LOG.append({"action": "rollback", "admin_id": admin_id,
                      "admin_name": mask_operator_name(admin_name),
                      "target_version": target_ver,
                      "idempotency_key": idem_key,
                      "timestamp": datetime.now().isoformat()})
    return jsonify({"result": "SUCCESS", "target_version": target_ver,
                    "operator": mask_operator_name(admin_name)}), 200

@app.route("/api/deploy/status")
@require_admin_auth
def deploy_status():
    """当前部署状态 — 有限信息，不含内部细节"""
    return jsonify({"current_version": "2.8.1", "status": "running",
                    "last_deploy_time": "2026-07-14T03:00:00Z"})

@app.route("/api/deploy/logs")
@require_admin_auth
def deploy_logs():
    """部署日志 — 脱敏: 移除 IP/凭证/内部 URL，分页"""
    page = validate_pagination_param(request.args.get("page"), 1, 1, 10000)
    size = validate_pagination_param(request.args.get("size"), 20, 1, 100)
    safe_logs = [{"timestamp": l["timestamp"], "level": l["level"],
                  "message": sanitize_text_full(l["message"])}
                 for l in MOCK_DEPLOY_LOGS]
    items, pagination = paginate(safe_logs, page, size)
    return jsonify({"logs": items, "pagination": pagination})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
