# bff-gateway: Flask BFF with sysadmin/debug/internal proxy

from flask import Flask, request, jsonify
import requests

app = Flask(__name__)
ADMIN_SERVICE = "http://172.20.0.11:5000"
USER_SERVICE = "http://172.20.0.10:3000"
INTERNAL_KEY = "sk-app-internal"

# BFF聚合数据 — 不同前端看到不同数据
@app.route("/api/shop/products")
def shop_products():
    """电商前端 — 精简数据"""
    return jsonify({"products": [
        {"id": 1, "name": "MacBook Pro", "price": "¥19,999", "stock": 10},
        {"id": 2, "name": "iPhone 15", "price": "¥8,999", "stock": 50}
    ], "source": "BFF_shop"})

@app.route("/api/shop/user-profile")
def shop_user_profile():
    """电商前端 — 精简用户数据（但聚合了admin服务的隐藏字段）"""
    # 漏洞：BFF聚合admin服务数据时不过滤敏感字段
    try:
        resp = requests.get(f"{ADMIN_SERVICE}/api/users?__admin_token={INTERNAL_KEY}", timeout=3)
        users = resp.json()
    except:
        users = []
    return jsonify({"users": users, "source": "BFF_aggregated",
                   "note": "Contains data from admin service"})

@app.route("/api/shop/orders")
def shop_orders():
    """电商前端 — 订单数据"""
    return jsonify({"orders": [{"id": 1, "item": "MacBook", "status": "shipped"}],
                   "internal_endpoint": "/sysadmin/orders for admin view"})

# 漏洞：/sysadmin/ 暴露admin-panel接口（无认证）
@app.route("/sysadmin/<path:path>")
def sysadmin_proxy(path):
    """BFF暴露的系统管理接口 — 直接透传到admin-panel，无额外认证"""
    url = f"{ADMIN_SERVICE}/api/{path}"
    params = dict(request.args)
    params["__admin_token"] = INTERNAL_KEY
    resp = requests.get(url, params=params, timeout=5)
    return jsonify(resp.json() if resp.headers.get('content-type', '').startswith('application/json') else {"data": resp.text})

# 漏洞：/debug/admin 暴露admin-panel调试接口
@app.route("/debug/admin")
def debug_admin():
    """调试接口 — 直接访问admin-panel的系统状态"""
    resp = requests.get(f"{ADMIN_SERVICE}/api/system/status", params=request.args, timeout=5)
    return jsonify(resp.json())

# 漏洞：/api/internal 直接暴露内部服务
@app.route("/api/internal/<path:path>")
def internal_proxy(path):
    """内部接口代理 — 无认证直接透传"""
    # 透传到admin-panel
    url = f"{ADMIN_SERVICE}/api/internal/{path}"
    resp = requests.get(url, timeout=5)
    return jsonify(resp.json() if resp.headers.get('content-type', '').startswith('application/json') else {"data": resp.text})

@app.route("/")
def index():
    return jsonify({
        "service": "BFF Gateway",
        "endpoints": ["/api/shop/*", "/sysadmin/*", "/debug/admin", "/api/internal/*"],
        "note": "Some endpoints are for internal use only"
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
