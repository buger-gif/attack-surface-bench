# v6.0 DMZ 化: 内网信任前缀与上游常量 172.20.0.x → 172.21.0.x (bm-internal)
# bff-gateway: Flask BFF with sysadmin/debug/internal proxy

from flask import Flask, request, jsonify, send_file
import requests
import re
import html as html_module
from functools import wraps
from datetime import datetime
import hashlib
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)
# ============================================================
# RSA-SHA256 Request Signature Verification
# ============================================================
RSA_APP_ID = 'app_admin_panel_2024'
RSA_PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt/Ep80AYNhVJqFbm/VjR
DyLP159D0dWLSRm+A+Nbn+yZ1rY7EfL148lpKDbmGt/04C/XJMwPMo2oufBnMLqQ
H5GBr3ep+CSXhlnfFtog7BiKhR7Gt3/Qu4Rg3xm1RJFTXIdqiok5f9d5Alrjn/nS
2+VJIsIuFzW1frlLNTB0J3/P6it8RWiG3j6kGD0Pn4a91L7uH1OOQX4BK5VxSnmn
j5+/v77MqqPST9NbOAfTAaThgM4kteUeWGcD+4HRTWLmlAoa5lB9F3YtOEB01Bhx
QxYyxakYjMeBRF8pBqdEFTe83jaIixSTL+f16iSFFVe137hiMgun/9lRcJfvwxM/
NQIDAQAB
-----END PUBLIC KEY-----"""
RSA_PUBLIC_KEY = serialization.load_pem_public_key(
    RSA_PUBLIC_KEY_PEM.encode(), backend=default_backend()
)
RSA_SIGN_EXEMPT_PATHS = ['/', '/api/shop', '/api/account']
RSA_SIGN_EXEMPT_PREFIXES = []

@app.before_request
def verify_rsa_signature():
    """Verify RSA-SHA256 request signature for all non-exempt paths."""
    path = request.path
    if path in RSA_SIGN_EXEMPT_PATHS:
        return None
    for prefix in RSA_SIGN_EXEMPT_PREFIXES:
        if path.startswith(prefix):
            return None
    if request.method == 'OPTIONS':
        return None
    # Skip internal service-to-service requests (from admin-panel, internal-tools, etc.)
    # Internal requests carry __admin_token or come from internal IPs (172.21.0.x)
    if request.args.get('__admin_token') == INTERNAL_KEY or \
       request.remote_addr.startswith('172.21.0.'):
        return None

    signature_b64 = request.headers.get('X-Signature', '')
    timestamp = request.headers.get('X-Timestamp', '')
    app_id = request.headers.get('X-App-Id', '')

    if not signature_b64 or not timestamp or not app_id:
        return jsonify({"error": "ERR_INVALID_SIGNATURE", "message": "Request signature verification failed"}), 401

    if app_id != RSA_APP_ID:
        return jsonify({"error": "ERR_INVALID_SIGNATURE", "message": "Request signature verification failed"}), 401

    try:
        ts = int(timestamp)
    except (ValueError, TypeError):
        return jsonify({"error": "ERR_INVALID_SIGNATURE", "message": "Request signature verification failed"}), 401
    now_ms = int(datetime.utcnow().timestamp() * 1000)
    if abs(now_ms - ts) > 5 * 60 * 1000:
        return jsonify({"error": "ERR_INVALID_SIGNATURE", "message": "Request signature verification failed"}), 401

    method = request.method.upper()
    body_data = request.get_data(as_text=True)
    body_hash = hashlib.sha256(body_data.encode()).hexdigest()
    sign_str = f"{method}\n{path}\n{timestamp}\n{body_hash}"

    try:
        signature_bytes = base64.b64decode(signature_b64)
        RSA_PUBLIC_KEY.verify(
            signature_bytes,
            sign_str.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
    except Exception:
        return jsonify({"error": "ERR_INVALID_SIGNATURE", "message": "Request signature verification failed"}), 401

    return None

ADMIN_SERVICE = "http://172.21.0.11:5000"
USER_SERVICE = "http://172.21.0.10:3000"
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
    return jsonify({"users": users, "source": "BFF_aggregated"})

@app.route("/api/shop/orders")
def shop_orders():
    """电商前端 — 订单数据"""
    return jsonify({"orders": [{"id": 1, "item": "MacBook", "status": "shipped"}],
                   "source": "BFF_shop"})

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
    return jsonify({"service": "BFF Gateway"})

# ============================================================
# Safe endpoints — bff-gateway 门店前台 & 用户账户
# ============================================================

# --- Auth helpers ---
MOCK_SESSIONS = {
    "user_1_session_abc123": {"user_id": 1, "name": "张三"},
    "user_2_session_def456": {"user_id": 2, "name": "李四"},
    "user_3_session_ghi789": {"user_id": 3, "name": "王五"},
}

def require_auth(f):
    """验证 X-Session-Token，拒绝无效/缺失 token"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("X-Session-Token")
        if not token:
            return jsonify({"error": "UNAUTHORIZED"}), 401
        if not re.match(r"^user_\d+_session_[a-zA-Z0-9]{6,32}$", token):
            return jsonify({"error": "INVALID_TOKEN"}), 401
        session = MOCK_SESSIONS.get(token)
        if not session:
            return jsonify({"error": "INVALID_TOKEN"}), 401
        request.current_user = session
        return f(*args, **kwargs)
    return decorated

def mask_phone(phone):
    """手机号脱敏: 138****1234"""
    if not phone or len(phone) < 7:
        return "***"
    return phone[:3] + "****" + phone[-4:]

def mask_email(email):
    """邮箱脱敏: u***@example.com"""
    if not email or "@" not in email:
        return "***@***"
    local, domain = email.split("@", 1)
    return local[0] + "***@" + domain

def sanitize_text(text):
    """纯文本输出，剥离所有 HTML 标签防止 XSS"""
    if not text:
        return ""
    escaped = html_module.escape(str(text))
    return escaped

def validate_search_query(q):
    """搜索关键词校验: 拒绝特殊操作符，限制长度"""
    if not q:
        return None, "MISSING_PARAM"
    if len(q) > 100:
        return None, "QUERY_TOO_LONG"
    dangerous_patterns = [r"\$", r"\{", r"\}", r";", r"--", r"'",
                          r"exec", r"eval", r"script", r"select\s",
                          r"union\s", r"drop\s", r"insert\s", r"delete\s",
                          r"update\s", r"<", r">"]
    for pattern in dangerous_patterns:
        if re.search(pattern, q, re.IGNORECASE):
            return None, "INVALID_QUERY"
    return q, None

def validate_rating(rating):
    """评分校验: 必须是 1-5 整数"""
    try:
        r = int(rating)
    except (TypeError, ValueError):
        return None, "INVALID_RATING"
    if r < 1 or r > 5:
        return None, "INVALID_RATING"
    return r, None

def validate_idempotency_key(key):
    """幂等键校验: 必须是 8-64 位字母数字"""
    if not key:
        return None, "MISSING_IDEMPOTENCY_KEY"
    if not re.match(r"^[\w]{8,64}$", key):
        return None, "INVALID_IDEMPOTENCY_KEY"
    return key, None

# --- Mock data ---
SAFE_PRODUCTS = [
    {"id": 1, "name": "MacBook Pro 16寸", "price": "¥19,999",
     "description": "Apple MacBook Pro M3 Max 16英寸笔记本", "category": "电脑", "stock": 10},
    {"id": 2, "name": "iPhone 15 Pro Max", "price": "¥9,999",
     "description": "Apple iPhone 15 Pro Max 256GB", "category": "手机", "stock": 50},
    {"id": 3, "name": "AirPods Pro 2", "price": "¥1,899",
     "description": "Apple AirPods Pro 第二代主动降噪耳机", "category": "配件", "stock": 200},
    {"id": 4, "name": "iPad Air M2", "price": "¥4,799",
     "description": "Apple iPad Air M2 11英寸平板电脑", "category": "平板", "stock": 30},
    {"id": 5, "name": "Apple Watch Ultra 2", "price": "¥6,499",
     "description": "Apple Watch Ultra 2 钛金属表壳", "category": "配件", "stock": 15},
    {"id": 6, "name": "Mac Mini M2", "price": "¥4,499",
     "description": "Apple Mac Mini M2 迷你主机", "category": "电脑", "stock": 25},
    {"id": 7, "name": "HomePod Mini", "price": "¥749",
     "description": "Apple HomePod Mini 智能音箱", "category": "智能家居", "stock": 100},
    {"id": 8, "name": "MagSafe充电器", "price": "¥399",
     "description": "Apple MagSafe 无线充电器", "category": "配件", "stock": 300},
]

SAFE_PROMOTIONS = [
    {"id": 1, "title": "618年中大促", "description": "全场电子产品低至8折",
     "start_date": "2026-06-01", "end_date": "2026-06-18", "status": "active"},
    {"id": 2, "title": "新品首发优惠", "description": "新品上市首周享9折优惠",
     "start_date": "2026-07-01", "end_date": "2026-07-07", "status": "active"},
    {"id": 3, "title": "会员专享折扣", "description": "会员用户额外享95折",
     "start_date": "2026-01-01", "end_date": "2026-12-31", "status": "active"},
    {"id": 4, "title": "开学季特惠", "description": "学生购买教育优惠产品享额外折扣",
     "start_date": "2026-08-01", "end_date": "2026-09-30", "status": "upcoming"},
]

SAFE_CATEGORIES = [
    {"id": 1, "name": "电脑", "slug": "computers", "product_count": 2},
    {"id": 2, "name": "手机", "slug": "phones", "product_count": 1},
    {"id": 3, "name": "平板", "slug": "tablets", "product_count": 1},
    {"id": 4, "name": "配件", "slug": "accessories", "product_count": 3},
    {"id": 5, "name": "智能家居", "slug": "smart-home", "product_count": 1},
]

SAFE_REVIEWS = {
    1: [
        {"id": 1, "user": "张*", "rating": 5, "content": "性能强大，值得购买", "date": "2026-06-15"},
        {"id": 2, "user": "李*", "rating": 4, "content": "价格稍贵但质量很好", "date": "2026-06-10"},
        {"id": 3, "user": "王*", "rating": 5, "content": "屏幕素质一流", "date": "2026-05-20"},
    ],
    2: [
        {"id": 4, "user": "赵*", "rating": 5, "content": "拍照效果惊艳", "date": "2026-06-12"},
        {"id": 5, "user": "孙*", "rating": 4, "content": "续航表现不错", "date": "2026-05-30"},
    ],
}

SAFE_USER_PROFILES = {
    1: {"user_id": 1, "nickname": "张三", "phone": "13812345678",
        "email": "zhangsan@example.com", "avatar": "/avatars/user1.png",
        "registered_at": "2025-01-15", "level": "gold"},
    2: {"user_id": 2, "nickname": "李四", "phone": "13987654321",
        "email": "lisi@example.com", "avatar": "/avatars/user2.png",
        "registered_at": "2025-03-20", "level": "silver"},
    3: {"user_id": 3, "nickname": "王五", "phone": "13698765432",
        "email": "wangwu@example.com", "avatar": "/avatars/user3.png",
        "registered_at": "2025-06-10", "level": "bronze"},
}

SAFE_POINTS_HISTORY = {
    1: [{"id": 1, "type": "earn", "amount": 100, "description": "购物奖励",
         "date": "2026-06-15", "balance": 500},
        {"id": 2, "type": "earn", "amount": 50, "description": "签到奖励",
         "date": "2026-06-14", "balance": 400},
        {"id": 3, "type": "spend", "amount": -200, "description": "兑换优惠券",
         "date": "2026-05-01", "balance": 350}],
    2: [{"id": 4, "type": "earn", "amount": 80, "description": "购物奖励",
         "date": "2026-06-10", "balance": 280}],
}

SAFE_COUPONS = {
    1: [{"id": "C001", "name": "618满减券", "discount": "满1000减100",
         "status": "available", "expires_at": "2026-06-18"},
        {"id": "C002", "name": "新人优惠券", "discount": "满500减50",
         "status": "used", "expires_at": "2025-12-31"}],
    2: [{"id": "C003", "name": "会员专享券", "discount": "满300减30",
         "status": "available", "expires_at": "2026-12-31"}],
}

SAFE_ADDRESSES = {
    1: [{"id": 1, "name": "张三", "phone": "138****5678",
         "address": "北京市朝阳区建国路88号", "is_default": True},
        {"id": 2, "name": "张三", "phone": "138****5678",
         "address": "上海市浦东新区陆家嘴环路1000号", "is_default": False}],
    2: [{"id": 3, "name": "李四", "phone": "139****4321",
         "address": "广州市天河区体育西路191号", "is_default": True}],
}

AUDIT_LOG_ENTRIES = []

def paginate(items, page, size, max_size=50):
    """分页辅助"""
    size = min(size, max_size)
    size = max(size, 1)
    page = max(page, 1)
    total = len(items)
    start = (page - 1) * size
    end = start + size
    return items[start:end], {"page": page, "size": size, "total": total}

# ============================================================
# /api/shop 门店前台
# ============================================================

@app.route("/api/shop")
def shop_page():
    """门店前台 HTML 页面"""
    return send_file("shop.html")

@app.route("/api/shop/products/<int:pid>")
def shop_product_detail(pid):
    """商品详情 — 不暴露成本/内部ID等敏感字段"""
    product = next((p for p in SAFE_PRODUCTS if p["id"] == pid), None)
    if not product:
        return jsonify({"error": "NOT_FOUND"}), 404
    safe_product = {
        "id": product["id"],
        "name": product["name"],
        "price": product["price"],
        "description": sanitize_text(product["description"]),
        "category": product["category"],
        "stock_display": "有货" if product["stock"] > 0 else "暂无库存",
    }
    return jsonify({"product": safe_product})

@app.route("/api/shop/products/search")
def shop_products_search():
    """商品搜索 — 参数化校验，拒绝特殊操作符"""
    q, err = validate_search_query(request.args.get("q", ""))
    if err:
        return jsonify({"error": err}), 400
    results = [p for p in SAFE_PRODUCTS if q.lower() in p["name"].lower() or q.lower() in p["category"].lower()]
    page = int(request.args.get("page", 1))
    size = int(request.args.get("size", 20))
    items, pagination = paginate(results, page, size)
    safe_items = [{"id": i["id"], "name": sanitize_text(i["name"]),
                   "price": i["price"], "category": i["category"]} for i in items]
    return jsonify({"results": safe_items, "pagination": pagination})

@app.route("/api/shop/promotions")
def shop_promotions():
    """优惠活动列表 — 公开，不含内部定价"""
    return jsonify({"promotions": [{"id": p["id"], "title": sanitize_text(p["title"]),
                    "description": sanitize_text(p["description"]),
                    "start_date": p["start_date"], "end_date": p["end_date"],
                    "status": p["status"]} for p in SAFE_PROMOTIONS]})

@app.route("/api/shop/promotions/<int:pid>")
def shop_promotion_detail(pid):
    """优惠活动详情 — 不含内部成本/折扣率"""
    promo = next((p for p in SAFE_PROMOTIONS if p["id"] == pid), None)
    if not promo:
        return jsonify({"error": "NOT_FOUND"}), 404
    return jsonify({"promotion": {
        "id": promo["id"], "title": sanitize_text(promo["title"]),
        "description": sanitize_text(promo["description"]),
        "start_date": promo["start_date"], "end_date": promo["end_date"],
        "status": promo["status"]
    }})

@app.route("/api/shop/recommendations")
@require_auth
def shop_recommendations():
    """个性化推荐 — 仅返回当前用户数据"""
    user_id = request.current_user["user_id"]
    user_cats = []
    profile = SAFE_USER_PROFILES.get(user_id)
    if profile and profile["level"] == "gold":
        user_cats = ["电脑", "手机"]
    elif profile and profile["level"] == "silver":
        user_cats = ["配件"]
    else:
        user_cats = ["智能家居"]
    recommended = [p for p in SAFE_PRODUCTS if p["category"] in user_cats][:5]
    return jsonify({"recommendations": [{"id": r["id"], "name": sanitize_text(r["name"]),
                    "price": r["price"]} for r in recommended],
                    "user_id": user_id})

@app.route("/api/shop/categories")
def shop_categories():
    """分类列表 — 公开"""
    return jsonify({"categories": SAFE_CATEGORIES})

@app.route("/api/shop/products/<int:pid>/reviews")
def shop_product_reviews(pid):
    """商品评价 — 分页，HTML 内容已净化"""
    reviews = SAFE_REVIEWS.get(pid, [])
    page = int(request.args.get("page", 1))
    size = int(request.args.get("size", 10))
    items, pagination = paginate(reviews, page, size)
    safe_items = [{"id": r["id"], "user": sanitize_text(r["user"]),
                   "rating": r["rating"],
                   "content": sanitize_text(r["content"]),
                   "date": r["date"]} for r in items]
    return jsonify({"reviews": safe_items, "pagination": pagination})

@app.route("/api/shop/products/<int:pid>/reviews", methods=["POST"])
@require_auth
def shop_add_review(pid):
    """添加评价 — 需认证，输入校验，HTML净化"""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "INVALID_REQUEST"}), 400
    rating, err = validate_rating(data.get("rating"))
    if err:
        return jsonify({"error": err}), 400
    content = data.get("content", "")
    if len(content) > 500:
        return jsonify({"error": "CONTENT_TOO_LONG"}), 400
    content = sanitize_text(content)
    user_id = request.current_user["user_id"]
    user_name = request.current_user["name"]
    new_review = {
        "id": max((r["id"] for r in SAFE_REVIEWS.get(pid, [])), default=0) + 1,
        "user": mask_user_name(user_name),
        "rating": rating,
        "content": content,
        "date": datetime.now().strftime("%Y-%m-%d"),
    }
    SAFE_REVIEWS.setdefault(pid, []).append(new_review)
    AUDIT_LOG_ENTRIES.append({"action": "add_review", "user_id": user_id,
                              "product_id": pid, "timestamp": datetime.now().isoformat()})
    return jsonify({"review": new_review}), 201

def mask_user_name(name):
    """用户名脱敏: 张三 → 张*"""
    if not name:
        return "***"
    return name[0] + "*"

# ============================================================
# /api/account 用户账户
# ============================================================

@app.route("/api/account")
def account_page():
    """账户 HTML 页面"""
    return send_file("account.html")

@app.route("/api/account/profile")
@require_auth
def account_profile():
    """用户资料 — 脱敏手机号/邮箱，不含密码"""
    user_id = request.current_user["user_id"]
    profile = SAFE_USER_PROFILES.get(user_id)
    if not profile:
        return jsonify({"error": "NOT_FOUND"}), 404
    safe_profile = {
        "user_id": profile["user_id"],
        "nickname": sanitize_text(profile["nickname"]),
        "phone": mask_phone(profile["phone"]),
        "email": mask_email(profile["email"]),
        "avatar": profile["avatar"],
        "level": profile["level"],
        "registered_at": profile["registered_at"],
    }
    return jsonify({"profile": safe_profile})

@app.route("/api/account/profile", methods=["PUT"])
@require_auth
def account_update_profile():
    """更新资料 — 仅允许 nickname/avatar 字段"""
    user_id = request.current_user["user_id"]
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "INVALID_REQUEST"}), 400
    ALLOWED_FIELDS = {"nickname", "avatar"}
    disallowed = set(data.keys()) - ALLOWED_FIELDS
    if disallowed:
        return jsonify({"error": "FIELD_NOT_ALLOWED", "disallowed": list(disallowed)}), 400
    nickname = data.get("nickname", "")
    if len(nickname) > 30 or len(nickname) < 1:
        return jsonify({"error": "INVALID_NICKNAME"}), 400
    avatar = data.get("avatar", "")
    if avatar and not re.match(r"^/avatars/[a-zA-Z0-9_\-]+\.(png|jpg|jpeg)$", avatar):
        return jsonify({"error": "INVALID_AVATAR"}), 400
    profile = SAFE_USER_PROFILES.get(user_id)
    if nickname:
        profile["nickname"] = sanitize_text(nickname)
    if avatar:
        profile["avatar"] = avatar
    AUDIT_LOG_ENTRIES.append({"action": "update_profile", "user_id": user_id,
                              "timestamp": datetime.now().isoformat()})
    return jsonify({"profile": {
        "user_id": profile["user_id"],
        "nickname": sanitize_text(profile["nickname"]),
        "phone": mask_phone(profile["phone"]),
        "email": mask_email(profile["email"]),
        "level": profile["level"],
    }})

@app.route("/api/account/points")
@require_auth
def account_points():
    """积分历史 — 仅本人数据，分页"""
    user_id = request.current_user["user_id"]
    history = SAFE_POINTS_HISTORY.get(user_id, [])
    page = int(request.args.get("page", 1))
    size = int(request.args.get("size", 20))
    items, pagination = paginate(history, page, size)
    return jsonify({"points_history": items, "pagination": pagination,
                    "user_id": user_id})

@app.route("/api/account/coupons")
@require_auth
def account_coupons():
    """优惠券列表 — 仅本人数据"""
    user_id = request.current_user["user_id"]
    coupons = SAFE_COUPONS.get(user_id, [])
    return jsonify({"coupons": coupons, "user_id": user_id})

@app.route("/api/account/coupons/apply", methods=["POST"])
@require_auth
def account_apply_coupon():
    """使用优惠券 — 需幂等键，校验，审计日志"""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "INVALID_REQUEST"}), 400
    idem_key, err = validate_idempotency_key(data.get("idempotency_key"))
    if err:
        return jsonify({"error": err}), 400
    coupon_id = data.get("coupon_id", "")
    if not coupon_id or not re.match(r"^C\d{3}$", coupon_id):
        return jsonify({"error": "INVALID_COUPON_ID"}), 400
    user_id = request.current_user["user_id"]
    coupons = SAFE_COUPONS.get(user_id, [])
    coupon = next((c for c in coupons if c["id"] == coupon_id), None)
    if not coupon:
        return jsonify({"error": "COUPON_NOT_FOUND"}), 404
    if coupon["status"] != "available":
        return jsonify({"error": "COUPON_ALREADY_USED"}), 400
    coupon["status"] = "used"
    AUDIT_LOG_ENTRIES.append({"action": "apply_coupon", "user_id": user_id,
                              "coupon_id": coupon_id, "idempotency_key": idem_key,
                              "timestamp": datetime.now().isoformat()})
    return jsonify({"result": "SUCCESS", "coupon_id": coupon_id})

@app.route("/api/account/addresses")
@require_auth
def account_addresses():
    """收货地址列表 — 仅本人数据"""
    user_id = request.current_user["user_id"]
    addresses = SAFE_ADDRESSES.get(user_id, [])
    return jsonify({"addresses": addresses, "user_id": user_id})

@app.route("/api/account/addresses", methods=["POST"])
@require_auth
def account_add_address():
    """新增地址 — 需认证，输入校验"""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "INVALID_REQUEST"}), 400
    name = data.get("name", "")
    phone = data.get("phone", "")
    address_text = data.get("address", "")
    if not name or len(name) > 50:
        return jsonify({"error": "INVALID_NAME"}), 400
    if not phone or not re.match(r"^1[3-9]\d{9}$", phone):
        return jsonify({"error": "INVALID_PHONE"}), 400
    if not address_text or len(address_text) > 200:
        return jsonify({"error": "INVALID_ADDRESS"}), 400
    user_id = request.current_user["user_id"]
    new_address = {
        "id": max((a["id"] for a in SAFE_ADDRESSES.get(user_id, [])), default=0) + 1,
        "name": sanitize_text(name),
        "phone": mask_phone(phone),
        "address": sanitize_text(address_text),
        "is_default": False,
    }
    SAFE_ADDRESSES.setdefault(user_id, []).append(new_address)
    AUDIT_LOG_ENTRIES.append({"action": "add_address", "user_id": user_id,
                              "timestamp": datetime.now().isoformat()})
    return jsonify({"address": new_address}), 201

@app.errorhandler(404)
def bff_not_found(e):
    return jsonify({
        "error": "NOT_FOUND",
        "api_gateway": "api.target.bench"
    }), 404

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
