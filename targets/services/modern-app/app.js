// modern-app: Express + JWT + MongoDB + GraphQL + SSRF benchmark service

const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { MongoClient, ObjectId } = require('mongodb');
const axios = require('axios');
const { graphqlHTTP } = require('express-graphql');
const { buildSchema } = require('graphql');
const DOMPurify = require('isomorphic-dompurify');
const swaggerUi = require('swagger-ui-express');
const OPENAPI_SPEC = require('./openapi-spec');
const app = express();

// NOTE: Default query parser (qs) is intentionally kept to allow nested object parsing
// (e.g. username[$ne] becomes {username: {$ne: ...}}) which is required for the
// M4/M5 NoSQL injection test cases. Do NOT set 'simple' query parser here.

app.use(express.json());

// M9: CORS过宽（允许任意来源+携带凭证）
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization, X-Sign, X-Timestamp, X-App-Key');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Credentials', 'true');
    next();
});

// ============================================================
// HMAC-SHA256 Request Signature Verification
// All API requests must carry X-Sign, X-Timestamp, X-App-Key headers
// Exempt paths: /, /api/auth/login, /api/auth/register, /shop, /community, /support, /api/docs, /graphql
// ============================================================
const HMAC_APP_KEY = 'ak_www_pub_2024';
const HMAC_APP_SECRET = 'sk_www_sign_hmac_2024';
const HMAC_EXEMPT_PATHS = ['/', '/api/auth/login', '/api/auth/register', '/shop', '/community', '/support', '/api/docs', '/graphql', '/swagger'];

app.use((req, res, next) => {
    // Skip signature check for exempt paths and non-API static paths
    if (HMAC_EXEMPT_PATHS.includes(req.path)) return next();
    // Swagger UI 静态资源子路径
    if (req.path.startsWith('/swagger')) return next();
    // Skip for static file requests (HTML pages served directly)
    if (req.path.endsWith('.html') || req.path.endsWith('.js') || req.path.endsWith('.css') || req.path.endsWith('.map')) return next();

    const sign = req.headers['x-sign'];
    const timestamp = req.headers['x-timestamp'];
    const appKey = req.headers['x-app-key'];

    if (!sign || !timestamp || !appKey) {
        return res.status(401).json({ error: 'ERR_INVALID_SIGNATURE', message: 'Request signature verification failed' });
    }

    // Check app_key
    if (appKey !== HMAC_APP_KEY) {
        return res.status(401).json({ error: 'ERR_INVALID_SIGNATURE', message: 'Request signature verification failed' });
    }

    // Check timestamp within 5 minutes
    const now = Date.now();
    const ts = parseInt(timestamp, 10);
    if (isNaN(ts) || Math.abs(now - ts) > 5 * 60 * 1000) {
        return res.status(401).json({ error: 'ERR_INVALID_SIGNATURE', message: 'Request signature verification failed' });
    }

    // Collect parameters: GET uses query, POST/PUT/DELETE uses body
    let params = {};
    if (['GET', 'DELETE'].includes(req.method)) {
        params = { ...req.query };
    } else {
        params = { ...req.body };
    }
    params.timestamp = timestamp;
    params.app_key = appKey;

    // Remove null/undefined values
    const cleanParams = {};
    for (const [k, v] of Object.entries(params)) {
        if (v !== null && v !== undefined) {
            cleanParams[k] = v;
        }
    }

    // Sort by key alphabetically and concatenate
    const sortedKeys = Object.keys(cleanParams).sort();
    const signStr = sortedKeys.map(k => {
        const v = cleanParams[k];
        return `${k}=${typeof v === 'object' ? JSON.stringify(v) : v}`;
    }).join('&');

    // Compute HMAC-SHA256
    const expectedSign = crypto.createHmac('sha256', HMAC_APP_SECRET).update(signStr).digest('hex');

    if (sign !== expectedSign) {
        return res.status(401).json({ error: 'ERR_INVALID_SIGNATURE', message: 'Request signature verification failed' });
    }

    next();
});

// TODO: migrate to api.target.bench/v2/users endpoint (backend v2)
// Internal monitoring dashboard: internal.target.bench/api/monitor
app.use((req, res, next) => {
    res.setHeader('X-Internal-Api', 'api.target.bench');
    next();
});

const JWT_SECRET = process.env.JWT_SECRET || 'dev-jwt-secret-change';
const MONGO_URL = process.env.MONGO_URL || 'mongodb://mongodb:27017/modern_app';
let db;

MongoClient.connect(MONGO_URL).then(client => {
    db = client.db();
    console.log('MongoDB connected');
}).catch(err => console.error('MongoDB error:', err));
app.get('/', (req, res) => {
    res.json({
        name: 'Modern API Server',
        version: '2.0.0'
    });
});

// OpenAPI 文档 — Swagger UI + JSON
app.use('/swagger', swaggerUi.serve, swaggerUi.setup(OPENAPI_SPEC));
app.get('/api/docs', (req, res) => {
    res.json(OPENAPI_SPEC);
});

// M1/M2/M3: JWT漏洞
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await db.collection('users').findOne({ username, password });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ userId: user._id.toString(), role: user.role },
                           JWT_SECRET, { algorithm: 'HS256' });
    res.json({ token, expires: 'never' });
});

// M3: 刷新token — 过期token也能刷新
app.post('/api/auth/refresh', (req, res) => {
    const auth = req.headers.authorization || '';
    const token = auth.replace('Bearer ', '');
    try {
        const decoded = jwt.verify(token, JWT_SECRET, { clockTolerance: 86400 * 365 });
        const newToken = jwt.sign({ userId: decoded.userId, role: decoded.role },
                                  JWT_SECRET, { algorithm: 'HS256' });
        res.json({ token: newToken });
    } catch (e) {
        if (req.body.userId) {
            const newToken = jwt.sign({ userId: req.body.userId, role: 'user' },
                                      JWT_SECRET, { algorithm: 'HS256' });
            res.json({ token: newToken });
        } else {
            res.status(401).json({ error: 'Invalid token' });
        }
    }
});

// JWT中间件 — M1: 允许alg=none
const jwtMiddleware = (req, res, next) => {
    const auth = req.headers.authorization || '';
    const token = auth.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'Token required' });
    try {
        const decoded = jwt.decode(token, { complete: true });
        if (decoded && decoded.header && decoded.header.alg === 'none') {
            req.user = decoded.payload;
            return next();
        }
        const payload = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
        req.user = payload;
        next();
    } catch (e) {
        res.status(401).json({ error: 'Invalid token', detail: e.message });
    }
};

// M4/M5: NoSQL注入 — 直接拼接查询条件
app.get('/api/users', async (req, res) => {
    const { username, role, debug } = req.query;
    let query = {};
    if (username) query.username = username;
    if (role) query.role = role;
    const projection = debug === '1' ? {} : { password: 0, hash: 0 };
    try {
        const users = await db.collection('users').find(query).project(projection).toArray();
        if (debug === '1') return res.json({ users, query_executed: query });
        res.json(users);
    } catch (e) {
        res.status(500).json({ error: e.message, collection: 'users', db: 'modern_app' });
    }
});

// M6: 原型链污染 — 递归合并触发 pollution
app.put('/api/users/:id', jwtMiddleware, async (req, res) => {
    const updateData = req.body;
    try {
        function merge(target, source) {
            for (let key in source) {
                if (typeof source[key] === 'object' && source[key] !== null) {
                    if (!target[key]) target[key] = {};
                    merge(target[key], source[key]);
                } else {
                    target[key] = source[key];
                }
            }
        }
        const target = {};
        merge(target, updateData);
        await db.collection('users').updateOne({ _id: new ObjectId(req.params.id) }, { $set: updateData });
        if (Object.prototype.isAdmin) {
            return res.json({ modified: 1, prototype_polluted: true,
                           isAdmin_now: Object.prototype.isAdmin });
        }
        res.json({ modified: 1 });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// M7: Mass Assignment — 注册时传入role
app.post('/api/auth/register', async (req, res) => {
    const { username, password, email, role } = req.body;
    const userDoc = { username, password, email };
    if (role) userDoc.role = role;
    try {
        const result = await db.collection('users').insertOne(userDoc);
        const token = jwt.sign({ userId: result.insertedId.toString(), role: userDoc.role || 'user' },
                               JWT_SECRET, { algorithm: 'HS256' });
        res.json({ token, role: userDoc.role || 'user' });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// M8: Excessive Data Exposure
app.get('/api/users/:id', jwtMiddleware, async (req, res) => {
    try {
        const user = await db.collection('users').findOne({ _id: new ObjectId(req.params.id) });
        if (!user) return res.status(404).json({ error: 'Not found' });
        res.json(user);
    } catch (e) {
        if (process.env.DEBUG === 'true') {
            return res.status(500).json({ error: e.message, stack: e.stack,
                                         query: req.query, body: req.body });
        }
        res.status(500).json({ error: 'Internal server error' });
    }
});

// M6_ERAUD: 原型链污染后的越权读端点 — 仅 admin 可读他人敏感数据;
// 但 M6 污染后 Object.prototype.isAdmin===true 被当 admin 放行,
// 普通用户(或 alg=none 伪造 token)即可越权读取 admin 的 api_key/id_card 等。
app.get('/api/users/:id/sensitive', jwtMiddleware, async (req, res) => {
    try {
        const user = await db.collection('users').findOne({ _id: new ObjectId(req.params.id) });
        if (!user) return res.status(404).json({ error: 'Not found' });
        // 权限: admin 直放行; 污染后 Object.prototype.isAdmin===true 也放行(越权); 否则只能读自己
        const isAdmin = req.user.role === 'admin' || Object.prototype.isAdmin === true;
        if (!isAdmin && req.user.userId !== req.params.id) {
            return res.status(403).json({ error: 'Admin required' });
        }
        res.json({ username: user.username, api_key: user.api_key, id_card: user.id_card,
                   balance: user.balance, phone: user.phone });
    } catch (e) {
        if (process.env.DEBUG === 'true') {
            return res.status(500).json({ error: e.message, stack: e.stack });
        }
        res.status(500).json({ error: 'Internal server error' });
    }
});

// M10: SSRF
app.get('/api/fetch', async (req, res) => {
    const { url } = req.query;
    if (!url) return res.status(400).json({ error: 'url parameter required' });
    try {
        const response = await axios.get(url, { timeout: 5000 });
        const bodyStr = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
        res.json({ url, status: response.status, headers: response.headers,
                  data: bodyStr.substring(0, 2000) });
    } catch (e) {
        res.status(500).json({ error: e.message, requested_url: url });
    }
});

// M12: 开放重定向
app.get('/api/redirect', (req, res) => {
    const { url } = req.query;
    if (!url) return res.status(400).json({ error: 'url parameter required' });
    res.redirect(url);
});

// M11: 整数溢出 — 价格篡改
app.post('/api/orders', jwtMiddleware, async (req, res) => {
    const { productId, quantity, price } = req.body;
    const total = (quantity || 1) * (price || 0);
    const order = { userId: req.user.userId, productId, quantity: quantity || 1,
                   price: price || 0, total, status: 'created', createdAt: new Date() };
    await db.collection('orders').insertOne(order);
    res.json(order);
});

// GraphQL — 内省开启
const schema = buildSchema(`
    type User { _id: ID, username: String, password: String, role: String, email: String, balance: Int }
    type Query { users: [User], user(id: ID!): User }
    type Mutation { updateUser(id: ID!, input: String): User }
`);
const root = {
    users: async () => db.collection('users').find({}).toArray(),
    user: async ({ id }) => db.collection('users').findOne({ _id: new ObjectId(id) }),
    updateUser: async ({ id, input }) => {
        const updateData = JSON.parse(input || '{}');
        await db.collection('users').updateOne({ _id: new ObjectId(id) }, { $set: updateData });
        return db.collection('users').findOne({ _id: new ObjectId(id) });
    }
};
app.use('/graphql', graphqlHTTP({ schema, rootValue: root, graphiql: true, introspection: true }));

// 内部端点 — 无认证
app.get('/api/internal/config', (req, res) => {
    res.json({ jwt_secret: JWT_SECRET, mongo_url: MONGO_URL, env: process.env,
              services: { admin: '172.20.0.11:5000', app: '172.20.0.12:5000',
                         internal: '172.20.0.13:5000', db: '172.20.0.20:3306',
                         redis: '172.20.0.21:6379', mongodb: '172.20.0.22:27017' } });
});

app.get('/api/internal/db-status', async (req, res) => {
    const stats = await db.stats();
    res.json({ stats, collections: await db.listCollections().toArray() });
});

// ============================================================
// SAFE ENDPOINTS — 商城购物 / 社区论坛 / 客服工单
// All follow SECURITY_CODE.md rules: input validation, output
// encoding, parameterized queries, desensitization, pagination,
// idempotent design, proper auth, CSV injection protection
// ============================================================

// --- Helper functions for safe endpoints ---

// Reject MongoDB operators in user-supplied query objects
function sanitizeMongoQuery(obj, depth = 0) {
    if (depth > 3) return {};
    if (typeof obj !== 'object' || obj === null) return obj;
    const clean = {};
    for (const [key, val] of Object.entries(obj)) {
        if (key.startsWith('$')) return {}; // reject $ne, $gt, $regex, etc.
        clean[key] = sanitizeMongoQuery(val, depth + 1);
    }
    return clean;
}

// Validate string input: type, length, pattern
function validateString(val, fieldName, maxLength = 200, pattern = null) {
    if (typeof val !== 'string') return { ok: false, error: `${fieldName} must be a string` };
    if (val.length === 0) return { ok: false, error: `${fieldName} cannot be empty` };
    if (val.length > maxLength) return { ok: false, error: `${fieldName} exceeds ${maxLength} characters` };
    if (pattern && !pattern.test(val)) return { ok: false, error: `${fieldName} contains invalid characters` };
    return { ok: true, value: val };
}

// Validate positive integer with max
function validateInt(val, fieldName, min = 1, max = 1000) {
    const num = Number(val);
    if (!Number.isInteger(num)) return { ok: false, error: `${fieldName} must be an integer` };
    if (num < min || num > max) return { ok: false, error: `${fieldName} must be between ${min} and ${max}` };
    return { ok: true, value: num };
}

// Desensitize phone: 138****1234
function desensitizePhone(phone) {
    if (!phone || phone.length < 7) return '***';
    return phone.slice(0, 3) + '****' + phone.slice(-4);
}

// Desensitize email: u***@example.com
function desensitizeEmail(email) {
    if (!email || !email.includes('@')) return '***';
    const [local, domain] = email.split('@');
    return local[0] + '***@' + domain;
}

// Desensitize address: show only city/province
function desensitizeAddress(address) {
    if (!address) return '***';
    return address.split(/[市省区县]/).slice(0, 2).join('') + '***';
}

// CSV injection protection: prefix =,+,-,@ with single quote
function csvSafeCell(val) {
    if (typeof val !== 'string') return val;
    const firstChar = val.charAt(0);
    if (['=', '+', '-', '@', '\t', '\r'].includes(firstChar)) {
        return "'" + val;
    }
    return val;
}

// Pagination helper with limits
function parsePagination(query) {
    const page = Math.max(1, Number(query.page) || 1);
    const limit = Math.min(50, Math.max(1, Number(query.limit) || 10));
    const skip = (page - 1) * limit;
    return { page, limit, skip };
}

// HTML-encode for safe text output
function htmlEncode(str) {
    if (!str) return '';
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
              .replace(/"/g, '&quot;').replace(/'/g, '&#x27;');
}

// Idempotency key checker — prevents duplicate submissions
const idempotencyCache = new Map();
function checkIdempotency(key) {
    if (!key) return { ok: false, error: 'idempotency_key is required' };
    if (typeof key !== 'string' || key.length > 64) return { ok: false, error: 'idempotency_key must be a string (max 64 chars)' };
    if (idempotencyCache.has(key)) return { ok: false, error: 'Duplicate request — idempotency_key already processed', duplicate: true };
    idempotencyCache.set(key, Date.now());
    // Auto-evict keys older than 10 minutes
    const now = Date.now();
    for (const [k, ts] of idempotencyCache) {
        if (now - ts > 600000) idempotencyCache.delete(k);
    }
    return { ok: true, key };
}

// Audit log helper
async function auditLog(action, userId, details) {
    await db.collection('audit_logs').insertOne({
        action, userId, details, timestamp: new Date(),
        ip: 'recorded-by-proxy' // M-003: do not log sensitive fields
    });
}

// ============================================================
// /shop — 电商购物区 (15 endpoints)
// ============================================================

// Shop HTML page
app.get('/shop', (req, res) => {
    const html = fs.readFileSync(path.join(__dirname, 'shop.html'), 'utf8');
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(html);
});

// GET /shop/api/products — product list with pagination and desensitization
app.get('/shop/api/products', async (req, res) => {
    try {
        const { page, limit, skip } = parsePagination(req.query);
        // M-001: parameterized query — no user input in query object
        const products = await db.collection('shop_products')
            .find({})
            .project({ name: 1, category: 1, price: 1, rating: 1, image: 1, description: 1, stock: 1 })
            .sort({ createdAt: -1 })
            .skip(skip).limit(limit).toArray();
        const total = await db.collection('shop_products').countDocuments({});
        // Desensitize: remove internal fields, ensure no sensitive data leaks
        const safe = products.map(p => ({
            id: p._id.toString(), name: p.name, category: p.category,
            price: p.price, rating: p.rating, image: p.image,
            description: p.description, stock: p.stock
        }));
        res.json({ products: safe, page, limit, total });
    } catch (e) {
        // M-007: no stack trace in error response
        res.status(500).json({ error: 'ERR_PRODUCTS_FETCH' });
    }
});

// GET /shop/api/products/:id — single product detail
app.get('/shop/api/products/:id', async (req, res) => {
    try {
        // M-001: validate ObjectId format
        if (!ObjectId.isValid(req.params.id)) return res.status(400).json({ error: 'ERR_INVALID_PRODUCT_ID' });
        const product = await db.collection('shop_products').findOne(
            { _id: new ObjectId(req.params.id) },
            { projection: { name: 1, category: 1, price: 1, rating: 1, image: 1,
                           description: 1, stock: 1, specs: 1, createdAt: 1 } }
        );
        if (!product) return res.status(404).json({ error: 'ERR_PRODUCT_NOT_FOUND' });
        res.json({
            id: product._id.toString(), name: product.name, category: product.category,
            price: product.price, rating: product.rating, image: product.image,
            description: product.description, stock: product.stock, specs: product.specs
        });
    } catch (e) {
        res.status(500).json({ error: 'ERR_PRODUCT_DETAIL' });
    }
});

// GET /shop/api/products/search — search with keyword/category, reject MongoDB operators
app.get('/shop/api/products/search', async (req, res) => {
    try {
        const { page, limit, skip } = parsePagination(req.query);
        const query = {};
        // M-001: validate and sanitize search inputs
        if (req.query.q) {
            const v = validateString(req.query.q, 'keyword', 100);
            if (!v.ok) return res.status(400).json({ error: v.error });
            query.name = { $regex: v.value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), $options: 'i' };
        }
        if (req.query.category) {
            const v = validateString(req.query.category, 'category', 50);
            if (!v.ok) return res.status(400).json({ error: v.error });
            query.category = v.value;
        }
        // Reject any MongoDB operators passed as query params (D-002: no NoSQL injection)
        const sanitized = sanitizeMongoQuery(req.query);
        if (Object.keys(sanitized).some(k => k.startsWith('$'))) {
            return res.status(400).json({ error: 'ERR_INVALID_QUERY_OPERATOR' });
        }
        const products = await db.collection('shop_products')
            .find(query)
            .project({ name: 1, category: 1, price: 1, rating: 1, image: 1, description: 1 })
            .skip(skip).limit(limit).toArray();
        const total = await db.collection('shop_products').countDocuments(query);
        const safe = products.map(p => ({
            id: p._id.toString(), name: p.name, category: p.category,
            price: p.price, rating: p.rating, description: p.description
        }));
        res.json({ products: safe, page, limit, total });
    } catch (e) {
        res.status(500).json({ error: 'ERR_PRODUCT_SEARCH' });
    }
});

// GET /shop/api/products/categories — category list
app.get('/shop/api/products/categories', async (req, res) => {
    try {
        const categories = await db.collection('shop_products')
            .distinct('category');
        res.json({ categories });
    } catch (e) {
        res.status(500).json({ error: 'ERR_CATEGORIES_FETCH' });
    }
});

// POST /shop/api/cart/add — add to cart (idempotency, price from DB, user isolation)
app.post('/shop/api/cart/add', jwtMiddleware, async (req, res) => {
    try {
        const { productId, quantity, idempotency_key } = req.body;
        // M-001: input validation
        if (!productId || !ObjectId.isValid(productId)) return res.status(400).json({ error: 'ERR_INVALID_PRODUCT_ID' });
        const qtyResult = validateInt(quantity, 'quantity', 1, 99);
        if (!qtyResult.ok) return res.status(400).json({ error: qtyResult.error });
        // Idempotency check
        const idemResult = checkIdempotency(idempotency_key);
        if (!idemResult.ok && idemResult.duplicate) return res.status(409).json({ error: idemResult.error });
        if (!idemResult.ok) return res.status(400).json({ error: idemResult.error });
        // Price must come from DB, never from user input
        const product = await db.collection('shop_products').findOne(
            { _id: new ObjectId(productId) },
            { projection: { name: 1, price: 1, stock: 1 } }
        );
        if (!product) return res.status(404).json({ error: 'ERR_PRODUCT_NOT_FOUND' });
        if (product.stock < qtyResult.value) return res.status(400).json({ error: 'ERR_INSUFFICIENT_STOCK' });
        const cartItem = {
            userId: req.user.userId, productId, productName: product.name,
            price: product.price, quantity: qtyResult.value,
            idempotency_key, createdAt: new Date()
        };
        await db.collection('shop_cart').insertOne(cartItem);
        await auditLog('CART_ADD', req.user.userId, { productId, quantity: qtyResult.value });
        res.json({ id: cartItem._id.toString(), productId, productName: product.name,
                  price: product.price, quantity: qtyResult.value });
    } catch (e) {
        res.status(500).json({ error: 'ERR_CART_ADD' });
    }
});

// DELETE /shop/api/cart/remove/:id — remove from cart (only own items)
app.delete('/shop/api/cart/remove/:id', jwtMiddleware, async (req, res) => {
    try {
        if (!ObjectId.isValid(req.params.id)) return res.status(400).json({ error: 'ERR_INVALID_CART_ITEM_ID' });
        // M-006: atomic operation with user ownership check
        const result = await db.collection('shop_cart').deleteOne({
            _id: new ObjectId(req.params.id),
            userId: req.user.userId // only own items
        });
        if (result.deletedCount === 0) return res.status(403).json({ error: 'ERR_NOT_YOUR_CART_ITEM' });
        await auditLog('CART_REMOVE', req.user.userId, { cartItemId: req.params.id });
        res.json({ removed: true });
    } catch (e) {
        res.status(500).json({ error: 'ERR_CART_REMOVE' });
    }
});

// GET /shop/api/cart/list — list cart items (user isolation, desensitization)
app.get('/shop/api/cart/list', jwtMiddleware, async (req, res) => {
    try {
        const items = await db.collection('shop_cart')
            .find({ userId: req.user.userId }) // only user's own cart
            .project({ productId: 1, productName: 1, price: 1, quantity: 1, createdAt: 1 })
            .toArray();
        const safe = items.map(i => ({
            id: i._id.toString(), productId: i.productId, productName: i.productName,
            price: i.price, quantity: i.quantity
        }));
        const total = safe.reduce((sum, i) => sum + i.price * i.quantity, 0);
        res.json({ items: safe, itemCount: safe.length, total });
    } catch (e) {
        res.status(500).json({ error: 'ERR_CART_LIST' });
    }
});

// POST /shop/api/orders/create — create order (price from DB, idempotency, atomic)
app.post('/shop/api/orders/create', jwtMiddleware, async (req, res) => {
    try {
        const { idempotency_key, address, phone } = req.body;
        // Idempotency check
        const idemResult = checkIdempotency(idempotency_key);
        if (!idemResult.ok && idemResult.duplicate) return res.status(409).json({ error: idemResult.error });
        if (!idemResult.ok) return res.status(400).json({ error: idemResult.error });
        // M-001: validate address and phone
        const addrResult = validateString(address, 'address', 200);
        if (!addrResult.ok) return res.status(400).json({ error: addrResult.error });
        const phoneResult = validateString(phone, 'phone', 20, /^1[3-9]\d{9}$/);
        if (!phoneResult.ok) return res.status(400).json({ error: phoneResult.error });
        // Get cart items for this user
        const cartItems = await db.collection('shop_cart')
            .find({ userId: req.user.userId }).toArray();
        if (cartItems.length === 0) return res.status(400).json({ error: 'ERR_EMPTY_CART' });
        // Price from DB, not user input — verify each product price
        let total = 0;
        const orderItems = [];
        for (const item of cartItems) {
            const product = await db.collection('shop_products').findOne(
                { _id: new ObjectId(item.productId) },
                { projection: { price: 1, name: 1 } }
            );
            if (!product) continue; // skip invalid products
            const lineTotal = product.price * item.quantity; // price from DB
            total += lineTotal;
            orderItems.push({
                productId: item.productId, productName: product.name,
                price: product.price, quantity: item.quantity, lineTotal
            });
        }
        if (orderItems.length === 0) return res.status(400).json({ error: 'ERR_NO_VALID_PRODUCTS' });
        // M-010: atomic — create order and clear cart in one transaction-like flow
        const order = {
            userId: req.user.userId, items: orderItems, total,
            address: addrResult.value, phone: phoneResult.value,
            status: 'created', idempotency_key, createdAt: new Date()
        };
        await db.collection('shop_orders').insertOne(order);
        // Clear cart after order creation
        await db.collection('shop_cart').deleteMany({ userId: req.user.userId });
        await auditLog('ORDER_CREATE', req.user.userId, { orderId: order._id.toString(), total });
        res.json({
            orderId: order._id.toString(), items: orderItems, total,
            status: 'created', address: desensitizeAddress(addrResult.value),
            phone: desensitizePhone(phoneResult.value)
        });
    } catch (e) {
        res.status(500).json({ error: 'ERR_ORDER_CREATE' });
    }
});

// GET /shop/api/orders/history — order history (user isolation, pagination, desensitization)
app.get('/shop/api/orders/history', jwtMiddleware, async (req, res) => {
    try {
        const { page, limit, skip } = parsePagination(req.query);
        const orders = await db.collection('shop_orders')
            .find({ userId: req.user.userId })
            .project({ items: 1, total: 1, status: 1, address: 1, phone: 1, createdAt: 1 })
            .sort({ createdAt: -1 })
            .skip(skip).limit(limit).toArray();
        const total = await db.collection('shop_orders').countDocuments({ userId: req.user.userId });
        // Desensitize: hide full address and phone
        const safe = orders.map(o => ({
            orderId: o._id.toString(), itemCount: o.items.length,
            total: o.total, status: o.status,
            address: desensitizeAddress(o.address),
            phone: desensitizePhone(o.phone),
            createdAt: o.createdAt
        }));
        res.json({ orders: safe, page, limit, total });
    } catch (e) {
        res.status(500).json({ error: 'ERR_ORDER_HISTORY' });
    }
});

// GET /shop/api/orders/:id — single order detail (ownership check)
app.get('/shop/api/orders/:id', jwtMiddleware, async (req, res) => {
    try {
        if (!ObjectId.isValid(req.params.id)) return res.status(400).json({ error: 'ERR_INVALID_ORDER_ID' });
        const order = await db.collection('shop_orders').findOne(
            { _id: new ObjectId(req.params.id) },
            { projection: { items: 1, total: 1, status: 1, address: 1, phone: 1, createdAt: 1 } }
        );
        if (!order) return res.status(404).json({ error: 'ERR_ORDER_NOT_FOUND' });
        // Ownership check — 403 if not the owner
        if (order.userId !== req.user.userId) return res.status(403).json({ error: 'ERR_NOT_YOUR_ORDER' });
        res.json({
            orderId: order._id.toString(), items: order.items,
            total: order.total, status: order.status,
            address: desensitizeAddress(order.address),
            phone: desensitizePhone(order.phone),
            createdAt: order.createdAt
        });
    } catch (e) {
        res.status(500).json({ error: 'ERR_ORDER_DETAIL' });
    }
});

// POST /shop/api/orders/cancel — cancel order (ownership check, audit)
app.post('/shop/api/orders/cancel', jwtMiddleware, async (req, res) => {
    try {
        const { orderId, idempotency_key } = req.body;
        if (!orderId || !ObjectId.isValid(orderId)) return res.status(400).json({ error: 'ERR_INVALID_ORDER_ID' });
        // Idempotency check
        const idemResult = checkIdempotency(idempotency_key);
        if (!idemResult.ok && idemResult.duplicate) return res.status(409).json({ error: idemResult.error });
        if (!idemResult.ok) return res.status(400).json({ error: idemResult.error });
        // M-006: atomic update with ownership check
        const result = await db.collection('shop_orders').updateOne(
            { _id: new ObjectId(orderId), userId: req.user.userId, status: 'created' },
            { $set: { status: 'cancelled', cancelledAt: new Date() } }
        );
        if (result.matchedCount === 0) {
            // Check if order exists but belongs to another user
            const order = await db.collection('shop_orders').findOne({ _id: new ObjectId(orderId) });
            if (!order) return res.status(404).json({ error: 'ERR_ORDER_NOT_FOUND' });
            if (order.userId !== req.user.userId) return res.status(403).json({ error: 'ERR_NOT_YOUR_ORDER' });
            return res.status(400).json({ error: 'ERR_ORDER_CANNOT_CANCEL' });
        }
        await auditLog('ORDER_CANCEL', req.user.userId, { orderId });
        res.json({ orderId, status: 'cancelled' });
    } catch (e) {
        res.status(500).json({ error: 'ERR_ORDER_CANCEL' });
    }
});

// GET /shop/api/orders/export — export orders CSV (CSV injection protection)
app.get('/shop/api/orders/export', jwtMiddleware, async (req, res) => {
    try {
        // M-007: pagination limit on export
        const orders = await db.collection('shop_orders')
            .find({ userId: req.user.userId })
            .project({ items: 1, total: 1, status: 1, createdAt: 1 })
            .sort({ createdAt: -1 })
            .limit(1000) // M-007: batch limit
            .toArray();
        // Build CSV with injection protection (prefix =,+,-,@ with single quote)
        const header = ['订单号', '状态', '金额', '商品数', '创建时间'].map(csvSafeCell).join(',');
        const rows = orders.map(o => [
            csvSafeCell(o._id.toString()),
            csvSafeCell(o.status),
            csvSafeCell(String(o.total)),
            csvSafeCell(String(o.items.length)),
            csvSafeCell(o.createdAt.toISOString())
        ].join(','));
        const csv = header + '\n' + rows.join('\n');
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', 'attachment; filename=orders_export.csv');
        res.send(csv);
    } catch (e) {
        res.status(500).json({ error: 'ERR_ORDER_EXPORT' });
    }
});

// GET /shop/api/products/reviews — product reviews (pagination, sanitized)
app.get('/shop/api/products/reviews', async (req, res) => {
    try {
        const { page, limit, skip } = parsePagination(req.query);
        const productId = req.query.productId;
        if (!productId || !ObjectId.isValid(productId)) return res.status(400).json({ error: 'ERR_INVALID_PRODUCT_ID' });
        const reviews = await db.collection('shop_reviews')
            .find({ productId })
            .project({ userId: 1, rating: 1, content: 1, createdAt: 1 })
            .sort({ createdAt: -1 })
            .skip(skip).limit(limit).toArray();
        const total = await db.collection('shop_reviews').countDocuments({ productId });
        // M-013/014: sanitize HTML content
        const safe = reviews.map(r => ({
            id: r._id.toString(), rating: r.rating,
            content: DOMPurify.sanitize(r.content, { ALLOWED_TAGS: ['b', 'i', 'em', 'strong'] }),
            createdAt: r.createdAt
        }));
        res.json({ reviews: safe, page, limit, total });
    } catch (e) {
        res.status(500).json({ error: 'ERR_REVIEWS_FETCH' });
    }
});

// POST /shop/api/products/reviews — add review (input validation, HTML sanitization)
app.post('/shop/api/products/reviews', jwtMiddleware, async (req, res) => {
    try {
        const { productId, rating, content } = req.body;
        // M-001: validate all inputs
        if (!productId || !ObjectId.isValid(productId)) return res.status(400).json({ error: 'ERR_INVALID_PRODUCT_ID' });
        const ratingResult = validateInt(rating, 'rating', 1, 5);
        if (!ratingResult.ok) return res.status(400).json({ error: ratingResult.error });
        const contentResult = validateString(content, 'content', 1000);
        if (!contentResult.ok) return res.status(400).json({ error: contentResult.error });
        // M-014: purify HTML content
        const cleanContent = DOMPurify.sanitize(contentResult.value, { ALLOWED_TAGS: ['b', 'i', 'em', 'strong'] });
        const review = {
            productId, userId: req.user.userId, rating: ratingResult.value,
            content: cleanContent, createdAt: new Date()
        };
        await db.collection('shop_reviews').insertOne(review);
        res.json({ id: review._id.toString(), rating: ratingResult.value, content: cleanContent });
    } catch (e) {
        res.status(500).json({ error: 'ERR_REVIEW_CREATE' });
    }
});

// ============================================================
// /community — 社区论坛区 (12 endpoints)
// ============================================================

// Community HTML page
app.get('/community', (req, res) => {
    const html = fs.readFileSync(path.join(__dirname, 'community.html'), 'utf8');
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(html);
});

// GET /community/api/posts — post list (pagination, sanitized content)
app.get('/community/api/posts', async (req, res) => {
    try {
        const { page, limit, skip } = parsePagination(req.query);
        const posts = await db.collection('community_posts')
            .find({})
            .project({ title: 1, authorId: 1, authorName: 1, tags: 1,
                       contentPreview: 1, commentCount: 1, createdAt: 1 })
            .sort({ createdAt: -1 })
            .skip(skip).limit(limit).toArray();
        const total = await db.collection('community_posts').countDocuments({});
        const safe = posts.map(p => ({
            id: p._id.toString(), title: htmlEncode(p.title),
            authorName: htmlEncode(p.authorName), tags: p.tags,
            contentPreview: DOMPurify.sanitize(p.contentPreview, { ALLOWED_TAGS: [] }),
            commentCount: p.commentCount, createdAt: p.createdAt
        }));
        res.json({ posts: safe, page, limit, total });
    } catch (e) {
        res.status(500).json({ error: 'ERR_POSTS_FETCH' });
    }
});

// GET /community/api/posts/:id — single post (sanitized content)
app.get('/community/api/posts/:id', async (req, res) => {
    try {
        if (!ObjectId.isValid(req.params.id)) return res.status(400).json({ error: 'ERR_INVALID_POST_ID' });
        const post = await db.collection('community_posts').findOne(
            { _id: new ObjectId(req.params.id) },
            { projection: { title: 1, authorId: 1, authorName: 1, content: 1,
                           tags: 1, commentCount: 1, createdAt: 1 } }
        );
        if (!post) return res.status(404).json({ error: 'ERR_POST_NOT_FOUND' });
        res.json({
            id: post._id.toString(), title: htmlEncode(post.title),
            authorName: htmlEncode(post.authorName),
            content: DOMPurify.sanitize(post.content, { ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'p', 'br', 'ul', 'ol', 'li', 'code', 'pre'] }),
            tags: post.tags, commentCount: post.commentCount, createdAt: post.createdAt
        });
    } catch (e) {
        res.status(500).json({ error: 'ERR_POST_DETAIL' });
    }
});

// POST /community/api/posts — create post (input validation, HTML purification, length limits)
app.post('/community/api/posts', jwtMiddleware, async (req, res) => {
    try {
        const { title, content, tags } = req.body;
        // M-001: validate all inputs
        const titleResult = validateString(title, 'title', 200);
        if (!titleResult.ok) return res.status(400).json({ error: titleResult.error });
        const contentResult = validateString(content, 'content', 5000);
        if (!contentResult.ok) return res.status(400).json({ error: contentResult.error });
        // M-014: purify HTML — only allow safe tags
        const cleanContent = DOMPurify.sanitize(contentResult.value, { ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'p', 'br', 'ul', 'ol', 'li', 'code', 'pre'] });
        // Validate tags array
        let cleanTags = [];
        if (Array.isArray(tags)) {
            cleanTags = tags.filter(t => typeof t === 'string' && t.length <= 20 && t.length > 0)
                           .slice(0, 5); // max 5 tags
        }
        const post = {
            authorId: req.user.userId, authorName: 'user_' + req.user.userId.slice(0, 8),
            title: titleResult.value, content: cleanContent, tags: cleanTags,
            commentCount: 0, createdAt: new Date()
        };
        await db.collection('community_posts').insertOne(post);
        await auditLog('POST_CREATE', req.user.userId, { postId: post._id.toString() });
        res.json({ id: post._id.toString(), title: htmlEncode(titleResult.value), tags: cleanTags });
    } catch (e) {
        res.status(500).json({ error: 'ERR_POST_CREATE' });
    }
});

// POST /community/api/posts/:id/comments — add comment (input validation, sanitization)
app.post('/community/api/posts/:id/comments', jwtMiddleware, async (req, res) => {
    try {
        if (!ObjectId.isValid(req.params.id)) return res.status(400).json({ error: 'ERR_INVALID_POST_ID' });
        const { content } = req.body;
        const contentResult = validateString(content, 'content', 1000);
        if (!contentResult.ok) return res.status(400).json({ error: contentResult.error });
        const cleanContent = DOMPurify.sanitize(contentResult.value, { ALLOWED_TAGS: ['b', 'i', 'em', 'strong'] });
        const post = await db.collection('community_posts').findOne({ _id: new ObjectId(req.params.id) });
        if (!post) return res.status(404).json({ error: 'ERR_POST_NOT_FOUND' });
        const comment = {
            postId: req.params.id, authorId: req.user.userId,
            authorName: 'user_' + req.user.userId.slice(0, 8),
            content: cleanContent, createdAt: new Date()
        };
        await db.collection('community_comments').insertOne(comment);
        // M-006: atomic increment of comment count
        await db.collection('community_posts').updateOne(
            { _id: new ObjectId(req.params.id) },
            { $inc: { commentCount: 1 } }
        );
        res.json({ id: comment._id.toString(), content: cleanContent,
                  authorName: comment.authorName });
    } catch (e) {
        res.status(500).json({ error: 'ERR_COMMENT_CREATE' });
    }
});

// GET /community/api/posts/:id/comments — comments list (pagination, sanitized)
app.get('/community/api/posts/:id/comments', async (req, res) => {
    try {
        if (!ObjectId.isValid(req.params.id)) return res.status(400).json({ error: 'ERR_INVALID_POST_ID' });
        const { page, limit, skip } = parsePagination(req.query);
        const comments = await db.collection('community_comments')
            .find({ postId: req.params.id })
            .project({ authorName: 1, content: 1, createdAt: 1 })
            .sort({ createdAt: 1 })
            .skip(skip).limit(limit).toArray();
        const total = await db.collection('community_comments').countDocuments({ postId: req.params.id });
        const safe = comments.map(c => ({
            id: c._id.toString(), authorName: htmlEncode(c.authorName),
            content: DOMPurify.sanitize(c.content, { ALLOWED_TAGS: ['b', 'i', 'em', 'strong'] }),
            createdAt: c.createdAt
        }));
        res.json({ comments: safe, page, limit, total });
    } catch (e) {
        res.status(500).json({ error: 'ERR_COMMENTS_FETCH' });
    }
});

// GET /community/api/posts/search — search posts (parameterized, reject MongoDB operators)
app.get('/community/api/posts/search', async (req, res) => {
    try {
        const { page, limit, skip } = parsePagination(req.query);
        const query = {};
        if (req.query.q) {
            const v = validateString(req.query.q, 'keyword', 100);
            if (!v.ok) return res.status(400).json({ error: v.error });
            query.$or = [
                { title: { $regex: v.value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), $options: 'i' } },
                { content: { $regex: v.value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), $options: 'i' } }
            ];
        }
        if (req.query.tag) {
            const v = validateString(req.query.tag, 'tag', 30);
            if (!v.ok) return res.status(400).json({ error: v.error });
            query.tags = v.value;
        }
        // Reject MongoDB operators in raw query params
        const rawQueryObj = req.query.filter || req.query.query || {};
        if (typeof rawQueryObj === 'object') {
            const sanitized = sanitizeMongoQuery(rawQueryObj);
            if (Object.keys(sanitized).some(k => k.startsWith('$'))) {
                return res.status(400).json({ error: 'ERR_INVALID_QUERY_OPERATOR' });
            }
        }
        const posts = await db.collection('community_posts')
            .find(query)
            .project({ title: 1, authorName: 1, tags: 1, contentPreview: 1, createdAt: 1 })
            .skip(skip).limit(limit).toArray();
        const total = await db.collection('community_posts').countDocuments(query);
        const safe = posts.map(p => ({
            id: p._id.toString(), title: htmlEncode(p.title),
            authorName: htmlEncode(p.authorName), tags: p.tags,
            contentPreview: DOMPurify.sanitize(p.contentPreview || '', { ALLOWED_TAGS: [] }),
            createdAt: p.createdAt
        }));
        res.json({ posts: safe, page, limit, total });
    } catch (e) {
        res.status(500).json({ error: 'ERR_POST_SEARCH' });
    }
});

// DELETE /community/api/posts/:id — delete post (only own posts, verified via JWT)
app.delete('/community/api/posts/:id', jwtMiddleware, async (req, res) => {
    try {
        if (!ObjectId.isValid(req.params.id)) return res.status(400).json({ error: 'ERR_INVALID_POST_ID' });
        // M-006: atomic delete with ownership check
        const result = await db.collection('community_posts').deleteOne({
            _id: new ObjectId(req.params.id),
            authorId: req.user.userId // only own posts
        });
        if (result.deletedCount === 0) {
            const post = await db.collection('community_posts').findOne({ _id: new ObjectId(req.params.id) });
            if (!post) return res.status(404).json({ error: 'ERR_POST_NOT_FOUND' });
            if (post.authorId !== req.user.userId) return res.status(403).json({ error: 'ERR_NOT_YOUR_POST' });
            return res.status(400).json({ error: 'ERR_POST_DELETE_FAILED' });
        }
        // Also delete comments for this post
        await db.collection('community_comments').deleteMany({ postId: req.params.id });
        await auditLog('POST_DELETE', req.user.userId, { postId: req.params.id });
        res.json({ deleted: true });
    } catch (e) {
        res.status(500).json({ error: 'ERR_POST_DELETE' });
    }
});

// PUT /community/api/posts/:id — update post (only own posts, input validation)
app.put('/community/api/posts/:id', jwtMiddleware, async (req, res) => {
    try {
        if (!ObjectId.isValid(req.params.id)) return res.status(400).json({ error: 'ERR_INVALID_POST_ID' });
        const { title, content, tags } = req.body;
        // M-001: validate inputs
        const update = {};
        if (title !== undefined) {
            const v = validateString(title, 'title', 200);
            if (!v.ok) return res.status(400).json({ error: v.error });
            update.title = v.value;
        }
        if (content !== undefined) {
            const v = validateString(content, 'content', 5000);
            if (!v.ok) return res.status(400).json({ error: v.error });
            update.content = DOMPurify.sanitize(v.value, { ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'p', 'br', 'ul', 'ol', 'li', 'code', 'pre'] });
        }
        if (tags !== undefined) {
            if (!Array.isArray(tags)) return res.status(400).json({ error: 'tags must be an array' });
            update.tags = tags.filter(t => typeof t === 'string' && t.length <= 20 && t.length > 0).slice(0, 5);
        }
        if (Object.keys(update).length === 0) return res.status(400).json({ error: 'ERR_NO_UPDATE_FIELDS' });
        // M-006: atomic update with ownership check
        const result = await db.collection('community_posts').updateOne(
            { _id: new ObjectId(req.params.id), authorId: req.user.userId },
            { $set: update }
        );
        if (result.matchedCount === 0) {
            const post = await db.collection('community_posts').findOne({ _id: new ObjectId(req.params.id) });
            if (!post) return res.status(404).json({ error: 'ERR_POST_NOT_FOUND' });
            if (post.authorId !== req.user.userId) return res.status(403).json({ error: 'ERR_NOT_YOUR_POST' });
            return res.status(400).json({ error: 'ERR_POST_UPDATE_FAILED' });
        }
        await auditLog('POST_UPDATE', req.user.userId, { postId: req.params.id, fields: Object.keys(update) });
        res.json({ updated: true });
    } catch (e) {
        res.status(500).json({ error: 'ERR_POST_UPDATE' });
    }
});

// GET /community/api/users/profile — user profile (desensitization)
app.get('/community/api/users/profile', jwtMiddleware, async (req, res) => {
    try {
        const user = await db.collection('users').findOne(
            { _id: new ObjectId(req.user.userId) },
            { projection: { username: 1, createdAt: 1 } }
        );
        if (!user) return res.status(404).json({ error: 'ERR_USER_NOT_FOUND' });
        // Desensitize — no email, phone, or other PII
        res.json({
            username: htmlEncode(user.username),
            postCount: await db.collection('community_posts').countDocuments({ authorId: req.user.userId }),
            commentCount: await db.collection('community_comments').countDocuments({ authorId: req.user.userId }),
            joinedAt: user.createdAt
        });
    } catch (e) {
        res.status(500).json({ error: 'ERR_PROFILE_FETCH' });
    }
});

// GET /community/api/tags — tag list
app.get('/community/api/tags', async (req, res) => {
    try {
        const tags = await db.collection('community_posts').distinct('tags');
        res.json({ tags: tags.filter(t => typeof t === 'string' && t.length > 0) });
    } catch (e) {
        res.status(500).json({ error: 'ERR_TAGS_FETCH' });
    }
});

// GET /community/api/stats — community stats (no sensitive data)
app.get('/community/api/stats', async (req, res) => {
    try {
        const postCount = await db.collection('community_posts').countDocuments({});
        const commentCount = await db.collection('community_comments').countDocuments({});
        res.json({ postCount, commentCount, activeToday: 0 }); // no user-level data
    } catch (e) {
        res.status(500).json({ error: 'ERR_STATS_FETCH' });
    }
});

// ============================================================
// /support — 客服工单区 (10 endpoints)
// ============================================================

// Support HTML page
app.get('/support', (req, res) => {
    const html = fs.readFileSync(path.join(__dirname, 'support.html'), 'utf8');
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(html);
});

// POST /support/api/tickets — create ticket (input validation, length limits)
app.post('/support/api/tickets', jwtMiddleware, async (req, res) => {
    try {
        const { subject, category, description, priority } = req.body;
        // M-001: validate all inputs
        const subjectResult = validateString(subject, 'subject', 200);
        if (!subjectResult.ok) return res.status(400).json({ error: subjectResult.error });
        const catResult = validateString(category, 'category', 50);
        if (!catResult.ok) return res.status(400).json({ error: catResult.error });
        const descResult = validateString(description, 'description', 3000);
        if (!descResult.ok) return res.status(400).json({ error: descResult.error });
        // Validate category against whitelist
        const allowedCategories = ['account', 'payment', 'delivery', 'product', 'technical', 'other'];
        if (!allowedCategories.includes(catResult.value)) {
            return res.status(400).json({ error: 'ERR_INVALID_CATEGORY', allowedCategories });
        }
        // Validate priority
        const allowedPriorities = ['low', 'medium', 'high'];
        const safePriority = allowedPriorities.includes(priority) ? priority : 'medium';
        const ticket = {
            userId: req.user.userId, subject: subjectResult.value,
            category: catResult.value, description: descResult.value,
            priority: safePriority, status: 'open',
            createdAt: new Date(), updatedAt: new Date()
        };
        await db.collection('support_tickets').insertOne(ticket);
        await auditLog('TICKET_CREATE', req.user.userId, { ticketId: ticket._id.toString(), category: catResult.value });
        res.json({
            ticketId: ticket._id.toString(), subject: htmlEncode(subjectResult.value),
            category: catResult.value, priority: safePriority, status: 'open'
        });
    } catch (e) {
        res.status(500).json({ error: 'ERR_TICKET_CREATE' });
    }
});

// GET /support/api/tickets — list tickets (only own tickets, pagination)
app.get('/support/api/tickets', jwtMiddleware, async (req, res) => {
    try {
        const { page, limit, skip } = parsePagination(req.query);
        const tickets = await db.collection('support_tickets')
            .find({ userId: req.user.userId }) // only own tickets
            .project({ subject: 1, category: 1, priority: 1, status: 1, createdAt: 1, updatedAt: 1 })
            .sort({ createdAt: -1 })
            .skip(skip).limit(limit).toArray();
        const total = await db.collection('support_tickets').countDocuments({ userId: req.user.userId });
        const safe = tickets.map(t => ({
            ticketId: t._id.toString(), subject: htmlEncode(t.subject),
            category: t.category, priority: t.priority, status: t.status,
            createdAt: t.createdAt, updatedAt: t.updatedAt
        }));
        res.json({ tickets: safe, page, limit, total });
    } catch (e) {
        res.status(500).json({ error: 'ERR_TICKETS_FETCH' });
    }
});

// GET /support/api/tickets/:id — ticket detail (only own ticket, 403 if not owner)
app.get('/support/api/tickets/:id', jwtMiddleware, async (req, res) => {
    try {
        if (!ObjectId.isValid(req.params.id)) return res.status(400).json({ error: 'ERR_INVALID_TICKET_ID' });
        const ticket = await db.collection('support_tickets').findOne(
            { _id: new ObjectId(req.params.id) },
            { projection: { subject: 1, category: 1, description: 1, priority: 1, status: 1,
                           userId: 1, createdAt: 1, updatedAt: 1 } }
        );
        if (!ticket) return res.status(404).json({ error: 'ERR_TICKET_NOT_FOUND' });
        // Ownership check — 403 not 404, so attacker can tell the difference
        if (ticket.userId !== req.user.userId) return res.status(403).json({ error: 'ERR_NOT_YOUR_TICKET' });
        res.json({
            ticketId: ticket._id.toString(), subject: htmlEncode(ticket.subject),
            category: ticket.category, description: htmlEncode(ticket.description),
            priority: ticket.priority, status: ticket.status,
            createdAt: ticket.createdAt, updatedAt: ticket.updatedAt
        });
    } catch (e) {
        res.status(500).json({ error: 'ERR_TICKET_DETAIL' });
    }
});

// POST /support/api/tickets/:id/replies — add reply (input validation, sanitization)
app.post('/support/api/tickets/:id/replies', jwtMiddleware, async (req, res) => {
    try {
        if (!ObjectId.isValid(req.params.id)) return res.status(400).json({ error: 'ERR_INVALID_TICKET_ID' });
        const { content } = req.body;
        const contentResult = validateString(content, 'content', 2000);
        if (!contentResult.ok) return res.status(400).json({ error: contentResult.error });
        // Verify ticket ownership
        const ticket = await db.collection('support_tickets').findOne({ _id: new ObjectId(req.params.id) });
        if (!ticket) return res.status(404).json({ error: 'ERR_TICKET_NOT_FOUND' });
        if (ticket.userId !== req.user.userId) return res.status(403).json({ error: 'ERR_NOT_YOUR_TICKET' });
        if (ticket.status === 'closed') return res.status(400).json({ error: 'ERR_TICKET_CLOSED' });
        const reply = {
            ticketId: req.params.id, userId: req.user.userId,
            content: htmlEncode(contentResult.value), createdAt: new Date()
        };
        await db.collection('support_replies').insertOne(reply);
        // Update ticket timestamp
        await db.collection('support_tickets').updateOne(
            { _id: new ObjectId(req.params.id) },
            { $set: { updatedAt: new Date() } }
        );
        res.json({ id: reply._id.toString(), content: htmlEncode(contentResult.value) });
    } catch (e) {
        res.status(500).json({ error: 'ERR_REPLY_CREATE' });
    }
});

// GET /support/api/tickets/:id/replies — list replies (pagination)
app.get('/support/api/tickets/:id/replies', jwtMiddleware, async (req, res) => {
    try {
        if (!ObjectId.isValid(req.params.id)) return res.status(400).json({ error: 'ERR_INVALID_TICKET_ID' });
        // Verify ticket ownership first
        const ticket = await db.collection('support_tickets').findOne({ _id: new ObjectId(req.params.id) });
        if (!ticket) return res.status(404).json({ error: 'ERR_TICKET_NOT_FOUND' });
        if (ticket.userId !== req.user.userId) return res.status(403).json({ error: 'ERR_NOT_YOUR_TICKET' });
        const { page, limit, skip } = parsePagination(req.query);
        const replies = await db.collection('support_replies')
            .find({ ticketId: req.params.id })
            .project({ content: 1, createdAt: 1 })
            .sort({ createdAt: 1 })
            .skip(skip).limit(limit).toArray();
        const total = await db.collection('support_replies').countDocuments({ ticketId: req.params.id });
        const safe = replies.map(r => ({
            id: r._id.toString(), content: htmlEncode(r.content), createdAt: r.createdAt
        }));
        res.json({ replies: safe, page, limit, total });
    } catch (e) {
        res.status(500).json({ error: 'ERR_REPLIES_FETCH' });
    }
});

// PUT /support/api/tickets/:id/close — close ticket (only own ticket)
app.put('/support/api/tickets/:id/close', jwtMiddleware, async (req, res) => {
    try {
        if (!ObjectId.isValid(req.params.id)) return res.status(400).json({ error: 'ERR_INVALID_TICKET_ID' });
        // M-006: atomic update with ownership check
        const result = await db.collection('support_tickets').updateOne(
            { _id: new ObjectId(req.params.id), userId: req.user.userId, status: { $ne: 'closed' } },
            { $set: { status: 'closed', closedAt: new Date(), updatedAt: new Date() } }
        );
        if (result.matchedCount === 0) {
            const ticket = await db.collection('support_tickets').findOne({ _id: new ObjectId(req.params.id) });
            if (!ticket) return res.status(404).json({ error: 'ERR_TICKET_NOT_FOUND' });
            if (ticket.userId !== req.user.userId) return res.status(403).json({ error: 'ERR_NOT_YOUR_TICKET' });
            if (ticket.status === 'closed') return res.status(400).json({ error: 'ERR_TICKET_ALREADY_CLOSED' });
            return res.status(400).json({ error: 'ERR_TICKET_CLOSE_FAILED' });
        }
        await auditLog('TICKET_CLOSE', req.user.userId, { ticketId: req.params.id });
        res.json({ ticketId: req.params.id, status: 'closed' });
    } catch (e) {
        res.status(500).json({ error: 'ERR_TICKET_CLOSE' });
    }
});

// GET /support/api/faq — FAQ list (static, no sensitive data)
app.get('/support/api/faq', (req, res) => {
    // Static FAQ data — no database access, no user data
    const faq = [
        { id: 1, question: '如何修改密码?', answer: '前往账户设置页面修改密码。' },
        { id: 2, question: '退款政策是什么?', answer: '订单创建后24小时内可申请退款。' },
        { id: 3, question: '如何联系客服?', answer: '通过本页面的工单系统提交问题。' },
        { id: 4, question: '配送需要多长时间?', answer: '通常3-5个工作日内送达。' },
        { id: 5, question: '支持哪些支付方式?', answer: '支持支付宝、微信支付和银行卡。' }
    ];
    res.json({ faq });
});

// GET /support/api/categories — ticket categories
app.get('/support/api/categories', (req, res) => {
    // Whitelist categories — static, no database access needed
    res.json({ categories: [
        { id: 'account', name: '账户问题' },
        { id: 'payment', name: '支付问题' },
        { id: 'delivery', name: '配送问题' },
        { id: 'product', name: '商品问题' },
        { id: 'technical', name: '技术问题' },
        { id: 'other', name: '其他问题' }
    ]});
});

// POST /support/api/tickets/:id/attach — upload attachment (whitelist png/jpeg, 5MB, path outside web root)
app.post('/support/api/tickets/:id/attach', jwtMiddleware, async (req, res) => {
    try {
        if (!ObjectId.isValid(req.params.id)) return res.status(400).json({ error: 'ERR_INVALID_TICKET_ID' });
        // Verify ticket ownership
        const ticket = await db.collection('support_tickets').findOne({ _id: new ObjectId(req.params.id) });
        if (!ticket) return res.status(404).json({ error: 'ERR_TICKET_NOT_FOUND' });
        if (ticket.userId !== req.user.userId) return res.status(403).json({ error: 'ERR_NOT_YOUR_TICKET' });
        // P-001: Only allow image/png and image/jpeg, max 5MB
        const contentType = req.headers['content-type'] || '';
        if (!contentType.startsWith('multipart/form-data')) {
            return res.status(400).json({ error: 'ERR_MUST_USE_MULTIPART' });
        }
        // For this simplified endpoint, we handle base64-encoded file data in body
        const { file_data, file_type, file_name } = req.body;
        // P-001: whitelist file types
        const allowedTypes = ['image/png', 'image/jpeg'];
        if (!allowedTypes.includes(file_type)) {
            return res.status(400).json({ error: 'ERR_FILE_TYPE_NOT_ALLOWED', allowedTypes });
        }
        // P-001: max 5MB
        const fileSize = Buffer.byteLength(file_data, 'base64');
        if (fileSize > 5 * 1024 * 1024) {
            return res.status(400).json({ error: 'ERR_FILE_TOO_LARGE', maxSize: '5MB' });
        }
        // Validate file_name
        const nameResult = validateString(file_name, 'file_name', 100, /^[a-zA-Z0-9_\-. ]+$/);
        if (!nameResult.ok) return res.status(400).json({ error: nameResult.error });
        // P-001: store outside web root, use random path component to prevent traversal
        const safeName = crypto.randomBytes(8).toString('hex') + '_' + nameResult.value.replace(/[/.\\]/g, '_');
        const uploadDir = path.join(__dirname, '..', 'uploads', 'support'); // outside web root
        // Ensure upload directory exists
        if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
        const filePath = path.join(uploadDir, safeName);
        // D-004: verify resolved path is within uploadDir (path traversal protection)
        const resolved = path.resolve(filePath);
        if (!resolved.startsWith(path.resolve(uploadDir))) {
            return res.status(400).json({ error: 'ERR_PATH_INVALID' });
        }
        fs.writeFileSync(resolved, Buffer.from(file_data, 'base64'));
        // Store attachment reference in DB (not the URL to access it directly — P-001)
        const attachment = {
            ticketId: req.params.id, userId: req.user.userId,
            fileName: nameResult.value, fileType: file_type,
            fileSize, storedPath: safeName, createdAt: new Date()
        };
        await db.collection('support_attachments').insertOne(attachment);
        await auditLog('TICKET_ATTACH', req.user.userId, { ticketId: req.params.id, fileName: nameResult.value });
        res.json({ id: attachment._id.toString(), fileName: nameResult.value, fileType: file_type });
    } catch (e) {
        res.status(500).json({ error: 'ERR_ATTACHMENT_UPLOAD' });
    }
});

app.use((err, req, res, next) => {
    if (process.env.DEBUG === 'true') {
        return res.status(500).json({ error: err.message, stack: err.stack,
                                     query: req.query, body: req.body });
    }
    res.status(500).json({ error: 'Internal server error' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => console.log(`Modern app on port ${PORT}`));
