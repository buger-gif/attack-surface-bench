// SECURITY-REVIEWED: 2026-07-09 | RULES: v2.6.0-draft
// modern-app: Express + JWT + MongoDB + GraphQL + SSRF benchmark service

const express = require('express');
const jwt = require('jsonwebtoken');
const { MongoClient, ObjectId } = require('mongodb');
const axios = require('axios');
const { graphqlHTTP } = require('express-graphql');
const { buildSchema } = require('graphql');
const app = express();

app.use(express.json());

// M9: CORS过宽（允许任意来源+携带凭证）
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Credentials', 'true');
    next();
});

const JWT_SECRET = process.env.JWT_SECRET || 'dev-jwt-secret-change';
const MONGO_URL = process.env.MONGO_URL || 'mongodb://mongodb:27017/modern_app';
let db;

MongoClient.connect(MONGO_URL).then(client => {
    db = client.db();
    console.log('MongoDB connected');
}).catch(err => console.error('MongoDB error:', err));

// 首页 — API文档+前端痕迹
app.get('/', (req, res) => {
    res.json({
        name: 'Modern API Server',
        version: '2.0.0',
        env: 'development',
        docs: '/api/docs',
        hint: 'Set ?debug=1 or ?trace=1 for troubleshooting'
    });
});

// API文档 — 含隐藏端点标注
app.get('/api/docs', (req, res) => {
    res.json({
        endpoints: [
            { path: '/api/auth/login', method: 'POST', auth: false },
            { path: '/api/auth/register', method: 'POST', auth: false },
            { path: '/api/users', method: 'GET', auth: 'Bearer' },
            { path: '/api/users/:id', method: 'GET', auth: 'Bearer' },
            { path: '/api/users/:id', method: 'PUT', auth: 'Bearer', note: 'Vulnerable to mass assignment' },
            { path: '/api/orders', method: 'POST', auth: 'Bearer', note: 'Price modifiable' },
            { path: '/api/products', method: 'GET', auth: false },
            { path: '/api/fetch', method: 'GET', auth: false, note: 'Internal use only' },
            { path: '/api/redirect', method: 'GET', auth: false },
            { path: '/api/internal/config', method: 'GET', auth: false, note: 'DEPRECATED' },
            { path: '/api/internal/db-status', method: 'GET', auth: false, note: 'DEPRECATED' },
            { path: '/graphql', method: 'POST', auth: false, note: 'Introspection enabled' }
        ]
    });
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
            res.json({ token: newToken, note: 'emergency refresh' });
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
        if (debug === '1') return res.json({ users, query_executed: query, flag: 'NOSQL_INJECTION_DEBUG' });
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
            return res.json({ modified: 1, prototype_polluted: true, isAdmin_now: Object.prototype.isAdmin,
                           flag: 'PROTOTYPE_POLLUTION_SUCCESS' });
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
        res.json({ token, role: userDoc.role || 'user',
                  flag: role === 'admin' ? 'MASS_ASSIGNMENT_ADMIN' : null });
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
        res.status(500).json({ error: e.message, requested_url: url,
                              hint: 'Try file:///etc/passwd or http://172.20.0.11:5000/internal/health' });
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

app.use((err, req, res, next) => {
    if (process.env.DEBUG === 'true') {
        return res.status(500).json({ error: err.message, stack: err.stack,
                                     query: req.query, body: req.body });
    }
    res.status(500).json({ error: 'Internal server error' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => console.log(`Modern app on port ${PORT}`));
