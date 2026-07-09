// SECURITY-REVIEWED: 2026-07-09 | RULES: v2.6.0-draft
// MongoDB seeding script for modern-app

const { MongoClient } = require('mongodb');
const MONGO_URL = process.env.MONGO_URL || 'mongodb://mongodb:27017/modern_app';
async function seed() {
    const client = await MongoClient.connect(MONGO_URL);
    const db = client.db();
    await db.collection('users').deleteMany({});
    await db.collection('users').insertMany([
        { username: 'admin', password: 'admin123', email: 'admin@target.com', role: 'admin',
          balance: 999999, phone: '13800138000', id_card: '110101199001011234', api_key: 'ak_live_abc123def456' },
        { username: 'zhangsan', password: 'zs123456', email: 'zhangsan@target.com', role: 'user', balance: 10000 },
        { username: 'lisi', password: 'ls123456', email: 'lisi@target.com', role: 'user', balance: 5000 }
    ]);
    await db.collection('products').deleteMany({});
    await db.collection('products').insertMany([
        { name: 'MacBook Pro', price: 19999 }, { name: 'iPhone 15', price: 8999 }, { name: 'AirPods Pro', price: 1999 }
    ]);
    await db.collection('orders').deleteMany({});
    console.log('Database seeded'); client.close();
}
seed().catch(console.error);
