// SECURITY-REVIEWED: 2026-07-14 | RULES: v2.6.0-draft
// MongoDB seeding script for modern-app

const { MongoClient } = require('mongodb');
const MONGO_URL = process.env.MONGO_URL || 'mongodb://mongodb:27017/modern_app';
async function seed() {
    const client = await MongoClient.connect(MONGO_URL);
    const db = client.db();
    await db.collection('users').deleteMany({});
    await db.collection('users').insertMany([
        { username: 'admin', password: 'admin123', email: 'admin@target.bench', role: 'admin',
          balance: 999999, phone: '13800138000', id_card: '110101199001011234', api_key: 'ak_live_abc123def456' },
        { username: 'zhangsan', password: 'zs123456', email: 'zhangsan@target.bench', role: 'user', balance: 10000 },
        { username: 'lisi', password: 'ls123456', email: 'lisi@target.bench', role: 'user', balance: 5000 }
    ]);
    await db.collection('products').deleteMany({});
    await db.collection('products').insertMany([
        { name: 'MacBook Pro 16英寸', price: 19999, category: '数码', rating: 4.8,
          description: 'Apple M3 Pro芯片，18GB统一内存，512GB固态硬盘，Liquid Retina XDR显示屏',
          originalPrice: 22999, reviews: [
            { user: '张先生', date: '2026-06-20', rating: 5, text: '性能强劲，屏幕惊艳，开发者必备' },
            { user: '李女士', date: '2026-06-18', rating: 4, text: '整体不错，续航比上一代好很多' }
          ] },
        { name: 'iPhone 15 Pro Max', price: 9999, category: '数码', rating: 4.7,
          description: 'A17 Pro芯片，钛金属边框，4800万像素主摄，256GB存储',
          originalPrice: 11999, reviews: [
            { user: '王同学', date: '2026-06-15', rating: 5, text: '拍照效果一流，钛金属手感好' },
            { user: '赵先生', date: '2026-06-10', rating: 4, text: '性能提升明显，价格略高' }
          ] },
        { name: 'AirPods Pro 2代', price: 1899, category: '数码', rating: 4.6,
          description: '自适应降噪，个性化空间音频，MagSafe充电盒，USB-C接口',
          originalPrice: 2199, reviews: [
            { user: '陈先生', date: '2026-06-22', rating: 5, text: '降噪效果比1代强很多，佩戴舒适' }
          ] },
        { name: '戴森V15吸尘器', price: 4990, category: '家电', rating: 4.5,
          description: '激光探测微尘，整机HEPA过滤，60分钟续航，智能吸力调节',
          originalPrice: 5490, reviews: [
            { user: '刘女士', date: '2026-06-08', rating: 4, text: '吸力强劲，激光功能很实用' },
            { user: '孙先生', date: '2026-06-05', rating: 5, text: '家里有宠物必备，清理效果极佳' }
          ] },
        { name: '索尼WH-1000XM5耳机', price: 2499, category: '数码', rating: 4.7,
          description: '行业领先降噪，30小时续航，多点连接，轻量舒适设计',
          originalPrice: 2999, reviews: [
            { user: '周先生', date: '2026-06-12', rating: 5, text: '降噪之王，通勤必备' }
          ] },
        { name: '华为MatePad Pro', price: 3499, category: '数码', rating: 4.4,
          description: '12.6英寸OLED屏，鸿蒙系统，M-Pencil手写笔，8GB+256GB',
          originalPrice: 3999, reviews: [
            { user: '吴女士', date: '2026-06-19', rating: 4, text: '屏幕效果好，手写笔很流畅' },
            { user: '郑同学', date: '2026-06-16', rating: 5, text: '记笔记神器，鸿蒙生态完善' }
          ] },
        { name: '小米净水器H800G', price: 1999, category: '家电', rating: 4.3,
          description: '800G大通量，5级深度过滤，智能TDS检测，无桶设计',
          originalPrice: 2499, reviews: [
            { user: '黄女士', date: '2026-06-09', rating: 4, text: '出水快，过滤效果好，安装方便' }
          ] },
        { name: '优衣库轻羽绒服', price: 499, category: '服饰', rating: 4.2,
          description: '轻量保暖，90%白鸭绒填充，便携折叠设计，多色可选',
          originalPrice: 799, reviews: [
            { user: '林女士', date: '2026-06-21', rating: 4, text: '很轻很暖，冬天必备' },
            { user: '许先生', date: '2026-06-14', rating: 3, text: '款式简约，性价比高' }
          ] }
    ]);
    await db.collection('orders').deleteMany({});
    await db.collection('cart').deleteMany({});
    // --- Safe endpoint seed data ---
    // Shop products (separate collection from vulnerable /api/products)
    await db.collection('shop_products').deleteMany({});
    await db.collection('shop_products').insertMany([
        { name: '无线降噪耳机', category: '数码配件', price: 299, rating: 4.5, stock: 120,
          description: '高品质主动降噪，40小时续航', image: '/images/headphones.jpg',
          specs: { brand: 'SoundMax', weight: '250g', connectivity: '蓝牙5.2' }, createdAt: new Date() },
        { name: '智能手表Pro', category: '智能穿戴', price: 1599, rating: 4.8, stock: 50,
          description: '心率监测、GPS定位、50米防水', image: '/images/watch.jpg',
          specs: { brand: 'TechFit', display: '1.4英寸AMOLED', battery: '7天' }, createdAt: new Date() },
        { name: '便携蓝牙音箱', category: '数码配件', price: 199, rating: 4.2, stock: 200,
          description: 'IPX7防水，12小时续航', image: '/images/speaker.jpg',
          specs: { brand: 'BoomBox', power: '20W', weight: '580g' }, createdAt: new Date() },
        { name: '机械键盘RGB', category: '电脑外设', price: 499, rating: 4.6, stock: 80,
          description: '热插拔轴体，全键无冲，RGB背光', image: '/images/keyboard.jpg',
          specs: { brand: 'KeyCraft', switches: 'Cherry MX', layout: '87键' }, createdAt: new Date() },
        { name: '电竞鼠标', category: '电脑外设', price: 349, rating: 4.7, stock: 150,
          description: '26000DPI，67g超轻设计', image: '/images/mouse.jpg',
          specs: { brand: 'AimSharp', sensor: 'PAW3950', buttons: '6' }, createdAt: new Date() },
        { name: '4K显示器', category: '电脑设备', price: 3299, rating: 4.4, stock: 30,
          description: '27英寸4K IPS，HDR400', image: '/images/monitor.jpg',
          specs: { brand: 'ViewPro', resolution: '3840x2160', refreshRate: '60Hz' }, createdAt: new Date() },
        { name: '移动电源20000mAh', category: '数码配件', price: 149, rating: 4.3, stock: 300,
          description: '65W快充，三口输出', image: '/images/charger.jpg',
          specs: { brand: 'PowerMax', capacity: '20000mAh', output: '65W USB-C' }, createdAt: new Date() },
        { name: '运动背包', category: '生活用品', price: 89, rating: 4.1, stock: 500,
          description: '防水面料，多隔层设计', image: '/images/bag.jpg',
          specs: { brand: 'TrailPack', material: '尼龙', capacity: '35L' }, createdAt: new Date() }
    ]);
    // Community posts
    await db.collection('community_posts').deleteMany({});
    await db.collection('community_posts').insertMany([
        { authorId: 'seed_user_1', authorName: '数码达人', title: '2026年最佳降噪耳机推荐',
          content: '<p>经过三个月的测试，我整理了今年最好的降噪耳机清单。</p><p><b>重点推荐</b>：SoundMax无线降噪耳机，40小时续航非常给力。</p>',
          contentPreview: '经过三个月的测试，我整理了今年最好的降噪耳机清单。',
          tags: ['数码', '耳机', '评测'], commentCount: 3, createdAt: new Date() },
        { authorId: 'seed_user_2', authorName: '编程爱好者', title: 'Node.js性能优化实战经验',
          content: '<p>分享几个在大型项目中用到的Node.js性能优化技巧。</p><p><b>1. 异步处理</b>：所有数据库操作都使用async/await。</p>',
          contentPreview: '分享几个在大型项目中用到的Node.js性能优化技巧。',
          tags: ['编程', 'Node.js', '性能'], commentCount: 5, createdAt: new Date() },
        { authorId: 'seed_user_3', authorName: '健身教练', title: '居家健身入门指南',
          content: '<p>不需要器械也能练出好身材！以下是我的居家健身计划。</p>',
          contentPreview: '不需要器械也能练出好身材！以下是我的居家健身计划。',
          tags: ['健身', '生活', '入门'], commentCount: 2, createdAt: new Date() },
        { authorId: 'seed_user_4', authorName: '美食博主', title: '一周健康食谱分享',
          content: '<p>这是我一周的健康饮食安排，每天不重复，营养均衡。</p>',
          contentPreview: '这是我一周的健康饮食安排，每天不重复，营养均衡。',
          tags: ['美食', '健康', '食谱'], commentCount: 8, createdAt: new Date() }
    ]);
    // Community comments
    await db.collection('community_comments').deleteMany({});
    await db.collection('community_comments').insertMany([
        { postId: 'seed', authorId: 'seed_user_5', authorName: '路人甲', content: '不错的推荐，已下单！', createdAt: new Date() },
        { postId: 'seed', authorId: 'seed_user_6', authorName: '技术宅', content: '补充一下，还可以用cluster模式提升吞吐量。', createdAt: new Date() },
        { postId: 'seed', authorId: 'seed_user_7', authorName: '新手小白', content: '请问初学者应该从哪个耳机开始？', createdAt: new Date() }
    ]);
    // Support tickets
    await db.collection('support_tickets').deleteMany({});
    await db.collection('support_tickets').insertMany([
        { userId: 'seed_user_1', subject: '耳机发货延迟', category: 'delivery', priority: 'medium',
          description: '下单后超过7天仍未发货，请帮我查看物流状态。', status: 'open',
          createdAt: new Date(), updatedAt: new Date() },
        { userId: 'seed_user_2', subject: '退款申请', category: 'payment', priority: 'high',
          description: '商品与描述不符，申请退款处理。', status: 'open',
          createdAt: new Date(), updatedAt: new Date() }
    ]);
    // Support replies
    await db.collection('support_replies').deleteMany({});
    await db.collection('support_replies').insertMany([
        { ticketId: 'seed', userId: 'seed_user_1', content: '请问我的订单号是ORD-20260101，能帮忙查一下吗？', createdAt: new Date() }
    ]);
    // Shop reviews
    await db.collection('shop_reviews').deleteMany({});
    await db.collection('shop_reviews').insertMany([
        { productId: 'seed', userId: 'seed_user_1', rating: 5, content: '降噪效果非常好，续航超长！', createdAt: new Date() },
        { productId: 'seed', userId: 'seed_user_2', rating: 4, content: '音质不错，但佩戴稍重。', createdAt: new Date() }
    ]);
    // Ensure other safe endpoint collections exist
    await db.collection('shop_cart').deleteMany({});
    await db.collection('shop_orders').deleteMany({});
    await db.collection('audit_logs').deleteMany({});
    await db.collection('support_attachments').deleteMany({});
    console.log('Database seeded (including safe endpoint collections)'); client.close();
}
seed().catch(console.error);
