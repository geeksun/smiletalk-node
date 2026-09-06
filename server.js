const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'secret';

const uploadDir = path.join(__dirname, 'public/uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadDir),
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname);
        cb(null, Date.now() + '-' + Math.round(Math.random() * 1E9) + ext);
    }
});
const upload = multer({
    storage,
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) cb(null, true);
        else cb(new Error('只允许上传图片文件'));
    }
});

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const db = new sqlite3.Database('./db.sqlite', (err) => {
    if (err) console.error('数据库连接失败:', err.message);
    else console.log('SQLite 数据库已连接.');
});

// 初始化数据库表
db.serialize(() => {
    // 1. 用户表
    db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT,
      display_name TEXT
    )
  `);

    // 2. 微博表
    db.run(`
    CREATE TABLE IF NOT EXISTS tweets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      content TEXT,
      image_url TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id)
    )
  `);

    // 3. 关注关系表 (关注者, 被关注者)
    db.run(`
    CREATE TABLE IF NOT EXISTS follows (
      follower_id INTEGER,
      following_id INTEGER,
      PRIMARY KEY (follower_id, following_id),
      FOREIGN KEY(follower_id) REFERENCES users(id),
      FOREIGN KEY(following_id) REFERENCES users(id)
    )
  `);

    // 创建默认管理员
    const adminUser = process.env.ADMIN_USER || 'admin';
    const adminPass = process.env.ADMIN_PASS || 'admin123';
    const adminName = process.env.ADMIN_NAME || '管理员';

    db.get('SELECT * FROM users WHERE username = ?', [adminUser], (err, row) => {
        if (!row) {
            const hash = bcrypt.hashSync(adminPass, 10);
            db.run('INSERT INTO users (username, password, display_name) VALUES (?, ?, ?)',
                [adminUser, hash, adminName]
            );
        }
    });
});

// JWT 校验中间件
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: '请先登录' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: '登录身份已过期，请重新登录' });
        req.user = user;
        next();
    });
}

/* ================= API 路由 ================= */

// 登录 API
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
        if (err || !user) return res.status(400).json({ error: '用户名或密码错误' });

        if (bcrypt.compareSync(password, user.password)) {
            const token = jwt.sign(
                { id: user.id, username: user.username, name: user.display_name },
                JWT_SECRET,
                { expiresIn: '30d' }
            );
            res.json({ token, user: { id: user.id, username: user.username, name: user.display_name } });
        } else {
            res.status(400).json({ error: '用户名或密码错误' });
        }
    });
});

// 获取当前用户信息
app.get('/api/me', authenticateToken, (req, res) => {
    res.json({ user: req.user });
});

// 获取时间线推文 (核心修改：必须登录，且仅看自己 + 关注的人)
app.get('/api/tweets', authenticateToken, (req, res) => {
    const userId = req.user.id;
    const sql = `
    SELECT tweets.*, users.display_name, users.username 
    FROM tweets 
    JOIN users ON tweets.user_id = users.id 
    WHERE tweets.user_id = ? 
       OR tweets.user_id IN (SELECT following_id FROM follows WHERE follower_id = ?)
    ORDER BY tweets.created_at DESC 
    LIMIT 100
  `;
    db.all(sql, [userId, userId], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// 发布微博 (需要登录)
app.post('/api/tweets', authenticateToken, upload.single('image'), (req, res) => {
    const { content } = req.body;
    const imageUrl = req.file ? `/uploads/${req.file.filename}` : null;

    if (!content && !imageUrl) {
        return res.status(400).json({ error: '内容或图片不能为空' });
    }

    db.run(
        'INSERT INTO tweets (user_id, content, image_url) VALUES (?, ?, ?)',
        [req.user.id, content || '', imageUrl],
        function (err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ id: this.lastID, success: true });
        }
    );
});

// 删除微博
app.delete('/api/tweets/:id', authenticateToken, (req, res) => {
    const tweetId = req.params.id;
    db.get('SELECT * FROM tweets WHERE id = ?', [tweetId], (err, tweet) => {
        if (err || !tweet) return res.status(404).json({ error: '微博不存在' });
        if (tweet.user_id !== req.user.id) return res.status(403).json({ error: '无权删除此条动态' });

        if (tweet.image_url) {
            const filePath = path.join(__dirname, 'public', tweet.image_url);
            if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
        }

        db.run('DELETE FROM tweets WHERE id = ?', [tweetId], (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true });
        });
    });
});

// 获取所有用户及关注状态 (供在边栏展现和关注/取消关注)
app.get('/api/users', authenticateToken, (req, res) => {
    const currentUserId = req.user.id;
    const sql = `
    SELECT u.id, u.username, u.display_name,
      EXISTS(SELECT 1 FROM follows WHERE follower_id = ? AND following_id = u.id) AS is_following
    FROM users u
    WHERE u.id != ?
  `;
    db.all(sql, [currentUserId, currentUserId], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// 关注/取消关注 切换接口
app.post('/api/follow/:targetId', authenticateToken, (req, res) => {
    const followerId = req.user.id;
    const targetId = parseInt(req.params.targetId);

    if (followerId === targetId) return res.status(400).json({ error: '不能关注自己' });

    db.get('SELECT 1 FROM follows WHERE follower_id = ? AND following_id = ?', [followerId, targetId], (err, row) => {
        if (row) {
            // 已关注 -> 取消关注
            db.run('DELETE FROM follows WHERE follower_id = ? AND following_id = ?', [followerId, targetId], () => {
                res.json({ is_following: false });
            });
        } else {
            // 未关注 -> 关注
            db.run('INSERT INTO follows (follower_id, following_id) VALUES (?, ?)', [followerId, targetId], () => {
                res.json({ is_following: true });
            });
        }
    });
});

app.listen(PORT, () => {
    console.log(`极简私密微博服务已运行在: http://localhost:${PORT}`);
});
