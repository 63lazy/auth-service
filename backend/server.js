const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = 3000;

app.use(cors());
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true }));

const db = new Database('./auth.db');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    email TEXT,
    phone TEXT,
    verification_code TEXT,
    verification_code_expiry INTEGER,
    public_key TEXT,
    certificate TEXT,
    created_at INTEGER DEFAULT (strftime('%s', 'now'))
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS login_sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    random_r TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )
`);

function generateSalt(length = 16) {
  return crypto.randomBytes(length).toString('hex');
}

function hashPassword(password, salt) {
  return crypto.createHash('sha256').update(password + salt).digest('hex');
}

function generateVerificationCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

const emailTransporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER || 'test@example.com',
    pass: process.env.EMAIL_PASS || 'testpass'
  }
});

async function sendVerificationEmail(email, code) {
  try {
    await emailTransporter.sendMail({
      from: process.env.EMAIL_USER || 'test@example.com',
      to: email,
      subject: '验证码',
      text: `您的验证码是：${code}`
    });
    console.log(`验证码已发送到 ${email}`);
    return true;
  } catch (error) {
    console.log('模拟发送邮件:', email, code);
    return true;
  }
}

app.post('/api/register', (req, res) => {
  try {
    const { username, password, email, phone, certificate } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ success: false, message: '用户名和密码必填' });
    }

    const existingUser = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
    if (existingUser) {
      return res.status(400).json({ success: false, message: '用户名已存在' });
    }

    const userId = uuidv4();
    const salt = generateSalt(16);
    const passwordHash = hashPassword(password, salt);

    const stmt = db.prepare(`
      INSERT INTO users (id, username, password_hash, salt, email, phone, certificate)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(userId, username, passwordHash, salt, email || null, phone || null, certificate || null);

    res.json({ success: true, message: '注册成功', userId });
  } catch (error) {
    console.error('注册错误:', error);
    res.status(500).json({ success: false, message: '注册失败' });
  }
});

app.post('/api/login/password', (req, res) => {
  try {
    const { username, password } = req.body;
    
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    if (!user) {
      return res.status(400).json({ success: false, message: '用户不存在' });
    }

    const passwordHash = hashPassword(password, user.salt);
    if (passwordHash !== user.password_hash) {
      return res.status(400).json({ success: false, message: '密码错误' });
    }

    res.json({ success: true, message: '登录成功', user: { id: user.id, username: user.username } });
  } catch (error) {
    console.error('密码登录错误:', error);
    res.status(500).json({ success: false, message: '登录失败' });
  }
});

app.post('/api/login/verification-code/request', (req, res) => {
  try {
    const { username, contact } = req.body;
    
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    if (!user) {
      return res.status(400).json({ success: false, message: '用户不存在' });
    }

    const code = generateVerificationCode();
    const expiry = Date.now() + 5 * 60 * 1000;

    db.prepare(`
      UPDATE users 
      SET verification_code = ?, verification_code_expiry = ?
      WHERE username = ?
    `).run(code, expiry, username);

    if (contact.includes('@')) {
      sendVerificationEmail(contact, code);
    } else {
      console.log('模拟发送短信到:', contact, '验证码:', code);
    }

    res.json({ success: true, message: '验证码已发送' });
  } catch (error) {
    console.error('请求验证码错误:', error);
    res.status(500).json({ success: false, message: '发送失败' });
  }
});

app.post('/api/login/verification-code/verify', (req, res) => {
  try {
    const { username, code } = req.body;
    
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    if (!user) {
      return res.status(400).json({ success: false, message: '用户不存在' });
    }

    if (!user.verification_code || user.verification_code !== code) {
      return res.status(400).json({ success: false, message: '验证码错误' });
    }

    if (Date.now() > user.verification_code_expiry) {
      return res.status(400).json({ success: false, message: '验证码已过期' });
    }

    db.prepare(`
      UPDATE users 
      SET verification_code = NULL, verification_code_expiry = NULL
      WHERE username = ?
    `).run(username);

    res.json({ success: true, message: '验证成功', user: { id: user.id, username: user.username } });
  } catch (error) {
    console.error('验证验证码错误:', error);
    res.status(500).json({ success: false, message: '验证失败' });
  }
});

app.post('/api/login/signature/init', (req, res) => {
  try {
    const { username } = req.body;
    
    console.log('=== Signature Init Debug ===');
    console.log('username:', username);
    
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    if (!user) {
      return res.status(400).json({ success: false, message: '用户不存在' });
    }

    if (!user.certificate) {
      return res.status(400).json({ success: false, message: '用户未注册证书' });
    }

    const sessionId = uuidv4();
    const randomR = crypto.randomBytes(16).toString('hex');
    const timestamp = Date.now();
    const expiresAt = timestamp + 5 * 60 * 1000;

    db.prepare(`
      INSERT INTO login_sessions (id, user_id, random_r, timestamp, expires_at)
      VALUES (?, ?, ?, ?, ?)
    `).run(sessionId, user.id, randomR, timestamp, expiresAt);

    console.log('randomR (stored):', randomR);
    console.log('timestamp (stored):', timestamp, typeof timestamp);

    res.json({ 
      success: true, 
      sessionId, 
      randomR, 
      timestamp,
      message: '请签名后返回'
    });
  } catch (error) {
    console.error('签名初始化错误:', error);
    res.status(500).json({ success: false, message: '初始化失败' });
  }
});

app.post('/api/login/signature/verify', (req, res) => {
  try {
    const { sessionId, signature, timestamp } = req.body;
    
    console.log('=== Signature Verify Debug ===');
    console.log('sessionId:', sessionId);
    console.log('signature (first 40):', signature ? signature.substring(0, 40) : 'undefined');
    console.log('timestamp:', timestamp, typeof timestamp);
    
    const session = db.prepare('SELECT * FROM login_sessions WHERE id = ?').get(sessionId);
    if (!session) {
      return res.status(400).json({ success: false, message: '会话不存在' });
    }

    if (Date.now() > session.expires_at) {
      db.prepare('DELETE FROM login_sessions WHERE id = ?').run(sessionId);
      return res.status(400).json({ success: false, message: '会话已过期' });
    }

    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(session.user_id);
    if (!user || !user.certificate) {
      return res.status(400).json({ success: false, message: '用户证书不存在' });
    }

    const messageToVerify = session.random_r + timestamp.toString();
    
    console.log('randomR:', session.random_r, typeof session.random_r);
    console.log('messageToVerify:', messageToVerify);
    
    try {
      let certData;
      try {
        certData = JSON.parse(user.certificate);
      } catch (e) {
        return res.status(400).json({ success: false, message: '证书格式错误' });
      }
      
      const publicKeyPem = `-----BEGIN PUBLIC KEY-----\n${Buffer.from(certData.publicKey, 'hex').toString('base64')}\n-----END PUBLIC KEY-----`;
      
      const verify = crypto.createVerify('SHA256');
      verify.update(messageToVerify);
      verify.end();
      
      const isValid = verify.verify({
        key: publicKeyPem,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
      }, signature, 'hex');
      
      console.log('Signature valid:', isValid);
      
      if (isValid) {
        db.prepare('DELETE FROM login_sessions WHERE id = ?').run(sessionId);
        res.json({ success: true, message: '签名验证成功', user: { id: user.id, username: user.username } });
      } else {
        res.status(400).json({ success: false, message: '签名验证失败' });
      }
    } catch (verifyError) {
      console.error('验证签名错误:', verifyError);
      res.status(400).json({ success: false, message: '签名验证失败' });
    }
  } catch (error) {
    console.error('签名验证错误:', error);
    res.status(500).json({ success: false, message: '验证失败' });
  }
});

app.get('/api/user/:username', (req, res) => {
  try {
    const { username } = req.params;
    const user = db.prepare('SELECT id, username, email, phone, certificate FROM users WHERE username = ?').get(username);
    
    if (!user) {
      return res.status(404).json({ success: false, message: '用户不存在' });
    }

    res.json({ success: true, user });
  } catch (error) {
    console.error('获取用户信息错误:', error);
    res.status(500).json({ success: false, message: '获取失败' });
  }
});

app.listen(PORT, () => {
  console.log(`服务器运行在 http://localhost:${PORT}`);
});
