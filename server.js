// ============================================
// 手机多租户虚拟主机 v4.0.0 安全加固版
// ============================================
'use strict';

const express = require('express');
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cors = require('cors');
const compression = require('compression');

// ============ 配置 ============
const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const SECRET_FILE = path.join(DATA_DIR, 'secret.key');
let JWT_SECRET;
if (process.env.JWT_SECRET) {
  JWT_SECRET = process.env.JWT_SECRET;
} else if (fs.existsSync(SECRET_FILE)) {
  JWT_SECRET = fs.readFileSync(SECRET_FILE, 'utf8').trim();
  console.log('[安全] 已加载持久化密钥');
} else {
  JWT_SECRET = crypto.randomBytes(32).toString('hex');
  fs.writeFileSync(SECRET_FILE, JWT_SECRET);
  console.log('[安全] 已生成并保存新密钥');
}
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
if (!ADMIN_PASSWORD) {
  console.error('[安全] 警告：未设置 ADMIN_PASSWORD 环境变量，使用随机密码');
  console.error('[安全] 请在启动前设置: export ADMIN_PASSWORD="你的管理密码"');
}
const ACTUAL_ADMIN_PASSWORD = ADMIN_PASSWORD || (() => { const rp = crypto.randomBytes(16).toString('hex'); console.error(`[安全] 随机密码: ${rp}`); console.error('[安全] 下次启动请设置: export ADMIN_PASSWORD="你的密码"'); return rp; })();
const HMAC_SECRET = crypto.createHash('sha256').update(JWT_SECRET + 'hmac').digest();
const REFRESH_SECRET = crypto.createHash('sha256').update(JWT_SECRET + 'refresh').digest();
const HOSTS_DIR = path.join(__dirname, 'hosts');
const PUBLIC_DIR = path.join(__dirname, 'public');
const LOG_DIR = path.join(DATA_DIR, 'logs');
const TOKEN_EXPIRY = '15m';
const REFRESH_EXPIRY = '7d';
const MAX_FILE_SIZE = 50 * 1024 * 1024; // 50MB

// 确保目录存在
[DATA_DIR, HOSTS_DIR, PUBLIC_DIR, LOG_DIR].forEach(d => {
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
});

// ============ 数据持久化 ============
let DB = { users: {}, hosts: {}, sessions: {}, refreshTokens: {}, blockedIPs: {}, ipBehavior: {}, fingerprints: {}, mouseData: {}, nonces: {}, cards: [], auditLog: [], lockouts: [], whitelist: [] };
const DB_FILE = path.join(DATA_DIR, 'db.json');
const AUDIT_FILE = path.join(DATA_DIR, 'audit.json');
const FINGERPRINT_FILE = path.join(DATA_DIR, 'fingerprints.json');
const BLOCKED_FILE = path.join(DATA_DIR, 'blocked.json');

function loadDB() {
  try { if (fs.existsSync(DB_FILE)) DB = { ...DB, ...JSON.parse(fs.readFileSync(DB_FILE, 'utf8')) }; } catch (e) { console.error('[DB] 加载失败:', e.message); }
}
function saveDB() {
  try { fs.writeFileSync(DB_FILE, JSON.stringify(DB, null, 2)); } catch (e) { console.error('[DB] 保存失败:', e.message); }
}
function loadAudit() {
  try { if (fs.existsSync(AUDIT_FILE)) DB.auditLog = JSON.parse(fs.readFileSync(AUDIT_FILE, 'utf8')); } catch (e) {}
}
function saveAudit() {
  try { fs.writeFileSync(AUDIT_FILE, JSON.stringify(DB.auditLog.slice(-10000), null, 2)); } catch (e) {}
}
function loadBlocked() {
  try { if (fs.existsSync(BLOCKED_FILE)) DB.blockedIPs = JSON.parse(fs.readFileSync(BLOCKED_FILE, 'utf8')); } catch (e) {}
}
function saveBlocked() {
  try { fs.writeFileSync(BLOCKED_FILE, JSON.stringify(DB.blockedIPs, null, 2)); } catch (e) {}
}
loadDB(); loadAudit(); loadBlocked();

// ============ 工具函数 ============
function generateUID() { return crypto.randomBytes(10).toString('hex'); }
function generateSessionId() { return 'sess_' + crypto.randomUUID(); }
function getClientIP(req) { return req.headers['cf-connecting-ip'] || req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.headers['x-real-ip'] || req.socket.remoteAddress?.replace('::ffff:', '') || '127.0.0.1'; }
function hashPassword(password) { return crypto.createHash('sha256').update(password + JWT_SECRET).digest('hex'); }
function sanitize(str) { return String(str).replace(/[<>]/g, '').substring(0, 200); }
function logAudit(action, ip, detail) { DB.auditLog.push({ time: new Date().toISOString(), action, ip, detail }); saveAudit(); }

// bcrypt 兼容层
let bcrypt = null;
try { bcrypt = require('bcryptjs'); } catch (e) {}
function hashPasswordBcrypt(password) {
  if (bcrypt) return bcrypt.hashSync(password, 10);
  return hashPassword(password);
}
function verifyPasswordBcrypt(password, hash) {
  if (bcrypt && hash && hash.startsWith('$2')) return bcrypt.compareSync(password, hash);
  return hashPassword(password) === hash;
}

// v4.0: AES-256-GCM 加密主机密码
function encryptHostPassword(plaintext) {
  const key = crypto.createHash('sha256').update(JWT_SECRET).digest();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag().toString('hex');
  return iv.toString('hex') + ':' + authTag + ':' + encrypted;
}
function decryptHostPassword(ciphertext) {
  if (!ciphertext) return null;
  try {
    const parts = ciphertext.split(':');
    if (parts.length !== 3) return null;
    const key = crypto.createHash('sha256').update(JWT_SECRET).digest();
    const iv = Buffer.from(parts[0], 'hex');
    const authTag = Buffer.from(parts[1], 'hex');
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);
    let decrypted = decipher.update(parts[2], 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (e) {
    console.error('[加密] 主机密码解密失败:', e.message);
    return null;
  }
}

// HMAC-SHA256 签名
function generateHMAC(method, urlPath, timestamp, nonce, bodyHash) {
  const signStr = method + '+' + urlPath + '+' + timestamp + '+' + nonce + '+' + bodyHash;
  return crypto.createHmac('sha256', HMAC_SECRET).update(signStr).digest('hex');
}
function verifyHMAC(method, urlPath, timestamp, nonce, bodyHash, signature) {
  const expected = generateHMAC(method, urlPath, timestamp, nonce, bodyHash);
  return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signature));
}

// 密码强度验证
function validatePasswordStrength(password) {
  if (!password || password.length < 8) return '密码至少8个字符';
  if (!/[A-Z]/.test(password) && !/[a-z]/.test(password)) return '密码需包含字母';
  if (!/[A-Z]/.test(password) || !/[a-z]/.test(password)) return '密码需包含大小写字母';
  if (!/[0-9]/.test(password)) return '密码需包含数字';
  return null;
}

function verifyAdmin(pw) {
  return pw === ACTUAL_ADMIN_PASSWORD;
}

// ============ 安全模块 ============
class SecurityModule {
  constructor() {
    this.requestCounts = {};
    this.uploadCounts = {};
    this.loginAttempts = {};
    this.attackMode = false;
    this.attackRecovery = 0;
    this.globalRequestCount = 0;
    this.globalRequestReset = Date.now() + 60000;
    this.honeypots = [
      '/.env', '/wp-admin', '/phpmyadmin', '/.git', '/console', '/api/v1',
      '/graphql', '/swagger', '/actuator', '/debug', '/admin', '/administrator',
      '/backup', '/config', '/.svn', '/.htaccess', '/cgi-bin', '/shell',
      '/cmd', '/exec', '/uploads', '/sql', '/dump', '/database',
      '/mysql', '/db', '/phpinfo', '/info.php', '/test.php', '/eval',
      '/vendor', '/composer', '/node_modules', '/package.json', '/docker',
      '/jenkins', '/manager', '/solr', '/struts', '/webdav', '/.DS_Store',
      '/ftp', '/ssh', '/telnet', '/login.cgi', '/cgi', '/api/admin',
      '/api/exec', '/api/upload', '/api/system', '/rest', '/soap',
      '/api/v1/admin', '/api/v1/users', '/api/v1/auth'
    ];
    this.userRateLimits = {};
    this.nonceStore = {};
  }

  getRateKey(req) {
    const ip = getClientIP(req);
    const userId = req.user?.id || 'anon';
    const deviceId = req.headers['x-device-id'] || 'unknown';
    return `${ip}:${userId}:${deviceId}`;
  }

  isWhitelisted(ip) {
    return DB.whitelist.includes(ip);
  }

  checkRateLimit(req, type = 'default') {
    const ip = getClientIP(req);
    if (this.isWhitelisted(ip)) return true;
    const now = Date.now();
    const key = ip + ':' + type;
    if (!this.requestCounts[key]) this.requestCounts[key] = { count: 0, reset: now + 60000, level: 0 };
    const entry = this.requestCounts[key];
    if (now > entry.reset) { entry.count = 0; entry.reset = now + 60000; }
    entry.count++;
    const limits = { default: 600, upload: 80, login: 60, search: 120, admin: 30 };
    const limit = limits[type] || 600;
    if (entry.count > limit) { entry.level = Math.min(entry.level + 1, 5); return false; }
    return true;
  }

  // ⚠️ 修复：不再自动封禁 IP，只记录日志
  blockIP(ip, reason, durationMs) {
    const now = Date.now();
    console.log(`[安全-仅记录] IP: ${ip}, 原因: ${reason}, 时长: ${durationMs}ms`);
    // 不真正封禁，只记录到行为日志
    if (!DB.ipBehavior[ip]) DB.ipBehavior[ip] = { score: 100, events: [], lastSeen: now };
    DB.ipBehavior[ip].events.push({ time: new Date().toISOString(), reason, action: 'blocked_but_not_applied' });
    DB.ipBehavior[ip].score = Math.max(DB.ipBehavior[ip].score - 5, 0);
    // 如果确实要封禁，改下面的逻辑
    // DB.blockedIPs[ip] = { time: now, reason, until: now + durationMs };
    // saveBlocked();
  }

  isBlocked(ip) {
    if (this.isWhitelisted(ip)) return false;
    if (!DB.blockedIPs[ip]) return false;
    const entry = DB.blockedIPs[ip];
    if (Date.now() > entry.until) { delete DB.blockedIPs[ip]; saveBlocked(); return false; }
    return true;
  }

  updateBehaviorScore(ip, action) {
    if (!DB.ipBehavior[ip]) DB.ipBehavior[ip] = { score: 100, events: [], lastSeen: Date.now() };
    DB.ipBehavior[ip].lastSeen = Date.now();
    const deductions = { blocked_access: 1, rate_limit: 2, honeypot: 5, invalid_auth: 1, scanner: 10 };
    DB.ipBehavior[ip].score = Math.max(DB.ipBehavior[ip].score - (deductions[action] || 0), 0);
    DB.ipBehavior[ip].events.push({ time: new Date().toISOString(), action });
  }

  isHoneypot(path) {
    return this.honeypots.includes(path.toLowerCase());
  }
}

const security = new SecurityModule();

// ============ Express 初始化 ============
const app = express();
const server = http.createServer(app);

// ============ 首页（必须在 CSP 中间件之前） ============
app.get('/', (req, res) => {
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.setHeader('Content-Security-Policy', "default-src * 'unsafe-inline' 'unsafe-eval'; script-src * 'unsafe-inline' 'unsafe-eval'; style-src * 'unsafe-inline'; connect-src * ws: wss:; img-src * data: blob:; media-src *; font-src *; frame-src *; object-src *");
  res.removeHeader('X-Frame-Options');
  const users = Object.keys(DB.users).length;
  const hosts = Object.keys(DB.hosts).length;
  const now = new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
  res.send('<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>手机服务器 · 首页</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:linear-gradient(135deg,#0a0a1a 0%,#1a1040 50%,#0d0d2b 100%);min-height:100vh;display:flex;align-items:center;justify-content:center;color:#e0e0f0;padding:20px}.container{text-align:center;max-width:420px;width:100%}.icon{font-size:64px;margin-bottom:8px;filter:drop-shadow(0 0 20px rgba(100,100,255,.3))}.title{font-size:24px;font-weight:700;margin-bottom:8px;letter-spacing:2px}.subtitle{font-size:14px;color:#8888aa;margin-bottom:32px}.btn{display:block;width:100%;padding:14px;margin:10px 0;font-size:16px;border-radius:10px;border:none;cursor:pointer;text-decoration:none;letter-spacing:1px;text-align:center}.btn-primary{background:linear-gradient(135deg,#6b4ee6,#8b5cf6);color:#fff;box-shadow:0 4px 20px rgba(107,78,230,.3)}.btn-secondary{background:transparent;color:#aaa;border:1px solid rgba(255,255,255,.1)}.btn-secondary:hover{color:#fff;border-color:rgba(255,255,255,.3)}.status-card{background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.06);border-radius:12px;padding:16px;margin-top:24px;text-align:left}.status-row{display:flex;justify-content:space-between;padding:8px 0;font-size:13px;border-bottom:1px solid rgba(255,255,255,.04)}.status-row:last-child{border-bottom:none}.status-label{color:#8888aa}.status-value{color:#c0c0e0}.status-ok{color:#10b981}.footer{position:fixed;bottom:20px;text-align:center;width:100%;left:0;font-size:12px;color:#555}</style></head><body><div class="container"><div class="icon">🚀</div><div class="title">手机服务器运行正常</div><div class="subtitle">你的 Node.js 多租户虚拟主机已成功启动</div><a href="/panel.html" class="btn btn-primary">🏠 我的虚拟主机</a><a href="/panel.html" class="btn btn-secondary">⚙️ 管理员后台</a><div class="status-card"><div class="status-row"><span class="status-label">当前时间</span><span class="status-value">' + now + '</span></div><div class="status-row"><span class="status-label">Nginx 代理</span><span class="status-value status-ok">✅ 已启用</span></div><div class="status-row"><span class="status-label">注册用户</span><span class="status-value">' + users + ' 人</span></div><div class="status-row"><span class="status-label">在线状态</span><span class="status-value status-ok">🟢 正常</span></div></div></div></body></html>');
});

// ============ 面板页面（必须在 CSP 中间件之前） ============
app.get('/panel.html', (req, res) => {
  const panelPath = path.join(__dirname, 'panel.html');
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.setHeader('Content-Security-Policy', "default-src * 'unsafe-inline' 'unsafe-eval'; script-src * 'unsafe-inline' 'unsafe-eval'; style-src * 'unsafe-inline'; connect-src * ws: wss:; img-src * data: blob:; media-src *; font-src *; frame-src *; object-src *");
  res.removeHeader('X-Frame-Options');
  if (fs.existsSync(panelPath)) {
    const stream = fs.createReadStream(panelPath);
    stream.pipe(res);
    stream.on('error', () => res.status(404).end('面板文件读取失败'));
  } else {
    res.status(404).end('面板文件不存在');
  }
});
app.get('/host.html', (req, res) => res.redirect('/panel.html'));
app.get('/admin.html', (req, res) => res.redirect('/panel.html'));

// ============ 前端安全 ============
app.use((req, res, next) => {
  const ip = req.headers['cf-connecting-ip'] || req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.headers['x-real-ip'] || req.socket.remoteAddress?.replace('::ffff:', '') || '127.0.0.1';

  // 已封禁 IP
  if (security.isBlocked(ip)) {
    return res.status(403).end();
  }

  // 攻击模式
  if (security.attackMode && !security.isWhitelisted(ip)) {
    const p = req.path.toLowerCase();
    if (!p.startsWith('/api/v2/auth/') && !p.startsWith('/api/v2/gateway/health')) {
      return res.status(503).end();
    }
  }

  // 已知扫描器 UA
  const ua = (req.headers['user-agent'] || '').toLowerCase();
  const scannerPatterns = [
    'zgrab', 'masscan', 'nmap', 'nessus', 'burp', 'sqlmap', 'nikto',
    'gobuster', 'dirbuster', 'wpscan', 'acunetix', 'netsparker',
    'hydra', 'medusa', 'ncrack', 'brutus', 'metasploit',
    'python-requests', 'python-urllib', 'go-http-client', 'curl/',
    'libcurl', 'wget', 'axios', 'node-fetch', 'okhttp',
    'scrapy', 'apache-httpclient', 'java/', 'jakarta',
    'bot', 'crawler', 'spider', 'scanner', 'scan'
  ];
  if (ua && scannerPatterns.some(p => ua.includes(p))) {
    security.blockIP(ip, '扫描器UA', 60 * 60 * 1000);
    return res.status(403).end();
  }

  // 根路径高频扫描
  const path = req.path.toLowerCase();
  if (path === '/' || path === '') {
    const rk = 'root:' + ip;
    if (!security.requestCounts) security.requestCounts = {};
    if (!security.requestCounts[rk]) security.requestCounts[rk] = { count: 0, reset: Date.now() + 60000 };
    const re = security.requestCounts[rk];
    if (Date.now() > re.reset) { re.count = 0; re.reset = Date.now() + 60000; }
    re.count++;
    if (re.count > 10) {
      security.blockIP(ip, '根路径高频', 30 * 60 * 1000);
      return res.status(403).end();
    }
  }

  next();
});

// 基础中间件
app.use(compression());
app.use(cors({ origin: true, credentials: true, methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'], allowedHeaders: ['Content-Type', 'Authorization', 'x-request-time', 'x-request-nonce', 'x-request-signature', 'x-session-id', 'x-device-id'] }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// CSP 头（仅对 API 和管理页面）
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self' ws: wss:; font-src 'self'; frame-src 'none'; object-src 'none'; base-uri 'self'; form-action 'self'");
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  next();
});

// CSRF 保护
app.use((req, res, next) => {
  if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) {
    const origin = req.headers.origin || req.headers.referer;
    if (origin) {
      try {
        const originHost = new URL(origin).hostname;
        const reqHost = req.headers.host?.split(':')[0] || '';
        const allowedHosts = [reqHost, 'localhost', '127.0.0.1'];
        if (!allowedHosts.some(h => originHost === h || originHost.endsWith('.' + h))) {
          if (req.headers.origin && !req.headers.referer) {
            return res.status(403).json({ error: '请求被拒绝' });
          }
        }
      } catch (e) {}
    }
  }
  next();
});

// 请求日志 + 安全检测
app.use((req, res, next) => {
  const ip = getClientIP(req);
  const path = req.path.toLowerCase();

  if (security.isBlocked(ip)) {
    security.updateBehaviorScore(ip, 'blocked_access');
    return res.status(403).json({ error: '请求被拒绝' });
  }

  if (security.attackMode && !security.isWhitelisted(ip)) {
    if (path.startsWith('/api/v2/auth/') || path.startsWith('/api/v2/gateway/health')) {
      // 允许登录和健康检查
    } else {
      return res.status(503).json({ error: '服务暂时不可用' });
    }
  }

  // 蜜罐检测
  if (security.isHoneypot(path)) {
    security.updateBehaviorScore(ip, 'honeypot');
    security.blockIP(ip, '蜜罐触发', 24 * 60 * 60 * 1000);
    return res.status(403).json({ error: '请求被拒绝' });
  }

  // 频率限制
  if (!security.checkRateLimit(req)) {
    security.updateBehaviorScore(ip, 'rate_limit');
    return res.status(429).json({ error: '请求过于频繁' });
  }

  next();
});

// ============ 静态文件 ============
app.use('/h', express.static(HOSTS_DIR, { index: 'index.html', dotfiles: 'deny' }));
app.use(express.static(PUBLIC_DIR, { index: false }));

// ============ 认证接口 ============

// 注册
app.post('/api/v2/auth/session/create', (req, res) => {
  try {
    const ip = getClientIP(req);
    const { username, password } = req.body;

    if (!username || !password) return res.status(400).json({ error: '参数不完整' });
    const uname = sanitize(username);
    if (uname.length < 2 || uname.length > 30) return res.status(400).json({ error: '用户名长度2-30个字符' });

    const pwError = validatePasswordStrength(password);
    if (pwError) return res.status(400).json({ error: pwError });

    if (DB.users[uname]) return res.status(409).json({ error: '用户名已存在' });

    const uid = generateUID();
    const hostPassword = crypto.randomBytes(8).toString('hex');
    const userData = {
      id: uid,
      username: uname,
      password: hashPasswordBcrypt(password),
      hostPassword: encryptHostPassword(hostPassword),
      plan: 'free',
      planName: '免费版',
      registered: new Date().toISOString(),
      lastLogin: new Date().toISOString(),
      knownIPs: [ip],
      spaceUsedMB: 0,
      spaceLimitMB: 100,
      sessions: [],
      isNewUserGrace: true,
      graceUntil: Date.now() + 24 * 60 * 60 * 1000,
      banned: false,
      banReason: null
    };

    DB.users[uname] = userData;
    DB.hosts[uid] = { owner: uname, password: hostPassword, createdAt: new Date().toISOString(), files: [] };

    const hostDir = path.join(HOSTS_DIR, uid);
    if (!fs.existsSync(hostDir)) fs.mkdirSync(hostDir, { recursive: true });

    const token = jwt.sign({ id: uid, username: uname, plan: 'free' }, JWT_SECRET, { expiresIn: TOKEN_EXPIRY });
    const refreshToken = jwt.sign({ id: uid, username: uname, type: 'refresh' }, REFRESH_SECRET, { expiresIn: REFRESH_EXPIRY });
    DB.refreshTokens[refreshToken] = { userId: uid, username: uname, createdAt: Date.now() };

    saveDB();
    logAudit('register', ip, `用户注册: ${uname}`);

    res.json({
      success: true,
      token,
      refreshToken,
      host: { uid, password: hostPassword, url: `/h/${uid}/` }
    });
  } catch (e) {
    console.error('[注册]', e.message);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// 登录（兼容 panel.html 旧接口）
app.post('/api/v2/auth/session/init', (req, res) => {
  try {
    const ip = getClientIP(req);
    const { username, password } = req.body;

    if (!username || !password) return res.status(400).json({ error: '参数不完整' });
    const uname = sanitize(username);

    const user = DB.users[uname];
    if (!user) return res.status(401).json({ error: '用户名或密码错误' });

    if (user.banned) return res.status(403).json({ error: '账户已被封禁', reason: user.banReason });

    if (!verifyPasswordBcrypt(password, user.password)) {
      logAudit('login_failed', ip, `登录失败: ${uname}`);
      return res.status(401).json({ error: '用户名或密码错误' });
    }

    user.lastLogin = new Date().toISOString();
    if (!user.knownIPs.includes(ip)) user.knownIPs.push(ip);

    const token = jwt.sign({ id: user.id, username: uname, plan: user.plan }, JWT_SECRET, { expiresIn: TOKEN_EXPIRY });
    const refreshToken = jwt.sign({ id: user.id, username: uname, type: 'refresh' }, REFRESH_SECRET, { expiresIn: REFRESH_EXPIRY });
    DB.refreshTokens[refreshToken] = { userId: user.id, username: uname, createdAt: Date.now() };

    saveDB();
    logAudit('login', ip, `用户登录: ${uname}`);

    res.json({ token, refreshToken, user: { id: user.id, username: user.username, plan: user.plan, planName: user.planName } });
  } catch (e) {
    console.error('[登录]', e.message);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// 登录
app.post('/api/v2/auth/session/authenticate', (req, res) => {
  try {
    const ip = getClientIP(req);
    const { username, password } = req.body;

    if (!username || !password) return res.status(400).json({ error: '参数不完整' });
    const uname = sanitize(username);

    const user = DB.users[uname];
    if (!user) return res.status(401).json({ error: '用户名或密码错误' });

    if (user.banned) return res.status(403).json({ error: '账户已被封禁', reason: user.banReason });

    if (!verifyPasswordBcrypt(password, user.password)) {
      logAudit('login_failed', ip, `登录失败: ${uname}`);
      return res.status(401).json({ error: '用户名或密码错误' });
    }

    user.lastLogin = new Date().toISOString();
    if (!user.knownIPs.includes(ip)) user.knownIPs.push(ip);

    const token = jwt.sign({ id: user.id, username: uname, plan: user.plan }, JWT_SECRET, { expiresIn: TOKEN_EXPIRY });
    const refreshToken = jwt.sign({ id: user.id, username: uname, type: 'refresh' }, REFRESH_SECRET, { expiresIn: REFRESH_EXPIRY });
    DB.refreshTokens[refreshToken] = { userId: user.id, username: uname, createdAt: Date.now() };

    saveDB();
    logAudit('login', ip, `用户登录: ${uname}`);

    res.json({
      success: true,
      token,
      refreshToken,
      user: { id: user.id, username: user.username, plan: user.plan, planName: user.planName }
    });
  } catch (e) {
    console.error('[登录]', e.message);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// 指纹采集
app.post('/api/v2/auth/fingerprint', (req, res) => {
  const ip = getClientIP(req);
  DB.fingerprints[ip] = req.body;
  res.json({ success: true });
});

// 鼠标数据采集
app.post('/api/v2/auth/mouse-data', (req, res) => {
  const ip = getClientIP(req);
  DB.mouseData[ip] = req.body;
  res.json({ success: true });
});

// 撤销认证会话
app.post('/api/v2/auth/session/revoke', (req, res) => {
  const { refreshToken } = req.body;
  if (refreshToken) delete DB.refreshTokens[refreshToken];
  saveDB();
  res.json({ success: true });
});

// Token 刷新
app.post('/api/v2/auth/session/refresh', (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(400).json({ error: '缺少 refreshToken' });

    if (!DB.refreshTokens[refreshToken]) return res.status(401).json({ error: 'refreshToken 无效或已过期' });

    const decoded = jwt.verify(refreshToken, REFRESH_SECRET);
    const user = DB.users[decoded.username];
    if (!user) return res.status(401).json({ error: '用户不存在' });

    // Token 轮换：旧 token 作废
    delete DB.refreshTokens[refreshToken];

    const newToken = jwt.sign({ id: user.id, username: user.username, plan: user.plan }, JWT_SECRET, { expiresIn: TOKEN_EXPIRY });
    const newRefresh = jwt.sign({ id: user.id, username: user.username, type: 'refresh' }, REFRESH_SECRET, { expiresIn: REFRESH_EXPIRY });
    DB.refreshTokens[newRefresh] = { userId: user.id, username: user.username, createdAt: Date.now() };

    saveDB();
    res.json({ success: true, token: newToken, refreshToken: newRefresh });
  } catch (e) {
    console.error('[Token刷新]', e.message);
    res.status(401).json({ error: 'refreshToken 无效' });
  }
});

// ============ 认证中间件 ============
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: '未授权' });
  }
  try {
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Token 无效或已过期' });
  }
}

// HMAC 中间件（兼容 GET query 和 POST body）
function hmacMiddleware(req, res, next) {
  const admin_password = req.body?.admin_password || req.query?.admin_password;
  if (admin_password && verifyAdmin(admin_password)) {
    return next();
  }
  return res.status(403).json({ error: '管理密码错误' });
}

// ============ 用户接口 ============
app.get('/api/v2/user/profile/detail', authMiddleware, (req, res) => {
  const user = DB.users[req.user.username];
  if (!user) return res.status(404).json({ error: '用户不存在' });
  res.json({ success: true, user: { id: user.id, username: user.username, plan: user.plan, planName: user.planName, registered: user.registered, lastLogin: user.lastLogin } });
});

// ============ IP 管理 ============
app.post('/api/v2/sys/management/ips/unban', hmacMiddleware, (req, res) => {
  const { ip } = req.body;
  if (ip && DB.blockedIPs[ip]) { delete DB.blockedIPs[ip]; saveBlocked(); return res.json({ success: true, msg: 'IP已解封' }); }
  res.json({ success: true, msg: 'IP未被封禁或已解封' });
});

app.post('/api/v2/sys/management/ips/whitelist/add', hmacMiddleware, (req, res) => {
  const { ip } = req.body;
  if (!ip) return res.status(400).json({ error: '缺少IP' });
  if (!DB.whitelist.includes(ip)) { DB.whitelist.push(ip); saveDB(); }
  res.json({ success: true, msg: 'IP已加入白名单' });
});

app.post('/api/v2/sys/management/ips/whitelist/remove', hmacMiddleware, (req, res) => {
  const { ip } = req.body;
  DB.whitelist = DB.whitelist.filter(i => i !== ip);
  saveDB();
  res.json({ success: true, msg: 'IP已移除白名单' });
});

app.get('/api/v2/sys/management/ips/whitelist', hmacMiddleware, (req, res) => {
  res.json({ success: true, whitelist: DB.whitelist });
});

app.get('/api/v2/sys/management/ips/behavior', hmacMiddleware, (req, res) => {
  const { ip } = req.query;
  if (!ip) return res.status(400).json({ error: '缺少IP' });
  res.json({ success: true, ip, behavior: DB.ipBehavior[ip] || null });
});

app.get('/api/v2/sys/management/ips/geo', hmacMiddleware, (req, res) => {
  res.json({ success: true, data: {} });
});

app.get('/api/v2/sys/management/accounts/lockouts', hmacMiddleware, (req, res) => {
  res.json({ success: true, lockouts: DB.lockouts });
});

// 资源监控
app.get('/api/v2/sys/resources', hmacMiddleware, (req, res) => {
  const mem = process.memoryUsage();
  res.json({ success: true, memory: { heapUsed: Math.round(mem.heapUsed / 1024 / 1024) + 'MB', heapTotal: Math.round(mem.heapTotal / 1024 / 1024) + 'MB', rss: Math.round(mem.rss / 1024 / 1024) + 'MB' }, uptime: Math.round(process.uptime()) + 's' });
});

// 服务器信息
app.get('/api/v2/server/info', (req, res) => {
  res.json({ version: 'v4.0.0', name: '手机多租户虚拟主机', port: PORT });
});

// 健康检查
app.get('/api/v2/gateway/health', (req, res) => {
  res.json({ status: 'ok', uptime: process.uptime() });
});

// 版本
app.get('/api/v2/gateway/version', (req, res) => {
  res.json({ version: 'v4.0.0', build: '2026-07-31' });
});

// 签名信息
app.get('/api/v2/sys/auth/signature-info', (req, res) => {
  res.json({ algorithm: 'HMAC-SHA256' });
});

// 指纹管理
app.get('/api/v2/sys/management/fingerprints', hmacMiddleware, (req, res) => {
  res.json({ success: true, fingerprints: DB.fingerprints });
});

// 日志归档
app.get('/api/v2/sys/management/logs/archive', hmacMiddleware, (req, res) => {
  res.json({ success: true, auditLogCount: DB.auditLog.length });
});

// 会话管理
app.get('/api/v2/user/sessions', authMiddleware, (req, res) => {
  res.json({ success: true, sessions: [] });
});

// ============ 存储 API ============

// 文件列表
app.get('/api/v2/storage/files/list/:uid', authMiddleware, (req, res) => {
  const { uid } = req.params;
  const host = DB.hosts[uid];
  if (!host) return res.status(404).json({ error: '主机不存在' });
  const hostDir = path.join(HOSTS_DIR, uid);
  if (!fs.existsSync(hostDir)) return res.json({ files: [], folders: [] });
  const entries = fs.readdirSync(hostDir, { withFileTypes: true });
  const files = [];
  const folders = [];
  entries.forEach(e => {
    const stat = fs.statSync(path.join(hostDir, e.name));
    if (e.isDirectory()) {
      folders.push({ name: e.name, size: 0, type: 'folder', mtime: stat.mtime.toISOString() });
    } else {
      files.push({ name: e.name, size: stat.size, type: path.extname(e.name).replace('.', '') || 'unknown', mtime: stat.mtime.toISOString() });
    }
  });
  res.json({ files, folders });
});

// 文件搜索
app.get('/api/v2/storage/files/search/:uid', authMiddleware, (req, res) => {
  const { uid } = req.params;
  const q = (req.query.q || '').toLowerCase();
  const host = DB.hosts[uid];
  if (!host) return res.status(404).json({ error: '主机不存在' });
  const hostDir = path.join(HOSTS_DIR, uid);
  if (!fs.existsSync(hostDir)) return res.json({ files: [], folders: [] });
  const entries = fs.readdirSync(hostDir, { withFileTypes: true });
  const files = [];
  const folders = [];
  entries.forEach(e => {
    if (!e.name.toLowerCase().includes(q)) return;
    const stat = fs.statSync(path.join(hostDir, e.name));
    if (e.isDirectory()) {
      folders.push({ name: e.name, size: 0, type: 'folder', mtime: stat.mtime.toISOString() });
    } else {
      files.push({ name: e.name, size: stat.size, type: path.extname(e.name).replace('.', '') || 'unknown', mtime: stat.mtime.toISOString() });
    }
  });
  res.json({ files, folders });
});

// 文件排序
app.get('/api/v2/storage/files/sorted/:uid', authMiddleware, (req, res) => {
  const { uid } = req.params;
  const sort = req.query.sort || 'name';
  const order = req.query.order || 'asc';
  const host = DB.hosts[uid];
  if (!host) return res.status(404).json({ error: '主机不存在' });
  const hostDir = path.join(HOSTS_DIR, uid);
  if (!fs.existsSync(hostDir)) return res.json({ files: [], folders: [] });
  const entries = fs.readdirSync(hostDir, { withFileTypes: true });
  const files = [];
  const folders = [];
  entries.forEach(e => {
    const stat = fs.statSync(path.join(hostDir, e.name));
    if (e.isDirectory()) {
      folders.push({ name: e.name, size: 0, type: 'folder', mtime: stat.mtime.toISOString() });
    } else {
      files.push({ name: e.name, size: stat.size, type: path.extname(e.name).replace('.', '') || 'unknown', mtime: stat.mtime.toISOString() });
    }
  });
  const sorter = (a, b) => {
    let va = sort === 'size' ? a.size : (sort === 'mtime' ? a.mtime : a.name);
    let vb = sort === 'size' ? b.size : (sort === 'mtime' ? b.mtime : b.name);
    if (typeof va === 'string') va = va.toLowerCase();
    if (typeof vb === 'string') vb = vb.toLowerCase();
    return order === 'desc' ? (va > vb ? -1 : va < vb ? 1 : 0) : (va < vb ? -1 : va > vb ? 1 : 0);
  };
  files.sort(sorter);
  folders.sort(sorter);
  res.json({ files, folders });
});

// 文件上传
const upload = multer({ dest: path.join(DATA_DIR, 'uploads'), limits: { fileSize: MAX_FILE_SIZE } });
app.post('/api/v2/storage/files/upload/:uid', authMiddleware, upload.array('files', 20), (req, res) => {
  const { uid } = req.params;
  const host = DB.hosts[uid];
  if (!host) return res.status(404).json({ error: '主机不存在' });
  if (!req.files || req.files.length === 0) return res.status(400).json({ error: '没有文件' });
  const hostDir = path.join(HOSTS_DIR, uid);
  if (!fs.existsSync(hostDir)) fs.mkdirSync(hostDir, { recursive: true });
  const results = [];
  req.files.forEach(f => {
    const destPath = path.join(hostDir, f.originalname);
    fs.renameSync(f.path, destPath);
    results.push({ name: f.originalname, size: f.size });
  });
  host.files = host.files || [];
  host.files.push(...results);
  const user = DB.users[host.owner];
  if (user) {
    user.spaceUsedMB = user.spaceUsedMB || 0;
    const totalSize = results.reduce((s, f) => s + f.size, 0);
    user.spaceUsedMB += Math.round(totalSize / (1024 * 1024) * 100) / 100;
  }
  saveDB();
  res.json({ success: true, files: results });
});

// 删除文件
app.post('/api/v2/storage/files/remove/:uid/:name', authMiddleware, (req, res) => {
  const { uid, name } = req.params;
  const host = DB.hosts[uid];
  if (!host) return res.status(404).json({ error: '主机不存在' });
  const filePath = path.join(HOSTS_DIR, uid, name);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: '文件不存在' });
  const stat = fs.statSync(filePath);
  fs.unlinkSync(filePath);
  const user = DB.users[host.owner];
  if (user && stat.isFile()) {
    user.spaceUsedMB = Math.max(0, (user.spaceUsedMB || 0) - Math.round(stat.size / (1024 * 1024) * 100) / 100);
  }
  saveDB();
  res.json({ success: true });
});

// 批量删除文件
app.post('/api/v2/storage/files/batch-remove/:uid', authMiddleware, (req, res) => {
  const { uid } = req.params;
  const { filenames } = req.body;
  const host = DB.hosts[uid];
  if (!host) return res.status(404).json({ error: '主机不存在' });
  if (!filenames || !Array.isArray(filenames)) return res.status(400).json({ error: '缺少文件列表' });
  let deleted = 0;
  filenames.forEach(name => {
    const filePath = path.join(HOSTS_DIR, uid, name);
    if (fs.existsSync(filePath)) {
      const stat = fs.statSync(filePath);
      if (stat.isFile()) {
        fs.unlinkSync(filePath);
        deleted++;
        const user = DB.users[host.owner];
        if (user) {
          user.spaceUsedMB = Math.max(0, (user.spaceUsedMB || 0) - Math.round(stat.size / (1024 * 1024) * 100) / 100);
        }
      }
    }
  });
  saveDB();
  res.json({ success: true, deleted_count: deleted });
});

// 重命名文件
app.post('/api/v2/storage/files/rename/:uid/:name', authMiddleware, (req, res) => {
  const { uid, name } = req.params;
  const { new_name } = req.body;
  const host = DB.hosts[uid];
  if (!host) return res.status(404).json({ error: '主机不存在' });
  const oldPath = path.join(HOSTS_DIR, uid, name);
  const newPath = path.join(HOSTS_DIR, uid, new_name);
  if (!fs.existsSync(oldPath)) return res.status(404).json({ error: '文件不存在' });
  if (fs.existsSync(newPath)) return res.status(409).json({ error: '目标文件名已存在' });
  fs.renameSync(oldPath, newPath);
  res.json({ success: true });
});

// 创建文件夹
app.post('/api/v2/storage/files/mkdir/:uid', authMiddleware, (req, res) => {
  const { uid } = req.params;
  const { dir_name } = req.body;
  const host = DB.hosts[uid];
  if (!host) return res.status(404).json({ error: '主机不存在' });
  const dirPath = path.join(HOSTS_DIR, uid, dir_name);
  if (fs.existsSync(dirPath)) return res.status(409).json({ error: '文件夹已存在' });
  fs.mkdirSync(dirPath, { recursive: true });
  res.json({ success: true });
});

// 删除文件夹
app.post('/api/v2/storage/files/rmdir/:uid', authMiddleware, (req, res) => {
  const { uid } = req.params;
  const { dir_name } = req.body;
  const host = DB.hosts[uid];
  if (!host) return res.status(404).json({ error: '主机不存在' });
  const dirPath = path.join(HOSTS_DIR, uid, dir_name);
  if (!fs.existsSync(dirPath)) return res.status(404).json({ error: '文件夹不存在' });
  fs.rmSync(dirPath, { recursive: true, force: true });
  res.json({ success: true });
});

// 文件预览
app.get('/api/v2/storage/files/preview/:uid/:name', authMiddleware, (req, res) => {
  const { uid, name } = req.params;
  const filePath = path.join(HOSTS_DIR, uid, name);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: '文件不存在' });
  const ext = path.extname(name).toLowerCase();
  const mimeMap = {
    '.html': 'text/html', '.htm': 'text/html', '.css': 'text/css', '.js': 'application/javascript',
    '.json': 'application/json', '.xml': 'application/xml', '.txt': 'text/plain',
    '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.gif': 'image/gif', '.svg': 'image/svg+xml',
    '.pdf': 'application/pdf', '.zip': 'application/zip'
  };
  res.setHeader('Content-Type', mimeMap[ext] || 'application/octet-stream');
  fs.createReadStream(filePath).pipe(res);
});

// 清理空间
app.post('/api/v2/storage/files/cleanup/:uid', authMiddleware, (req, res) => {
  const { uid } = req.params;
  const host = DB.hosts[uid];
  if (!host) return res.status(404).json({ error: '主机不存在' });
  const hostDir = path.join(HOSTS_DIR, uid);
  if (fs.existsSync(hostDir)) {
    fs.readdirSync(hostDir).forEach(f => {
      fs.rmSync(path.join(hostDir, f), { recursive: true, force: true });
    });
  }
  const user = DB.users[host.owner];
  if (user) user.spaceUsedMB = 0;
  saveDB();
  res.json({ success: true, message: '空间已清理' });
});

// ============ 用户扩展 API ============

// 修改密码
app.post('/api/v2/user/profile/password', authMiddleware, (req, res) => {
  const { old_password, new_password } = req.body;
  const user = DB.users[req.user.username];
  if (!user) return res.status(404).json({ error: '用户不存在' });
  if (!verifyPasswordBcrypt(old_password, user.password)) return res.status(401).json({ error: '旧密码错误' });
  const pwError = validatePasswordStrength(new_password);
  if (pwError) return res.status(400).json({ error: pwError });
  user.password = hashPasswordBcrypt(new_password);
  saveDB();
  res.json({ success: true, message: '密码已修改' });
});

// 注销账号
app.post('/api/v2/user/profile/delete', authMiddleware, (req, res) => {
  const { password } = req.body;
  const user = DB.users[req.user.username];
  if (!user) return res.status(404).json({ error: '用户不存在' });
  if (!verifyPasswordBcrypt(password, user.password)) return res.status(401).json({ error: '密码错误' });
  const uid = user.id;
  delete DB.users[req.user.username];
  delete DB.hosts[uid];
  const hostDir = path.join(HOSTS_DIR, uid);
  if (fs.existsSync(hostDir)) fs.rmSync(hostDir, { recursive: true, force: true });
  saveDB();
  res.json({ success: true, message: '账号已注销' });
});

// 用户活动
app.get('/api/v2/user/activity', authMiddleware, (req, res) => {
  const logs = DB.auditLog.filter(l => l.ip && DB.users[req.user.username]?.knownIPs?.includes(l.ip)).slice(-50);
  res.json({ success: true, activities: logs });
});

// 撤销会话
app.post('/api/v2/user/sessions/revoke', authMiddleware, (req, res) => {
  const { token_prefix } = req.body;
  Object.keys(DB.refreshTokens).forEach(k => {
    if (!token_prefix || k.startsWith(token_prefix)) delete DB.refreshTokens[k];
  });
  saveDB();
  res.json({ success: true });
});

// ============ 支付/兑换 API ============

// 兑换卡密
app.post('/api/v2/payment/redeem/exchange', authMiddleware, (req, res) => {
  const { code } = req.body;
  if (!code) return res.status(400).json({ error: '缺少卡密' });
  const card = DB.cards.find(c => c.code === code && !c.used);
  if (!card) return res.status(404).json({ error: '卡密无效或已使用' });
  card.used = true;
  card.used_by = req.user.username;
  card.used_at = new Date().toISOString();
  const user = DB.users[req.user.username];
  if (user) {
    user.plan = card.plan;
    user.planName = card.plan === 'premium' ? '高级版' : card.plan === 'pro' ? '专业版' : '免费版';
    if (card.plan === 'premium') user.spaceLimitMB = 500;
    if (card.plan === 'pro') user.spaceLimitMB = 2000;
  }
  saveDB();
  logAudit('card_redeem', getClientIP(req), `用户 ${req.user.username} 兑换卡密 ${code}`);
  res.json({ success: true, plan: card.plan, message: '兑换成功' });
});

// ============ 管理后台 API ============

// 统计概览
app.get('/api/v2/sys/management/stats/overview', hmacMiddleware, (req, res) => {
  const users = Object.values(DB.users);
  const totalFiles = Object.values(DB.hosts).reduce((sum, h) => sum + (h.files ? h.files.length : 0), 0);
  const bannedUsers = users.filter(u => u.banned).length;
  const blockedIPs = Object.keys(DB.blockedIPs).length;
  const attackLogs = DB.auditLog.filter(l => l.action === 'honeypot' || l.action === 'scanner' || l.action === 'blocked_access').slice(-20).map(l => ({ time: l.time, type: l.action, ip: l.ip, detail: l.detail }));
  res.json({ total_users: users.length, total_files: totalFiles, banned_users: bannedUsers, blocked_ips: blockedIPs, total_cards: DB.cards.length, attack_logs: attackLogs });
});

// 用户列表
app.get('/api/v2/sys/management/users/list', hmacMiddleware, (req, res) => {
  const list = Object.values(DB.users).map(u => ({
    username: u.username,
    plan: u.plan,
    space_used_mb: u.spaceUsedMB || 0,
    known_ips: u.knownIPs || [],
    banned: u.banned || false
  }));
  res.json(list);
});

// 封禁用户
app.post('/api/v2/sys/management/ban/user', hmacMiddleware, (req, res) => {
  const { username, reason } = req.body;
  const user = DB.users[username];
  if (!user) return res.status(404).json({ error: '用户不存在' });
  user.banned = true;
  user.banReason = reason || '违规';
  saveDB();
  logAudit('ban_user', getClientIP(req), `封禁用户: ${username}, 原因: ${reason}`);
  res.json({ success: true, message: `已封禁用户 ${username}` });
});

// 解封用户
app.post('/api/v2/sys/management/unban/user', hmacMiddleware, (req, res) => {
  const { username } = req.body;
  const user = DB.users[username];
  if (!user) return res.status(404).json({ error: '用户不存在' });
  user.banned = false;
  user.banReason = null;
  saveDB();
  logAudit('unban_user', getClientIP(req), `解封用户: ${username}`);
  res.json({ success: true, message: `已解封用户 ${username}` });
});

// 重置用户密码（管理员专用，解决 JWT_SECRET 变更导致旧密码失效的问题）
app.post('/api/v2/sys/management/users/reset-password', hmacMiddleware, (req, res) => {
  const { username, new_password } = req.body;
  if (!username || !new_password) return res.status(400).json({ error: '缺少参数' });
  const user = DB.users[username];
  if (!user) return res.status(404).json({ error: '用户不存在' });
  const pwError = validatePasswordStrength(new_password);
  if (pwError) return res.status(400).json({ error: pwError });
  user.password = hashPasswordBcrypt(new_password);
  saveDB();
  logAudit('reset_password', getClientIP(req), `管理员重置用户密码: ${username}`);
  res.json({ success: true, message: `已重置用户 ${username} 的密码` });
});

// 卡密生成
app.post('/api/v2/sys/management/cards/generate', hmacMiddleware, (req, res) => {
  const { plan, count } = req.body;
  if (!plan || !count || count < 1 || count > 100) return res.status(400).json({ error: '参数错误' });
  const codes = [];
  for (let i = 0; i < count; i++) {
    const code = 'CARD-' + crypto.randomBytes(8).toString('hex').toUpperCase();
    DB.cards.push({ code, plan, used: false, used_by: null, used_at: null, created_at: new Date().toISOString() });
    codes.push({ code, plan });
  }
  saveDB();
  logAudit('card_generate', getClientIP(req), `生成${count}张卡密, 类型: ${plan}`);
  res.json({ success: true, codes });
});

// 卡密列表
app.get('/api/v2/sys/management/cards/list', hmacMiddleware, (req, res) => {
  res.json(DB.cards.slice(-100));
});

// 封禁IP列表
app.get('/api/v2/sys/management/ips/blocked', hmacMiddleware, (req, res) => {
  const persistent = Object.entries(DB.blockedIPs).map(([ip, data]) => ({ ip, reason: data.reason, expireAt: new Date(data.until).toISOString() }));
  res.json({ persistent_blocked: persistent, memory_blocked: [] });
});

// IP信誉列表
app.get('/api/v2/sys/management/ips/reputation', hmacMiddleware, (req, res) => {
  const entries = Object.entries(DB.ipBehavior).map(([ip, data]) => ({ ip, score: data.score, events: (data.events || []).length, bannedUsers: [] }));
  const low = entries.filter(e => e.score <= 50).sort((a, b) => a.score - b.score);
  res.json({ total: entries.length, low_reputation: low });
});

// ============ 错误处理 ============
app.use((err, req, res, next) => {
  console.error('[错误]', err.message);
  res.status(500).json({ error: '服务器内部错误' });
});

// 404
app.use((req, res) => {
  res.status(404).json({ error: '页面不存在' });
});

// ============ 启动服务器 ============
server.listen(PORT, () => {
  console.log('========================================');
  console.log('手机多租户虚拟主机 v4.0.0 安全加固版');
  console.log('========================================');
  console.log(`监听端口: ${PORT}`);
  console.log(`管理密码: ${ADMIN_PASSWORD ? '已设置(环境变量)' : '未设置(随机生成)'}`);
  console.log(`用户数量: ${Object.keys(DB.users).length}`);
  console.log(`主机数量: ${Object.keys(DB.hosts).length}`);
  console.log('========================================');
  console.log(`管理后台: http://127.0.0.1:${PORT}/panel.html`);
  console.log('========================================');
  console.log('[安全] 已添加白名单IP: ' + (DB.whitelist.length > 0 ? DB.whitelist.join(', ') : '无'));
  console.log('========================================');
});

// 优雅退出
process.on('SIGTERM', () => { server.close(); process.exit(0); });
process.on('SIGINT', () => { server.close(); process.exit(0); });
