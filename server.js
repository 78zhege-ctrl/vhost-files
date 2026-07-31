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
const ws = require('ws');
const { MultiplayerServer } = require('./multiplayer-server');
const compression = require('compression');

// ============ 配置 ============
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
if (!ADMIN_PASSWORD) {
  console.error('[安全] 警告：未设置 ADMIN_PASSWORD 环境变量，使用随机密码');
  console.error('[安全] 请在启动前设置: export ADMIN_PASSWORD="你的管理密码"');
}
const ACTUAL_ADMIN_PASSWORD = ADMIN_PASSWORD || (() => { const rp = crypto.randomBytes(16).toString('hex'); console.error(`[安全] 随机密码: ${rp}`); console.error('[安全] 下次启动请设置: export ADMIN_PASSWORD="你的密码"'); return rp; })();
const HMAC_SECRET = crypto.createHash('sha256').update(JWT_SECRET + 'hmac').digest();
const REFRESH_SECRET = crypto.createHash('sha256').update(JWT_SECRET + 'refresh').digest();
const DATA_DIR = path.join(__dirname, 'data');
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
let DB = { users: {}, hosts: {}, sessions: {}, refreshTokens: {}, blockedIPs: {}, ipBehavior: {}, fingerprints: {}, mouseData: {}, nonces: {}, auditLog: [], lockouts: [], whitelist: [] };
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
    if (!DB.ipBehavior[ip]) DB.ipBehavior[ip] = { score: 100, events: [], lastSeen: now };
    DB.ipBehavior[ip].events.push({ time: new Date().toISOString(), reason, action: 'blocked_but_not_applied' });
    DB.ipBehavior[ip].score = Math.max(DB.ipBehavior[ip].score - 5, 0);
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

// ⚠️ 关键修复：游戏路由放在最前面，在 CSP 中间件之前
// 这样游戏页面不会被全局 CSP 限制

// ============ 游戏首页（必须在 CSP 中间件之前） ============
app.get('/', (req, res) => {
  const gamePath = path.join(__dirname, '钢铁前线1944联机版.html');
  if (fs.existsSync(gamePath)) {
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Content-Security-Policy', "default-src * 'unsafe-inline' 'unsafe-eval'; script-src * 'unsafe-inline' 'unsafe-eval'; style-src * 'unsafe-inline'; connect-src * ws: wss:; img-src * data: blob:; media-src *; font-src *; frame-src *; object-src *");
    res.removeHeader('X-Frame-Options');
    const stream = fs.createReadStream(gamePath);
    stream.pipe(res);
    stream.on('error', () => {
      res.status(404).end('游戏文件读取失败');
    });
  } else {
    res.status(200).type('html').send('<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><title>钢铁前线1944</title></head><body style="background:#0a0c08;color:#eee;text-align:center;padding-top:40vh"><h1>游戏文件未部署</h1><p>请将钢铁前线1944联机版.html放到服务器根目录</p></body></html>');
  }
});

// ============ 测试页面 ============
app.get('/test', (req, res) => {
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.setHeader('Content-Security-Policy', "default-src * 'unsafe-inline' 'unsafe-eval'; script-src * 'unsafe-inline' 'unsafe-eval'; style-src * 'unsafe-inline'; connect-src * ws: wss:;");
  res.removeHeader('X-Frame-Options');
  res.send('<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>测试</title><style>body{background:#0a0c08;color:#eee;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;flex-direction:column;gap:16px}.btn{padding:16px 40px;font-size:18px;border:2px solid #8a7c50;background:linear-gradient(180deg,#5a5236,#3a3422);color:#f0e6c0;border-radius:6px;cursor:pointer}.msg{color:#8f8;margin-top:12px;font-size:14px}</style></head><body><h1>测试页面</h1><button class="btn" onclick="document.getElementById(\'r1\').textContent=\'点击成功！\'">测试按钮 1</button><button class="btn" id="btn2">测试按钮 2</button><div class="msg" id="r1"></div><div class="msg" id="r2"></div><script>document.getElementById(\'btn2\').onclick=function(){document.getElementById(\'r2\').textContent=\'JS绑定也正常！\';};</script></body></html>');
});

// ============ 前端安全（仅对 API 和管理页面生效） ============
app.use((req, res, next) => {
  const ip = getClientIP(req);
  if (security.isBlocked(ip)) return res.status(403).end();
  if (security.attackMode && !security.isWhitelisted(ip)) {
    const p = req.path.toLowerCase();
    if (!p.startsWith('/api/v2/auth/') && !p.startsWith('/api/v2/gateway/health')) return res.status(503).end();
  }
  const ua = (req.headers['user-agent'] || '').toLowerCase();
  const scannerPatterns = ['zgrab', 'masscan', 'nmap', 'nessus', 'burp', 'sqlmap', 'nikto', 'gobuster', 'dirbuster', 'wpscan', 'acunetix', 'netsparker', 'hydra', 'medusa', 'ncrack', 'brutus', 'metasploit', 'python-requests', 'python-urllib', 'go-http-client', 'curl/', 'libcurl', 'wget', 'axios', 'node-fetch', 'okhttp', 'scrapy', 'apache-httpclient', 'java/', 'jakarta', 'bot', 'crawler', 'spider', 'scanner', 'scan'];
  if (ua && scannerPatterns.some(p => ua.includes(p))) {
    security.blockIP(ip, '扫描器UA', 60 * 60 * 1000);
    return res.status(403).end();
  }
  const rpath = req.path.toLowerCase();
  if (rpath === '/' || rpath === '') {
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
          if (req.headers.origin && !req.headers.referer) return res.status(403).json({ error: '请求被拒绝' });
        }
      } catch (e) {}
    }
  }
  next();
});

// 请求日志 + 安全检测
app.use((req, res, next) => {
  const ip = getClientIP(req);
  const rpath = req.path.toLowerCase();
  if (security.isBlocked(ip)) { security.updateBehaviorScore(ip, 'blocked_access'); return res.status(403).json({ error: '请求被拒绝' }); }
  if (security.attackMode && !security.isWhitelisted(ip)) {
    if (!rpath.startsWith('/api/v2/auth/') && !rpath.startsWith('/api/v2/gateway/health')) return res.status(503).json({ error: '服务暂时不可用' });
  }
  if (security.isHoneypot(rpath)) { security.updateBehaviorScore(ip, 'honeypot'); security.blockIP(ip, '蜜罐触发', 24 * 60 * 60 * 1000); return res.status(403).json({ error: '请求被拒绝' }); }
  if (!security.checkRateLimit(req)) { security.updateBehaviorScore(ip, 'rate_limit'); return res.status(429).json({ error: '请求过于频繁' }); }
  next();
});

// ============ 静态文件 ============
app.use('/h', express.static(HOSTS_DIR, { index: 'index.html', dotfiles: 'deny' }));
app.use(express.static(PUBLIC_DIR, { index: false }));

// ============ 面板页面 ============
app.get('/panel.html', (req, res) => {
  const panelPath = path.join(__dirname, 'panel.html');
  if (fs.existsSync(panelPath)) { res.sendFile(panelPath); }
  else { res.sendFile(path.join(PUBLIC_DIR, 'panel.html')); }
});
app.get('/host.html', (req, res) => res.redirect('/panel.html'));
app.get('/admin.html', (req, res) => res.redirect('/panel.html'));

// ============ 认证接口 ============
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
    const userData = { id: uid, username: uname, password: hashPasswordBcrypt(password), hostPassword: encryptHostPassword(hostPassword), plan: 'free', planName: '免费版', registered: new Date().toISOString(), lastLogin: new Date().toISOString(), knownIPs: [ip], spaceUsedMB: 0, spaceLimitMB: 100, sessions: [], isNewUserGrace: true, graceUntil: Date.now() + 24 * 60 * 60 * 1000, banned: false, banReason: null };
    DB.users[uname] = userData;
    DB.hosts[uid] = { owner: uname, password: hostPassword, createdAt: new Date().toISOString(), files: [] };
    const hostDir = path.join(HOSTS_DIR, uid);
    if (!fs.existsSync(hostDir)) fs.mkdirSync(hostDir, { recursive: true });
    const token = jwt.sign({ id: uid, username: uname, plan: 'free' }, JWT_SECRET, { expiresIn: TOKEN_EXPIRY });
    const refreshToken = jwt.sign({ id: uid, username: uname, type: 'refresh' }, REFRESH_SECRET, { expiresIn: REFRESH_EXPIRY });
    DB.refreshTokens[refreshToken] = { userId: uid, username: uname, createdAt: Date.now() };
    saveDB();
    logAudit('register', ip, `用户注册: ${uname}`);
    res.json({ success: true, token, refreshToken, host: { uid, password: hostPassword, url: `/h/${uid}/` } });
  } catch (e) { console.error('[注册]', e.message); res.status(500).json({ error: '服务器内部错误' }); }
});

app.post('/api/v2/auth/session/authenticate', (req, res) => {
  try {
    const ip = getClientIP(req);
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: '参数不完整' });
    const uname = sanitize(username);
    const user = DB.users[uname];
    if (!user) return res.status(401).json({ error: '用户名或密码错误' });
    if (user.banned) return res.status(403).json({ error: '账户已被封禁', reason: user.banReason });
    if (!verifyPasswordBcrypt(password, user.password)) { logAudit('login_failed', ip, `登录失败: ${uname}`); return res.status(401).json({ error: '用户名或密码错误' }); }
    user.lastLogin = new Date().toISOString();
    if (!user.knownIPs.includes(ip)) user.knownIPs.push(ip);
    const token = jwt.sign({ id: user.id, username: uname, plan: user.plan }, JWT_SECRET, { expiresIn: TOKEN_EXPIRY });
    const refreshToken = jwt.sign({ id: user.id, username: uname, type: 'refresh' }, REFRESH_SECRET, { expiresIn: REFRESH_EXPIRY });
    DB.refreshTokens[refreshToken] = { userId: user.id, username: uname, createdAt: Date.now() };
    saveDB();
    logAudit('login', ip, `用户登录: ${uname}`);
    res.json({ success: true, token, refreshToken, user: { id: user.id, username: user.username, plan: user.plan, planName: user.planName } });
  } catch (e) { console.error('[登录]', e.message); res.status(500).json({ error: '服务器内部错误' }); }
});

app.post('/api/v2/auth/session/refresh', (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(400).json({ error: '缺少 refreshToken' });
    if (!DB.refreshTokens[refreshToken]) return res.status(401).json({ error: 'refreshToken 无效或已过期' });
    const decoded = jwt.verify(refreshToken, REFRESH_SECRET);
    const user = DB.users[decoded.username];
    if (!user) return res.status(401).json({ error: '用户不存在' });
    delete DB.refreshTokens[refreshToken];
    const newToken = jwt.sign({ id: user.id, username: user.username, plan: user.plan }, JWT_SECRET, { expiresIn: TOKEN_EXPIRY });
    const newRefresh = jwt.sign({ id: user.id, username: user.username, type: 'refresh' }, REFRESH_SECRET, { expiresIn: REFRESH_EXPIRY });
    DB.refreshTokens[newRefresh] = { userId: user.id, username: user.username, createdAt: Date.now() };
    saveDB();
    res.json({ success: true, token: newToken, refreshToken: newRefresh });
  } catch (e) { console.error('[Token刷新]', e.message); res.status(401).json({ error: 'refreshToken 无效' }); }
});

// ============ 认证中间件 ============
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ error: '未授权' });
  try { const token = authHeader.split(' ')[1]; const decoded = jwt.verify(token, JWT_SECRET); req.user = decoded; next(); }
  catch (e) { return res.status(401).json({ error: 'Token 无效或已过期' }); }
}

function hmacMiddleware(req, res, next) {
  const { admin_password } = req.body || req.query || {};
  if (admin_password && verifyAdmin(admin_password)) return next();
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

app.get('/api/v2/sys/management/ips/reputation', hmacMiddleware, (req, res) => {
  res.json({ success: true, data: DB.ipBehavior });
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

app.get('/api/v2/sys/resources', hmacMiddleware, (req, res) => {
  const mem = process.memoryUsage();
  res.json({ success: true, memory: { heapUsed: Math.round(mem.heapUsed / 1024 / 1024) + 'MB', heapTotal: Math.round(mem.heapTotal / 1024 / 1024) + 'MB', rss: Math.round(mem.rss / 1024 / 1024) + 'MB' }, uptime: Math.round(process.uptime()) + 's' });
});

app.get('/api/v2/server/info', (req, res) => {
  res.json({ version: 'v4.0.0', name: '手机多租户虚拟主机', port: PORT });
});

app.get('/api/v2/gateway/health', (req, res) => {
  res.json({ status: 'ok', uptime: process.uptime() });
});

app.get('/api/v2/gateway/version', (req, res) => {
  res.json({ version: 'v4.0.0', build: '2026-07-31' });
});

app.get('/api/v2/sys/auth/signature-info', (req, res) => {
  res.json({ algorithm: 'HMAC-SHA256' });
});

app.get('/api/v2/sys/management/fingerprints', hmacMiddleware, (req, res) => {
  res.json({ success: true, fingerprints: DB.fingerprints });
});

app.get('/api/v2/sys/management/logs/archive', hmacMiddleware, (req, res) => {
  res.json({ success: true, auditLogCount: DB.auditLog.length });
});

app.get('/api/v2/user/sessions', authMiddleware, (req, res) => {
  res.json({ success: true, sessions: [] });
});

app.get('/api/v2/sys/multiplayer/stats', hmacMiddleware, (req, res) => {
  if (!verifyAdmin(req.query.admin_password || req.body?.admin_password)) return res.status(403).json({ error: '管理密码错误' });
  res.json(mpServer.getStats());
});

// ============ 多人联机 WebSocket ============
const wss = new ws.WebSocketServer({ server, path: '/gateway/realtime' });
const mpServer = new MultiplayerServer(wss, (token) => {
  if (!token) return { valid: false, userId: 'anon', username: '游客' };
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    return { valid: true, userId: decoded.id || decoded.sub, username: decoded.username || '战士' };
  } catch (e) { return { valid: false, userId: 'anon', username: '游客' }; }
});
wss.on('connection', (ws, req) => { mpServer.onConnection(ws, req); });
mpServer.start();

// ============ 错误处理 ============
app.use((err, req, res, next) => { console.error('[错误]', err.message); res.status(500).json({ error: '服务器内部错误' }); });
app.use((req, res) => { res.status(404).json({ error: '页面不存在' }); });

// ============ 启动服务器 ============
server.listen(PORT, () => {
  console.log('[联机] 服务器已启动 tick=15Hz');
  console.log('========================================');
  console.log('手机多租户虚拟主机 v4.0.0 安全加固版');
  console.log('========================================');
  console.log(`监听端口: ${PORT}`);
  console.log(`管理密码: ${ADMIN_PASSWORD ? '已设置(环境变量)' : '未设置(随机生成)'}`);
  console.log(`用户数量: ${Object.keys(DB.users).length}`);
  console.log(`主机数量: ${Object.keys(DB.hosts).length}`);
  console.log('========================================');
  console.log(`游戏页面: http://127.0.0.1:${PORT}/`);
  console.log(`测试页面: http://127.0.0.1:${PORT}/test`);
  console.log(`管理后台: http://127.0.0.1:${PORT}/panel.html`);
  console.log('========================================');
  console.log('[安全] 已添加白名单IP: ' + (DB.whitelist.length > 0 ? DB.whitelist.join(', ') : '无'));
  console.log('[安全] IP封禁功能已禁用（仅记录不封禁）');
  console.log('[CSP] 游戏页面已放开CSP，允许内联脚本和CDN资源');
  console.log('========================================');
});

process.on('SIGTERM', () => { server.close(); process.exit(0); });
process.on('SIGINT', () => { server.close(); process.exit(0); });
