// ============================================
// 手机多租户虚拟主机 v4.0.0 安全加固版
// ============================================
'use strict';

const express = require('express');
const http = require('http');
const https = require('https');
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
let DB = { users: {}, hosts: {}, sessions: {}, refreshTokens: {}, blockedIPs: {}, ipBehavior: {}, fingerprints: {}, mouseData: {}, nonces: {}, auditLog: [], lockouts: {}, whitelist: [] };
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

// bcrypt 兼容层（优先使用 bcryptjs，否则降级 SHA256）
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
    this.userRateLimits = {}; // 用户级限流
    this.nonceStore = {}; // nonce 持久化防重放
  }

  // 获取请求计数键
  getRateKey(req) {
    const ip = getClientIP(req);
    const userId = req.user?.id || 'anon';
    const deviceId = req.headers['x-device-id'] || 'unknown';
    return `${ip}:${userId}:${deviceId}`;
  }

  // 检查白名单
  isWhitelisted(ip) {
    return DB.whitelist.includes(ip);
  }

  // 频率限制
  checkRateLimit(req, type = 'default') {
    const ip = getClientIP(req);
    if (this.isWhitelisted(ip)) return true;

    const now = Date.now();
    const key = ip + ':' + type;

    if (!this.requestCounts[key]) this.requestCounts[key] = { count: 0, reset: now + 60000, level: 0 };
    const entry = this.requestCounts[key];

    if (now > entry.reset) { entry.count = 0; entry.reset = now + 60000; }
    entry.count++;

    const limits = {
      default: 600, upload: 80, login: 60, search: 120, admin: 30
    };
    const limit = limits[type] || 600;

    if (entry.count > limit) {
      entry.level = Math.min(entry.level + 1, 5);
      return false;
    }
    return true;
  }

  getRateLimitLevel(req, type = 'default') {
    const ip = getClientIP(req);
    const key = ip + ':' + type;
    const entry = this.requestCounts[key];
    return entry ? entry.level : 0;
  }

  // 检查登录尝试
  checkLoginAttempt(username) {
    const now = Date.now();
    if (!this.loginAttempts[username]) {
      this.loginAttempts[username] = { count: 0, firstAttempt: now, lockedUntil: 0 };
    }
    const entry = this.loginAttempts[username];
    if (now < entry.lockedUntil) {
      const remaining = Math.ceil((entry.lockedUntil - now) / 1000 / 60);
      return { locked: true, remaining };
    }
    if (now - entry.firstAttempt > 15 * 60 * 1000) {
      entry.count = 0;
      entry.firstAttempt = now;
    }
    return { locked: false };
  }

  recordLoginFailure(username) {
    const entry = this.loginAttempts[username] || { count: 0, firstAttempt: Date.now(), lockedUntil: 0 };
    entry.count++;
    if (entry.count >= 20) entry.lockedUntil = Date.now() + 24 * 60 * 60 * 1000;
    else if (entry.count >= 10) entry.lockedUntil = Date.now() + 30 * 60 * 1000;
    else if (entry.count >= 5) entry.lockedUntil = Date.now() + 5 * 60 * 1000;
    this.loginAttempts[username] = entry;
  }

  resetLoginAttempt(username) {
    delete this.loginAttempts[username];
  }

  // CC攻击检测
  checkCCAttack(ip) {
    const now = Date.now();
    const key = ip + ':cc';
    if (!this.requestCounts[key]) this.requestCounts[key] = { count: 0, reset: now + 10000 };
    const entry = this.requestCounts[key];
    if (now > entry.reset) { entry.count = 0; entry.reset = now + 10000; }
    entry.count++;
    return entry.count > 250;
  }

  // 全局熔断
  checkGlobalCircuitBreaker() {
    const now = Date.now();
    if (now > this.globalRequestReset) {
      this.globalRequestCount = 0;
      this.globalRequestReset = now + 60000;
      if (this.attackMode && now > this.attackRecovery) {
        this.attackMode = false;
        console.log('[防护] 攻击模式已解除');
      }
    }
    this.globalRequestCount++;
    if (this.globalRequestCount > 8000 && !this.attackMode) {
      this.attackMode = true;
      this.attackRecovery = now + 10 * 60 * 1000;
      console.log('[防护] 全局熔断：进入攻击模式10分钟');
      fs.writeFileSync(path.join(DATA_DIR, '.attack_shutdown'), '1');
    }
    return this.attackMode;
  }

  // 封禁IP
  blockIP(ip, reason = '安全策略', duration = 30 * 60 * 1000) {
    if (this.isWhitelisted(ip)) return;
    DB.blockedIPs[ip] = Date.now() + duration;
    saveBlocked();
    console.log(`[封禁] ${ip} - ${reason} - ${duration / 1000 / 60}分钟`);
  }

  isBlocked(ip) {
    if (this.isWhitelisted(ip)) return false;
    const unblockTime = DB.blockedIPs[ip];
    if (!unblockTime) return false;
    if (Date.now() > unblockTime) {
      delete DB.blockedIPs[ip];
      saveBlocked();
      return false;
    }
    return true;
  }

  // 蜜罐检测
  checkHoneypot(path) {
    return this.honeypots.some(h => path.toLowerCase().startsWith(h.toLowerCase()) || path.toLowerCase() === h.toLowerCase());
  }

  // 文件类型验证
  validateFileType(filePath, mimeType) {
    const dangerousExtensions = ['.exe', '.dll', '.so', '.dylib', '.php', '.phtml', '.php3', '.php4', '.php5', '.phar', '.py', '.pyc', '.sh', '.bash', '.cgi', '.pl', '.jsp', '.asp', '.aspx', '.war', '.jar', '.rb', '.bat', '.cmd', '.ps1', '.vbs', '.wsf', '.msi', '.com'];
    const ext = path.extname(filePath).toLowerCase();
    if (dangerousExtensions.includes(ext)) return false;
    // 魔术字节检测
    try {
      const buf = fs.readFileSync(filePath);
      if (buf.length > 4) {
        if (buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46) return false; // ELF
        if (buf[0] === 0x4d && buf[1] === 0x5a) return false; // PE/DOS
        if (buf.toString('utf8', 0, 5) === '<?php') return false; // PHP
      }
    } catch (e) {}
    return true;
  }

  // 浏览器指纹存储
  storeFingerprint(userId, fingerprint, ip) {
    const hash = crypto.createHash('md5').update(JSON.stringify(fingerprint)).digest('hex');
    if (!DB.fingerprints[userId]) {
      DB.fingerprints[userId] = { hash, firstSeen: new Date().toISOString(), lastSeen: new Date().toISOString(), ip, changeCount: 0, history: [hash] };
      return { changed: false, score: 100 };
    }
    const entry = DB.fingerprints[userId];
    if (entry.hash !== hash) {
      entry.changeCount++;
      entry.history.push(hash);
      if (entry.history.length > 10) entry.history.shift();
      if (entry.changeCount > 3) {
        const last24h = entry.history.filter((h, i) => {
          const ts = new Date(entry.lastSeen);
          return Date.now() - ts.getTime() < 24 * 60 * 60 * 1000;
        });
        if (last24h.length > 3) {
          this.blockIP(ip, '指纹频繁变化', 24 * 60 * 60 * 1000);
          return { changed: true, score: 0, blocked: true };
        }
      }
    }
    entry.hash = hash;
    entry.lastSeen = new Date().toISOString();
    entry.ip = ip;
    return { changed: entry.hash !== hash, score: Math.max(0, 100 - entry.changeCount * 20) };
  }

  // 请求间隔分析
  analyzeRequestIntervals(ip, intervals) {
    if (intervals.length < 2) return { isAutomated: false, confidence: 0 };
    const mean = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    const variance = intervals.reduce((a, b) => a + (b - mean) ** 2, 0) / intervals.length;
    const cv = Math.sqrt(variance) / mean;
    // 变异系数过低表示自动化
    const isAutomated = cv < 0.1;
    const confidence = Math.min(1, Math.max(0, 1 - cv));
    return { isAutomated, confidence, cv, mean };
  }

  // 鼠标轨迹分析
  analyzeMouseData(events) {
    if (!events || events.length < 5) return { isHuman: false, confidence: 0, reason: '数据不足' };
    // 直线段比例
    let straightSegments = 0;
    let totalSegments = events.length - 1;
    for (let i = 1; i < events.length; i++) {
      const dx = events[i].x - events[i - 1].x;
      const dy = events[i].y - events[i - 1].y;
      const dist = Math.sqrt(dx * dx + dy * dy);
      const prevDx = i > 1 ? events[i - 1].x - events[i - 2].x : 0;
      const prevDy = i > 1 ? events[i - 1].y - events[i - 2].y : 0;
      const prevDist = Math.sqrt(prevDx * prevDx + prevDy * prevDy);
      if (dist > 0 && prevDist > 0) {
        const dot = (dx * prevDx + dy * prevDy) / (dist * prevDist);
        if (Math.abs(dot) > 0.99) straightSegments++;
      }
    }
    // 速度变化
    const speeds = [];
    for (let i = 1; i < events.length; i++) {
      const dt = events[i].t - events[i - 1].t;
      if (dt > 0) {
        const dx = events[i].x - events[i - 1].x;
        const dy = events[i].y - events[i - 1].y;
        speeds.push(Math.sqrt(dx * dx + dy * dy) / dt);
      }
    }
    const speedVariation = speeds.length > 1 ? Math.sqrt(speeds.reduce((a, v) => a + (v - speeds.reduce((a, b) => a + b, 0) / speeds.length) ** 2, 0) / speeds.length) / (speeds.reduce((a, b) => a + b, 0) / speeds.length) : 0;
    const straightRatio = straightSegments / Math.max(1, totalSegments);
    const isHuman = straightRatio < 0.7 && speedVariation > 0.2;
    const confidence = ((1 - straightRatio) * 0.5 + Math.min(speedVariation, 1) * 0.5);
    return { isHuman, confidence, straightRatio, speedVariation };
  }

  // 行为评分
  updateBehaviorScore(ip, action) {
    if (!DB.ipBehavior[ip]) DB.ipBehavior[ip] = { score: 100, totalRequests: 0, suspiciousActions: 0, lastSeen: new Date().toISOString() };
    const entry = DB.ipBehavior[ip];
    entry.totalRequests++;
    entry.lastSeen = new Date().toISOString();
    const penalties = { honeypot: 40, blocked_access: 30, rapid_request: 20, invalid_auth: 15, suspicious_upload: 25, invalid_signature: 20, csrf_violation: 25 };
    if (penalties[action]) {
      entry.score -= penalties[action];
      entry.suspiciousActions++;
      if (entry.score < 30) this.blockIP(ip, '行为评分过低', 24 * 60 * 60 * 1000);
    }
    return entry;
  }

  // 用户级限流
  checkUserRateLimit(userId, type = 'default') {
    const now = Date.now();
    const key = `user:${userId}:${type}`;
    if (!this.userRateLimits[key]) this.userRateLimits[key] = { count: 0, reset: now + 60000 };
    const entry = this.userRateLimits[key];
    if (now > entry.reset) { entry.count = 0; entry.reset = now + 60000; }
    entry.count++;
    const limits = { default: 300, upload: 60, delete: 30, password: 10 };
    return entry.count <= (limits[type] || 300);
  }

  // Nonce 防重放
  checkNonce(nonce, maxAge = 300000) {
    const now = Date.now();
    // 清理过期 nonce
    for (const [n, ts] of Object.entries(this.nonceStore)) {
      if (now - ts > maxAge) delete this.nonceStore[n];
    }
    if (this.nonceStore[nonce]) return false;
    this.nonceStore[nonce] = now;
    return true;
  }

  // 检查资源过载
  checkResourceOverload() {
    const memUsage = process.memoryUsage();
    const heapUsedMB = memUsage.heapUsed / 1024 / 1024;
    const heapTotalMB = memUsage.heapTotal / 1024 / 1024;
    if (heapUsedMB / heapTotalMB > 0.9) {
      this.attackMode = true;
      this.attackRecovery = Date.now() + 10 * 60 * 1000;
      return true;
    }
    return false;
  }
}

const security = new SecurityModule();

// ============ Express 初始化 ============
const app = express();
const server = http.createServer(app);

// ⚡ 闪电盾：最早拦截层 — 在压缩/CORS/body解析之前就拒绝
// 扫描器请求在这里被秒杀，不消耗任何业务资源
app.use((req, res, next) => {
  const ip = req.headers['cf-connecting-ip'] || req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.headers['x-real-ip'] || req.socket.remoteAddress?.replace('::ffff:', '') || '127.0.0.1';

  // 1. 已封禁 IP → 直接拒绝，跳过所有后续处理
  if (security.isBlocked(ip)) {
    return res.status(403).end();
  }

  // 2. 全局攻击模式 → 只放行白名单和登录
  if (security.attackMode && !security.isWhitelisted(ip)) {
    const p = req.path.toLowerCase();
    if (!p.startsWith('/api/v2/auth/') && !p.startsWith('/api/v2/gateway/health')) {
      return res.status(503).end();
    }
  }

  // 3. 已知扫描器 UA → 秒封
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

  // 4. 缺失 User-Agent 的请求 → 大概率是扫描器
  // 排除本地/白名单/局域网IP，防止误封自己
  if (!ua && !req.path.startsWith('/api/') && !security.isWhitelisted(ip) &&
      !ip.startsWith('127.') && !ip.startsWith('::1') && !ip.startsWith('192.168.') && !ip.startsWith('10.') && !ip.startsWith('172.')) {
    const k = 'noua:' + ip;
    if (!security.requestCounts) security.requestCounts = {};
    if (!security.requestCounts[k]) security.requestCounts[k] = { count: 0, reset: Date.now() + 60000 };
    const e = security.requestCounts[k];
    if (Date.now() > e.reset) { e.count = 0; e.reset = Date.now() + 60000; }
    e.count++;
    if (e.count > 5) {
      console.log(`[安全] 无UA请求: ${ip}，仅记录不封禁（来源可疑但非明确攻击）`);
      // 不再自动封禁，改为日志警告
    }
  }

  // 5. 根路径高频扫描 → 秒封
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

// CSP 头
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
          // 放宽：允许无Origin的请求（原生App等）
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

  // 检查封禁
  if (security.isBlocked(ip)) {
    security.updateBehaviorScore(ip, 'blocked_access');
    return res.status(403).json({ error: '请求被拒绝' });
  }

  // 攻击模式
  if (security.attackMode && !security.isWhitelisted(ip)) {
    if (path.startsWith('/api/v2/auth/') || path.startsWith('/api/v2/gateway/health')) {
      // 允许登录和健康检查
    } else {
      return res.status(503).json({ error: '服务暂时不可用' });
    }
  }

  // 蜜罐检测
  if (security.checkHoneypot(path)) {
    security.blockIP(ip, '触碰蜜罐', 7 * 24 * 60 * 60 * 1000);
    security.updateBehaviorScore(ip, 'honeypot');
    return res.status(404).end();
  }

  // CC攻击检测
  if (security.checkCCAttack(ip)) {
    security.blockIP(ip, 'CC攻击', 30 * 60 * 1000);
    security.updateBehaviorScore(ip, 'rapid_request');
    return res.status(429).json({ error: '请求过于频繁' });
  }

  // 速率限制
  if (!security.checkRateLimit(req)) {
    const level = security.getRateLimitLevel(req);
    const messages = ['', '请放慢速度', '请放慢速度', '临时限流，5分钟后自动恢复', '严重限流，15分钟后自动恢复', ''];
    if (level >= 5) {
      security.blockIP(ip, '5级限流触发', 60 * 60 * 1000);
      return res.status(429).json({ error: '请求过于频繁' });
    }
    if (level >= 3) {
      security.blockIP(ip, `${level}级限流`, [0, 0, 0, 5, 15][level] * 60 * 1000);
    }
    return res.status(429).json({ error: messages[level] || '请求过于频繁' });
  }

  // 全局熔断
  security.checkGlobalCircuitBreaker();

  // 资源检查
  security.checkResourceOverload();

  next();
});

// JWT 认证中间件
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: '请先登录' });
  }
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (e) {
    if (e.name === 'TokenExpiredError') {
      return res.status(401).json({ error: '令牌已过期', code: 'TOKEN_EXPIRED' });
    }
    return res.status(401).json({ error: '认证失败' });
  }
}

// HMAC 签名验证中间件（管理接口）
function hmacMiddleware(req, res, next) {
  const timestamp = req.headers['x-request-time'];
  const nonce = req.headers['x-request-nonce'];
  const signature = req.headers['x-request-signature'];
  if (!timestamp || !nonce || !signature) {
    return res.status(400).json({ error: '缺少签名参数' });
  }
  const now = Date.now();
  if (Math.abs(now - parseInt(timestamp)) > 5 * 60 * 1000) {
    return res.status(400).json({ error: '请求已过期' });
  }
  if (!security.checkNonce(nonce)) {
    return res.status(400).json({ error: '请求已处理' });
  }
  const bodyHash = crypto.createHash('sha256').update(JSON.stringify(req.body || {})).digest('hex');
  if (!verifyHMAC(req.method, req.path, timestamp, nonce, bodyHash, signature)) {
    security.updateBehaviorScore(getClientIP(req), 'invalid_signature');
    return res.status(400).json({ error: '签名验证失败' });
  }
  next();
}

// 文件上传配置
const upload = multer({
  dest: path.join(DATA_DIR, 'uploads'),
  limits: { fileSize: MAX_FILE_SIZE, files: 1 },
  fileFilter: (req, file, cb) => {
    const dangerousMime = ['application/x-msdownload', 'application/x-msdos-program', 'application/x-elf', 'application/x-php', 'text/x-php', 'text/x-python', 'application/x-sh'];
    if (dangerousMime.includes(file.mimetype)) {
      cb(new Error('文件类型不允许'), false);
    } else {
      cb(null, true);
    }
  }
});

// ============ 静态文件 ============
app.use('/h', express.static(HOSTS_DIR, { index: 'index.html', dotfiles: 'deny' }));
app.use(express.static(PUBLIC_DIR, { index: false }));

// ============ 面板页面 ============
app.get('/panel.html', (req, res) => {
  const panelPath = path.join(__dirname, 'panel.html');
  if (fs.existsSync(panelPath)) {
    res.sendFile(panelPath);
  } else {
    res.sendFile(path.join(PUBLIC_DIR, 'panel.html'));
  }
});
app.get('/host.html', (req, res) => res.redirect('/panel.html'));
app.get('/admin.html', (req, res) => res.redirect('/panel.html'));

// ============ 测试页面（验证CSP修复） ============
app.get('/test', (req, res) => {
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.setHeader('Content-Security-Policy', "default-src * 'unsafe-inline' 'unsafe-eval'; script-src * 'unsafe-inline' 'unsafe-eval'; style-src * 'unsafe-inline'; connect-src * ws: wss:; img-src * data: blob:;");
  res.removeHeader('X-Frame-Options');
  res.type('html').send(`<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>测试页面</title>
<style>
body{background:#0a0c08;color:#eee;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;flex-direction:column;gap:16px}
.btn{padding:16px 40px;font-size:18px;border:2px solid #8a7c50;background:linear-gradient(180deg,#5a5236,#3a3422);color:#f0e6c0;border-radius:6px;cursor:pointer}
.btn:hover{box-shadow:0 0 18px rgba(220,190,110,.4)}
.msg{color:#8f8;margin-top:12px;font-size:14px}
</style></head>
<body>
<h1>✅ CSP 修复测试</h1>
<button class="btn" onclick="document.getElementById('r1').textContent='点击成功！按钮正常工作'">测试按钮 1</button>
<button class="btn" id="btn2">测试按钮 2(JS绑定)</button>
<div class="msg" id="r1"></div>
<div class="msg" id="r2"></div>
<script>
document.getElementById('btn2').onclick=function(){
  document.getElementById('r2').textContent='JS绑定按钮也正常工作！';
};
console.log('测试页面脚本已执行');
</script>
</body></html>`);
});

// ============ 认证接口 ============

// ① 注册
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

    // 创建主机目录
    const hostDir = path.join(HOSTS_DIR, uid);
    if (!fs.existsSync(hostDir)) fs.mkdirSync(hostDir, { recursive: true });

    // 生成 tokens
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

// ② 登录
app.post('/api/v2/auth/session/init', (req, res) => {
  try {
    const ip = getClientIP(req);
    const { username, password } = req.body;

    if (!username || !password) return res.status(400).json({ error: '参数不完整' });
    const uname = sanitize(username);

    // 检查账户锁定
    const lockCheck = security.checkLoginAttempt(uname);
    if (lockCheck.locked) {
      return res.status(423).json({ error: `账户已锁定，${lockCheck.remaining}分钟后重试` });
    }

    const user = DB.users[uname];
    if (!user || !verifyPasswordBcrypt(password, user.password)) {
      security.recordLoginFailure(uname);
      return res.status(401).json({ error: '用户名或密码错误' });
    }

    if (user.banned) {
      return res.status(403).json({ error: user.banReason || '账号已被封禁' });
    }

    security.resetLoginAttempt(uname);

    // 更新登录信息
    user.lastLogin = new Date().toISOString();
    if (!user.knownIPs) user.knownIPs = [];
    if (!user.knownIPs.includes(ip)) {
      user.knownIPs.push(ip);
      if (user.knownIPs.length > 10) user.knownIPs.shift();
    }

    // 检查异地登录
    let geoAlert = null;
    if (user.knownIPs.length > 1) {
      const uniqueIPs = [...new Set(user.knownIPs)];
      if (uniqueIPs.length > 1) {
        geoAlert = { message: '异地登录风险', uniqueIPs: uniqueIPs.length };
      }
    }

    // 生成 tokens
    const token = jwt.sign({ id: user.id, username: uname, plan: user.plan }, JWT_SECRET, { expiresIn: TOKEN_EXPIRY });
    const refreshToken = jwt.sign({ id: user.id, username: uname, type: 'refresh' }, REFRESH_SECRET, { expiresIn: REFRESH_EXPIRY });
    DB.refreshTokens[refreshToken] = { userId: user.id, username: uname, createdAt: Date.now() };

    // 会话管理
    const sessionId = generateSessionId();
    if (!DB.sessions[user.id]) DB.sessions[user.id] = [];
    DB.sessions[user.id].push({ token: sessionId, ip, device: req.headers['user-agent']?.substring(0, 100) || 'Unknown', loginTime: new Date().toISOString(), lastSeen: new Date().toISOString() });
    if (DB.sessions[user.id].length > 10) DB.sessions[user.id].shift();

    // 新用户保护期
    if (user.isNewUserGrace && Date.now() > (user.graceUntil || 0)) {
      user.isNewUserGrace = false;
    }

    saveDB();
    logAudit('login', ip, `用户登录: ${uname}`);

    res.json({ success: true, token, refreshToken, geoAlert, sessionId });
  } catch (e) {
    console.error('[登录]', e.message);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ㉘ Refresh Token 刷新
app.post('/api/v2/auth/session/refresh', (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(400).json({ error: '参数不完整' });

    const stored = DB.refreshTokens[refreshToken];
    if (!stored) return res.status(401).json({ error: 'Refresh Token 无效' });

    try {
      const decoded = jwt.verify(refreshToken, REFRESH_SECRET);
      if (decoded.type !== 'refresh') return res.status(401).json({ error: 'Token 类型错误' });

      // Token 轮换：旧 token 失效
      delete DB.refreshTokens[refreshToken];

      const user = DB.users[decoded.username];
      if (!user) return res.status(401).json({ error: '用户不存在' });

      const newToken = jwt.sign({ id: decoded.id, username: decoded.username, plan: user.plan }, JWT_SECRET, { expiresIn: TOKEN_EXPIRY });
      const newRefreshToken = jwt.sign({ id: decoded.id, username: decoded.username, type: 'refresh' }, REFRESH_SECRET, { expiresIn: REFRESH_EXPIRY });
      DB.refreshTokens[newRefreshToken] = { userId: decoded.id, username: decoded.username, createdAt: Date.now() };

      saveDB();
      res.json({ success: true, token: newToken, refreshToken: newRefreshToken, userId: decoded.id, username: decoded.username });
    } catch (e) {
      delete DB.refreshTokens[refreshToken];
      return res.status(401).json({ error: 'Refresh Token 已过期' });
    }
  } catch (e) {
    console.error('[刷新Token]', e.message);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ㉙ 登出
app.post('/api/v2/auth/session/revoke', authMiddleware, (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (refreshToken) {
      delete DB.refreshTokens[refreshToken];
    } else {
      // 撤销所有
      for (const [rt, data] of Object.entries(DB.refreshTokens)) {
        if (data.userId === req.user.id) delete DB.refreshTokens[rt];
      }
    }
    saveDB();
    res.json({ success: true, message: '已登出' });
  } catch (e) {
    console.error('[登出]', e.message);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ㉞ 浏览器指纹提交
app.post('/api/v2/auth/fingerprint', (req, res) => {
  try {
    const ip = getClientIP(req);
    const { fingerprint } = req.body;
    if (!fingerprint) return res.status(400).json({ error: '参数不完整' });

    const userId = req.user?.id || req.headers['x-session-id'] || 'anon';
    const result = security.storeFingerprint(userId, fingerprint, ip);
    res.json({ success: true, ...result });
  } catch (e) {
    console.error('[指纹]', e.message);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ㉟ 鼠标轨迹提交
app.post('/api/v2/auth/mouse-data', (req, res) => {
  try {
    const { events, sessionId } = req.body;
    if (!events || !Array.isArray(events) || events.length > 50) {
      return res.status(400).json({ error: '参数无效' });
    }

    const key = sessionId || getClientIP(req);
    if (!DB.mouseData[key]) DB.mouseData[key] = [];
    DB.mouseData[key].push(...events);
    if (DB.mouseData[key].length > 200) DB.mouseData[key] = DB.mouseData[key].slice(-200);

    const result = security.analyzeMouseData(DB.mouseData[key]);
    res.json({ success: true, ...result });
  } catch (e) {
    console.error('[鼠标]', e.message);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ============ 用户接口 ============

// ③ 获取用户信息
app.get('/api/v2/user/profile/detail', authMiddleware, (req, res) => {
  try {
    const user = DB.users[req.user.username];
    if (!user) return res.status(404).json({ error: '用户不存在' });

    const host = DB.hosts[user.id];
    const hostPassword = decryptHostPassword(user.hostPassword) || '解密失败';

    res.json({
      username: user.username,
      uid: user.id,
      plan: user.plan,
      planName: user.planName,
      registered: user.registered,
      lastLogin: user.lastLogin,
      spaceUsedMB: user.spaceUsedMB || 0,
      spaceLimitMB: user.spaceLimitMB || 100,
      hostPassword: hostPassword,
      hostUrl: `/h/${user.id}/`,
      isNewUserGrace: user.isNewUserGrace || false,
      banned: user.banned || false,
      banReason: user.banReason || null
    });
  } catch (e) {
    console.error('[用户信息]', e.message);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ⑪ 修改密码
app.post('/api/v2/user/profile/password', authMiddleware, (req, res) => {
  try {
    const { old_password, new_password } = req.body;
    if (!old_password || !new_password) return res.status(400).json({ error: '参数不完整' });

    const user = DB.users[req.user.username];
    if (!user) return res.status(404).json({ error: '用户不存在' });

    if (!verifyPasswordBcrypt(old_password, user.password)) {
      return res.status(400).json({ error: '旧密码错误' });
    }

    const pwError = validatePasswordStrength(new_password);
    if (pwError) return res.status(400).json({ error: pwError });

    user.password = hashPasswordBcrypt(new_password);
    saveDB();
    logAudit('password_change', getClientIP(req), `用户修改密码: ${req.user.username}`);
    res.json({ success: true });
  } catch (e) {
    console.error('[修改密码]', e.message);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ⑬ 删除账号
app.post('/api/v2/user/profile/delete', authMiddleware, (req, res) => {
  try {
    const { password } = req.body;
    if (!password) return res.status(400).json({ error: '参数不完整' });

    const user = DB.users[req.user.username];
    if (!user) return res.status(404).json({ error: '用户不存在' });

    if (!verifyPasswordBcrypt(password, user.password)) {
      return res.status(400).json({ error: '密码错误' });
    }

    // 删除主机目录
    const hostDir = path.join(HOSTS_DIR, user.id);
    if (fs.existsSync(hostDir)) fs.rmSync(hostDir, { recursive: true, force: true });

    // 删除用户数据
    delete DB.users[req.user.username];
    delete DB.hosts[user.id];
    delete DB.sessions[user.id];
    for (const [rt, data] of Object.entries(DB.refreshTokens)) {
      if (data.userId === user.id) delete DB.refreshTokens[rt];
    }

    saveDB();
    logAudit('account_delete', getClientIP(req), `用户删除账号: ${req.user.username}`);
    res.json({ success: true, message: '账号已删除' });
  } catch (e) {
    console.error('[删除账号]', e.message);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ㉒ 会话管理 - 查看
app.get('/api/v2/user/sessions', authMiddleware, (req, res) => {
  try {
    const sessions = DB.sessions[req.user.id] || [];
    res.json({ sessions, total: sessions.length });
  } catch (e) {
    console.error('[会话]', e.message);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ㉓ 会话管理 - 撤销
app.post('/api/v2/user/sessions/revoke', authMiddleware, (req, res) => {
  try {
    const { token_prefix } = req.body;
    const sessions = DB.sessions[req.user.id] || [];
    DB.sessions[req.user.id] = sessions.filter(s => !s.token.startsWith(token_prefix));
    saveDB();
    res.json({ success: true });
  } catch (e) {
    console.error('[撤销会话]', e.message);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ㉔ 用户活动日志
app.get('/api/v2/user/activity', authMiddleware, (req, res) => {
  try {
    const user = DB.users[req.user.username];
    if (!user) return res.status(404).json({ error: '用户不存在' });

    res.json({
      username: user.username,
      registered: user.registered,
      lastLogin: user.lastLogin,
      plan: user.plan,
      planName: user.planName,
      spaceUsedMB: user.spaceUsedMB || 0,
      spaceLimitMB: user.spaceLimitMB || 100,
      knownIPs: user.knownIPs || [],
      ipCount: (user.knownIPs || []).length,
      sessions: (DB.sessions[user.id] || []).length,
      isNewUserGrace: user.isNewUserGrace || false,
      banned: user.banned || false,
      banReason: user.banReason || null
    });
  } catch (e) {
    console.error('[活动日志]', e.message);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ============ 存储接口 ============

// ⑤ 上传文件
app.post('/api/v2/storage/files/upload/:uid', authMiddleware, (req, res) => {
  try {
    const ip = getClientIP(req);
    const { uid } = req.params;

    if (!security.checkRateLimit(req, 'upload')) {
      return res.status(429).json({ error: '上传过于频繁' });
    }

    const user = DB.users[req.user.username];
    if (!user) return res.status(404).json({ error: '用户不存在' });
    if (user.id !== uid) return res.status(403).json({ error: '无权操作此主机' });

    upload.single('file')(req, res, (err) => {
      if (err) {
        if (err.code === 'LIMIT_FILE_SIZE') return res.status(413).json({ error: '文件超过50MB限制' });
        return res.status(400).json({ error: '上传失败' });
      }

      if (!req.file) return res.status(400).json({ error: '请选择文件' });

      const originalName = sanitize(req.file.originalname || 'unnamed');
      const hostDir = path.join(HOSTS_DIR, uid);
      if (!fs.existsSync(hostDir)) fs.mkdirSync(hostDir, { recursive: true });

      const destPath = path.join(hostDir, originalName);

      // 文件类型验证
      if (!security.validateFileType(req.file.path, req.file.mimetype)) {
        fs.unlinkSync(req.file.path);
        security.updateBehaviorScore(ip, 'suspicious_upload');
        return res.status(400).json({ error: '文件类型不允许' });
      }

      // 检查空间
      const hostFiles = DB.hosts[uid]?.files || [];
      let totalSize = 0;
      hostFiles.forEach(f => { totalSize += f.size || 0; });
      if (totalSize + req.file.size > user.spaceLimitMB * 1024 * 1024) {
        fs.unlinkSync(req.file.path);
        return res.status(413).json({ error: '空间不足' });
      }

      // 移动文件
      fs.renameSync(req.file.path, destPath);

      // 更新记录
      const existingIdx = hostFiles.findIndex(f => f.name === originalName);
      const fileInfo = { name: originalName, size: req.file.size, uploadedAt: new Date().toISOString(), type: req.file.mimetype };
      if (existingIdx >= 0) {
        hostFiles[existingIdx] = fileInfo;
      } else {
        hostFiles.push(fileInfo);
      }
      if (!DB.hosts[uid]) DB.hosts[uid] = { owner: req.user.username, files: [] };
      DB.hosts[uid].files = hostFiles;

      // 更新空间使用
      user.spaceUsedMB = Math.round(totalSize + req.file.size) / 1024 / 1024;

      saveDB();
      logAudit('upload', ip, `上传文件: ${uid}/${originalName}`);
      res.json({ success: true, file: fileInfo });
    });
  } catch (e) {
    console.error('[上传]', e.message);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ⑥ 文件列表
app.get('/api/v2/storage/files/list/:uid', authMiddleware, (req, res) => {
  try {
    const { uid } = req.params;
    const user = DB.users[req.user.username];
    if (!user || user.id !== uid) return res.status(403).json({ error: '无权访问' });

    const host = DB.hosts[uid] || { files: [] };
    const hostDir = path.join(HOSTS_DIR, uid);
    const dirs = [];
    const files = [];

    if (fs.existsSync(hostDir)) {
      const entries = fs.readdirSync(hostDir, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.isDirectory()) {
          dirs.push({ name: entry.name, type: 'directory' });
        } else {
          const stat = fs.statSync(path.join(hostDir, entry.name));
          files.push({ name: entry.name, size: stat.size, type: 'file', uploadedAt: stat.mtime.toISOString() });
        }
      }
    }

    res.json({ dirs, files, total: dirs.length + files.length });
  } catch (e) {
    console.error('[文件列表]', e.message);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ⑦ 删除文件
app.post('/api/v2/storage/files/remove/:uid/:filename', authMiddleware, (req, res) => {
  try {
    const { uid, filename } = req.params;
    const user = DB.users[req.user.username];
    if (!user || user.id !== uid) return res.status(403).json({ error: '无权操作' });

    // 密码确认（文件删除）
    const { password } = req.body || {};
    if (password) {
      if (!verifyPasswordBcrypt(password, user.password)) {
        return res.status(400).json({ error: '密码错误' });
      }
    }

    const filePath = path.join(HOSTS_DIR, uid, sanitize(filename));
    if (!fs.existsSync(filePath)) return res.status(404).json({ error: '文件不存在' });

    const stat = fs.statSync(filePath);
    fs.unlinkSync(filePath);

    // 更新空间
    user.spaceUsedMB = Math.max(0, (user.spaceUsedMB || 0) - stat.size / 1024 / 1024);

    // 更新文件列表
    if (DB.hosts[uid]?.files) {
      DB.hosts[uid].files = DB.hosts[uid].files.filter(f => f.name !== filename);
    }

    saveDB();
    logAudit('delete', getClientIP(req), `删除文件: ${uid}/${filename}`);
    res.json({ success: true });
  } catch (e) {
    console.error('[删除文件]', e.message);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ⑦-1 文件改名
app.post('/api/v2/storage/files/rename/:uid/:filename', authMiddleware, (req, res) => {
  try {
    const { uid, filename } = req.params;
    const { new_name } = req.body;
    if (!new_name) return res.status(400).json({ error: '参数不完整' });

    const user = DB.users[req.user.username];
    if (!user || user.id !== uid) return res.status(403).json({ error: '无权操作' });

    const oldPath = path.join(HOSTS_DIR, uid, sanitize(filename));
    const newPath = path.join(HOSTS_DIR, uid, sanitize(new_name));
    if (!fs.existsSync(oldPath)) return res.status(404).json({ error: '文件不存在' });
    if (fs.existsSync(newPath)) return res.status(409).json({ error: '目标文件名已存在' });

    fs.renameSync(oldPath, newPath);

    if (DB.hosts[uid]?.files) {
      const file = DB.hosts[uid].files.find(f => f.name === filename);
      if (file) file.name = sanitize(new_name);
    }

    saveDB();
    res.json({ success: true });
  } catch (e) {
    console.error('[改名]', e.message);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ⑦-2 创建文件夹
app.post('/api/v2/storage/files/mkdir/:uid', authMiddleware, (req, res) => {
  try {
    const { uid } = req.params;
    const { dir_name } = req.body;
    if (!dir_name) return res.status(400).json({ error: '参数不完整' });

    const user = DB.users[req.user.username];
    if (!user || user.id !== uid) return res.status(403).json({ error: '无权操作' });

    const dirPath = path.join(HOSTS_DIR, uid, sanitize(dir_name));
    if (fs.existsSync(dirPath)) return res.status(409).json({ error: '文件夹已存在' });

    fs.mkdirSync(dirPath, { recursive: true });
    res.json({ success: true });
  } catch (e) {
    console.error('[创建文件夹]', e.message);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ⑦-3 文件预览
app.get('/api/v2/storage/files/preview/:uid/:filename', authMiddleware, (req, res) => {
  try {
    const { uid, filename } = req.params;
    const user = DB.users[req.user.username];
    if (!user || user.id !== uid) return res.status(403).json({ error: '无权操作' });

    const filePath = path.join(HOSTS_DIR, uid, sanitize(filename));
    if (!fs.existsSync(filePath)) return res.status(404).json({ error: '文件不存在' });

    const ext = path.extname(filename).toLowerCase();
    const textTypes = ['.txt', '.html', '.htm', '.css', '.js', '.json', '.xml', '.md', '.svg', '.csv', '.log', '.yml', '.yaml', '.ini', '.cfg', '.conf'];
    const imageTypes = ['.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp', '.ico', '.svg'];

    if (textTypes.includes(ext)) {
      const content = fs.readFileSync(filePath, 'utf8');
      res.json({ type: 'text', content });
    } else if (imageTypes.includes(ext)) {
      res.sendFile(filePath);
    } else {
      res.json({ type: 'binary', message: '不支持预览此文件类型' });
    }
  } catch (e) {
    console.error('[预览]', e.message);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ⑦-4 文件下载
app.get('/api/v2/storage/files/download/:uid/:filename', authMiddleware, (req, res) => {
  try {
    const { uid, filename } = req.params;
    const user = DB.users[req.user.username];
    if (!user || user.id !== uid) return res.status(403).json({ error: '无权操作' });

    const filePath = path.join(HOSTS_DIR, uid, sanitize(filename));
    if (!fs.existsSync(filePath)) return res.status(404).json({ error: '文件不存在' });

    res.download(filePath, filename);
  } catch (e) {
    console.error('[下载]', e.message);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ⑦-5 一键清理空间
app.post('/api/v2/storage/files/cleanup/:uid', authMiddleware, (req, res) => {
  try {
    const { uid } = req.params;
    const { password } = req.body;
    if (!password) return res.status(400).json({ error: '参数不完整' });

    const user = DB.users[req.user.username];
    if (!user || user.id !== uid) return res.status(403).json({ error: '无权操作' });

    if (!verifyPasswordBcrypt(password, user.password)) {
      return res.status(400).json({ error: '密码错误' });
    }

    const hostDir = path.join(HOSTS_DIR, uid);
    if (fs.existsSync(hostDir)) {
      const entries = fs.readdirSync(hostDir);
      for (const entry of entries) {
        const entryPath = path.join(hostDir, entry);
        fs.rmSync(entryPath, { recursive: true, force: true });
      }
    }

    if (DB.hosts[uid]) DB.hosts[uid].files = [];
    user.spaceUsedMB = 0;

    saveDB();
    logAudit('cleanup', getClientIP(req), `清空空间: ${uid}`);
    res.json({ success: true });
  } catch (e) {
    console.error('[清理]', e.message);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ⑫ 删除文件夹
app.post('/api/v2/storage/files/rmdir/:uid', authMiddleware, (req, res) => {
  try {
    const { uid } = req.params;
    const { dir_name } = req.body;
    if (!dir_name) return res.status(400).json({ error: '参数不完整' });

    const user = DB.users[req.user.username];
    if (!user || user.id !== uid) return res.status(403).json({ error: '无权操作' });

    const dirPath = path.join(HOSTS_DIR, uid, sanitize(dir_name));
    if (!fs.existsSync(dirPath)) return res.status(404).json({ error: '文件夹不存在' });

    const stat = fs.statSync(dirPath);
    if (!stat.isDirectory()) return res.status(400).json({ error: '不是文件夹' });

    // 计算大小
    let dirSize = 0;
    function calcSize(dir) {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        const p = path.join(dir, entry.name);
        if (entry.isDirectory()) calcSize(p);
        else dirSize += fs.statSync(p).size;
      }
    }
    calcSize(dirPath);

    fs.rmSync(dirPath, { recursive: true, force: true });
    user.spaceUsedMB = Math.max(0, (user.spaceUsedMB || 0) - dirSize / 1024 / 1024);

    saveDB();
    res.json({ success: true });
  } catch (e) {
    console.error('[删除文件夹]', e.message);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ⑱ 文件搜索
app.get('/api/v2/storage/files/search/:uid', authMiddleware, (req, res) => {
  try {
    const { uid } = req.params;
    const q = req.query.q || '';
    if (q.length < 2) return res.status(400).json({ error: '搜索关键词至少2个字符' });

    const user = DB.users[req.user.username];
    if (!user || user.id !== uid) return res.status(403).json({ error: '无权操作' });

    const results = [];
    const hostDir = path.join(HOSTS_DIR, uid);
    if (fs.existsSync(hostDir)) {
      function searchDir(dir, prefix = '') {
        const entries = fs.readdirSync(dir, { withFileTypes: true });
        for (const entry of entries) {
          const relPath = prefix + entry.name;
          if (entry.name.toLowerCase().includes(q.toLowerCase())) {
            const stat = fs.statSync(path.join(dir, entry.name));
            results.push({
              name: relPath,
              type: entry.isDirectory() ? 'directory' : 'file',
              size: stat.size,
              modifiedAt: stat.mtime.toISOString()
            });
          }
          if (entry.isDirectory()) {
            searchDir(path.join(dir, entry.name), relPath + '/');
          }
        }
      }
      searchDir(hostDir);
    }

    res.json({ query: q, results, total: results.length });
  } catch (e) {
    console.error('[搜索]', e.message);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ⑲ 批量删除文件
app.post('/api/v2/storage/files/batch-remove/:uid', authMiddleware, (req, res) => {
  try {
    const { uid } = req.params;
    const { files } = req.body;
    if (!files || !Array.isArray(files) || files.length > 50) {
      return res.status(400).json({ error: '参数无效，单次最多50个文件' });
    }

    const user = DB.users[req.user.username];
    if (!user || user.id !== uid) return res.status(403).json({ error: '无权操作' });

    let totalRemoved = 0;
    for (const filename of files) {
      const filePath = path.join(HOSTS_DIR, uid, sanitize(filename));
      if (fs.existsSync(filePath)) {
        const stat = fs.statSync(filePath);
        fs.unlinkSync(filePath);
        totalRemoved += stat.size;
      }
    }

    user.spaceUsedMB = Math.max(0, (user.spaceUsedMB || 0) - totalRemoved / 1024 / 1024);
    if (DB.hosts[uid]?.files) {
      DB.hosts[uid].files = DB.hosts[uid].files.filter(f => !files.includes(f.name));
    }

    saveDB();
    res.json({ success: true, removed: files.length, freedBytes: totalRemoved });
  } catch (e) {
    console.error('[批量删除]', e.message);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ㉑ 文件排序
app.get('/api/v2/storage/files/sorted/:uid', authMiddleware, (req, res) => {
  try {
    const { uid } = req.params;
    const sort = req.query.sort || 'name';
    const order = req.query.order || 'asc';

    const user = DB.users[req.user.username];
    if (!user || user.id !== uid) return res.status(403).json({ error: '无权操作' });

    const hostDir = path.join(HOSTS_DIR, uid);
    const entries = [];
    if (fs.existsSync(hostDir)) {
      const dirEntries = fs.readdirSync(hostDir, { withFileTypes: true });
      for (const entry of dirEntries) {
        const stat = fs.statSync(path.join(hostDir, entry.name));
        entries.push({
          name: entry.name,
          type: entry.isDirectory() ? 'directory' : 'file',
          size: stat.size,
          date: stat.mtime.toISOString()
        });
      }
    }

    entries.sort((a, b) => {
      // 目录始终在前
      if (a.type === 'directory' && b.type !== 'directory') return -1;
      if (a.type !== 'directory' && b.type === 'directory') return 1;

      let cmp = 0;
      if (sort === 'name') cmp = a.name.localeCompare(b.name);
      else if (sort === 'size') cmp = a.size - b.size;
      else if (sort === 'date') cmp = new Date(a.date) - new Date(b.date);

      return order === 'desc' ? -cmp : cmp;
    });

    res.json({ entries, total: entries.length });
  } catch (e) {
    console.error('[排序]', e.message);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ============ 支付接口 ============

// ⑧ 兑换卡密
app.post('/api/v2/payment/redeem/exchange', authMiddleware, (req, res) => {
  try {
    const { code } = req.body;
    if (!code) return res.status(400).json({ error: '参数不完整' });

    // 简易卡密验证
    const validCodes = {
      'VIP-5YUAN-XS3K9M2W': { plan: 'basic', planName: '基础版', days: 30 },
      'VIP-10YUAN-PQ7R4N8L': { plan: 'pro', planName: '高级版', days: 90 },
      'VIP-20YUAN-TY6H1J9F': { plan: 'year', planName: '年度版', days: 365 }
    };

    const cardInfo = validCodes[code];
    if (!cardInfo) return res.status(400).json({ error: '卡密无效' });

    const user = DB.users[req.user.username];
    if (!user) return res.status(404).json({ error: '用户不存在' });

    user.plan = cardInfo.plan;
    user.planName = cardInfo.planName;
    user.planExpiry = new Date(Date.now() + cardInfo.days * 24 * 60 * 60 * 1000).toISOString();
    user.spaceLimitMB = cardInfo.plan === 'pro' ? 500 : cardInfo.plan === 'year' ? 2000 : 250;

    saveDB();
    logAudit('redeem', getClientIP(req), `兑换卡密: ${req.user.username} -> ${cardInfo.planName}`);
    res.json({ success: true, plan: cardInfo.plan, planName: cardInfo.planName, spaceLimitMB: user.spaceLimitMB });
  } catch (e) {
    console.error('[兑换]', e.message);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ============ 服务器信息 ============

// ④ 获取服务器网址
app.get('/api/v2/server/info', (req, res) => {
  try {
    const tunnels = [];
    // 尝试从 tunnel.log 获取网址
    const tunnelLog = path.join(__dirname, 'tunnel.log');
    if (fs.existsSync(tunnelLog)) {
      const content = fs.readFileSync(tunnelLog, 'utf8');
      const matches = content.match(/https:\/\/[a-z0-9-]+\.(trycloudflare\.com|cpolar\.top|r24\.cpolar\.top)/gi);
      if (matches) tunnels.push(...matches);
    }

    // 局域网地址
    const os = require('os');
    const interfaces = os.networkInterfaces();
    let lan = 'http://127.0.0.1:3000';
    for (const [name, ifaces] of Object.entries(interfaces)) {
      for (const iface of ifaces) {
        if (iface.family === 'IPv4' && !iface.internal) {
          lan = `http://${iface.address}:${PORT}`;
          break;
        }
      }
    }

    res.json({ tunnels: [...new Set(tunnels)], lan });
  } catch (e) {
    res.json({ tunnels: [], lan: `http://127.0.0.1:${PORT}` });
  }
});

// ⑯ 健康检查
app.get('/api/v2/gateway/health', (req, res) => {
  try {
    res.json({
      status: 'ok',
      time: new Date().toISOString(),
      uptime: process.uptime(),
      php: false,
      users: Object.keys(DB.users).length,
      files: Object.values(DB.hosts).reduce((a, h) => a + (h.files?.length || 0), 0),
      blocked: Object.keys(DB.blockedIPs).length,
      attackMode: security.attackMode,
      memory: process.memoryUsage()
    });
  } catch (e) {
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ⑰ 版本查询
app.get('/api/v2/gateway/version', (req, res) => {
  res.json({
    version: '4.0.0',
    build: '20260730',
    changelog: 'v4.0.0: 安全加固 - 环境变量密码管理、bcrypt密码哈希、AES-256-GCM主机密码加密、CSRF/CSP/HSTS保护、Refresh Token轮换、Session安全随机、资源过载保护、错误信息最小化、原型污染防护、审计日志持久化'
  });
});

// ============ 管理接口 ============

// 管理密码验证
function verifyAdmin(password) {
  if (!password) return false;
  return password === ACTUAL_ADMIN_PASSWORD;
}

// ⑭ 查看封禁IP列表
app.get('/api/v2/sys/management/ips/blocked', hmacMiddleware, (req, res) => {
  try {
    const adminPassword = req.query.admin_password;
    if (!verifyAdmin(adminPassword)) return res.status(403).json({ error: '管理密码错误' });

    const blocked = [];
    for (const [ip, until] of Object.entries(DB.blockedIPs)) {
      if (Date.now() < until) {
        blocked.push({ ip, until: new Date(until).toISOString(), remaining: Math.ceil((until - Date.now()) / 1000 / 60) + '分钟' });
      }
    }

    res.json({ blocked, total: blocked.length });
  } catch (e) {
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ⑮ 解封IP
app.post('/api/v2/sys/management/ips/unban', hmacMiddleware, (req, res) => {
  try {
    const { admin_password, ip } = req.body;
    if (!verifyAdmin(admin_password)) return res.status(403).json({ error: '管理密码错误' });

    delete DB.blockedIPs[ip];
    saveBlocked();
    logAudit('unban', getClientIP(req), `解封IP: ${ip}`);
    res.json({ success: true, message: `已解封 ${ip}` });
  } catch (e) {
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ⑳ IP信誉查询
app.get('/api/v2/sys/management/ips/reputation', hmacMiddleware, (req, res) => {
  try {
    const adminPassword = req.query.admin_password;
    if (!verifyAdmin(adminPassword)) return res.status(403).json({ error: '管理密码错误' });

    const targetIP = req.query.ip;
    if (targetIP) {
      const behavior = DB.ipBehavior[targetIP] || null;
      return res.json({ ip: targetIP, found: !!behavior, ...(behavior || {}) });
    }

    const lowReputation = [];
    for (const [ip, behavior] of Object.entries(DB.ipBehavior)) {
      if (behavior.score < 50) {
        lowReputation.push({ ip, ...behavior });
      }
    }

    res.json({ low_reputation: lowReputation, total: lowReputation.length });
  } catch (e) {
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ㉕ 系统资源监控
app.get('/api/v2/sys/resources', hmacMiddleware, (req, res) => {
  try {
    const adminPassword = req.query.admin_password;
    if (!verifyAdmin(adminPassword)) return res.status(403).json({ error: '管理密码错误' });

    const os = require('os');
    const totalMem = os.totalmem();
    const freeMem = os.freemem();
    const usedMem = totalMem - freeMem;

    res.json({
      hostname: os.hostname(),
      platform: os.platform() + ' ' + os.arch(),
      uptime: process.uptime(),
      memory: {
        total: Math.round(totalMem / 1024 / 1024) + 'MB',
        used: Math.round(usedMem / 1024 / 1024) + 'MB',
        free: Math.round(freeMem / 1024 / 1024) + 'MB',
        usagePercent: Math.round((usedMem / totalMem) * 100)
      },
      cpu: {
        cores: os.cpus().length,
        model: os.cpus()[0]?.model || 'Unknown',
        loadAvg: os.loadavg()
      },
      server: {
        connections: 0,
        blocked: Object.keys(DB.blockedIPs).length,
        whitelist: DB.whitelist.length,
        attackMode: security.attackMode
      }
    });
  } catch (e) {
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// ㉖ IP白名单管理
app.get('/api/v2/sys/management/ips/whitelist', hmacMiddleware, (req, res) => {
  const adminPassword = req.query.admin_password;
  if (!verifyAdmin(adminPassword)) return res.status(403).json({ error: '管理密码错误' });
  res.json({ whitelist: DB.whitelist, total: DB.whitelist.length });
});

app.post('/api/v2/sys/management/ips/whitelist/add', hmacMiddleware, (req, res) => {
  const { admin_password, ip } = req.body;
  if (!verifyAdmin(admin_password)) return res.status(403).json({ error: '管理密码错误' });
  if (!DB.whitelist.includes(ip)) {
    DB.whitelist.push(ip);
    saveDB();
  }
  res.json({ success: true, whitelist: DB.whitelist });
});

app.post('/api/v2/sys/management/ips/whitelist/remove', hmacMiddleware, (req, res) => {
  const { admin_password, ip } = req.body;
  if (!verifyAdmin(admin_password)) return res.status(403).json({ error: '管理密码错误' });
  DB.whitelist = DB.whitelist.filter(i => i !== ip);
  saveDB();
  res.json({ success: true, whitelist: DB.whitelist });
});

// ㉗ 行为评分查询
app.get('/api/v2/sys/management/ips/behavior', hmacMiddleware, (req, res) => {
  const adminPassword = req.query.admin_password;
  if (!verifyAdmin(adminPassword)) return res.status(403).json({ error: '管理密码错误' });
  const ip = req.query.ip;
  if (!ip) return res.status(400).json({ error: '缺少IP参数' });

  const behavior = DB.ipBehavior[ip];
  if (!behavior) return res.json({ ip, found: false });
  res.json({ ip, found: true, ...behavior });
});

// ㉚ 账户锁定管理
app.get('/api/v2/sys/management/accounts/lockouts', hmacMiddleware, (req, res) => {
  const adminPassword = req.query.admin_password;
  if (!verifyAdmin(adminPassword)) return res.status(403).json({ error: '管理密码错误' });

  const lockouts = [];
  for (const [username, entry] of Object.entries(security.loginAttempts)) {
    if (entry.lockedUntil > Date.now()) {
      lockouts.push({ username, lockedUntil: new Date(entry.lockedUntil).toISOString(), attempts: entry.count });
    }
  }
  res.json({ lockouts, total: lockouts.length });
});

app.post('/api/v2/sys/management/accounts/unlock', hmacMiddleware, (req, res) => {
  const { admin_password, username } = req.body;
  if (!verifyAdmin(admin_password)) return res.status(403).json({ error: '管理密码错误' });
  security.resetLoginAttempt(username);
  res.json({ success: true, message: `已解锁 ${username}` });
});

// ㉛ 境外IP统计
app.get('/api/v2/sys/management/ips/geo', hmacMiddleware, (req, res) => {
  const adminPassword = req.query.admin_password;
  if (!verifyAdmin(adminPassword)) return res.status(403).json({ error: '管理密码错误' });

  const foreignIPs = [];
  for (const [ip, behavior] of Object.entries(DB.ipBehavior)) {
    // 简单判定：非192/10/172/127开头的为境外IP
    if (!ip.startsWith('192.') && !ip.startsWith('10.') && !ip.startsWith('172.') && !ip.startsWith('127.')) {
      foreignIPs.push({ ip, requests: behavior.totalRequests, isBlocked: !!DB.blockedIPs[ip] });
    }
  }
  res.json({ foreignIPs, total: foreignIPs.length });
});

// ㉜ 日志归档
app.get('/api/v2/sys/management/logs/archive', hmacMiddleware, (req, res) => {
  const adminPassword = req.query.admin_password;
  if (!verifyAdmin(adminPassword)) return res.status(403).json({ error: '管理密码错误' });

  const logFiles = [];
  if (fs.existsSync(LOG_DIR)) {
    const files = fs.readdirSync(LOG_DIR);
    for (const f of files) {
      const stat = fs.statSync(path.join(LOG_DIR, f));
      logFiles.push({ name: f, size: stat.size, createdAt: stat.mtime.toISOString() });
    }
  }
  res.json({ archives: logFiles, auditEntries: DB.auditLog.length });
});

app.post('/api/v2/sys/management/logs/rotate', hmacMiddleware, (req, res) => {
  const { admin_password } = req.body;
  if (!verifyAdmin(admin_password)) return res.status(403).json({ error: '管理密码错误' });

  const ts = new Date().toISOString().replace(/:/g, '-');
  const archivePath = path.join(LOG_DIR, `server-${ts}.log`);
  const serverLog = path.join(__dirname, 'server.log');
  if (fs.existsSync(serverLog)) {
    fs.copyFileSync(serverLog, archivePath);
    fs.writeFileSync(serverLog, '');
  }
  res.json({ success: true, archivePath: `data/logs/server-${ts}.log` });
});

// ㉝ HMAC签名信息
app.get('/api/v2/sys/auth/signature-info', (req, res) => {
  res.json({
    version: '4.0.0',
    algorithm: 'HMAC-SHA256',
    headers: ['x-request-time', 'x-request-nonce', 'x-request-signature'],
    signFormat: 'METHOD+PATH+TIMESTAMP+NONCE+BODY_HASH'
  });
});

// ㊱ 指纹管理
app.get('/api/v2/sys/management/fingerprints', hmacMiddleware, (req, res) => {
  const adminPassword = req.query.admin_password;
  if (!verifyAdmin(adminPassword)) return res.status(403).json({ error: '管理密码错误' });

  const fingerprints = [];
  let blockedCount = 0;
  for (const [userId, entry] of Object.entries(DB.fingerprints)) {
    const isBlocked = entry.score === 0;
    if (isBlocked) blockedCount++;
    fingerprints.push({
      userId,
      score: entry.score || 100,
      firstSeen: entry.firstSeen,
      lastSeen: entry.lastSeen,
      ip: entry.ip,
      changeCount: entry.changeCount || 0
    });
  }

  res.json({ success: true, count: fingerprints.length, blockedCount, fingerprints });
});

// ============ JS Challenge ============
const challenges = {};

app.get('/challenge', (req, res) => {
  const challengeId = crypto.randomUUID();
  const a = Math.floor(Math.random() * 20) + 1;
  const b = Math.floor(Math.random() * 20) + 1;
  const answer = a + b;
  challenges[challengeId] = { answer, createdAt: Date.now(), ip: getClientIP(req) };

  // 清理过期
  for (const [id, c] of Object.entries(challenges)) {
    if (Date.now() - c.createdAt > 5 * 60 * 1000) delete challenges[id];
  }

  res.send(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>人机验证</title>
<style>
  body { font-family: sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; background: #f5f5f5; }
  .box { background: #fff; padding: 30px; border-radius: 12px; box-shadow: 0 2px 12px rgba(0,0,0,0.1); text-align: center; max-width: 400px; width: 90%; }
  h1 { color: #333; margin-bottom: 10px; }
  .q { font-size: 24px; margin: 20px 0; color: #555; }
  input { padding: 10px; font-size: 18px; width: 80px; text-align: center; border: 2px solid #ddd; border-radius: 6px; }
  button { padding: 10px 30px; font-size: 16px; background: #4CAF50; color: #fff; border: none; border-radius: 6px; cursor: pointer; margin-top: 10px; }
  button:hover { background: #45a049; }
  .error { color: #e74c3c; margin-top: 10px; }
</style>
</head>
<body>
<div class="box">
  <h1>🤖 人机验证</h1>
  <p>请完成以下计算以继续访问</p>
  <div class="q">${a} + ${b} = ?</div>
  <input type="number" id="answer" placeholder="?">
  <br>
  <button onclick="verify()">验证</button>
  <div class="error" id="error"></div>
</div>
<script>
async function verify() {
  const answer = document.getElementById('answer').value;
  const resp = await fetch('/challenge/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ challenge_id: '${challengeId}', answer: parseInt(answer) })
  });
  const data = await resp.json();
  if (data.success) {
    document.querySelector('.box').innerHTML = '<h1>✅ 验证通过</h1><p>即将跳转...</p>';
    setTimeout(() => { window.location.href = '/panel.html'; }, 1500);
  } else {
    document.getElementById('error').textContent = data.error || '验证失败，请重试';
  }
}
</script>
</body>
</html>`);
});

app.post('/challenge/verify', (req, res) => {
  const { challenge_id, answer } = req.body;
  const challenge = challenges[challenge_id];
  if (!challenge) return res.status(400).json({ success: false, error: '验证已过期' });

  if (challenge.answer === answer) {
    security.resetLoginAttempt(challenge.ip);
    delete challenges[challenge_id];
    res.json({ success: true });
  } else {
    res.json({ success: false, error: '答案错误' });
  }
});

// ============ 多人联机 WebSocket ============
const wss = new ws.WebSocketServer({ server, path: '/gateway/realtime' });

// 联机服务器
const mpServer = new MultiplayerServer(wss, (token) => {
  // 复用现有账号鉴权
  if (!token) return { valid: false, userId: 'anon', username: '游客' };
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    return { valid: true, userId: decoded.id || decoded.sub, username: decoded.username || '战士' };
  } catch (e) {
    return { valid: false, userId: 'anon', username: '游客' };
  }
});

wss.on('connection', (ws, req) => {
  mpServer.onConnection(ws, req);
});

mpServer.start();

// 联机统计 API
app.get('/api/v2/sys/multiplayer/stats', hmacMiddleware, (req, res) => {
  const adminPassword = req.query.admin_password;
  if (!verifyAdmin(adminPassword)) return res.status(403).json({ error: '管理密码错误' });
  res.json(mpServer.getStats());
});

// ============ 游戏首页 ============
app.get('/', (req, res) => {
  const gamePath = path.join(__dirname, '钢铁前线1944联机版.html');
  if (fs.existsSync(gamePath)) {
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    // 游戏页面需要覆盖 CSP，允许内联脚本和 CDN 资源
    res.setHeader('Content-Security-Policy', "default-src * 'unsafe-inline' 'unsafe-eval'; script-src * 'unsafe-inline' 'unsafe-eval'; style-src * 'unsafe-inline'; connect-src * ws: wss:; img-src * data: blob:; media-src *; font-src *; frame-src *; object-src *");
    res.removeHeader('X-Frame-Options');
    res.sendFile(gamePath);
  } else {
    // 游戏文件不存在时，返回提示页面
    res.status(200).type('html').send(`<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>钢铁前线1944 · 联机版</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0c08;color:#ccc;font-family:"Microsoft YaHei",sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;text-align:center}
.panel{background:rgba(255,255,255,.04);border:1px solid #333;border-radius:12px;padding:40px;max-width:500px}
h1{color:#e8dcb0;font-size:28px;letter-spacing:4px;margin-bottom:12px}
p{color:#888;margin:8px 0;line-height:1.8}
a{color:#b8a86a}
</style></head><body>
<div class="panel">
<h1>⚔ 钢铁前线1944</h1>
<p>游戏文件尚未部署到服务器。</p>
<p>请将 <code>钢铁前线1944联机版.html</code> 放到服务器根目录后重启。</p>
<p style="margin-top:16px"><a href="/panel.html">→ 管理后台</a></p>
</div>
</body></html>`);
  }
});

// ============ 错误处理 ============
app.use((err, req, res, next) => {
  console.error('[错误]', err.message);
  res.status(500).json({ error: '服务器内部错误' });
});

// 404
app.use((req, res) => {
  res.status(404).json({ error: '未找到' });
});

// ============ 原型污染防护 ============
['__proto__', 'constructor', 'prototype'].forEach(key => {
  Object.defineProperty(Object.prototype, key, {
    set(val) {
      // 阻止修改原型
      return val;
    },
    get() { return undefined; }
  });
});

// ============ 启动服务器 ============
server.listen(PORT, '0.0.0.0', () => {
  console.log('');
  console.log('==========================================');
  console.log('  手机多租户虚拟主机 v4.0.0 安全加固版');
  console.log('==========================================');
  console.log(`  监听端口: ${PORT}`);
  if (ACTUAL_ADMIN_PASSWORD === ADMIN_PASSWORD) { console.log('  管理密码: 已设置(环境变量)'); } else { console.log(`  管理密码: ${ACTUAL_ADMIN_PASSWORD} (随机生成，请保存!)`); }
  console.log(`  用户数量: ${Object.keys(DB.users).length}`);
  console.log(`  主机数量: ${Object.keys(DB.hosts).length}`);
  console.log('==========================================');
  console.log('');
});

// 定期保存数据
setInterval(saveDB, 60000);
setInterval(saveBlocked, 60000);
setInterval(saveAudit, 300000);

// 定期清理过期数据
setInterval(() => {
  const now = Date.now();
  // 清理过期封禁
  for (const [ip, until] of Object.entries(DB.blockedIPs)) {
    if (now > until) delete DB.blockedIPs[ip];
  }
  // 清理过期 nonce
  for (const [nonce, ts] of Object.entries(security.nonceStore)) {
    if (now - ts > 300000) delete security.nonceStore[nonce];
  }
  // 清理过期 challenge
  for (const [id, c] of Object.entries(challenges)) {
    if (now - c.createdAt > 5 * 60 * 1000) delete challenges[id];
  }
  // 新用户保护期检查
  for (const [username, user] of Object.entries(DB.users)) {
    if (user.isNewUserGrace && now > (user.graceUntil || 0)) {
      user.isNewUserGrace = false;
    }
  }
  saveBlocked();
}, 60000);

// 信号处理
process.on('SIGTERM', () => {
  console.log('[关闭] 正在保存数据...');
  saveDB();
  saveBlocked();
  saveAudit();
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('[关闭] 正在保存数据...');
  saveDB();
  saveBlocked();
  saveAudit();
  process.exit(0);
});