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

  getRateLimitLevel(req, type = 'default') {
    const ip = getClientIP(req);
    const key = ip + ':' + type;
    const entry = this.requestCounts[key];
    return entry ? entry.level : 0;
  }

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

  checkCCAttack(ip) {
    const now = Date.now();
    const key = ip + ':cc';
    if (!this.requestCounts[key]) this.requestCounts[key] = { count: 0, reset: now + 10000 };
    const entry = this.requestCounts[key];
    if (now > entry.reset) { entry.count = 0; entry.reset = now + 10000; }
    entry.count++;
    return entry.count > 250;
  }

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

  checkHoneypot(path) {
    return this.honeypots.some(h => path.toLowerCase().startsWith(h.toLowerCase()) || path.toLowerCase() === h.toLowerCase());
  }

  validateFileType(filePath, mimeType) {
    const dangerousExtensions = ['.exe', '.dll', '.so', '.dylib', '.php', '.phtml', '.php3', '.php4', '.php5', '.phar', '.py', '.pyc', '.sh', '.bash', '.cgi', '.pl', '.jsp', '.asp', '.aspx', '.war', '.jar', '.rb', '.bat', '.cmd', '.ps1', '.vbs', '.wsf', '.msi', '.com'];
    const ext = path.extname(filePath).toLowerCase();
    if (dangerousExtensions.includes(ext)) return false;
    try {
      const buf = fs.readFileSync(filePath);
      if (buf.length > 4) {
        if (buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46) return false;
        if (buf[0] === 0x4d && buf[1] === 0x5a) return false;
        if (buf.toString('utf8', 0, 5) === '<?php') return false;
      }
    } catch (e) {}
    return true;
  }

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

  analyzeRequestIntervals(ip, intervals) {
    if (intervals.length < 2) return { isAutomated: false, confidence: 0 };
    const mean = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    const variance = intervals.reduce((a, b) => a + (b - mean) ** 2, 0) / intervals.length;
    const cv = Math.sqrt(variance) / mean;
    const isAutomated = cv < 0.1;
    const confidence = Math.min(1, Math.max(0, 1 - cv));
    return { isAutomated, confidence, cv, mean };
  }

  analyzeMouseData(events) {
    if (!events || events.length < 5) return { isHuman: false, confidence: 0, reason: '数据不足' };
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

  checkNonce(nonce, maxAge = 300000) {
    const now = Date.now();
    for (const [n, ts] of Object.entries(this.nonceStore)) {
      if (now - ts > maxAge) delete this.nonceStore[n];
    }
    if (this.nonceStore[nonce]) return false;
    this.nonceStore[nonce] = now;
    return true;
  }

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

// ⚡ 闪电盾
app.use((req, res, next) => {
  const ip = req.headers['cf-connecting-ip'] || req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.headers['x-real-ip'] || req.socket.remoteAddress?.replace('::ffff:', '') || '127.0.0.1';
  if (security.isBlocked(ip)) { return res.status(403).end(); }
  if (security.attackMode && !security.isWhitelisted(ip)) {
    const p = req.path.toLowerCase();
    if (!p.startsWith('/api/v2/auth/') && !p.startsWith('/api/v2/gateway/health')) { return res.status(503).end(); }
  }
  const ua = (req.headers['user-agent'] || '').toLowerCase();
  const scannerPatterns = ['zgrab', 'masscan', 'nmap', 'nessus', 'burp', 'sqlmap', 'nikto', 'gobuster', 'dirbuster', 'wpscan', 'acunetix', 'netsparker', 'hydra', 'medusa', 'ncrack', 'brutus', 'metasploit', 'python-requests', 'python-urllib', 'go-http-client', 'curl/', 'libcurl', 'wget', 'axios', 'node-fetch', 'okhttp', 'scrapy', 'apache-httpclient', 'java/', 'jakarta', 'bot', 'crawler', 'spider', 'scanner', 'scan'];
  if (ua && scannerPatterns.some(p => ua.includes(p))) { security.blockIP(ip, '扫描器UA', 60 * 60 * 1000); return res.status(403).end(); }
  if (!ua && !req.path.startsWith('/api/') && !security.isWhitelisted(ip) && !ip.startsWith('127.') && !ip.startsWith('::1') && !ip.startsWith('192.168.') && !ip.startsWith('10.') && !ip.startsWith('172.')) {
    const k = 'noua:' + ip;
    if (!security.requestCounts) security.requestCounts = {};
    if (!security.requestCounts[k]) security.requestCounts[k] = { count: 0, reset: Date.now() + 60000 };
    const e = security.requestCounts[k];
    if (Date.now() > e.reset) { e.count = 0; e.reset = Date.now() + 60000; }
    e.count++;
    if (e.count > 5) { console.log(`[安全] 无UA请求: ${ip}，仅记录不封禁`); }
  }
  const path = req.path.toLowerCase();
  if (path === '/' || path === '') {
    const rk = 'root:' + ip;
    if (!security.requestCounts) security.requestCounts = {};
    if (!security.requestCounts[rk]) security.requestCounts[rk] = { count: 0, reset: Date.now() + 60000 };
    const re = security.requestCounts[rk];
    if (Date.now() > re.reset) { re.count = 0; re.reset = Date.now() + 60000; }
    re.count++;
    if (re.count > 10) { security.blockIP(ip, '根路径高频', 30 * 60 * 1000); return res.status(403).end(); }
  }
  next();
});

app.use(compression());
app.use(cors({ origin: true, credentials: true, methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'], allowedHeaders: ['Content-Type', 'Authorization', 'x-request-time', 'x-request-nonce', 'x-request-signature', 'x-session-id', 'x-device-id'] }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

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

app.use((req, res, next) => {
  if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) {
    const origin = req.headers.origin || req.headers.referer;
    if (origin) {
      try {
        const originHost = new URL(origin).hostname;
        const reqHost = req.headers.host?.split(':')[0] || '';
        const allowedHosts = [reqHost, 'localhost', '127.0.0.1'];
        if (!allowedHosts.some(h => originHost === h || originHost.endsWith('.' + h))) {
          if (req.headers.origin && !req.headers.referer) { return res.status(403).json({ error: '请求被拒绝' }); }
        }
      } catch (e) {}
    }
  }
  next();
});

app.use((req, res, next) => {
  const ip = getClientIP(req);
  const path = req.path.toLowerCase();
  if (security.isBlocked(ip)) { security.updateBehaviorScore(ip, 'blocked_access'); return res.status(403).json({ error: '请求被拒绝' }); }
  if (security.attackMode && !security.isWhitelisted(ip)) {
    if (path.startsWith('/api/v2/auth/') || path.startsWith('/api/v2/gateway/health')) {} else { return res.status(503).json({ error: '服务暂时不可用' }); }
  }
  if (security.checkHoneypot(path)) { security.blockIP(ip, '触碰蜜罐', 7 * 24 * 60 * 60 * 1000); security.updateBehaviorScore(ip, 'honeypot'); return res.status(404).end(); }
  if (security.checkCCAttack(ip)) { security.blockIP(ip, 'CC攻击', 30 * 60 * 1000); security.updateBehaviorScore(ip, 'rapid_request'); return res.status(429).json({ error: '请求过于频繁' }); }
  if (!security.checkRateLimit(req)) {
    const level = security.getRateLimitLevel(req);
    const messages = ['', '请放慢速度', '请放慢速度', '临时限流，5分钟后自动恢复', '严重限流，15分钟后自动恢复', ''];
    if (level >= 5) { security.blockIP(ip, '5级限流触发', 60 * 60 * 1000); return res.status(429).json({ error: '请求过于频繁' }); }
    if (level >= 3) { security.blockIP(ip, `${level}级限流`, [0, 0, 0, 5, 15][level] * 60 * 1000); }
    return res.status(429).json({ error: messages[level] || '请求过于频繁' });
  }
  security.checkGlobalCircuitBreaker();
  security.checkResourceOverload();
  next();
});

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) { return res.status(401).json({ error: '请先登录' }); }
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (e) {
    if (e.name === 'TokenExpiredError') { return res.status(401).json({ error: '令牌已过期', code: 'TOKEN_EXPIRED' }); }
    return res.status(401).json({ error: '认证失败' });
  }
}

function hmacMiddleware(req, res, next) {
  const timestamp = req.headers['x-request-time'];
  const nonce = req.headers['x-request-nonce'];
  const signature = req.headers['x-request-signature'];
  if (!timestamp || !nonce || !signature) { return res.status(400).json({ error: '缺少签名参数' }); }
  const now = Date.now();
  if (Math.abs(now - parseInt(timestamp)) > 5 * 60 * 1000) { return res.status(400).json({ error: '请求已过期' }); }
  if (!security.checkNonce(nonce)) { return res.status(400).json({ error: '请求已处理' }); }
  const bodyHash = crypto.createHash('sha256').update(JSON.stringify(req.body || {})).digest('hex');
  if (!verifyHMAC(req.method, req.path, timestamp, nonce, bodyHash, signature)) {
    security.updateBehaviorScore(getClientIP(req), 'invalid_signature');
    return res.status(400).json({ error: '签名验证失败' });
  }
  next();
}

const upload = multer({
  dest: path.join(DATA_DIR, 'uploads'),
  limits: { fileSize: MAX_FILE_SIZE, files: 1 },
  fileFilter: (req, file, cb) => {
    const dangerousMime = ['application/x-msdownload', 'application/x-msdos-program', 'application/x-elf', 'application/x-php', 'text/x-php', 'text/x-python', 'application/x-sh'];
    if (dangerousMime.includes(file.mimetype)) { cb(new Error('文件类型不允许'), false); } else { cb(null, true); }
  }
});

app.use('/h', express.static(HOSTS_DIR, { index: 'index.html', dotfiles: 'deny' }));
app.use(express.static(PUBLIC_DIR, { index: false }));

// ============ 面板页面 ============
app.get('/panel.html', (req, res) => {
  const panelPath = path.join(__dirname, 'panel.html');
  if (fs.existsSync(panelPath)) { res.sendFile(panelPath); } else { res.sendFile(path.join(PUBLIC_DIR, 'panel.html')); }
});
app.get('/host.html', (req, res) => res.redirect('/panel.html'));
app.get('/admin.html', (req, res) => res.redirect('/panel.html'));

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

app.get('/api/v2/sys/multiplayer/stats', hmacMiddleware, (req, res) => {
  const adminPassword = req.query.admin_password;
  if (!verifyAdmin(adminPassword)) return res.status(403).json({ error: '管理密码错误' });
  res.json(mpServer.getStats());
});

// ============ 游戏首页 ============
app.get('/', (req, res) => {
  const gamePath = path.join(__dirname, '钢铁前线1944联机版.html');
  if (fs.existsSync(gamePath)) {
    res.setHeader('Cache-Control', 'public, max-age=3600');
    res.sendFile(gamePath);
  } else {
    res.status(200).type('html').send('<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>钢铁前线1944 · 联机版</title><style>*{margin:0;padding:0;box-sizing:border-box}body{background:#0a0c08;color:#ccc;font-family:"Microsoft YaHei",sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;text-align:center}.panel{background:rgba(255,255,255,.04);border:1px solid #333;border-radius:12px;padding:40px;max-width:500px}h1{color:#e8dcb0;font-size:28px;letter-spacing:4px;margin-bottom:12px}p{color:#888;margin:8px 0;line-height:1.8}a{color:#b8a86a}</style></head><body><div class="panel"><h1>⚔ 钢铁前线1944</h1><p>游戏文件尚未部署到服务器。</p><p>请将 <code>钢铁前线1944联机版.html</code> 放到服务器根目录后重启。</p><p style="margin-top:16px"><a href="/panel.html">→ 管理后台</a></p></div></body></html>');
  }
});

// ============ 错误处理 ============
app.use((err, req, res, next) => { console.error('[错误]', err.message); res.status(500).json({ error: '服务器内部错误' }); });
app.use((req, res) => { res.status(404).json({ error: '未找到' }); });

['__proto__', 'constructor', 'prototype'].forEach(key => {
  Object.defineProperty(Object.prototype, key, { set(val) { return val; }, get() { return undefined; } });
});

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

setInterval(saveDB, 60000);
setInterval(saveBlocked, 60000);
setInterval(saveAudit, 300000);

setInterval(() => {
  const now = Date.now();
  for (const [ip, until] of Object.entries(DB.blockedIPs)) { if (now > until) delete DB.blockedIPs[ip]; }
  for (const [nonce, ts] of Object.entries(security.nonceStore)) { if (now - ts > 300000) delete security.nonceStore[nonce]; }
  for (const [id, c] of Object.entries(challenges)) { if (now - c.createdAt > 5 * 60 * 1000) delete challenges[id]; }
  for (const [username, user] of Object.entries(DB.users)) { if (user.isNewUserGrace && now > (user.graceUntil || 0)) { user.isNewUserGrace = false; } }
  saveBlocked();
}, 60000);

process.on('SIGTERM', () => { console.log('[关闭] 正在保存数据...'); saveDB(); saveBlocked(); saveAudit(); process.exit(0); });
process.on('SIGINT', () => { console.log('[关闭] 正在保存数据...'); saveDB(); saveBlocked(); saveAudit(); process.exit(0); });