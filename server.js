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
const compression = require('compression');

// ============ 配置 ============
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
if (!ADMIN_PASSWORD) {
  console.error('[安全] 警告：未设置 ADMIN_PASSWORD 环境变量，使用随机密码');
  console.error('[安全] 请在启动前设置: export ADMIN_PASSWORD="你的管理密码"');
}
const ACTUAL_ADMIN_PASSWORD = ADMIN_PASSWORD || crypto.randomBytes(16).toString('hex');
const HMAC_SECRET = crypto.createHash('sha256').update(JWT_SECRET + 'hmac').digest();
const REFRESH_SECRET = crypto.createHash('sha256').update(JWT_SECRET + 'refresh').digest();
const DATA_DIR = path.join(__dirname, 'data');
const HOSTS_DIR = path.join(__dirname, 'hosts');
const PUBLIC_DIR = path.join(__dirname, 'public');
const LOG_DIR = path.join(DATA_DIR, 'logs');
const TOKEN_EXPIRY = '15m';
const REFRESH_EXPIRY = '7d';
const MAX_FILE_SIZE = 50 * 1024 * 1024;

[DATA_DIR, HOSTS_DIR, PUBLIC_DIR, LOG_DIR].forEach(d => {
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
});

let DB = { users: {}, hosts: {}, sessions: {}, refreshTokens: {}, blockedIPs: {}, ipBehavior: {}, fingerprints: {}, mouseData: {}, nonces: {}, auditLog: [], lockouts: {}, whitelist: [] };
const DB_FILE = path.join(DATA_DIR, 'db.json');
const AUDIT_FILE = path.join(DATA_DIR, 'audit.json');
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

function generateUID() { return crypto.randomBytes(10).toString('hex'); }
function generateSessionId() { return 'sess_' + crypto.randomUUID(); }
function getClientIP(req) { return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.headers['x-real-ip'] || req.socket.remoteAddress?.replace('::ffff:', '') || '127.0.0.1'; }
function hashPassword(password) { return crypto.createHash('sha256').update(password + JWT_SECRET).digest('hex'); }
function sanitize(str) { return String(str).replace(/[<>]/g, '').substring(0, 200); }
function logAudit(action, ip, detail) { DB.auditLog.push({ time: new Date().toISOString(), action, ip, detail }); saveAudit(); }

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

function generateHMAC(method, urlPath, timestamp, nonce, bodyHash) {
  const signStr = method + '+' + urlPath + '+' + timestamp + '+' + nonce + '+' + bodyHash;
  return crypto.createHmac('sha256', HMAC_SECRET).update(signStr).digest('hex');
}
function verifyHMAC(method, urlPath, timestamp, nonce, bodyHash, signature) {
  const expected = generateHMAC(method, urlPath, timestamp, nonce, bodyHash);
  return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signature));
}

function validatePasswordStrength(password) {
  if (!password || password.length < 8) return '密码至少8个字符';
  if (!/[A-Z]/.test(password) && !/[a-z]/.test(password)) return '密码需包含字母';
  if (!/[A-Z]/.test(password) || !/[a-z]/.test(password)) return '密码需包含大小写字母';
  if (!/[0-9]/.test(password)) return '密码需包含数字';
  return null;
}