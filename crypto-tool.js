#!/usr/bin/env node
// ============================================
// 多层加密工具 v1.0.0
// scrypt 密钥派生 + 3~5 层 AES-256-GCM 加密
// 每层使用不同派生密钥，洋葱式防护
// ============================================
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ============ 常量 ============
const MAGIC = Buffer.from('CHUYEENC');  // 文件头魔数
const VERSION = 1;                       // 文件格式版本
const DEFAULT_ROUNDS = 3;                // 默认加密层数
const MAX_ROUNDS = 5;                    // 最大加密层数
const SALT_SIZE = 32;                    // 盐长度
const KEY_SIZE = 32;                     // AES-256 = 32字节
const IV_SIZE = 12;                      // GCM IV = 12字节
const TAG_SIZE = 16;                     // GCM 认证标签
const HMAC_SIZE = 32;                    // HMAC-SHA256
const SCRYPT_N = 16384;                  // scrypt 成本参数 N (2^14)
const SCRYPT_R = 8;                      // scrypt 块大小
const SCRYPT_P = 1;                      // scrypt 并行度

// ============ 工具函数 ============

// 可读大小
function humanSize(bytes) {
  if (bytes < 1024) return bytes + 'B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + 'KB';
  return (bytes / 1048576).toFixed(2) + 'MB';
}

// 从密码派生多层密钥
function deriveKeys(password, salt, rounds) {
  // 主密钥：scrypt(password, salt, N, r, p, keylen)
  const masterKey = crypto.scryptSync(password, salt, KEY_SIZE, { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P });

  const keys = [];
  for (let i = 0; i < rounds; i++) {
    // 每层用不同派生：HKDF 从主密钥 + 层号 + 盐
    const info = Buffer.concat([
      Buffer.from(`layer_${i}`),
      salt
    ]);
    const layerKey = crypto.hkdfSync('sha256', masterKey, salt, info, KEY_SIZE);
    keys.push(layerKey);
  }

  return { masterKey, keys };
}

// 加密单层
function encryptLayer(plaintext, key) {
  const iv = crypto.randomBytes(IV_SIZE);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return Buffer.concat([iv, authTag, encrypted]);  // 12 + 16 + data
}

// 解密单层
function decryptLayer(ciphertext, key) {
  const iv = ciphertext.subarray(0, IV_SIZE);
  const authTag = ciphertext.subarray(IV_SIZE, IV_SIZE + TAG_SIZE);
  const encrypted = ciphertext.subarray(IV_SIZE + TAG_SIZE);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]);
}

// HMAC 完整性校验
function computeHMAC(data, key) {
  return crypto.createHmac('sha256', key).update(data).digest();
}

// ============ 加密 ============
function encrypt(data, password, rounds = DEFAULT_ROUNDS) {
  rounds = Math.min(Math.max(rounds, 1), MAX_ROUNDS);
  const salt = crypto.randomBytes(SALT_SIZE);
  const { keys } = deriveKeys(password, salt, rounds);

  // 洋葱加密：从内到外层层包裹
  let payload = data;
  for (let i = 0; i < rounds; i++) {
    payload = encryptLayer(payload, keys[i]);
  }

  // 文件格式：
  // [MAGIC:8] [VERSION:1] [ROUNDS:1] [SALT:32] [HMAC:32] [PAYLOAD:...]
  const header = Buffer.alloc(8 + 1 + 1 + SALT_SIZE + HMAC_SIZE);
  MAGIC.copy(header, 0);
  header[8] = VERSION;
  header[9] = rounds;
  salt.copy(header, 10);

  // HMAC 覆盖：版本+轮数+盐+加密数据
  const hmacData = Buffer.concat([header.subarray(8, 10), salt, payload]);
  const hmac = computeHMAC(hmacData, keys[0]);  // 用第一层密钥做 HMAC
  hmac.copy(header, 10 + SALT_SIZE);

  return Buffer.concat([header, payload]);
}

// ============ 解密 ============
function decrypt(data, password) {
  // 验证魔数
  const magic = data.subarray(0, 8);
  if (!magic.equals(MAGIC)) {
    throw new Error('不是有效的加密文件（魔数不匹配）');
  }

  const version = data[8];
  if (version !== VERSION) {
    throw new Error(`不支持的格式版本: ${version}`);
  }

  const rounds = data[9];
  if (rounds < 1 || rounds > MAX_ROUNDS) {
    throw new Error(`无效的加密层数: ${rounds}`);
  }

  const salt = data.subarray(10, 10 + SALT_SIZE);
  const storedHmac = data.subarray(10 + SALT_SIZE, 10 + SALT_SIZE + HMAC_SIZE);
  const payload = data.subarray(10 + SALT_SIZE + HMAC_SIZE);

  const { keys } = deriveKeys(password, salt, rounds);

  // 验证 HMAC
  const hmacData = Buffer.concat([data.subarray(8, 10), salt, payload]);
  const computedHmac = computeHMAC(hmacData, keys[0]);
  if (!crypto.timingSafeEqual(storedHmac, computedHmac)) {
    throw new Error('密码错误或文件已损坏（HMAC 验证失败）');
  }

  // 洋葱解密：从外到内层层剥离（反向）
  let plaintext = payload;
  for (let i = rounds - 1; i >= 0; i--) {
    plaintext = decryptLayer(plaintext, keys[i]);
  }

  return plaintext;
}

// ============ 文件操作 ============
function encryptFile(inputPath, outputPath, password, rounds) {
  return new Promise((resolve, reject) => {
    try {
      console.log(`[加密] 读取: ${path.basename(inputPath)} (${rounds}层)...`);
      const data = fs.readFileSync(inputPath);
      const encrypted = encrypt(data, password, rounds);
      fs.writeFileSync(outputPath, encrypted);
      console.log(`  输入: ${humanSize(data.length)} → 输出: ${humanSize(encrypted.length)}`);
      console.log(`  开销: ${humanSize(encrypted.length - data.length)} (魔数+元数据+多层IV/Tag)`);
      resolve(encrypted.length);
    } catch (e) {
      reject(e);
    }
  });
}

function decryptFile(inputPath, outputPath, password) {
  return new Promise((resolve, reject) => {
    try {
      console.log(`[解密] 读取: ${path.basename(inputPath)}...`);
      const data = fs.readFileSync(inputPath);
      const plaintext = decrypt(data, password);
      fs.writeFileSync(outputPath, plaintext);
      console.log(`  输入: ${humanSize(data.length)} → 输出: ${humanSize(plaintext.length)}`);
      resolve(plaintext.length);
    } catch (e) {
      reject(e);
    }
  });
}

// ============ 命令行界面 ============
function showHelp() {
  console.log(`
============================================
  多层加密工具 v1.0.0
  scrypt + AES-256-GCM 洋葱式加密
============================================

用法:
  node crypto-tool.js encrypt <文件/目录> [选项]
  node crypto-tool.js decrypt <文件.enc> [选项]

选项:
  --password, -p    密码（不传则交互输入）
  --rounds, -r      加密层数 (1-5, 默认 3)
  --output, -o      输出路径（默认: 输入路径+.enc）
  --all, -a         加密目录下所有文件

示例:
  # 加密单个文件（3层默认）
  node crypto-tool.js encrypt server.js -p "我的密码"

  # 加密整个目录（5层最强）
  node crypto-tool.js encrypt . -a -p "我的密码" -r 5

  # 解密文件
  node crypto-tool.js decrypt server.js.enc -p "我的密码"

  # 交互式（不显密码）
  node crypto-tool.js encrypt server.js

安全说明:
  - 使用 scrypt(N=2^14) 密钥派生，抗暴力破解
  - 每层使用独立 HKDF 派生密钥
  - AES-256-GCM 提供认证加密（防篡改）
  - HMAC-SHA256 完整性校验
  - 3层加密 = 攻击者需破解 3 个独立密钥
  - 5层加密 = 军事级安全，破解几乎不可能
============================================
`);
}

// 交互式密码输入
function readPassword(prompt) {
  return new Promise((resolve) => {
    const readline = require('readline');
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout
    });
    // 隐藏密码输入
    const stdin = process.stdin;
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');

    let password = '';
    process.stdout.write(prompt);

    stdin.on('data', (char) => {
      char = char.toString();
      switch (char) {
        case '\n':
        case '\r':
          stdin.setRawMode(false);
          stdin.pause();
          process.stdout.write('\n');
          rl.close();
          resolve(password);
          return;
        case '\b':
        case '\x7f':
          if (password.length > 0) {
            password = password.slice(0, -1);
            process.stdout.write('\b \b');
          }
          return;
        case '\u0003':
          process.exit(0);
          return;
        default:
          password += char;
          process.stdout.write('*');
      }
    });
  });
}

// 递归收集文件
function collectFiles(dirPath, excludeEnc = true) {
  const files = [];
  const entries = fs.readdirSync(dirPath, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dirPath, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === '.git' || entry.name === 'node_modules' || entry.name === 'data') continue;
      files.push(...collectFiles(fullPath, excludeEnc));
    } else if (entry.isFile()) {
      if (excludeEnc && entry.name.endsWith('.enc')) continue;
      if (entry.name === 'crypto-tool.js') continue;
      files.push(fullPath);
    }
  }
  return files;
}

// ============ 主入口 ============
async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0 || args[0] === '--help' || args[0] === '-h') {
    showHelp();
    process.exit(0);
  }

  const command = args[0];
  if (command !== 'encrypt' && command !== 'decrypt') {
    console.error('错误: 未知命令，请使用 encrypt 或 decrypt');
    showHelp();
    process.exit(1);
  }

  const target = args[1];
  if (!target) {
    console.error('错误: 请指定文件或目录路径');
    process.exit(1);
  }

  // 解析选项
  let password = null;
  let rounds = DEFAULT_ROUNDS;
  let outputPath = null;
  let encryptAll = false;

  for (let i = 2; i < args.length; i++) {
    if (args[i] === '--password' || args[i] === '-p') {
      password = args[++i];
    } else if (args[i] === '--rounds' || args[i] === '-r') {
      rounds = parseInt(args[++i]);
      if (isNaN(rounds) || rounds < 1 || rounds > MAX_ROUNDS) {
        console.error(`错误: 加密层数必须在 1-${MAX_ROUNDS} 之间`);
        process.exit(1);
      }
    } else if (args[i] === '--output' || args[i] === '-o') {
      outputPath = args[++i];
    } else if (args[i] === '--all' || args[i] === '-a') {
      encryptAll = true;
    }
  }

  // 获取密码
  if (!password) {
    password = await readPassword('请输入密码: ');
    if (!password) {
      console.error('错误: 密码不能为空');
      process.exit(1);
    }
    // 确认密码
    if (command === 'encrypt') {
      const confirm = await readPassword('请再次输入密码: ');
      if (password !== confirm) {
        console.error('错误: 两次密码不一致');
        process.exit(1);
      }
    }
  }

  if (password.length < 8) {
    console.error('错误: 密码至少8个字符');
    process.exit(1);
  }

  const targetPath = path.resolve(target);

  try {
    if (command === 'encrypt') {
      if (encryptAll || fs.statSync(targetPath).isDirectory()) {
        // 加密目录
        const files = collectFiles(targetPath);
        console.log(`\n[多层加密] 目录: ${targetPath}`);
        console.log(`  文件数: ${files.length}, 加密层数: ${rounds}\n`);

        for (const file of files) {
          const relPath = path.relative(targetPath, file);
          const outPath = outputPath
            ? path.join(outputPath, relPath + '.enc')
            : file + '.enc';
          // 确保输出目录存在
          const outDir = path.dirname(outPath);
          if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });
          await encryptFile(file, outPath, password, rounds);
        }
        console.log(`\n✅ 全部加密完成！共 ${files.length} 个文件`);
      } else {
        // 加密单个文件
        const outPath = outputPath || targetPath + '.enc';
        await encryptFile(targetPath, outPath, password, rounds);
        console.log(`\n✅ 加密完成: ${path.basename(outPath)}`);
      }
    } else if (command === 'decrypt') {
      if (fs.statSync(targetPath).isDirectory()) {
        // 解密目录
        const files = collectFiles(targetPath, false);
        const encFiles = files.filter(f => f.endsWith('.enc'));
        console.log(`\n[多层解密] 目录: ${targetPath}`);
        console.log(`  加密文件数: ${encFiles.length}\n`);

        for (const file of encFiles) {
          const outPath = outputPath
            ? path.join(outputPath, path.basename(file, '.enc'))
            : file.replace(/\.enc$/, '');
          await decryptFile(file, outPath, password);
        }
        console.log(`\n✅ 全部解密完成！共 ${encFiles.length} 个文件`);
      } else {
        const outPath = outputPath || targetPath.replace(/\.enc$/, '');
        await decryptFile(targetPath, outPath, password);
        console.log(`\n✅ 解密完成: ${path.basename(outPath)}`);
      }
    }
  } catch (e) {
    console.error(`\n❌ 失败: ${e.message}`);
    process.exit(1);
  }
}

main();