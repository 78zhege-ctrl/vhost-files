// ============================================
// 钢铁前线 · 多人联机服务器 v1.0.0
// 适配 Termux Android 无 root 环境
// ============================================
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// MsgPack 二进制序列化 — 比 JSON 小 40-60%
let msgpackr = null;
try { msgpackr = require('msgpackr'); } catch (e) {}

// ============ 配置 ============
const CONFIG = {
  TICK_RATE: 15,              // 服务器 tick 频率 (次/秒)
  TICK_INTERVAL: 1000 / 15,   // ~66ms
  HEARTBEAT_INTERVAL: 5000,   // 心跳间隔 5秒
  HEARTBEAT_TIMEOUT: 15000,   // 15秒无心跳断线
  MAX_PLAYERS_PER_ROOM: 8,    // 单房间最大人数
  MAX_ROOMS: 20,              // 最大房间数
  ROOM_INACTIVE_TIMEOUT: 600000, // 房间10分钟无活动自动清理
  SYNC_DISTANCE: 80,          // 视野同步距离
  FAR_SYNC_RATE: 2,           // 视野外同步频率 (tick/次)
  GRAVITY: 20,                // 重力 (m/s²)
  MAX_POSITION_ERROR: 2.0,    // 最大位置偏差(米) — 超出则强制修正
  MAX_VELOCITY: 30,           // 最大速度 (m/s) — 防加速挂
};
Object.freeze(CONFIG);

// ============ 对象池 ============
class ObjectPool {
  constructor(factory, reset, initialSize = 64) {
    this.factory = factory;
    this.reset = reset;
    this.pool = [];
    for (let i = 0; i < initialSize; i++) this.pool.push(factory());
  }
  acquire() {
    const obj = this.pool.pop() || this.factory();
    this.reset(obj);
    return obj;
  }
  release(obj) {
    if (this.pool.length < 256) this.pool.push(obj);
  }
  get size() { return this.pool.length; }
}

// 数据包缓冲区池
const bufferPool = new ObjectPool(
  () => Buffer.allocUnsafe(512),
  (b) => b.fill(0),
  128
);

// 玩家对象池
const playerPool = new ObjectPool(
  () => ({
    id: '', name: '', team: 0, cls: 0,
    pos: { x: 0, y: 0, z: 0 },
    vel: { x: 0, y: 0, z: 0 },
    yaw: 0, pitch: 0,
    hp: 100, alive: false, deployed: false,
    crouch: false, prone: false, sprinting: false,
    ads: false, onGround: true,
    curWeapon: 0, firing: false,
    kills: 0, deaths: 0, score: 0,
    ws: null, roomId: null,
    lastInputSeq: 0, lastSyncTick: 0,
    dirty: false, // 脏标记
    lastHeartbeat: Date.now(),
    latency: 0, // ms
  }),
  (p) => {
    p.pos.x = p.pos.y = p.pos.z = 0;
    p.vel.x = p.vel.y = p.vel.z = 0;
    p.yaw = p.pitch = 0;
    p.hp = 100; p.alive = p.deployed = false;
    p.crouch = p.prone = p.sprinting = p.ads = false;
    p.onGround = true; p.curWeapon = 0; p.firing = false;
    p.kills = p.deaths = p.score = 0;
    p.dirty = false; p.lastSyncTick = 0;
    p.lastHeartbeat = Date.now();
    p.latency = 0;
  },
  32
);

// ============ 序列化 — 极致压缩 ============
// 不使用 MsgPack 时的手动二进制打包
// 每个玩家状态: 2+2+2+2+2+2+1+1+1+1+1+1+1+1+1+1 = 26 字节
function packPlayerState(p) {
  const buf = Buffer.allocUnsafe(32);
  let off = 0;
  // 位置: 3×int16 (分米精度, 范围 -3276.8m ~ +3276.7m)
  buf.writeInt16LE(Math.round(p.pos.x * 10), off); off += 2;
  buf.writeInt16LE(Math.round(p.pos.y * 10), off); off += 2;
  buf.writeInt16LE(Math.round(p.pos.z * 10), off); off += 2;
  // 朝向: 2×uint16 (yaw: 0-65535→0-2π, pitch: 0-65535→-π/2~π/2)
  buf.writeUInt16LE(Math.round(((p.yaw % (2 * Math.PI)) + 2 * Math.PI) % (2 * Math.PI) / (2 * Math.PI) * 65535), off); off += 2;
  buf.writeUInt16LE(Math.round((p.pitch + Math.PI / 2) / Math.PI * 65535), off); off += 2;
  // 速度: 2×int16 (cm/s 精度)
  buf.writeInt16LE(Math.round(p.vel.x * 100), off); off += 2;
  buf.writeInt16LE(Math.round(p.vel.z * 100), off); off += 2;
  // 状态标志位: 1字节
  let flags = 0;
  if (p.alive) flags |= 1;
  if (p.deployed) flags |= 2;
  if (p.crouch) flags |= 4;
  if (p.prone) flags |= 8;
  if (p.sprinting) flags |= 16;
  if (p.ads) flags |= 32;
  if (p.onGround) flags |= 64;
  if (p.firing) flags |= 128;
  buf.writeUInt8(flags, off); off += 1;
  // HP: 1字节 (0-100)
  buf.writeUInt8(Math.max(0, Math.min(255, Math.round(p.hp))), off); off += 1;
  // 武器: 1字节枚举
  buf.writeUInt8(p.curWeapon || 0, off); off += 1;
  // 保留
  buf.writeUInt8(0, off); off += 1;
  return buf.subarray(0, off);
}

function unpackPlayerState(buf, off = 0) {
  return {
    pos: {
      x: buf.readInt16LE(off) / 10, off: off + 2,
      y: buf.readInt16LE(off + 2) / 10,
      z: buf.readInt16LE(off + 4) / 10
    },
    yaw: buf.readUInt16LE(off + 6) / 65535 * 2 * Math.PI,
    pitch: buf.readUInt16LE(off + 8) / 65535 * Math.PI - Math.PI / 2,
    vel: {
      x: buf.readInt16LE(off + 10) / 100,
      z: buf.readInt16LE(off + 12) / 100
    },
    flags: buf.readUInt8(off + 14),
    hp: buf.readUInt8(off + 15),
    curWeapon: buf.readUInt8(off + 16),
  };
}

// JSON 序列化 (MsgPack 不可用时回退)
function serialize(msg) {
  if (msgpackr) {
    try { return msgpackr.pack(msg); } catch (e) {}
  }
  return Buffer.from(JSON.stringify(msg), 'utf8');
}

function deserialize(buf) {
  if (msgpackr) {
    try { return msgpackr.unpack(buf); } catch (e) {}
  }
  try { return JSON.parse(buf.toString('utf8')); } catch (e) { return null; }
}

// ============ 房间管理 ============
class Room {
  constructor(id, name, hostId, maxPlayers = 4) {
    this.id = id;
    this.name = name;
    this.hostId = hostId;
    this.maxPlayers = Math.min(maxPlayers, CONFIG.MAX_PLAYERS_PER_ROOM);
    this.players = new Map();   // playerId → playerObj
    this.aiEnabled = false;
    this.matchStarted = false;
    this.matchStartTime = 0;
    this.createdAt = Date.now();
    this.lastActivity = Date.now();
    this.tick = 0;
    this.inputHistory = new Map(); // playerId → inputs[]
  }

  get playerCount() { return this.players.size; }
  get isFull() { return this.playerCount >= this.maxPlayers; }
  get allReady() {
    if (this.playerCount < 2) return false;
    for (const p of this.players.values()) {
      if (p.id !== this.hostId && !p.ready) return false;
    }
    return true;
  }

  addPlayer(p) {
    if (this.isFull) return false;
    p.roomId = this.id;
    p.ready = (p.id === this.hostId);
    this.players.set(p.id, p);
    this.lastActivity = Date.now();
    return true;
  }

  removePlayer(playerId) {
    const p = this.players.get(playerId);
    if (p) {
      p.roomId = null;
      p.ready = false;
      this.players.delete(playerId);
    }
    this.lastActivity = Date.now();
    // 房主离开 → 转移房主
    if (playerId === this.hostId && this.players.size > 0) {
      this.hostId = this.players.keys().next().value;
    }
  }

  getState() {
    const members = [];
    for (const p of this.players.values()) {
      members.push({
        id: p.id, name: p.name, team: p.team, cls: p.cls,
        ready: p.ready, latency: p.latency, isHost: p.id === this.hostId,
        alive: p.alive, kills: p.kills, deaths: p.deaths, score: p.score,
      });
    }
    return {
      id: this.id, name: this.name, hostId: this.hostId,
      maxPlayers: this.maxPlayers, aiEnabled: this.aiEnabled,
      matchStarted: this.matchStarted, playerCount: this.playerCount,
      members,
    };
  }

  isEmpty() { return this.playerCount === 0; }
  isInactive() { return Date.now() - this.lastActivity > CONFIG.ROOM_INACTIVE_TIMEOUT; }
}

// ============ 联机服务器 ============
class MultiplayerServer {
  constructor(wss, authFn) {
    this.wss = wss;
    this.verifyAuth = authFn; // (token) => { valid, userId, username }
    this.rooms = new Map();
    this.players = new Map(); // playerId → playerObj
    this.roomSeq = 0;
    this.tickTimer = null;
    this.cleanupTimer = null;
    this.stats = {
      totalConnections: 0,
      totalMessages: 0,
      bytesSent: 0,
      bytesReceived: 0,
      peakPlayers: 0,
      droppedPackets: 0,
    };
  }

  start() {
    this.tickTimer = setInterval(() => this.tick(), CONFIG.TICK_INTERVAL);
    this.cleanupTimer = setInterval(() => this.cleanup(), 60000);
    console.log('[联机] 服务器已启动 tick=' + CONFIG.TICK_RATE + 'Hz');
  }

  stop() {
    if (this.tickTimer) clearInterval(this.tickTimer);
    if (this.cleanupTimer) clearInterval(this.cleanupTimer);
    this.tickTimer = null;
    this.cleanupTimer = null;
  }

  // ===== 认证 =====
  authenticate(token) {
    if (!this.verifyAuth) return { valid: false, userId: 'anon', username: '游客' };
    return this.verifyAuth(token);
  }

  // ===== 连接处理 =====
  onConnection(ws, req) {
    const ip = (req.headers['cf-connecting-ip'] ||
      req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
      req.headers['x-real-ip'] ||
      req.socket.remoteAddress?.replace('::ffff:', '') || '127.0.0.1');

    ws._mpIP = ip;
    ws._mpAlive = true;
    ws._mpHeartbeat = Date.now();
    ws._mpPlayerId = null;
    ws._mpBinary = false; // 是否支持二进制

    this.stats.totalConnections++;
    console.log(`[联机] 连接: ${ip}`);

    // 发送握手
    ws.send(JSON.stringify({
      type: 'handshake',
      protocol: 'steel-frontline-mp/1.0',
      tickRate: CONFIG.TICK_RATE,
      binary: !!msgpackr,
      serverTime: Date.now(),
    }));

    ws.on('message', (data) => {
      this.stats.totalMessages++;
      this.stats.bytesReceived += data.length || data.byteLength || 0;

      let msg;
      if (data instanceof Buffer || data instanceof ArrayBuffer) {
        ws._mpBinary = true;
        msg = deserialize(data instanceof ArrayBuffer ? Buffer.from(data) : data);
      } else {
        try { msg = JSON.parse(data.toString()); } catch (e) { return; }
      }

      if (!msg || !msg.type) return;
      this.handleMessage(ws, msg, ip);
    });

    ws.on('close', () => this.onDisconnect(ws));
    ws.on('error', () => this.onDisconnect(ws));

    // 心跳
    ws._mpHeartbeatTimer = setInterval(() => {
      if (Date.now() - ws._mpHeartbeat > CONFIG.HEARTBEAT_TIMEOUT) {
        ws._mpAlive = false;
        ws.close();
        return;
      }
      if (ws.readyState === 1) { // OPEN
        ws.send(JSON.stringify({ type: 'ping', t: Date.now() }));
      }
    }, CONFIG.HEARTBEAT_INTERVAL);
  }

  onDisconnect(ws) {
    if (ws._mpHeartbeatTimer) clearInterval(ws._mpHeartbeatTimer);
    if (ws._mpPlayerId) {
      const p = this.players.get(ws._mpPlayerId);
      if (p) {
        const room = this.rooms.get(p.roomId);
        if (room) {
          room.removePlayer(p.id);
          this.broadcastRoom(room, { type: 'playerLeave', playerId: p.id });
          if (room.isEmpty()) {
            this.rooms.delete(room.id);
          }
        }
        playerPool.release(p);
        this.players.delete(p.id);
      }
    }
    console.log(`[联机] 断开: ${ws._mpIP}`);
  }

  // ===== 消息处理 =====
  handleMessage(ws, msg, ip) {
    switch (msg.type) {
      case 'pong':
        ws._mpHeartbeat = Date.now();
        ws._mpAlive = true;
        break;

      case 'auth': {
        const auth = this.authenticate(msg.token);
        const playerId = auth.userId || ('player_' + crypto.randomBytes(6).toString('hex'));
        const playerName = msg.username || auth.username || '战士';

        // 检查是否已有同名连接
        const existing = this.players.get(playerId);
        if (existing) {
          existing.ws = ws;
          ws._mpPlayerId = playerId;
          ws.send(serialize({ type: 'authOk', playerId, name: playerName }));
          break;
        }

        const p = playerPool.acquire();
        p.id = playerId;
        p.name = playerName;
        p.ws = ws;
        p.lastHeartbeat = Date.now();
        this.players.set(playerId, p);
        ws._mpPlayerId = playerId;

        ws.send(serialize({ type: 'authOk', playerId, name: playerName }));
        console.log(`[联机] 认证: ${playerName} (${playerId})`);
        break;
      }

      case 'createRoom': {
        const p = this.players.get(ws._mpPlayerId);
        if (!p) { ws.send(JSON.stringify({ type: 'error', error: '请先认证' })); break; }

        const roomId = 'room_' + (++this.roomSeq);
        const room = new Room(roomId, msg.roomName || '战场', p.id, msg.maxPlayers || 4);
        room.aiEnabled = !!msg.aiEnabled;
        room.addPlayer(p);
        this.rooms.set(roomId, room);

        ws.send(serialize({ type: 'roomCreated', room: room.getState() }));
        console.log(`[联机] 房间创建: ${roomId} by ${p.name}`);
        break;
      }

      case 'joinRoom': {
        const p = this.players.get(ws._mpPlayerId);
        if (!p) { ws.send(JSON.stringify({ type: 'error', error: '请先认证' })); break; }

        const room = this.rooms.get(msg.roomId);
        if (!room) { ws.send(JSON.stringify({ type: 'error', error: '房间不存在' })); break; }
        if (room.matchStarted) { ws.send(JSON.stringify({ type: 'error', error: '对局已开始' })); break; }
        if (!room.addPlayer(p)) { ws.send(JSON.stringify({ type: 'error', error: '房间已满' })); break; }

        ws.send(serialize({ type: 'roomJoined', room: room.getState() }));
        this.broadcastRoom(room, { type: 'playerJoined', player: { id: p.id, name: p.name } });
        console.log(`[联机] ${p.name} 加入房间 ${room.id}`);
        break;
      }

      case 'leaveRoom': {
        const p = this.players.get(ws._mpPlayerId);
        if (!p || !p.roomId) break;
        const room = this.rooms.get(p.roomId);
        if (!room) break;

        room.removePlayer(p.id);
        ws.send(JSON.stringify({ type: 'roomLeft' }));
        this.broadcastRoom(room, { type: 'playerLeave', playerId: p.id });
        if (room.isEmpty()) this.rooms.delete(room.id);
        break;
      }

      case 'toggleReady': {
        const p = this.players.get(ws._mpPlayerId);
        if (!p || !p.roomId) break;
        p.ready = !p.ready;
        const room = this.rooms.get(p.roomId);
        this.broadcastRoom(room, { type: 'readyUpdate', playerId: p.id, ready: p.ready });

        if (room.allReady) {
          this.startMatch(room);
        }
        break;
      }

      case 'startMatch': {
        const p = this.players.get(ws._mpPlayerId);
        if (!p || !p.roomId) break;
        const room = this.rooms.get(p.roomId);
        if (!room || p.id !== room.hostId) break;
        this.startMatch(room);
        break;
      }

      case 'playerInput': {
        this.handlePlayerInput(msg);
        break;
      }

      case 'playerEvent': {
        this.handlePlayerEvent(msg);
        break;
      }

      case 'quickMatch': {
        const p = this.players.get(ws._mpPlayerId);
        if (!p) { ws.send(JSON.stringify({ type: 'error', error: '请先认证' })); break; }
        // 找第一个有空位的房间
        let room = null;
        for (const r of this.rooms.values()) {
          if (!r.isFull && !r.matchStarted) { room = r; break; }
        }
        if (!room) {
          room = new Room('room_' + (++this.roomSeq), '快速匹配', p.id, 4);
          this.rooms.set(room.id, room);
        }
        room.addPlayer(p);
        ws.send(serialize({ type: 'roomJoined', room: room.getState() }));
        this.broadcastRoom(room, { type: 'playerJoined', player: { id: p.id, name: p.name } });
        break;
      }

      case 'roomList': {
        const list = [];
        for (const r of this.rooms.values()) {
          if (!r.matchStarted) {
            list.push({ id: r.id, name: r.name, playerCount: r.playerCount, maxPlayers: r.maxPlayers });
          }
        }
        ws.send(serialize({ type: 'roomList', rooms: list }));
        break;
      }

      case 'chat': {
        const p = this.players.get(ws._mpPlayerId);
        if (!p || !p.roomId) break;
        const room = this.rooms.get(p.roomId);
        if (!room) break;
        const text = String(msg.text || '').substring(0, 100);
        this.broadcastRoom(room, { type: 'chat', playerId: p.id, playerName: p.name, text });
        break;
      }

      default:
        break;
    }
  }

  // ===== 玩家输入处理 =====
  handlePlayerInput(msg) {
    const p = this.players.get(msg.playerId);
    if (!p || !p.roomId) return;

    // 序列号去重/排序
    if (msg.seq <= p.lastInputSeq) return;
    p.lastInputSeq = msg.seq;

    const room = this.rooms.get(p.roomId);
    if (!room) return;

    // 更新玩家状态
    if (msg.pos) { p.pos.x = msg.pos.x; p.pos.y = msg.pos.y; p.pos.z = msg.pos.z; }
    if (msg.vel) { p.vel.x = msg.vel.x; p.vel.y = msg.vel.y; p.vel.z = msg.vel.z; }
    if (msg.yaw !== undefined) p.yaw = msg.yaw;
    if (msg.pitch !== undefined) p.pitch = msg.pitch;
    if (msg.alive !== undefined) p.alive = msg.alive;
    if (msg.deployed !== undefined) p.deployed = msg.deployed;
    if (msg.crouch !== undefined) p.crouch = msg.crouch;
    if (msg.prone !== undefined) p.prone = msg.prone;
    if (msg.sprinting !== undefined) p.sprinting = msg.sprinting;
    if (msg.ads !== undefined) p.ads = msg.ads;
    if (msg.onGround !== undefined) p.onGround = msg.onGround;
    if (msg.curWeapon !== undefined) p.curWeapon = msg.curWeapon;
    if (msg.firing !== undefined) p.firing = msg.firing;
    if (msg.hp !== undefined) p.hp = msg.hp;

    p.dirty = true;
    p.lastHeartbeat = Date.now();
  }

  // ===== 玩家事件处理（射击、受击、死亡等） =====
  handlePlayerEvent(msg) {
    const p = this.players.get(msg.playerId);
    if (!p || !p.roomId) return;
    const room = this.rooms.get(p.roomId);
    if (!room) return;

    // 高优先级事件立即广播
    const event = {
      type: 'playerEvent',
      playerId: p.id,
      eventType: msg.eventType, // fire, hit, kill, die, nade, skill, reload
      data: msg.data || {},
      tick: room.tick,
    };
    this.broadcastRoom(room, event, [p.id]);
  }

  // ===== 开始对局 =====
  startMatch(room) {
    room.matchStarted = true;
    room.matchStartTime = Date.now();
    room.tick = 0;

    // 分配队伍
    let team = 0;
    for (const p of room.players.values()) {
      p.team = team % 2;
      p.alive = true;
      p.deployed = true;
      p.hp = 100;
      p.kills = p.deaths = p.score = 0;
      p.dirty = true;
      team++;
    }

    this.broadcastRoom(room, {
      type: 'matchStart',
      matchTime: 15 * 60,
      players: Array.from(room.players.values()).map(p => ({
        id: p.id, name: p.name, team: p.team, cls: p.cls,
      })),
    });
    console.log(`[联机] 对局开始: ${room.id} (${room.playerCount}人)`);
  }

  // ===== Tick 循环 =====
  tick() {
    for (const room of this.rooms.values()) {
      if (!room.matchStarted) continue;
      room.tick++;

      // 收集脏数据
      const dirtyPlayers = [];
      for (const p of room.players.values()) {
        if (p.dirty || room.tick % 10 === 0) { // 每10 tick全量同步一次
          dirtyPlayers.push(p);
          p.dirty = false;
        }
      }

      if (dirtyPlayers.length === 0) continue;

      // 为每个玩家构建视野内同步数据
      for (const viewer of room.players.values()) {
        if (!viewer.ws || viewer.ws.readyState !== 1) continue;
        viewer.lastSyncTick = room.tick;

        const syncData = [];
        for (const p of dirtyPlayers) {
          if (p.id === viewer.id) continue; // 不发送自己的数据
          // 视野裁剪
          const dx = p.pos.x - viewer.pos.x;
          const dz = p.pos.z - viewer.pos.z;
          const dist = Math.sqrt(dx * dx + dz * dz);
          if (dist > CONFIG.SYNC_DISTANCE) {
            // 视野外低频同步
            if (room.tick % CONFIG.FAR_SYNC_RATE !== (p.id.charCodeAt(0) || 0) % CONFIG.FAR_SYNC_RATE) continue;
          }
          syncData.push(packPlayerState(p));
        }

        if (syncData.length === 0) continue;

        // 打包发送
        this.sendToPlayer(viewer, {
          type: 'sync',
          tick: room.tick,
          players: syncData,
        });
      }
    }
  }

  // ===== 发送 =====
  sendToPlayer(p, msg) {
    if (!p.ws || p.ws.readyState !== 1) return;
    try {
      const data = serialize(msg);
      p.ws.send(data);
      this.stats.bytesSent += data.length || data.byteLength || 0;
    } catch (e) {
      this.stats.droppedPackets++;
    }
  }

  broadcastRoom(room, msg, excludeIds = []) {
    const exclude = new Set(excludeIds);
    for (const p of room.players.values()) {
      if (exclude.has(p.id)) continue;
      this.sendToPlayer(p, msg);
    }
  }

  // ===== 清理 =====
  cleanup() {
    const now = Date.now();
    for (const [id, room] of this.rooms) {
      if (room.isEmpty() || room.isInactive()) {
        for (const p of room.players.values()) {
          if (p.ws) { try { p.ws.send(JSON.stringify({ type: 'roomClosed' })); } catch (e) {} }
          p.roomId = null;
          playerPool.release(p);
          this.players.delete(p.id);
        }
        this.rooms.delete(id);
        console.log(`[联机] 清理房间: ${id}`);
      }
    }
    // 更新峰值
    this.stats.peakPlayers = Math.max(this.stats.peakPlayers, this.players.size);
  }

  getStats() {
    return {
      ...this.stats,
      activePlayers: this.players.size,
      activeRooms: this.rooms.size,
      rooms: Array.from(this.rooms.values()).map(r => ({
        id: r.id, name: r.name, players: r.playerCount, max: r.maxPlayers, started: r.matchStarted,
      })),
    };
  }
}

module.exports = { MultiplayerServer, CONFIG };