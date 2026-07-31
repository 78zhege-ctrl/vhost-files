// ============================================
// 钢铁前线 · 多人联机客户端库 v1.0.0
// 集成到游戏 HTML 中即可使用
// ============================================
'use strict';

(function (global) {
  const MP = {};

  // ============ 配置 ============
  const CFG = {
    TICK_RATE: 15,
    SYNC_INTERVAL: 1000 / 15,  // 输入发送间隔
    RECONNECT_DELAY: 3000,
    MAX_RECONNECT: 5,
    INTERP_DELAY: 100,         // 插值延迟 (ms)
    PREDICTION_ENABLED: true,
    LOW_LATENCY_MODE: false,
  };

  // ============ 连接状态 ============
  let ws = null;
  let connected = false;
  let authenticated = false;
  let playerId = null;
  let playerName = '';
  let reconnectCount = 0;
  let reconnectTimer = null;
  let serverUrl = '';
  let serverToken = '';
  let lastPing = 0;
  let latency = 0;
  let latencyQuality = 0; // 0=绿 1=黄 2=红
  let packetLoss = 0;
  let packetsSent = 0;
  let packetsAcked = 0;

  // ============ 房间状态 ============
  let currentRoom = null;
  let matchStarted = false;
  let matchTick = 0;

  // ============ 远程玩家管理 ============
  // 远程玩家镜像: playerId → { pos, vel, yaw, pitch, hp, alive, ... }
  const remotePlayers = new Map();
  const remoteModels = new Map(); // playerId → THREE.Group

  // 插值状态
  const interpStates = new Map(); // playerId → { prev, next, alpha }

  // ============ 输入缓冲 ============
  let inputSeq = 0;
  let lastInputSend = 0;
  let inputBuffer = null;

  // ============ 回调 ============
  const callbacks = {
    onConnected: null,
    onDisconnected: null,
    onAuthOk: null,
    onRoomCreated: null,
    onRoomJoined: null,
    onRoomLeft: null,
    onPlayerJoined: null,
    onPlayerLeave: null,
    onReadyUpdate: null,
    onMatchStart: null,
    onSync: null,
    onPlayerEvent: null,
    onChat: null,
    onError: null,
    onLatencyUpdate: null,
  };

  // ============ 连接 ============
  MP.connect = function (url, token, username) {
    serverUrl = url;
    serverToken = token;
    if (username) playerName = username;
    reconnectCount = 0;
    _connect();
  };

  function _connect() {
    if (ws) {
      try { ws.close(); } catch (e) { }
    }

    try {
      ws = new WebSocket(serverUrl);
    } catch (e) {
      _onError('无法连接服务器');
      return;
    }

    ws.binaryType = 'arraybuffer';

    ws.onopen = () => {
      connected = true;
      if (callbacks.onConnected) callbacks.onConnected();

      // 握手后自动认证
      ws.onmessage = (e) => {
        let msg;
        if (e.data instanceof ArrayBuffer) {
          const buf = new Uint8Array(e.data);
          msg = _decode(buf);
        } else {
          try { msg = JSON.parse(e.data); } catch (err) { return; }
        }
        if (!msg) return;

        if (msg.type === 'handshake') {
          // 握手完成，发送认证
          _send({ type: 'auth', token: serverToken, username: playerName });
        } else {
          _handleMessage(msg);
        }
      };
    };

    ws.onclose = () => {
      connected = false;
      authenticated = false;
      if (callbacks.onDisconnected) callbacks.onDisconnected();
      _tryReconnect();
    };

    ws.onerror = () => {
      // onclose 会处理
    };
  }

  function _tryReconnect() {
    if (reconnectCount >= CFG.MAX_RECONNECT) {
      _onError('重连失败，已达最大次数');
      return;
    }
    reconnectCount++;
    reconnectTimer = setTimeout(() => {
      _connect();
    }, CFG.RECONNECT_DELAY);
  }

  MP.disconnect = function () {
    if (reconnectTimer) clearTimeout(reconnectTimer);
    reconnectCount = CFG.MAX_RECONNECT; // 禁止重连
    if (ws) { try { ws.close(); } catch (e) { } }
    ws = null;
    connected = false;
    authenticated = false;
    currentRoom = null;
    matchStarted = false;
    remotePlayers.clear();
    interpStates.clear();
  };

  MP.isConnected = function () { return connected && authenticated; };
  MP.getLatency = function () { return latency; };
  MP.getLatencyQuality = function () { return latencyQuality; };
  MP.getPlayerId = function () { return playerId; };
  MP.getRemotePlayers = function () { return remotePlayers; };
  MP.getRoom = function () { return currentRoom; };
  MP.isMatchStarted = function () { return matchStarted; };

  // ============ 消息处理 ============
  function _handleMessage(msg) {
    switch (msg.type) {
      case 'ping':
        _send({ type: 'pong', t: msg.t });
        break;

      case 'pong':
        lastPing = Date.now();
        break;

      case 'authOk':
        playerId = msg.playerId;
        playerName = msg.name;
        authenticated = true;
        if (callbacks.onAuthOk) callbacks.onAuthOk(msg);
        break;

      case 'roomCreated':
        currentRoom = msg.room;
        if (callbacks.onRoomCreated) callbacks.onRoomCreated(msg.room);
        break;

      case 'roomJoined':
        currentRoom = msg.room;
        if (callbacks.onRoomJoined) callbacks.onRoomJoined(msg.room);
        break;

      case 'roomLeft':
        currentRoom = null;
        if (callbacks.onRoomLeft) callbacks.onRoomLeft();
        break;

      case 'playerJoined':
        if (currentRoom && msg.player) {
          _addRemotePlayer(msg.player.id, msg.player.name);
        }
        if (callbacks.onPlayerJoined) callbacks.onPlayerJoined(msg);
        break;

      case 'playerLeave':
        _removeRemotePlayer(msg.playerId);
        if (callbacks.onPlayerLeave) callbacks.onPlayerLeave(msg);
        break;

      case 'readyUpdate':
        if (callbacks.onReadyUpdate) callbacks.onReadyUpdate(msg);
        break;

      case 'matchStart':
        matchStarted = true;
        matchTick = 0;
        // 初始化所有远程玩家
        remotePlayers.clear();
        interpStates.clear();
        if (msg.players) {
          msg.players.forEach(p => {
            if (p.id !== playerId) _addRemotePlayer(p.id, p.name, p.team);
          });
        }
        if (callbacks.onMatchStart) callbacks.onMatchStart(msg);
        break;

      case 'sync':
        matchTick = msg.tick;
        if (msg.players && Array.isArray(msg.players)) {
          _processSync(msg.players);
        }
        if (callbacks.onSync) callbacks.onSync(msg);
        break;

      case 'playerEvent':
        if (callbacks.onPlayerEvent) callbacks.onPlayerEvent(msg);
        break;

      case 'chat':
        if (callbacks.onChat) callbacks.onChat(msg);
        break;

      case 'roomClosed':
        currentRoom = null;
        matchStarted = false;
        if (callbacks.onError) callbacks.onError('房间已关闭');
        break;

      case 'error':
        _onError(msg.error);
        break;
    }
  }

  // ============ 同步处理 ============
  function _processSync(playerDataArray) {
    const now = performance.now();
    for (const item of playerDataArray) {
      let pid, state;
      if (item instanceof Buffer || item instanceof Uint8Array) {
        // 二进制格式 — 需要解析
        // 暂用 JSON 格式
        continue;
      } else if (item.id) {
        // JSON 格式
        pid = item.id;
        state = item;
      } else {
        continue;
      }

      if (pid === playerId) continue;

      let rp = remotePlayers.get(pid);
      if (!rp) {
        _addRemotePlayer(pid, state.name || '玩家');
        rp = remotePlayers.get(pid);
      }

      // 存储插值目标
      if (!interpStates.has(pid)) {
        interpStates.set(pid, { prev: null, next: null, time: 0 });
      }
      const is = interpStates.get(pid);

      // 从状态中提取数据
      if (state.pos) {
        is.prev = is.next ? { ...is.next } : { pos: { ...state.pos }, yaw: state.yaw || 0 };
        is.next = {
          pos: { ...state.pos },
          yaw: state.yaw || 0,
          pitch: state.pitch || 0,
          vel: state.vel || { x: 0, z: 0 },
          flags: state.flags || 0,
          hp: state.hp || 100,
          curWeapon: state.curWeapon || 0,
        };
        is.time = now;
      }

      // 更新远程玩家基础状态
      if (state.pos) rp.pos = { ...state.pos };
      if (state.yaw !== undefined) rp.yaw = state.yaw;
      if (state.pitch !== undefined) rp.pitch = state.pitch;
      if (state.vel) rp.vel = { ...state.vel };
      if (state.hp !== undefined) rp.hp = state.hp;
      if (state.alive !== undefined) rp.alive = state.alive;
      if (state.crouch !== undefined) rp.crouch = state.crouch;
      if (state.prone !== undefined) rp.prone = state.prone;
      if (state.sprinting !== undefined) rp.sprinting = state.sprinting;
      if (state.ads !== undefined) rp.ads = state.ads;
      if (state.firing !== undefined) rp.firing = state.firing;
      if (state.curWeapon !== undefined) rp.curWeapon = state.curWeapon;
      if (state.kills !== undefined) rp.kills = state.kills;
      if (state.deaths !== undefined) rp.deaths = state.deaths;
      if (state.score !== undefined) rp.score = state.score;
    }
  }

  // ============ 远程玩家管理 ============
  function _addRemotePlayer(id, name, team) {
    if (remotePlayers.has(id)) return;
    remotePlayers.set(id, {
      id, name, team: team || 0,
      pos: { x: 0, y: 0, z: 0 },
      vel: { x: 0, y: 0, z: 0 },
      yaw: 0, pitch: 0,
      hp: 100, alive: true,
      crouch: false, prone: false, sprinting: false, ads: false,
      firing: false, curWeapon: 0,
      kills: 0, deaths: 0, score: 0,
    });
  }

  function _removeRemotePlayer(id) {
    remotePlayers.delete(id);
    interpStates.delete(id);
    // 通知外部清理模型
    const model = remoteModels.get(id);
    if (model && callbacks.onPlayerLeave) {
      callbacks.onPlayerLeave({ playerId: id, model });
    }
    remoteModels.delete(id);
  }

  // ============ 插值计算 ============
  // 每帧调用，返回所有远程玩家插值后的位置
  MP.getInterpolatedStates = function () {
    const now = performance.now();
    const result = [];
    const renderTime = now - CFG.INTERP_DELAY;

    for (const [pid, is] of interpStates) {
      if (!is.prev || !is.next) continue;
      const rp = remotePlayers.get(pid);
      if (!rp) continue;

      // 丢包惯性补偿
      const elapsed = now - is.time;
      let alpha;
      if (elapsed > CFG.INTERP_DELAY * 2) {
        // 长时间没收到数据，用惯性推算
        alpha = 1;
        const dt = elapsed / 1000;
        is.next.pos.x += (rp.vel.x || 0) * dt;
        is.next.pos.z += (rp.vel.z || 0) * dt;
      } else {
        alpha = Math.min(1, (renderTime - is.time) / CFG.INTERP_DELAY);
      }

      const interp = {
        id: pid,
        name: rp.name,
        team: rp.team,
        pos: {
          x: is.prev.pos.x + (is.next.pos.x - is.prev.pos.x) * alpha,
          y: is.prev.pos.y + (is.next.pos.y - is.prev.pos.y) * alpha,
          z: is.prev.pos.z + (is.next.pos.z - is.prev.pos.z) * alpha,
        },
        yaw: _lerpAngle(is.prev.yaw, is.next.yaw, alpha),
        pitch: is.next.pitch,
        alive: rp.alive,
        hp: rp.hp,
        crouch: rp.crouch,
        prone: rp.prone,
        sprinting: rp.sprinting,
        ads: rp.ads,
        firing: rp.firing,
        curWeapon: rp.curWeapon,
        latency: rp.latency || 0,
      };
      result.push(interp);
    }
    return result;
  };

  function _lerpAngle(a, b, t) {
    let diff = b - a;
    while (diff > Math.PI) diff -= Math.PI * 2;
    while (diff < -Math.PI) diff += Math.PI * 2;
    return a + diff * t;
  }

  // ============ 发送 ============
  function _send(msg) {
    if (!ws || ws.readyState !== 1) return;
    try {
      const data = JSON.stringify(msg);
      ws.send(data);
      packetsSent++;
    } catch (e) { }
  }

  // ============ 玩家输入发送 ============
  // 每帧调用，传入当前玩家状态
  MP.sendInput = function (playerState) {
    if (!connected || !authenticated || !matchStarted) return;
    const now = performance.now();
    if (now - lastInputSend < CFG.SYNC_INTERVAL) return;
    lastInputSend = now;
    inputSeq++;

    _send({
      type: 'playerInput',
      playerId,
      seq: inputSeq,
      pos: playerState.pos,
      vel: playerState.vel,
      yaw: playerState.yaw,
      pitch: playerState.pitch,
      alive: playerState.alive,
      deployed: playerState.deployed,
      crouch: playerState.crouch,
      prone: playerState.prone,
      sprinting: playerState.sprinting,
      ads: playerState.ads,
      onGround: playerState.onGround,
      curWeapon: playerState.curWeapon,
      firing: playerState.firing,
      hp: playerState.hp,
    });
  };

  // ============ 事件发送 ============
  MP.sendEvent = function (eventType, data) {
    if (!connected || !authenticated) return;
    _send({
      type: 'playerEvent',
      playerId,
      eventType, // 'fire', 'hit', 'kill', 'die', 'nade', 'reload', 'skill'
      data: data || {},
    });
  };

  // ============ 房间操作 ============
  MP.createRoom = function (roomName, maxPlayers, aiEnabled) {
    _send({ type: 'createRoom', roomName: roomName || '战场', maxPlayers: maxPlayers || 4, aiEnabled: !!aiEnabled });
  };

  MP.joinRoom = function (roomId) {
    _send({ type: 'joinRoom', roomId });
  };

  MP.leaveRoom = function () {
    _send({ type: 'leaveRoom' });
  };

  MP.toggleReady = function () {
    _send({ type: 'toggleReady' });
  };

  MP.startMatch = function () {
    _send({ type: 'startMatch' });
  };

  MP.quickMatch = function () {
    _send({ type: 'quickMatch' });
  };

  MP.requestRoomList = function () {
    _send({ type: 'roomList' });
  };

  MP.sendChat = function (text) {
    _send({ type: 'chat', text: String(text).substring(0, 100) });
  };

  // ============ 回调注册 ============
  MP.on = function (event, fn) {
    callbacks[event] = fn;
  };

  // ============ 延迟测量 ============
  setInterval(() => {
    if (!connected || !authenticated) return;
    lastPing = performance.now();
    _send({ type: 'ping', t: Date.now() });
  }, 3000);

  // 监听 pong
  const origHandler = _handleMessage;
  // 在 _handleMessage 中处理 pong
  const origPong = callbacks.onLatencyUpdate;
  setInterval(() => {
    if (lastPing > 0) {
      latency = Math.round(performance.now() - lastPing);
      // 三色质量标识
      if (latency < 80) latencyQuality = 0;      // 绿
      else if (latency < 200) latencyQuality = 1; // 黄
      else latencyQuality = 2;                     // 红
      // 丢包率
      packetLoss = packetsSent > 0 ? Math.round((1 - packetsAcked / packetsSent) * 100) : 0;
      if (callbacks.onLatencyUpdate) {
        callbacks.onLatencyUpdate({ latency, quality: latencyQuality, packetLoss });
      }
      lastPing = 0;
    }
  }, 3000);

  // ============ 辅助 ============
  function _onError(msg) {
    console.error('[联机]', msg);
    if (callbacks.onError) callbacks.onError(msg);
  }

  function _decode(buf) {
    // 简易 JSON 解码 (后续可替换为 MsgPack)
    try {
      const str = new TextDecoder().decode(buf);
      return JSON.parse(str);
    } catch (e) {
      return null;
    }
  }

  // ============ 远程玩家模型管理 ============
  MP.setRemoteModel = function (playerId, model) {
    remoteModels.set(playerId, model);
  };

  MP.getRemoteModel = function (playerId) {
    return remoteModels.get(playerId);
  };

  MP.removeRemoteModel = function (playerId) {
    remoteModels.delete(playerId);
  };

  // ============ 导出 ============
  global.Multiplayer = MP;

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = MP;
  }
})(typeof window !== 'undefined' ? window : global);