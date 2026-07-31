// ============================================
// 钢铁前线 · 多人联机 UI 集成层
// 在游戏 HTML 的 </body> 前插入此脚本即可
// ============================================
(function () {
  'use strict';

  // 等待游戏初始化完成
  let gameReady = false;
  let player = null;
  let scene = null;
  let renderer = null;
  let camera = null;

  // 等待全局变量就绪
  function waitForGame() {
    if (typeof window.player !== 'undefined' && window.player) {
      player = window.player;
    }
    if (typeof window.scene !== 'undefined') scene = window.scene;
    if (typeof window.renderer !== 'undefined') renderer = window.renderer;
    if (typeof window.camera !== 'undefined') camera = window.camera;

    if (player && scene && renderer) {
      gameReady = true;
      initMultiplayer();
    } else {
      setTimeout(waitForGame, 500);
    }
  }

  // ============ 联机 UI ============
  function createMPUI() {
    const ui = document.createElement('div');
    ui.id = 'mpUI';
    ui.innerHTML = `
    <style>
#mpUI { position:fixed; z-index:100; pointer-events:none; }
#mpUI * { pointer-events:auto; }
#mpLobby { position:fixed; inset:0; z-index:100; display:none; align-items:center; justify-content:center; background:rgba(8,10,6,.94); color:#ddd; }
#mpLobby.show { display:flex; }
#mpLobby .panel { width:700px; max-width:94vw; max-height:92vh; overflow:auto; padding:30px 40px; }
#mpLobby h2 { font-size:36px; letter-spacing:6px; color:#e8dcb0; text-align:center; }
#mpLobby .subtitle { text-align:center; color:#9a9478; margin:8px 0 24px; font-size:13px; }
#mpLobby .btn { display:block; width:100%; padding:14px; margin:10px 0; font-size:16px; letter-spacing:3px; border:1px solid #666; border-radius:4px; background:rgba(255,255,255,.06); color:#ddd; cursor:pointer; transition:all .15s; font-family:inherit; }
#mpLobby .btn:hover { border-color:#b8a86a; color:#fff; background:rgba(200,175,95,.15); }
#mpLobby .btn.primary { background:linear-gradient(180deg,#5a5236,#3a3422); color:#f0e6c0; border:1px solid #8a7c50; }
#mpLobby .btn.primary:hover { box-shadow:0 0 18px rgba(220,190,110,.3); }
#mpLobby .btn.danger { border-color:#a44; color:#e88; }
#mpLobby .btn:disabled { opacity:.4; cursor:default; }
#mpLobby .input { width:100%; padding:12px; font-size:16px; background:rgba(255,255,255,.08); border:1px solid #555; border-radius:4px; color:#fff; margin:8px 0; font-family:inherit; }
#mpLobby .input:focus { border-color:#b8a86a; outline:none; }
#mpLobby .roomCard { background:rgba(255,255,255,.05); border:1px solid #444; border-radius:6px; padding:14px; margin:8px 0; cursor:pointer; transition:all .15s; }
#mpLobby .roomCard:hover { border-color:#b8a86a; background:rgba(200,175,95,.1); }
#mpLobby .roomCard .rname { color:#e8dcb0; font-size:17px; }
#mpLobby .roomCard .rinfo { color:#999; font-size:13px; margin-top:4px; }
#mpLobby .memberRow { display:flex; align-items:center; padding:8px 12px; margin:4px 0; background:rgba(255,255,255,.04); border-radius:4px; }
#mpLobby .memberRow .mname { flex:1; color:#ddd; }
#mpLobby .memberRow .mstatus { color:#999; font-size:13px; margin-right:12px; }
#mpLobby .memberRow .mready { color:#6f6; }
#mpLobby .memberRow .mnotready { color:#aa6; }
#mpLobby .memberRow .mhost { color:#f90; }
#mpLobby .latency { position:fixed; right:120px; top:10px; z-index:30; font-size:12px; letter-spacing:1px; padding:3px 8px; border-radius:3px; background:rgba(0,0,0,.5); }
#mpLobby .latency.green { color:#4f4; }
#mpLobby .latency.yellow { color:#ff4; }
#mpLobby .latency.red { color:#f44; }
#mpChat { position:fixed; left:10px; bottom:100px; z-index:30; width:280px; display:none; }
#mpChat .msgs { max-height:160px; overflow-y:auto; font-size:12px; color:#ccc; margin-bottom:4px; background:rgba(0,0,0,.45); border-radius:4px; padding:6px; }
#mpChat .msgs .m { margin:2px 0; }
#mpChat .msgs .m b { color:#ffd77a; }
#mpChat input { width:100%; padding:6px; background:rgba(0,0,0,.5); border:1px solid rgba(255,255,255,.2); color:#fff; border-radius:3px; font-size:12px; }
#quickChat { position:fixed; right:10px; top:40%; z-index:30; display:none; }
#quickChat .qc { display:block; padding:4px 10px; margin:3px 0; font-size:11px; background:rgba(0,0,0,.5); border:1px solid rgba(255,255,255,.2); color:#ddd; border-radius:3px; cursor:pointer; }
</style>

<div id="mpLobby">
  <div class="panel">
    <h2>⚔ 多人联机</h2>
    <div class="subtitle" id="mpStatus">未连接</div>
    <div id="mpMainMenu">
      <button class="btn primary" onclick="MPUI.createRoom()">创建房间</button>
      <button class="btn" onclick="MPUI.showJoinRoom()">输入房间号加入</button>
      <button class="btn" onclick="MPUI.quickMatch()">快速匹配</button>
      <button class="btn" onclick="MPUI.showRoomList()">房间列表</button>
      <button class="btn" onclick="MPUI.closeLobby()">返回游戏</button>
    </div>
    <div id="mpCreateRoom" style="display:none">
      <input class="input" id="mpRoomName" placeholder="房间名称" value="战场">
      <input class="input" id="mpMaxPlayers" placeholder="最大人数 (2-8)" value="4" type="number" min="2" max="8">
      <label style="color:#aaa;font-size:13px;display:flex;align-items:center;gap:8px;margin:8px 0">
        <input type="checkbox" id="mpAIEnabled"> 启用 AI 敌人
      </label>
      <button class="btn primary" onclick="MPUI.doCreateRoom()">确认创建</button>
      <button class="btn" onclick="MPUI.backToMenu()">返回</button>
    </div>
    <div id="mpJoinRoom" style="display:none">
      <input class="input" id="mpRoomId" placeholder="输入房间号">
      <button class="btn primary" onclick="MPUI.doJoinRoom()">加入房间</button>
      <button class="btn" onclick="MPUI.backToMenu()">返回</button>
    </div>
    <div id="mpRoomList" style="display:none"></div>
    <div id="mpRoomLobby" style="display:none">
      <div id="mpRoomInfo"></div>
      <div id="mpMemberList"></div>
      <div style="margin-top:16px;display:flex;gap:10px">
        <button class="btn primary" id="mpReadyBtn" onclick="MPUI.toggleReady()">准备</button>
        <button class="btn" id="mpStartBtn" onclick="MPUI.startMatch()" disabled>开始对局</button>
        <button class="btn danger" onclick="MPUI.leaveRoom()">离开房间</button>
      </div>
    </div>
  </div>
</div>

<div class="latency" id="mpLatency" style="display:none">联机: --ms</div>
<div id="mpChat">
  <div class="msgs" id="mpChatMsgs"></div>
  <input id="mpChatInput" placeholder="按 Enter 发送消息...">
</div>
<div id="quickChat">
  <button class="qc" onclick="MPUI.sendChat('掩护我！')">掩护我！</button>
  <button class="qc" onclick="MPUI.sendChat('发现敌人！')">发现敌人！</button>
  <button class="qc" onclick="MPUI.sendChat('需要支援！')">需要支援！</button>
  <button class="qc" onclick="MPUI.sendChat('干得好！')">干得好！</button>
</div>
`;
    document.body.appendChild(ui);
  }

  // ============ Multiplayer.getRemotePlayers 暴露联机数据 ============
  // 供游戏主循环调用

  // ============ UI 控制器 ============
  window.MPUI = {
    openLobby() {
      document.getElementById('mpLobby').classList.add('show');
      document.getElementById('mpMainMenu').style.display = 'block';
      document.getElementById('mpCreateRoom').style.display = 'none';
      document.getElementById('mpJoinRoom').style.display = 'none';
      document.getElementById('mpRoomList').style.display = 'none';
      document.getElementById('mpRoomLobby').style.display = 'none';
      // 解锁鼠标
      if (document.exitPointerLock) document.exitPointerLock();
    },

    closeLobby() {
      document.getElementById('mpLobby').classList.remove('show');
    },

    showCreateRoom() {
      document.getElementById('mpMainMenu').style.display = 'none';
      document.getElementById('mpCreateRoom').style.display = 'block';
    },

    showJoinRoom() {
      document.getElementById('mpMainMenu').style.display = 'none';
      document.getElementById('mpJoinRoom').style.display = 'block';
    },

    showRoomList() {
      document.getElementById('mpMainMenu').style.display = 'none';
      document.getElementById('mpRoomList').style.display = 'block';
      Multiplayer.requestRoomList();
    },

    backToMenu() {
      document.getElementById('mpMainMenu').style.display = 'block';
      document.getElementById('mpCreateRoom').style.display = 'none';
      document.getElementById('mpJoinRoom').style.display = 'none';
      document.getElementById('mpRoomList').style.display = 'none';
      document.getElementById('mpRoomLobby').style.display = 'none';
    },

    createRoom() {
      this.showCreateRoom();
    },

    doCreateRoom() {
      const name = document.getElementById('mpRoomName').value || '战场';
      const max = parseInt(document.getElementById('mpMaxPlayers').value) || 4;
      const ai = document.getElementById('mpAIEnabled').checked;
      Multiplayer.createRoom(name, Math.min(8, Math.max(2, max)), ai);
    },

    doJoinRoom() {
      const roomId = document.getElementById('mpRoomId').value.trim();
      if (roomId) Multiplayer.joinRoom(roomId);
    },

    quickMatch() {
      Multiplayer.quickMatch();
    },

    toggleReady() {
      Multiplayer.toggleReady();
    },

    startMatch() {
      Multiplayer.startMatch();
    },

    leaveRoom() {
      Multiplayer.leaveRoom();
      this.backToMenu();
    },

    sendChat(text) {
      Multiplayer.sendChat(text);
    },

    updateRoomLobby(room) {
      document.getElementById('mpMainMenu').style.display = 'none';
      document.getElementById('mpCreateRoom').style.display = 'none';
      document.getElementById('mpJoinRoom').style.display = 'none';
      document.getElementById('mpRoomList').style.display = 'none';
      document.getElementById('mpRoomLobby').style.display = 'block';

      document.getElementById('mpRoomInfo').innerHTML = '<div style="color:#e8dcb0;font-size:18px">房间: ' + (room.name || room.id) + '</div><div style="color:#999;font-size:13px">' + room.playerCount + '/' + room.maxPlayers + ' 人 | 房间号: ' + room.id + '</div>';

      let membersHTML = '';
      if (room.members) {
        room.members.forEach(m => {
          const status = m.ready ? '<span class="mready">✓ 已准备</span>' : '<span class="mnotready">○ 未准备</span>';
          const host = m.isHost ? ' <span class="mhost">[房主]</span>' : '';
          const you = m.id === Multiplayer.getPlayerId() ? ' (你)' : '';
          membersHTML += '<div class="memberRow"><span class="mname">' + m.name + you + host + '</span><span class="mstatus">' + status + ' | ' + (m.latency || '?') + 'ms</span></div>';
        });
      }
      document.getElementById('mpMemberList').innerHTML = membersHTML;

      // 房主才能开始
      const isHost = room.members && room.members.some(m => m.id === Multiplayer.getPlayerId() && m.isHost);
      document.getElementById('mpStartBtn').disabled = !isHost;
    },

    addChatMessage(playerName, text) {
      const msgs = document.getElementById('mpChatMsgs');
      msgs.innerHTML += '<div class="m"><b>' + playerName + ':</b> ' + text + '</div>';
      msgs.scrollTop = msgs.scrollHeight;
      // 只保留最近 50 条
      while (msgs.children.length > 50) msgs.removeChild(msgs.firstChild);
    },
  };

  // ============ 初始化联机 ============
  function initMultiplayer() {
    if (!window.Multiplayer) {
      console.error('[联机] Multiplayer 客户端库未加载');
      return;
    }

    createMPUI();

    // 获取服务器地址
    const wsUrl = (window.location.protocol === 'https:' ? 'wss://' : 'ws://') + window.location.host + '/gateway/realtime';

    // 注册回调
    Multiplayer.on('onConnected', () => {
      document.getElementById('mpStatus').textContent = '已连接';
    });

    Multiplayer.on('onDisconnected', () => {
      document.getElementById('mpStatus').textContent = '已断开';
      document.getElementById('mpLatency').style.display = 'none';
      document.getElementById('mpChat').style.display = 'none';
      document.getElementById('quickChat').style.display = 'none';
    });

    Multiplayer.on('onAuthOk', (msg) => {
      document.getElementById('mpStatus').textContent = '已认证: ' + msg.name;
    });

    Multiplayer.on('onRoomCreated', (room) => {
      window.MPUI.updateRoomLobby(room);
    });

    Multiplayer.on('onRoomJoined', (room) => {
      window.MPUI.updateRoomLobby(room);
    });

    Multiplayer.on('onRoomLeft', () => {
      window.MPUI.backToMenu();
    });

    Multiplayer.on('onPlayerJoined', (msg) => {
      if (Multiplayer.getRoom()) {
        window.MPUI.updateRoomLobby(Multiplayer.getRoom());
      }
    });

    Multiplayer.on('onPlayerLeave', (msg) => {
      if (Multiplayer.getRoom()) {
        window.MPUI.updateRoomLobby(Multiplayer.getRoom());
      }
      // 清理远程模型
      if (msg.model && scene) scene.remove(msg.model);
    });

    Multiplayer.on('onReadyUpdate', (msg) => {
      if (Multiplayer.getRoom()) {
        window.MPUI.updateRoomLobby(Multiplayer.getRoom());
      }
    });

    Multiplayer.on('onMatchStart', (msg) => {
      document.getElementById('mpLobby').classList.remove('show');
      document.getElementById('mpLatency').style.display = 'block';
      document.getElementById('mpChat').style.display = 'block';
      document.getElementById('quickChat').style.display = 'block';
      // 创建远程玩家模型
      createRemoteModels(msg.players);
    });

    Multiplayer.on('onChat', (msg) => {
      window.MPUI.addChatMessage(msg.playerName, msg.text);
    });

    Multiplayer.on('onLatencyUpdate', (data) => {
      const el = document.getElementById('mpLatency');
      el.style.display = 'block';
      el.textContent = '联机: ' + data.latency + 'ms';
      el.className = 'latency ' + (data.quality === 0 ? 'green' : data.quality === 1 ? 'yellow' : 'red');
    });

    Multiplayer.on('onError', (msg) => {
      document.getElementById('mpStatus').textContent = '错误: ' + msg;
    });

    // 连接
    Multiplayer.connect(wsUrl, '', player.name || '战士');

    // 注册快捷键
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && document.getElementById('mpChatInput') === document.activeElement) {
        const input = document.getElementById('mpChatInput');
        if (input.value.trim()) {
          window.MPUI.sendChat(input.value.trim());
          input.value = '';
        }
        e.preventDefault();
        e.stopPropagation();
      }
      if (e.key === 'm' && e.ctrlKey) {
        e.preventDefault();
        if (document.getElementById('mpLobby').classList.contains('show')) {
          window.MPUI.closeLobby();
        } else {
          window.MPUI.openLobby();
        }
      }
    });

    // 联机游戏循环
    function mpGameLoop() {
      if (!Multiplayer.isMatchStarted()) {
        requestAnimationFrame(mpGameLoop);
        return;
      }

      // 发送玩家状态
      if (player && player.pos) {
        Multiplayer.sendInput({
          pos: { x: player.pos.x, y: player.pos.y, z: player.pos.z },
          vel: player.vel || { x: 0, y: 0, z: 0 },
          yaw: player.yaw || 0,
          pitch: player.pitch || 0,
          alive: player.alive || false,
          deployed: player.deployed || false,
          crouch: player.crouch || false,
          prone: player.prone || false,
          sprinting: player.sprinting || false,
          ads: player.ads || false,
          onGround: player.onGround !== false,
          curWeapon: player.curW ? player.curW.key || 0 : 0,
          firing: player.fireT > 0,
          hp: player.hp || 100,
        });
      }

      // 更新远程玩家模型
      const states = Multiplayer.getInterpolatedStates();
      updateRemoteModels(states);

      requestAnimationFrame(mpGameLoop);
    }

    requestAnimationFrame(mpGameLoop);
    console.log('[联机] UI 已初始化');
  }

  // ============ 远程玩家模型 ============
  function createRemoteModels(players) {
    if (!players || !scene) return;

    players.forEach(p => {
      if (p.id === Multiplayer.getPlayerId()) return;
      if (Multiplayer.getRemoteModel(p.id)) return;

      // 创建简易角色模型
      const group = new THREE.Group();

      // 身体
      const bodyGeo = new THREE.CapsuleGeometry(0.35, 1.0, 4, 8);
      const bodyMat = new THREE.MeshStandardMaterial({ color: p.team === 0 ? 0x3366aa : 0xaa3333 });
      const body = new THREE.Mesh(bodyGeo, bodyMat);
      body.position.y = 1.0;
      body.castShadow = true;
      group.add(body);

      // 头部
      const headGeo = new THREE.SphereGeometry(0.2, 8, 8);
      const headMat = new THREE.MeshStandardMaterial({ color: 0xddaa88 });
      const head = new THREE.Mesh(headGeo, headMat);
      head.position.y = 1.9;
      group.add(head);

      // 名字标签 (使用 canvas)
      const canvas = document.createElement('canvas');
      canvas.width = 256;
      canvas.height = 64;
      const ctx = canvas.getContext('2d');
      ctx.fillStyle = p.team === 0 ? '#88bbff' : '#ff8888';
      ctx.font = 'bold 28px sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText(p.name, 128, 40);
      const tex = new THREE.CanvasTexture(canvas);
      const labelMat = new THREE.SpriteMaterial({ map: tex, transparent: true });
      const label = new THREE.Sprite(labelMat);
      label.position.y = 2.3;
      label.scale.set(2, 0.5, 1);
      group.add(label);

      scene.add(group);
      Multiplayer.setRemoteModel(p.id, group);
    });
  }

  function updateRemoteModels(states) {
    states.forEach(s => {
      const model = Multiplayer.getRemoteModel(s.id);
      if (!model) return;

      model.position.set(s.pos.x, s.pos.y, s.pos.z);
      model.rotation.y = s.yaw;

      // 更新姿态
      const body = model.children[0]; // body mesh
      const head = model.children[1]; // head mesh

      if (s.prone) {
        model.position.y -= 0.8;
        body.rotation.x = Math.PI / 2;
      } else if (s.crouch) {
        body.scale.y = 0.7;
        head.position.y = 1.5;
      } else {
        body.scale.y = 1;
        head.position.y = 1.9;
      }

      // 颜色随 HP 变化
      const hpRatio = s.hp / 100;
      if (body.material) {
        body.material.color.setRGB(
          s.team === 0 ? 0.2 + 0.3 * hpRatio : 0.6 * hpRatio,
          0.2 * hpRatio,
          s.team === 0 ? 0.5 * hpRatio : 0.2
        );
      }

      model.visible = s.alive;
    });
  }

  // 启动
  waitForGame();
})();