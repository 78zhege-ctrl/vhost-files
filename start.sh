#!/data/data/com.termux/files/usr/bin/bash
# ============================================
# 手机虚拟主机 一键启动脚本（cloudflared 优先）
# ============================================
cd "$(dirname "$0")"

echo "=========================================="
echo "  手机多租户虚拟主机 v4.0.0 安全加固版"
echo "=========================================="

# 防止手机息屏杀进程
termux-wake-lock 2>/dev/null

# 杀掉旧进程
pkill -f "node server.js" 2>/dev/null
sleep 1

# 安装依赖（已装则跳过）
if [ ! -d node_modules ]; then
  echo "[1/4] 安装依赖..."
  npm install express jsonwebtoken multer cors ws compression
else
  echo "[1/4] 依赖已存在，跳过"
fi

# HTML 同步到 public 目录（兜底用，server.js 已内嵌页面）
mkdir -p public
cp -f panel.html public/host.html 2>/dev/null
cp -f panel.html public/admin.html 2>/dev/null
cp -f panel.html public/panel.html 2>/dev/null

# 语法检查
echo "[2/4] 检查 server.js ..."
node --check server.js || { echo "server.js 语法错误！请重新下载 fix.zip"; exit 1; }

# 启动服务器（后台）
echo "[3/4] 启动服务器 ..."
nohup node server.js > server.log 2>&1 &
sleep 3
if pgrep -f "node server.js" > /dev/null; then
  echo "      服务器已启动: http://localhost:3000"
else
  echo "      启动失败！把 server.log 内容截图发我"
  cat server.log
  exit 1
fi

# 启动隧道（前台，窗口不能关）
echo "[4/4] 启动隧道 ..."
if command -v cloudflared >/dev/null 2>&1; then
  echo "cloudflared" > .tunnel_mode
  echo "使用 Cloudflare 隧道，网址马上出现（找 trycloudflare.com 那一行）"
  echo "------------------------------------------"
  cloudflared tunnel --url http://localhost:3000 2>&1 | tee tunnel.log
elif command -v cpolar >/dev/null 2>&1; then
  echo "cpolar" > .tunnel_mode
  echo "未安装 cloudflared，使用 cpolar 隧道"
  echo "------------------------------------------"
  cpolar http 3000
else
  echo "没有隧道工具！先安装一个："
  echo "  pkg install cloudflared    （推荐）"
  echo "服务器还在后台跑着，装完隧道再运行本脚本即可"
fi
