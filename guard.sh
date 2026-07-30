#!/data/data/com.termux/files/usr/bin/bash
# ============================================
# 守护脚本：服务器/隧道掉了自动拉起
# 用法：先运行 start.sh，再开新会话运行 bash guard.sh
# ============================================
cd "$(dirname "$0")"
termux-wake-lock 2>/dev/null

echo "守护进程已启动，每30秒检查一次（此窗口不能关）"

while true; do
  # ---- 攻击自动停机：等10分钟再恢复 ----
  if [ -f data/.attack_shutdown ]; then
    termux-notification -t "主机防护" -c "检测到过载攻击，主机已自动关闭，10分钟后自动恢复" 2>/dev/null
    echo "[守护] 攻击停机标志存在，等待10分钟..."
    sleep 600
    rm -f data/.attack_shutdown
    echo "[守护] 停机结束，恢复服务"
  fi

  # ---- 服务器进程检查 ----
  if ! pgrep -f "node server.js" > /dev/null; then
    echo "[守护] $(date +%H:%M:%S) 服务器掉线，自动重启..."
    termux-notification -t "主机守护" -c "服务器掉线，正在自动重启..." 2>/dev/null
    node --check server.js 2>/dev/null && nohup node server.js >> server.log 2>&1 &
    sleep 5
    pgrep -f "node server.js" > /dev/null && echo "[守护] 服务器已恢复"
  fi

  # ---- 隧道进程检查（cloudflared 掉了自动重开并通知新网址） ----
  if [ -f .tunnel_mode ]; then
    MODE=$(cat .tunnel_mode)
    if [ "$MODE" = "cloudflared" ] && ! pgrep -f cloudflared > /dev/null; then
      echo "[守护] $(date +%H:%M:%S) cloudflared 掉线，自动重开..."
      nohup cloudflared tunnel --url http://localhost:3000 > tunnel.log 2>&1 &
      sleep 10
      NEW_URL=$(grep -o "https://[a-z0-9-]*\.trycloudflare\.com" tunnel.log | head -1)
      if [ -n "$NEW_URL" ]; then
        echo "[守护] 隧道已恢复，新网址: $NEW_URL"
        termux-notification -t "主机守护" -c "隧道已重启，新网址: $NEW_URL" 2>/dev/null
      else
        echo "[守护] 隧道重启中，还没拿到网址，下轮再查"
      fi
    fi
    if [ "$MODE" = "cpolar" ] && ! pgrep -f cpolar > /dev/null; then
      echo "[守护] $(date +%H:%M:%S) cpolar 掉线！cpolar 需要看它的界面，请重新运行 start.sh"
      termux-notification -t "主机守护" -c "cpolar 隧道掉线，请重新运行 bash start.sh" 2>/dev/null
    fi
  fi

  # ---- 日志扫描：最近攻击事件统计通知 ----
  if [ -f server.log ]; then
    BAN_COUNT=$(grep -c "封禁IP" server.log 2>/dev/null || echo 0)
    if [ "$BAN_COUNT" -gt 0 ] && [ $((BAN_COUNT % 50)) -eq 0 ] && [ "$BAN_COUNT" != "$LAST_NOTIFY" ]; then
      termux-notification -t "主机防护" -c "已累计封禁 $BAN_COUNT 个恶意IP，防护正常运行中" 2>/dev/null
      LAST_NOTIFY=$BAN_COUNT
    fi
  fi

  sleep 30
done
