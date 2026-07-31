#!/data/data/com.termux/files/usr/bin/bash
# ============================================
# 一键解密脚本 - 解密所有 .enc 文件
# 用法: bash decrypt.sh
# 加密工具: crypto-tool.js (5层 AES-256-GCM)
# ============================================
cd "$(dirname "$0")"

echo "=========================================="
echo "  多层加密解密工具 v1.0.0"
echo "  scrypt + 5层 AES-256-GCM 洋葱加密"
echo "=========================================="
echo ""

# 检查 crypto-tool.js 是否存在
if [ ! -f crypto-tool.js ]; then
  echo "❌ 错误: crypto-tool.js 不存在！"
  exit 1
fi

# 统计加密文件数量
ENC_COUNT=$(ls *.enc 2>/dev/null | wc -l)
if [ "$ENC_COUNT" -eq 0 ]; then
  echo "❌ 没有找到 .enc 加密文件"
  exit 1
fi

echo "找到 ${ENC_COUNT} 个加密文件"
echo ""

# 解密
node crypto-tool.js decrypt . -a

echo ""
echo "=========================================="
echo "  解密完成！"
echo "=========================================="