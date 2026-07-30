# 手机虚拟主机 接口文档 v4.0.0

服务器地址（BASE_URL）= 当前隧道网址，例如 `https://xxxx.r24.cpolar.top` 或 `https://xxxx.trycloudflare.com`（每次重启隧道会变，登录合并页后"🔗 我的主机网址"卡片里有当前最新地址）。

登录后所有需要身份的接口都带请求头：`Authorization: Bearer 你的token`

## v4.0.0 安全变更

- **管理密码环境变量**：管理密码不再硬编码，需通过 `ADMIN_PASSWORD` 环境变量设置
- **bcrypt 密码哈希**：用户密码使用 bcrypt（10轮）存储，带随机盐，抵御彩虹表攻击
- **管理接口强制 HMAC 签名**：所有 `/api/v2/sys/management/` 接口必须携带 HMAC-SHA256 签名
- **CSRF 保护**：API 请求检查 Origin/Referer 头，跨源请求默认拒绝
- **Content-Security-Policy**：所有页面启用 CSP 头，防止 XSS 和数据注入
- **Refresh Token 轮换**：刷新令牌后旧 token 立即失效，颁发新 token
- **资源过载保护**：内存使用率过高时自动进入保护模式
- **错误信息最小化**：所有错误响应不泄露内部实现细节
- **Session ID 安全随机**：使用 `crypto.randomUUID()` 生成会话 ID

## v3.5.0 安全变更

- **HMAC-SHA256 签名验证**：所有 API 请求需携带 `x-request-time`、`x-request-nonce`、`x-request-signature` 请求头
- **JWT 短有效期**：Access Token 有效期 15 分钟，需通过 Refresh Token 刷新
- **账户锁定**：登录失败 5 次锁定 5 分钟，10 次锁定 30 分钟，20 次锁定 24 小时
- **文件类型验证**：上传文件通过魔术字节检测，禁止可执行文件和脚本文件
- **错误信息最小化**：生产环境不暴露内部错误详情

---

## 接口清单（按使用顺序编号）

### ① 注册
```
POST {BASE_URL}/api/v2/auth/session/create
Body(JSON): {"username":"用户名", "password":"密码"}
返回: {"success":true, "token":"...", "refreshToken":"...", "host":{"uid":"20位ID","password":"...","url":"/h/uid/"}}
注意: token(JWT)有效期15分钟，refreshToken有效期7天
```

### ② 登录
```
POST {BASE_URL}/api/v2/auth/session/init
Body(JSON): {"username":"用户名", "password":"密码"}
返回: {"success":true, "token":"...", "refreshToken":"...", "geoAlert":{"message":"异地登录风险","uniqueIPs":3} or null}
注意: 登录失败5次触发账户锁定，返回HTTP 423状态码
```

### ③ 获取用户信息（含主机uid、套餐、空间用量）
```
GET {BASE_URL}/api/v2/user/profile/detail
Header: Authorization: Bearer token
```

### ④ 获取当前服务器网址（隧道+局域网，无需登录）
```
GET {BASE_URL}/api/v2/server/info
返回: {"tunnels":["https://..."],"lan":"http://192.168.x.x:3000"}
```

### ⑤ 上传文件
```
POST {BASE_URL}/api/v2/storage/files/upload/{主机uid}
Header: Authorization: Bearer token
Body: multipart/form-data，字段名 file
限制: 单文件最大50MB，每分钟最多60次
```

### ⑥ 文件列表
```
GET {BASE_URL}/api/v2/storage/files/list/{主机uid}
Header: Authorization: Bearer token
```

### ⑦ 删除文件
```
POST {BASE_URL}/api/v2/storage/files/remove/{主机uid}/{文件名}
Header: Authorization: Bearer token
```

### ⑦-1 文件改名（v3.3 新增）
```
POST {BASE_URL}/api/v2/storage/files/rename/{主机uid}/{文件名}
Header: Authorization: Bearer token
Body(JSON): {"new_name":"新文件名"}
```

### ⑦-2 创建文件夹（v3.3 新增）
```
POST {BASE_URL}/api/v2/storage/files/mkdir/{主机uid}
Header: Authorization: Bearer token
Body(JSON): {"dir_name":"文件夹名"}
```

### ⑦-3 文件预览（v3.3.1 新增）
```
GET {BASE_URL}/api/v2/storage/files/preview/{主机uid}/{文件名}
Header: Authorization: Bearer token
返回: 文本文件返回JSON {"type":"text","content":"..."}，图片返回二进制流
```

### ⑦-4 文件下载（v3.3.1 新增）
```
GET {BASE_URL}/api/v2/storage/files/download/{主机uid}/{文件名}
Header: Authorization: Bearer token
返回: 二进制流，自动触发浏览器下载
```

### ⑦-5 一键清理空间（v3.3.1 新增）
```
POST {BASE_URL}/api/v2/storage/files/cleanup/{主机uid}
Header: Authorization: Bearer token
Body(JSON): {"password":"当前密码"}
注意：此操作会删除所有文件和文件夹，不可恢复
```

### ⑧ 兑换卡密
```
POST {BASE_URL}/api/v2/payment/redeem/exchange
Header: Authorization: Bearer token
Body(JSON): {"code":"VIP-5YUAN-XXXXXXXX"}
```

### ⑨ 访问托管的网站（无需登录，浏览器直接打开）
```
{BASE_URL}/h/{主机uid}/            → 自动打开 index.html / index.php
{BASE_URL}/h/{主机uid}/文件名      → 打开指定文件
```

### ⑩ WebSocket 实时通道（联机同步用）
```
ws://{BASE_URL去掉https}/gateway/realtime
```

### ⑪ 修改密码（v3.3 新增）
```
POST {BASE_URL}/api/v2/user/profile/password
Header: Authorization: Bearer token
Body(JSON): {"old_password":"旧密码", "new_password":"新密码"}
```

### ⑫ 删除文件夹（v3.3 新增）
```
POST {BASE_URL}/api/v2/storage/files/rmdir/{主机uid}
Header: Authorization: Bearer token
Body(JSON): {"dir_name":"文件夹名"}
注意：此操作会递归删除文件夹内所有内容，不可恢复
```

### ⑬ 删除账号（v3.3 新增）
```
POST {BASE_URL}/api/v2/user/profile/delete
Header: Authorization: Bearer token
Body(JSON): {"password":"当前密码"}
注意：此操作会永久删除账号和所有文件，不可恢复
```

### ⑭ 管理员 - 查看封禁IP列表（v3.3 新增）
```
GET {BASE_URL}/api/v2/sys/management/ips/blocked?admin_password=管理密码
```

### ⑮ 管理员 - 解封指定IP（v3.3 新增）
```
POST {BASE_URL}/api/v2/sys/management/ips/unban
Body(JSON): {"admin_password":"管理密码", "ip":"要解封的IP"}
```

### ⑯ 健康检查（v3.3.1 新增，无需登录）
```
GET {BASE_URL}/api/v2/gateway/health
返回: {"status":"ok","time":"...","uptime":123,"php":true,"users":5,"files":12,"blocked":0}
```

### ⑰ 版本查询（v3.3.1 新增，无需登录）
```
GET {BASE_URL}/api/v2/gateway/version
返回: {"version":"3.3.2","build":"20260730","changelog":"..."}
```

### ⑱ 文件搜索（v3.3.2 新增）
```
GET {BASE_URL}/api/v2/storage/files/search/{主机uid}?q=关键词
Header: Authorization: Bearer token
返回: {"query":"关键词","results":[...],"total":N}
注意：支持递归搜索子文件夹，关键词至少2个字符
```

### ⑲ 批量删除文件（v3.3.2 新增）
```
POST {BASE_URL}/api/v2/storage/files/batch-remove/{主机uid}
Header: Authorization: Bearer token
Body(JSON): {"files":["文件名1","文件名2",...]}
注意：单次最多50个文件
```

### ⑳ 管理员 - IP信誉查询（v3.3.2 新增）
```
GET {BASE_URL}/api/v2/sys/management/ips/reputation?admin_password=管理密码
返回: {"low_reputation":[{ip,score,bannedUsers,...}],"total":N}
也可指定IP: ?admin_password=管理密码&ip=指定IP
```

### ㉑ 文件排序（v3.4 新增）
```
GET {BASE_URL}/api/v2/storage/files/sorted/{主机uid}?sort=name&order=asc
Header: Authorization: Bearer token
sort: name | size | date, order: asc | desc
目录始终排在文件前面
```

### ㉒ 会话管理 - 查看活跃会话（v3.4 新增）
```
GET {BASE_URL}/api/v2/user/sessions
Header: Authorization: Bearer token
返回: {"sessions":[{token,ip,device,loginTime,lastSeen},...],"total":N}
```

### ㉓ 会话管理 - 撤销会话（v3.4 新增）
```
POST {BASE_URL}/api/v2/user/sessions/revoke
Header: Authorization: Bearer token
Body(JSON): {"token_prefix":"token前10位"}
```

### ㉔ 用户活动日志（v3.4 新增）
```
GET {BASE_URL}/api/v2/user/activity
Header: Authorization: Bearer token
返回: {username,registered,lastLogin,plan,planName,spaceUsedMB,spaceLimitMB,knownIPs,ipCount,sessions,isNewUserGrace,banned,banReason}
```

### ㉕ 管理员 - 系统资源监控（v3.4 新增）
```
GET {BASE_URL}/api/v2/sys/resources?admin_password=管理密码
返回: {hostname,platform,uptime,memory:{total,used,free,usagePercent},cpu:{cores,model,loadAvg},server:{connections,blocked,whitelist,attackMode}}
```

### ㉖ 管理员 - IP白名单管理（v3.4 新增）
```
查看: GET {BASE_URL}/api/v2/sys/management/ips/whitelist?admin_password=管理密码
添加: POST {BASE_URL}/api/v2/sys/management/ips/whitelist/add
      Body(JSON): {"admin_password":"管理密码","ip":"IP地址"}
移除: POST {BASE_URL}/api/v2/sys/management/ips/whitelist/remove
      Body(JSON): {"admin_password":"管理密码","ip":"IP地址"}
注意：白名单IP完全不受限流和封禁
```

### ㉗ 管理员 - 行为评分查询（v3.4 新增）
```
GET {BASE_URL}/api/v2/sys/management/ips/behavior?admin_password=管理密码&ip=IP地址
返回: {ip,found,score,totalRequests,suspiciousActions,lastSeen}
评分低于30分自动封禁
```

### ㉘ Refresh Token 刷新（v3.5 新增 / v4.0 增强）
```
POST {BASE_URL}/api/v2/auth/session/refresh
Body(JSON): {"refreshToken":"你的RefreshToken"}
返回: {"success":true, "token":"新的AccessToken", "refreshToken":"新的RefreshToken", "userId":"...", "username":"..."}
注意: RefreshToken有效期7天，过期后需重新登录
v4.0变更: 刷新后旧RefreshToken立即失效（Token轮换），需保存新的refreshToken
```

### ㉙ 登出/撤销Token（v3.5 新增）
```
POST {BASE_URL}/api/v2/auth/session/revoke
Header: Authorization: Bearer token
Body(JSON): {"refreshToken":"要撤销的RefreshToken"} 或不传则撤销所有
返回: {"success":true, "message":"已登出"}
```

### ㉚ 管理员 - 账户锁定管理（v3.5 新增）
```
查看锁定: GET {BASE_URL}/api/v2/sys/management/accounts/lockouts?admin_password=管理密码
解锁: POST {BASE_URL}/api/v2/sys/management/accounts/unlock
      Body(JSON): {"admin_password":"管理密码","username":"用户名"}
```

### ㉛ 管理员 - 境外IP统计（v3.5 新增）
```
GET {BASE_URL}/api/v2/sys/management/ips/geo?admin_password=管理密码
返回: {"foreignIPs":[{ip,requests,isBlocked},...],"total":N}
```

### ㉜ 管理员 - 日志归档（v3.5 新增）
```
查看状态: GET {BASE_URL}/api/v2/sys/management/logs/archive?admin_password=管理密码
归档日志: POST {BASE_URL}/api/v2/sys/management/logs/rotate
          Body(JSON): {"admin_password":"管理密码"}
归档位置: data/logs/server-YYYY-MM-DDTHH-MM-SS.log
```

### ㉝ 管理员 - HMAC签名信息（v3.5 新增）
```
GET {BASE_URL}/api/v2/sys/auth/signature-info
返回: {"version":"3.5.0","algorithm":"HMAC-SHA256","headers":[...],"signFormat":"METHOD+PATH+TIMESTAMP+NONCE+BODY_HASH"}
```

## v3.5.1 新增功能

### ㉞ 浏览器指纹提交（v3.5.1 新增）
```
POST {BASE_URL}/api/v2/auth/fingerprint
Header: Authorization: Bearer token（可选，未登录时用x-session-id关联）
Body(JSON): {"fingerprint":{"canvas":"...","webgl":"...","screen":{...},"fonts":[...],"timezone":{...},"platform":{...},"audio":"..."}}
返回: {"success":true, "changed":false, "score":100}
注意: 指纹会在登录时自动关联用户，检测指纹变化，24小时内变化超过3次将封禁
```

### ㉟ 鼠标轨迹提交（v3.5.1 新增）
```
POST {BASE_URL}/api/v2/auth/mouse-data
Header: x-session-id: 会话ID
Body(JSON): {"events":[{"x":100,"y":200,"t":1234567890,"speed":0.5}], "sessionId":"sess_xxx"}
返回: {"success":true, "isHuman":true, "confidence":0.8}
注意: 每10秒提交一批，单次最多50个事件，分析直线段比例和速度变化判断人机
```

### ㊱ 管理员 - 指纹管理（v3.5.1 新增）
```
GET {BASE_URL}/api/v2/sys/management/fingerprints?admin_password=管理密码
返回: {"success":true, "count":N, "blockedCount":N, "fingerprints":[{userId,score,firstSeen,lastSeen,ip,changeCount},...]}
```

### ㊲ JS Challenge 人机验证（v3.5 新增）
```
验证页面: GET {BASE_URL}/challenge
验证提交: POST {BASE_URL}/challenge/verify
          Body(JSON): {"challenge_id":"...", "answer":数字答案}
验证通过后IP加入临时白名单（1小时）
```

---
## 安全防护参数（v3.5.0 大幅优化）

### 请求签名（HMAC-SHA256）v3.5新增
| 请求头 | 说明 |
|--------|------|
| `x-request-time` | 当前Unix毫秒时间戳 |
| `x-request-nonce` | 随机字符串，防重放 |
| `x-request-signature` | HMAC-SHA256签名 |

签名公式: `HMAC-SHA256(secret, "METHOD+PATH+TIMESTAMP+NONCE+BODY_HASH")`

### 频率限制（5级渐进式警告）
| 级别 | 触发条件 | 处罚 |
|------|---------|------|
| 1级 | 轻微超限 | 记录警告，不拦截 |
| 2级 | 二次超限 | 返回"请放慢速度" |
| 3级 | 三次超限 | 临时限流5分钟（自动恢复） |
| 4级 | 四次超限 | 严重限流15分钟（自动恢复） |
| 5级 | 五次超限 | IP封禁 |

### 账户锁定（v3.5新增）
| 失败次数 | 锁定时间 |
|---------|---------|
| 5次 | 5分钟 |
| 10次 | 30分钟 |
| 20次 | 24小时 |

### 文件上传限制（v3.5增强）
| 限制项 | 值 |
|--------|-----|
| 单文件最大 | 50MB |
| 禁止扩展名 | .exe, .dll, .so, .php, .py, .sh, .cgi, .jsp, .asp 等 |
| 魔术字节检测 | 禁止PHP脚本、ELF/PE可执行文件 |

### 蜜罐陷阱（v3.5增强）
触碰以下路径自动封禁IP 7天: /.env, /wp-admin, /phpmyadmin, /.git, /console, /api/v1, /graphql, /swagger, /actuator, /debug 等50+路径

### 境外IP检测（v3.5新增）
系统自动检测非中国IP地址，可通过管理后台查看境外IP统计

| 限制项 | 免费版 | 基础版 | 高级版 | 说明 |
|--------|--------|--------|--------|------|
| 每分钟请求数 | 600 | 900 | 1200 | 普通API调用 |
| 每分钟上传 | 80 | 80 | 80 | 上传文件 |
| 每分钟登录 | 60 | 60 | 60 | 登录/注册 |
| 并发连接数 | 60 | 60 | 60 | 每IP |
| 暴力破解容忍 | 80次/15分钟 | 80次/15分钟 | 80次/15分钟 | 失败后封禁 |
| CC攻击阈值 | 250次/10秒 | 250次/10秒 | 250次/10秒 | 自动封禁30分钟 |
| 爬虫容忍 | 2000次/分钟 | 2000次/分钟 | 2000次/分钟 | 超过视为恶意爬虫 |
| 全局熔断阈值 | 8000次/分钟 | 8000次/分钟 | 8000次/分钟 | 防护模式10分钟 |
| 5级渐进警告 | ✅ | ✅ | ✅ | 1级放行→2级警告→3级限流5分钟→4级限流15分钟→5级封禁 |
| IP白名单 | ✅ | ✅ | ✅ | 白名单IP完全不受限流 |
| 新用户保护期 | ✅ | ✅ | ✅ | 注册后24小时内不受封禁 |
| IP信誉系统 | ✅ | ✅ | ✅ | 低信誉IP自动封禁 |
| 行为评分 | ✅ | ✅ | ✅ | 可疑行为扣分，低于30分自动封禁 |
| 会话管理 | ✅ | ✅ | ✅ | 查看/撤销活跃会话 |
| 自动解封 | ✅ | ✅ | ✅ | 限流级别3-4级自动解封 |
| HMAC签名 | ✅ | ✅ | ✅ | v3.5新增 |
| 账户锁定 | ✅ | ✅ | ✅ | v3.5新增 |
| 文件类型验证 | ✅ | ✅ | ✅ | v3.5新增 |
| 境外IP检测 | ✅ | ✅ | ✅ | v3.5新增 |

---

## AndLua+ 上传文件示例（Lua）

```lua
require "import"
import "android.net.*"

BASE_URL = "https://你的隧道网址"  -- 从接口④获取最新的
TOKEN = "登录后保存的token"
UID = "你的主机uid"

-- 登录示例
Http.post(BASE_URL.."/api/v2/auth/session/init",
  '{"username":"wuki","password":"123456"}',
  "application/json",
  function(code, body)
    if code == 200 then
      local d = require "cjson".decode(body)
      TOKEN = d.token
      print("登录成功")
    end
  end)

-- 上传示例（用 OkHttp MultipartBody）
import "okhttp3.*"
local file = File("/sdcard/Download/index.html")
local body = MultipartBody.Builder()
  .setType(MultipartBody.FORM)
  .addFormDataPart("file", "index.html",
    RequestBody.create(MediaType.parse("text/html"), file))
  .build()
local request = Request.Builder()
  .url(BASE_URL.."/api/v2/storage/files/upload/"..UID)
  .addHeader("Authorization", "Bearer "..TOKEN)
  .post(body)
  .build()
OkHttpClient().newCall(request):execute()  -- 建议放线程里跑
```

注意：App 的 UA 必须保留 okhttp 默认 UA，不要伪装成 curl/python（会被防火墙封）。

---

## 降低延迟指南（联机必看）

延迟从大到小排，优先用小的：

| 连接方式 | 延迟 | 怎么用 |
|---------|------|--------|
| 🏠 同一WiFi局域网直连 | 1-10ms | 联机双方连同一个WiFi，App 填 `http://手机IP:3000`（接口④可查）|
| 📶 同运营商4G/5G走隧道 | 80-200ms | 没办法直连时的首选 |
| 🌍 跨运营商/跨地区走隧道 | 150-300ms | 物理限制，无法避免 |

其他已做/可做的优化：

1. **服务器已开 gzip 压缩**（需跑一次 `npm install compression` 生效），文本传输量减 70%
2. **App 端减少请求次数**：登录后把 token 和用户信息存本地，别每次操作都重新登录
3. **轮询改 WebSocket**：联机同步走接口⑩的长连接，比反复 POST 快得多
4. **cloudflared 不稳定时换协议**：隧道窗口 Ctrl+C 后跑
   `cloudflared tunnel --url http://localhost:3000 --protocol http2`
5. **隧道二选一**：cloudflared 和 cpolar 同时开着时，让用户实测哪个快用哪个

---

## 网页端使用指南（普通用户）

1. 浏览器打开 `{BASE_URL}/host.html`，注册/登录
2. 点"📤 上传文件"区域，选择文件（或拖进去），点上传按钮
3. 传 `index.html` 后，点"🌐 打开我的网站"即可看到效果
4. "🔗 主机地址"卡片里的地址复制发给别人，就是你的网站
5. 在文件列表可以预览、下载、改名、删除文件
6. 用户卡片旁可修改密码、清理空间、删除账号
