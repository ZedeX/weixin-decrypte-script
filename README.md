# WeChat Decrypt Script

Windows 微信 4.x 本地数据解密工具集，支持数据库解密、消息读取、图片文件解密，以及 JSON API 服务。

> 基于 [xuxinhang 的技术文章](https://mp.weixin.qq.com/s/JbyzB3NmFbHlGQJlgVGuDw) 方法

## 功能

- 从微信进程内存提取 SQLCipher 4 数据库密钥
- 批量解密数据库文件（contact、message、session 等）
- 读取并解压 ZSTD 压缩的消息内容
- 解密 DAT 图片文件，支持三种加密格式：
  - 旧版 XOR（单字节异或，自动检测密钥）
  - V1 格式（AES-128-ECB + XOR，固定密钥 `cfcd208495d565ef`）
  - V2 格式（AES-128-ECB + XOR，从内存提取密钥）
- **JSON API 服务**：将聊天记录以 RESTful API 方式提供，支持查询消息、联系人、群聊、会话，支持关键词搜索和多格式输出（JSON/CSV/Text）
- **一键启动**：自动扫描密钥 → 自动解密数据库 → 启动 API 服务

## 环境要求

- Windows 10/11 x64
- Python 3.8+
- 微信 4.x（已登录）
- 管理员权限（密钥提取需要）

## 安装

```bash
pip install pymem psutil pycryptodome zstandard flask flask-cors
```

## 快速开始

### 方式一：一键启动 API 服务（推荐）

类似 [chatlog](https://github.com/sjzar/chatlog) 的体验，一条命令完成所有操作：

```bash
# 全自动：微信运行中，自动扫描密钥 + 解密 + 启动
python api_server.py "C:\Users\<USER>\Documents\xwechat_files\<wxid>"

# 指定密钥启动
python api_server.py "C:\Users\<USER>\Documents\xwechat_files\<wxid>" --key <hex_key>

# 指定密钥文件启动
python api_server.py "C:\Users\<USER>\Documents\xwechat_files\<wxid>" --key-file found_keys.txt

# 跳过解密（已有 .decrypted.db 文件）
python api_server.py "C:\Users\<USER>\Documents\xwechat_files\<wxid>" --no-decrypt
```

启动后访问 `http://localhost:5050` 即可使用 API。

### 方式二：分步操作

#### 1. 提取数据库密钥

```bash
# 以管理员身份运行，微信必须已登录
python scan_keys.py
```

#### 2. 解密数据库

```bash
# 批量解密
python decrypt_db.py --auto "C:\Users\<USER>\Documents\xwechat_files" found_keys.txt

# 单个文件
python decrypt_db.py <db_path> <hex_key>
```

#### 3. 读取消息

```bash
python read_messages.py <decrypted_db_path>

# 批量读取
python read_messages.py --batch "C:\Users\<USER>\Documents\xwechat_files"
```

#### 4. 解密图片

```bash
# XOR 格式（自动检测密钥）
python decrypt_dat.py --batch <attach_dir> <output_dir>

# V2 格式（需先提取 AES 密钥）
# 方法1: 一次性扫描（先在微信中查看2-3张图片，再运行）
python find_image_key.py <attach_dir>

# 方法2: 持续监控（推荐，启动后在微信中查看图片即可）
python monitor_image_key.py <attach_dir>

# 使用提取到的密钥批量解密
python decrypt_dat.py --batch <attach_dir> <output_dir> --aes-key <16字节密钥> --xor-key 0x5f
```

## JSON API 文档

### API 端点

| 端点 | 说明 |
|------|------|
| `GET /health` | 健康检查 |
| `GET /api/v1/chatlog` | 查询聊天记录 |
| `GET /api/v1/contact` | 查询联系人 |
| `GET /api/v1/chatroom` | 查询群聊 |
| `GET /api/v1/session` | 查询最近会话 |
| `GET /api/v1/search` | 全文搜索消息 |

### 查询聊天记录

```
GET /api/v1/chatlog?talker=<id>&time=<range>&keyword=<text>&limit=50&offset=0&format=json
```

| 参数 | 必填 | 说明 |
|------|------|------|
| `talker` | 是 | 微信 ID 或群聊 ID，逗号分隔多个 |
| `time` | 否 | 时间范围，如 `2025-01-01` 或 `2025-01-01,2025-06-01` |
| `sender` | 否 | 按发送者过滤 |
| `keyword` | 否 | 按关键词过滤 |
| `limit` | 否 | 返回数量，默认 50 |
| `offset` | 否 | 分页偏移，默认 0 |
| `format` | 否 | 输出格式：`json` / `csv` / `text`，默认 `json` |

**示例：**

```bash
# 查询群聊最近 10 条消息
curl "http://localhost:5050/api/v1/chatlog?talker=12345678@chatroom&limit=10"

# 查询指定时间范围的消息
curl "http://localhost:5050/api/v1/chatlog?talker=wxid_xxx&time=2025-01-01,2025-06-30"

# 关键词搜索
curl "http://localhost:5050/api/v1/chatlog?talker=12345678@chatroom&keyword=hello"

# 导出为 CSV
curl "http://localhost:5050/api/v1/chatlog?talker=wxid_xxx&format=csv" -o chatlog.csv

# 导出为纯文本
curl "http://localhost:5050/api/v1/chatlog?talker=wxid_xxx&format=text"
```

**响应示例：**

```json
{
  "total": 169737,
  "limit": 3,
  "offset": 0,
  "items": [
    {
      "seq": 1660613074000,
      "time": "2022-08-16 09:24:34",
      "talker": "12345678@chatroom",
      "talker_name": "My Group",
      "is_chatroom": true,
      "sender": "system",
      "sender_name": "",
      "is_self": false,
      "type": 10000,
      "sub_type": 0,
      "content": "You joined the group chat"
    }
  ]
}
```

### 查询联系人

```
GET /api/v1/contact?keyword=<name>&limit=50&offset=0
```

```bash
# 搜索联系人
curl "http://localhost:5050/api/v1/contact?keyword=John"

# 列出所有联系人
curl "http://localhost:5050/api/v1/contact?limit=100"
```

### 查询群聊

```
GET /api/v1/chatroom?keyword=<name>&limit=50&offset=0
```

```bash
# 搜索群聊
curl "http://localhost:5050/api/v1/chatroom?keyword=tech"
```

### 查询会话

```
GET /api/v1/session?keyword=<name>&limit=50&offset=0
```

```bash
# 最近会话
curl "http://localhost:5050/api/v1/session?limit=10"
```

### 全文搜索

```
GET /api/v1/search?keyword=<text>&limit=50&offset=0
```

```bash
# 跨所有聊天记录搜索
curl "http://localhost:5050/api/v1/search?keyword=hello"
```

### 消息类型说明

| type | 说明 |
|------|------|
| 1 | 文本消息 |
| 3 | 图片 |
| 34 | 语音 |
| 43 | 视频 |
| 47 | 表情动画 |
| 49 | 分享/链接/小程序等 |
| 10000 | 系统消息 |

## 脚本说明

| 脚本 | 功能 |
|------|------|
| `api_server.py` | JSON API 服务（支持一键启动，自动解密） |
| `decrypt_engine.py` | 解密引擎模块（密钥扫描 + 数据库解密） |
| `models.py` | 数据模型（消息/联系人/群聊/会话） |
| `db_service.py` | 数据库服务层（查询/搜索） |
| `scan_keys.py` | 从微信进程内存提取数据库加密密钥 |
| `decrypt_db.py` | 解密 SQLCipher 4 数据库 |
| `read_messages.py` | 读取解密后的消息（含 ZSTD 解压） |
| `decrypt_dat.py` | 解密 DAT 图片文件（XOR/V1/V2） |
| `find_image_key.py` | 一次性扫描 V2 图片 AES 密钥 |
| `monitor_image_key.py` | 持续监控自动捕获 V2 图片 AES 密钥 |

## 技术原理

### 数据库加密

微信 4.x 使用 SQLCipher 4（AES-256-CBC + HMAC-SHA512），密钥以 `x'<64位hex>'` 格式常驻进程内存，通过内存扫描提取。

### 图片加密

| 格式 | 文件头 | 加密方式 | 密钥来源 |
|------|--------|---------|---------|
| 旧版 XOR | 不固定 | 单字节 XOR | 自动检测 |
| V1 | `07 08 56 31 08 07` | AES-128-ECB + XOR | 固定 `cfcd208495d565ef` |
| V2 | `07 08 56 32 08 07` | AES-128-ECB + XOR | 内存提取 |

> V2 AES 密钥仅在微信查看图片时临时加载到内存，需先查看图片再扫描。

### API 服务架构

```
api_server.py (Flask HTTP API)
    |
    +-- decrypt_engine.py (自动解密: 密钥扫描 + SQLCipher 解密)
    |
    +-- db_service.py (数据库查询: 消息/联系人/群聊/会话/搜索)
         |
         +-- models.py (数据模型: Message/Contact/ChatRoom/Session)
```

启动流程：自动扫描密钥 → 增量解密数据库 → 加载数据 → 启动 HTTP 服务

详细技术文档见 [WEIXIN_DECRYPT_GUIDE.md](WEIXIN_DECRYPT_GUIDE.md)。

## 声明

本项目仅供个人数据备份与恢复等合法用途。请遵守相关法律法规，尊重他人隐私。
