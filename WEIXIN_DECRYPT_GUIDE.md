# Windows 微信 4.x 本地数据解密指南

> 基于 [xuxinhang 的技术文章](https://mp.weixin.qq.com/s/JbyzB3NmFbHlGQJlgVGuDw) 方法，适配微信 4.x 版本

## 目录

- [1. 概述](#1-概述)
- [2. 环境准备](#2-环境准备)
- [3. 数据目录结构](#3-数据目录结构)
- [4. 主数据库解密](#4-主数据库解密)
  - [4.1 加密原理](#41-加密原理)
  - [4.2 提取数据库密钥](#42-提取数据库密钥)
  - [4.3 解密数据库文件](#43-解密数据库文件)
- [5. 消息内容解压](#5-消息内容解压)
- [6. DAT 图片文件解密](#6-dat-图片文件解密)
  - [6.1 三种加密格式](#61-三种加密格式)
  - [6.2 旧版 XOR 格式](#62-旧版-xor-格式)
  - [6.3 V1 格式（固定 AES 密钥）](#63-v1-格式固定-aes-密钥)
  - [6.4 V2 格式（AES-128-ECB + XOR）](#64-v2-格式aes-128-ecb--xor)
  - [6.5 V2 AES 密钥提取](#65-v2-aes-密钥提取)
- [7. 数据库结构分析](#7-数据库结构分析)
- [8. 完整操作流程](#8-完整操作流程)
- [9. 脚本说明](#9-脚本说明)

***

## 1. 概述

Windows 微信 4.x 版本使用 **SQLCipher 4** 对本地数据库进行加密，使用 **XOR / AES-128-ECB** 对图片等媒体文件进行加密。本指南提供完整的解密方法，包括：

- 从微信进程内存中提取数据库加密密钥
- 解密 SQLCipher 4 格式的 SQLite 数据库
- 解压 ZSTD 压缩的消息内容
- 解密三种格式的 DAT 图片文件

***

## 2. 环境准备

### 2.1 Python 依赖安装

```bash
pip install pymem psutil pycryptodome zstandard
```

| 库              | 用途                      |
| -------------- | ----------------------- |
| `pymem`        | 读取微信进程内存，提取密钥           |
| `psutil`       | 查找微信进程 PID              |
| `pycryptodome` | AES 解密（数据库 + DAT V2 图片） |
| `zstandard`    | ZSTD 解压消息内容             |

### 2.2 权限要求

- **管理员权限**：密钥提取脚本需要以管理员身份运行，才能读取其他进程的内存
- **微信已登录**：提取密钥时微信必须处于运行且已登录状态

***

## 3. 数据目录结构

```
C:\Users\<USER>\Documents\xwechat_files\
├── <wxid>_<number>\                  # 微信账号目录
│   ├── db_storage\                   # 加密数据库目录
│   │   ├── contact\
│   │   │   ├── contact.db            # 联系人数据库
│   │   │   └── contact_fts.db        # 联系人全文搜索
│   │   ├── message\
│   │   │   ├── message_0.db ~ message_9.db  # 聊天消息（分片）
│   │   │   ├── biz_message_0.db ~ 4.db      # 服务号消息
│   │   │   ├── media_0.db ~ media_1.db      # 媒体索引
│   │   │   ├── message_resource.db          # 消息资源（含图片MD5映射）
│   │   │   └── message_fts.db               # 消息全文搜索
│   │   ├── session\session.db        # 会话列表
│   │   ├── sns\sns.db               # 朋友圈
│   │   ├── emoticon\emoticon.db     # 表情
│   │   ├── favorite\favorite.db     # 收藏
│   │   ├── general\general.db       # 通用设置
│   │   └── head_image\head_image.db # 头像
│   └── msg\
        └── attach\                   # 附件目录（含加密图片）
            └── <md5(username)>\
                └── <YYYY-MM>\
                    └── Img\
                        ├── *.dat     # 加密图片文件
                        └── *_t.dat   # 缩略图

```

***

## 4. 主数据库解密

### 4.1 加密原理

微信 4.x 使用 **SQLCipher 4** 加密，核心参数如下：

| 参数      | 值                  | 说明                        |
| ------- | ------------------ | ------------------------- |
| 加密算法    | AES-256-CBC        | 对称加密                      |
| 认证算法    | HMAC-SHA512        | 数据完整性校验                   |
| 密钥派生    | PBKDF2-HMAC-SHA512 | 盐值变换生成 MAC 密钥             |
| 页面大小    | 4096 字节            | SQLite 标准页大小              |
| 密钥长度    | 32 字节 (256 bit)    | 原始密钥                      |
| 盐值长度    | 16 字节              | 仅第一页开头                    |
| IV 长度   | 16 字节              | 每页独立 IV                   |
| HMAC 长度 | 64 字节              | SHA-512 输出                |
| 保留空间    | 80 字节              | IV(16) + HMAC(64)，16 字节对齐 |

**SQLCipher 4 页面结构：**

```
第一页 (4096 字节):
┌──────────┬──────────────────┬────────┬──────────┬──────────┐
│ 盐值(16B) │ 加密数据(3920B)   │ IV(16B)│HMAC(64B) │ 保留(80B) │
└──────────┴──────────────────┴────────┴──────────┴──────────┘

后续页 (4096 字节):
┌──────────────────┬────────┬──────────┬──────────┐
│ 加密数据(3936B)   │ IV(16B)│HMAC(64B) │ 保留(80B) │
└──────────────────┴────────┴──────────┴──────────┘
```

**密钥在内存中的格式：**

密钥以 `x'<64位十六进制>'` 格式存储在微信进程内存中，例如：

```
x'0123456789012345678901234567890123456789012345678901234567890123'
```

其中 64 个十六进制字符表示 32 字节的原始密钥。

### 4.2 提取数据库密钥

**前提条件：** 微信必须已启动并登录。

```bash
# 以管理员身份运行
python scan_keys.py
```

**工作原理：**

1. 通过 `psutil` 查找 `Weixin.exe` 进程（选择命令行参数最短的主进程）
2. 使用 `pymem` 扫描进程内存，搜索 `x'` 前缀
3. 对每个匹配位置，验证后续 64 个字符是否为合法十六进制，以及是否以 `'` 结尾
4. 按出现频率排序输出所有密钥

**输出示例：**

```
Weixin.exe found, PID: 12345
Scanning memory of Weixin.exe (PID: 12345)...
Found 1523 potential key prefixes, filtering...

Found 6 unique keys (sorted by frequency):

#    Frequency    Key (hex)
--------------------------------------------------------------------------------
0    19           0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
1    9            fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210
...

Keys saved to found_keys.txt
```

> **提示：** 出现频率最高的密钥通常是主数据库密钥，优先尝试。

### 4.3 解密数据库文件

**单个文件解密：**

```bash
python decrypt_db.py <db_path> <hex_key>
```

示例：

```bash
python decrypt_db.py "C:\Users\<USER>\Documents\xwechat_files\<wxid>\db_storage\contact\contact.db" 0123456789abcdef...
```

**批量自动解密：**

```bash
python decrypt_db.py --auto <xwechat_files_dir> found_keys.txt
```

示例：

```bash
python decrypt_db.py --auto "C:\Users\<USER>\Documents\xwechat_files" found_keys.txt
```

脚本会自动：

1. 从 `found_keys.txt` 加载所有密钥
2. 扫描目录下所有 `.db` 文件
3. 逐个尝试密钥，找到正确的进行解密
4. 解密后的文件保存为 `<原文件名>.decrypted.db`

**解密算法详解：**

```python
# 1. 从文件读取盐值（前16字节）
salt = file_data[:16]

# 2. 使用原始密钥（不再通过 PBKDF2 派生，直接使用）
key = rawkey  # 32 字节

# 3. 生成 MAC 密钥：盐值每个字节异或 0x3a，再用 PBKDF2 派生
mac_salt = bytes(x ^ 0x3a for x in salt)
mac_key = PBKDF2_HMAC_SHA512(key, mac_salt, iterations=2, dklen=32)

# 4. 验证 HMAC（确保密钥正确）
hmac = HMAC-SHA512(mac_key, page_data[:-80+16] + page_number_bytes)

# 5. AES-256-CBC 解密每页数据
#    IV 位于每页末尾保留区的前 16 字节
iv = page[-80:][:16]
plaintext = AES_CBC_decrypt(key, iv, page[:-80])
```

**使用 SQLiteStudio 验证（手动方式）：**

1. 打开 SQLiteStudio → 连接数据库
2. 类型选择 "SQLCipher"
3. 密码留空
4. 加密算法配置：
   - 密钥：`x'<hex_key>'`（含 `x'` 前缀和 `'` 后缀）
   - cipher\_page\_size: 4096
   - cipher\_compatibility: 4

***

## 5. 消息内容解压

微信 4.x 的消息内容使用 **ZSTD 压缩**（而非二次加密），通过 WCDB 注册的 `wcdb_decompress` 函数在查询时自动解压。

**ZSTD 压缩数据特征：** 以 `28 B5 2F FD` 开头（ZSTD 魔数）

**解压方法：**

```python
import zstandard

# 从数据库读取的 message_content 字段
data = bytes.fromhex('28b52ffd20e07d0500...')

# 直接解压
dctx = zstandard.ZstdDecompressor()
text = dctx.decompress(data, max_output_size=100 * 1024 * 1024).decode('utf-8')
print(text)
```

**使用 read\_messages.py 脚本：**

```bash
# 读取单个解密后的消息数据库
python read_messages.py <decrypted_db_path>

# 批量读取所有消息数据库
python read_messages.py --batch <xwechat_files_dir>

# 指定输出目录
python read_messages.py <decrypted_db_path> --output <output_dir>
```

**消息数据库结构：**

- `message_0.db` \~ `message_9.db`：按会话分片存储
- 每个库中有多个 `Msg_<MD5(会话ID)>` 表
- `Name2Id` 表存储会话 ID 映射
- `packed_info_data` 列存储 Protobuf 编码的元数据（含图片文件名等）

***

## 6. DAT 图片文件解密

### 6.1 三种加密格式

| 格式     | 文件头                 | 加密方式              | 密钥来源 | 出现时间     |
| ------ | ------------------- | ----------------- | ---- | -------- |
| 旧版 XOR | 不固定                 | 单字节 XOR           | 自动检测 | 早期版本     |
| V1     | `07 08 56 31 08 07` | AES-128-ECB + XOR | 固定密钥 | 2025 年中  |
| V2     | `07 08 56 32 08 07` | AES-128-ECB + XOR | 内存提取 | 2025-08+ |

### 6.2 旧版 XOR 格式

**原理：** 每个字节与固定密钥进行异或运算。

**密钥检测：** 通过对比加密文件头与已知图片格式的 magic bytes 自动推断：

| 图片格式 | Magic Bytes   | XOR Key 推算方式            |
| ---- | ------------- | ------------------------ |
| JPEG | `FF D8 FF`    | `header[0] ^ 0xFF`       |
| PNG  | `89 50 4E 47` | `header[0] ^ 0x89`       |
| GIF  | `47 49 46 38` | `header[0] ^ 0x47`       |
| BMP  | `42 4D`       | `header[0] ^ 0x42`       |
| WebP | `52 49 46 46` | `header[0] ^ 0x52`       |

### 6.3 V1 格式（固定 AES 密钥）

**文件结构：**

```
┌──────────────────────┬────────────┬────────────┬─────────┐
│ 签名 (6B)            │ aes_size   │ xor_size   │ padding │
│ 07 08 56 31 08 07    │ (4B, LE)   │ (4B, LE)   │ (1B)    │
├──────────────────────┼────────────┴────────────┴─────────┤
│                      │ AES 加密数据                       │
│                      │ (aligned_aes_size 字节)            │
│                      ├────────────────────────────────────┤
│                      │ 原始数据（未加密）                  │
│                      ├────────────────────────────────────┤
│                      │ XOR 加密数据 (xor_size 字节)       │
└──────────────────────┴────────────────────────────────────┘
```

**固定 AES 密钥：** `cfcd208495d565ef`（即 `md5("0")[:16]`）

**XOR 密钥：** 默认 `0x88`

### 6.4 V2 格式（AES-128-ECB + XOR）

**文件结构：** 与 V1 相同，但签名不同（`56 32` = "V2"）。

```
签名: 07 08 56 32 08 07  (6 字节)
aes_size: 4 字节小端序整数
xor_size: 4 字节小端序整数
padding: 1 字节
AES-ECB 加密数据: aligned_aes_size 字节（PKCS7 填充对齐到 16 字节）
原始数据: 未加密部分
XOR 加密数据: xor_size 字节（每字节异或 xor_key）
```

**AES 对齐公式：**

```python
aligned_aes_size = aes_size - ~(~aes_size % 16)
```

**解密流程：**

1. 解析文件头，提取 `aes_size` 和 `xor_size`
2. AES-128-ECB 解密前段数据（去除 PKCS7 填充）
3. 中间段为原始数据（不加密）
4. 末段 XOR 解密（每字节异或 `xor_key`）
5. 拼接三段得到完整图片数据

### 6.5 V2 AES 密钥提取

V2 格式的 AES 密钥需要从微信进程内存中提取，**密钥仅在微信查看图片时临时加载到内存**。

**一次性扫描：**

```bash
# 以管理员身份运行，先在微信中查看2-3张图片，然后立即运行
python find_image_key.py <xwechat_attach_dir>
```

**持续监控（推荐）：**

```bash
# 启动监控后，在微信中查看图片，脚本会自动捕获密钥
python monitor_image_key.py <xwechat_attach_dir> [--xor-key 0xNN]
```

示例：

```bash
python monitor_image_key.py "C:\Users\<USER>\Documents\xwechat_files\<wxid>\msg\attach"
```

**工作原理：**

1. 从 V2 DAT 文件中提取前 16 字节 AES 密文
2. 扫描微信进程内存，搜索所有 16/32 字符的字母数字字符串
3. 用每个候选密钥尝试 AES-ECB 解密密文，检查是否得到合法图片头
4. 找到匹配的密钥后自动保存到 `found_image_keys.txt`

**使用密钥解密 V2 文件：**

```bash
# 单个文件
python decrypt_dat.py <dat_file>

# 批量解密
python decrypt_dat.py --batch <input_dir> <output_dir> --aes-key <16字节AES密钥> --xor-key <0xNN>
```

***

## 7. 数据库结构分析

### 7.1 联系人数据库 (contact.db)

| 表名          | 说明    |
| ----------- | ----- |
| `WCContact` | 联系人信息 |
| `Friend`    | 好友列表  |

### 7.2 消息数据库 (message\_0.db \~ message\_9.db)

| 表名          | 说明       |
| ----------- | -------- |
| `Msg_<MD5>` | 各会话的聊天记录 |
| `Name2Id`   | 会话 ID 映射 |

**Msg 表关键字段：**

| 字段                 | 说明                                            |
| ------------------ | --------------------------------------------- |
| `local_id`         | 本地消息 ID                                       |
| `server_id`        | 服务器消息 ID                                      |
| `message_content`  | 消息内容（ZSTD 压缩或明文）                              |
| `message_type`     | 消息类型（1=文本, 3=图片, 34=语音, 43=视频, 47=表情, 49=链接等） |
| `createTime`       | 创建时间戳                                         |
| `packed_info_data` | Protobuf 编码的元数据                               |

### 7.3 消息资源数据库 (message\_resource.db)

存储图片等媒体文件的 MD5 映射，用于从 `local_id` 查找对应的 `.dat` 文件。

### 7.4 会话数据库 (session.db)

| 表名        | 说明          |
| --------- | ----------- |
| `Session` | 会话列表及最新消息摘要 |

***

## 8. 完整操作流程

### Step 1: 启动微信并登录

确保微信处于运行且已登录状态。

### Step 2: 提取数据库密钥

```bash
# 以管理员身份运行
python scan_keys.py
```

记录输出中出现频率最高的密钥。

### Step 3: 解密数据库

```bash
# 批量解密所有数据库
python decrypt_db.py --auto "C:\Users\<USER>\Documents\xwechat_files" found_keys.txt
```

### Step 4: 读取消息内容

```bash
# 读取解密后的消息数据库
python read_messages.py "C:\Users\<USER>\Documents\xwechat_files\<wxid>\db_storage\message\message_0.decrypted.db"
```

### Step 5: 解密图片文件

**旧版 XOR 格式（自动检测密钥）：**

```bash
# 单个文件
python decrypt_dat.py <dat_file>

# 批量解密
python decrypt_dat.py --batch "C:\Users\<USER>\Documents\xwechat_files\<wxid>\msg\attach" "D:\decrypted_images"
```

**V2 格式（需要提取 AES 密钥）：**

```bash
# 先提取密钥（先在微信中查看2-3张图片）
python find_image_key.py "C:\Users\<USER>\Documents\xwechat_files\<wxid>\msg\attach"

# 或使用持续监控模式
python monitor_image_key.py "C:\Users\<USER>\Documents\xwechat_files\<wxid>\msg\attach"

# 使用密钥批量解密
python decrypt_dat.py --batch <input_dir> <output_dir> --aes-key <16字节密钥> --xor-key <0xNN>
```

***

## 9. 脚本说明

| 脚本                     | 功能                        | 用法                                                                                                       |
| ---------------------- | ------------------------- | -------------------------------------------------------------------------------------------------------- |
| `scan_keys.py`         | 从微信进程内存提取数据库密钥            | `python scan_keys.py`                                                                                    |
| `decrypt_db.py`        | 解密 SQLCipher 4 数据库        | `python decrypt_db.py <db_path> <hex_key>` 或 `python decrypt_db.py --auto <dir> <keys_file>`             |
| `read_messages.py`     | 读取解密后的消息（含 ZSTD 解压）       | `python read_messages.py <decrypted_db>` 或 `python read_messages.py --batch <dir>`                       |
| `decrypt_dat.py`       | 解密 DAT 图片文件（支持 XOR/V1/V2） | `python decrypt_dat.py <dat_file>` 或 `python decrypt_dat.py --batch <dir> <output_dir> [options]`        |
| `find_image_key.py`    | 一次性扫描 V2 图片 AES 密钥        | `python find_image_key.py <attach_dir>`                                                                  |
| `monitor_image_key.py` | 持续监控自动捕获 V2 图片 AES 密钥     | `python monitor_image_key.py <attach_dir> [--xor-key 0xNN]`                                              |

***

## 附录：技术原理详解

### A. 密钥在内存中的存在形式

微信使用 WCDB（微信开源的数据库框架）操作 SQLCipher。在 `WCDB::Database::setCipherKey` 函数中，密钥被封装为 `CipherConfig` 对象。在 `CipherHandle::setCipherKey` 方法中，密钥被格式化为 SQLCipher 的 `PRAGMA key` 格式：

```
x'<64位十六进制密钥><32位十六进制盐值>'
```

由于密钥在进程生命周期内常驻内存，可以通过扫描进程内存空间找到所有密钥。

### B. SQLCipher 4 与旧版的区别

| 特性       | SQLCipher 3 (微信 3.x) | SQLCipher 4 (微信 4.x) |
| -------- | -------------------- | -------------------- |
| HMAC 算法  | SHA1 (20 字节)         | SHA512 (64 字节)       |
| 密钥派生迭代次数 | 64000                | 256000 (PBKDF2)      |
| 保留空间     | 48 字节                | 80 字节                |
| 密钥使用     | PBKDF2 派生            | 直接使用原始密钥             |

### C. DAT 文件格式演进

```
微信 3.x:  纯 XOR 加密（单字节密钥，通过文件头自动检测）
    |
微信 4.0:  新增 V1 格式（AES-128-ECB + XOR，固定密钥 cfcd208495d565ef）
    |
微信 4.1+: 新增 V2 格式（AES-128-ECB + XOR，密钥需从内存提取）
           旧版 XOR 格式仍同时存在
```

### D. 消息内容压缩

微信 4.x 使用 ZSTD 压缩消息内容，而非加密。WCDB 通过注册自定义 SQL 函数 `wcdb_decompress` 在查询时自动解压。压缩数据的特征是以 ZSTD 魔数 `28 B5 2F FD` 开头。

***

> **声明：** 本文档仅供个人数据备份与恢复等合法用途参考。请遵守相关法律法规，尊重他人隐私。
