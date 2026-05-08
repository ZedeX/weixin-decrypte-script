# WeChat Decrypt Script

Windows 微信 4.x 本地数据解密工具集，支持数据库解密、消息读取和图片文件解密。

> 基于 [xuxinhang 的技术文章](https://mp.weixin.qq.com/s/JbyzB3NmFbHlGQJlgVGuDw) 方法

## 功能

- 从微信进程内存提取 SQLCipher 4 数据库密钥
- 批量解密数据库文件（contact、message、session 等）
- 读取并解压 ZSTD 压缩的消息内容
- 解密 DAT 图片文件，支持三种加密格式：
  - 旧版 XOR（单字节异或，自动检测密钥）
  - V1 格式（AES-128-ECB + XOR，固定密钥 `cfcd208495d565ef`）
  - V2 格式（AES-128-ECB + XOR，从内存提取密钥）

## 环境要求

- Windows 10/11 x64
- Python 3.8+
- 微信 4.x（已登录）
- 管理员权限（密钥提取需要）

## 安装

```bash
pip install pymem psutil pycryptodome zstandard
```

## 快速开始

### 1. 提取数据库密钥

```bash
# 以管理员身份运行，微信必须已登录
python scan_keys.py
```

### 2. 解密数据库

```bash
# 批量解密
python decrypt_db.py --auto "C:\Users\<USER>\Documents\xwechat_files" found_keys.txt

# 单个文件
python decrypt_db.py <db_path> <hex_key>
```

### 3. 读取消息

```bash
python read_messages.py <decrypted_db_path>

# 批量读取
python read_messages.py --batch "C:\Users\<USER>\Documents\xwechat_files"
```

### 4. 解密图片

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

## 脚本说明

| 脚本 | 功能 |
|------|------|
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

详细技术文档见 [WEIXIN_DECRYPT_GUIDE.md](WEIXIN_DECRYPT_GUIDE.md)。

## 声明

本项目仅供个人数据备份与恢复等合法用途。请遵守相关法律法规，尊重他人隐私。
