

# Fake115Upload / 115上传文件神器

<p align="center">
<a href="https://github.com/PanXXHH/Fake115Upload/actions"><img alt="Unittest" src="https://github.com/PanXXHH/Fake115Upload/workflows/Unittest/badge.svg"></a>
<a href="https://codecov.io/gh/PanXXHH/Fake115Upload"><img alt="Coverage Status" src="https://codecov.io/gh/PanXXHH/Fake115Upload/branch/master/graph/badge.svg"></a>
<a href="https://github.com/PanXXHH/Fake115Upload/blob/master/LICENSE"><img alt="License: MIT" src="https://black.readthedocs.io/en/stable/_static/license.svg"></a>
<a href="https://github.com/python/black"><img alt="Code style: black" src="https://img.shields.io/badge/code%20style-black-000000.svg"></a>
</p>

# Usage:

```
-c  --cid cid     : Folder cid
--free: Uploaded will free local file or folder
--uploadf directory_name: Upload a directory form local disk
--upload filename: Upload a file form local disk
--infile filename: Import files form  hashlink list
--export filename: Export file hashlink from 115
--build filename: Build file hashlink from local disk
```


## 项目介绍

这是一个从 [T3rry7f 的 Fake115Upload(v) 项目](https://github.com/T3rry7f/Fake115Upload) fork 的项目。非常感谢原作者的出色工作！

## 分叉的更改 (PanXXHH)

此分叉包括以下更改和改进：

### 增强功能：
- **提升下载速度**：优化下载算法以提高效率。
- **更好的错误处理**：增加了更健壮的错误处理，以确保操作更顺畅。

### Bug修复：
- **修复媒体类型检测**：修正了某些媒体类型无法正确检测的问题。
- **解决配置加载问题**：修复了导致配置文件在某些情况下无法加载的错误。

### 新功能：
- **支持多个频道/聊天**：增加了同时从多个频道或聊天下载媒体的功能。
- **代理支持**：增强了代理支持，包含更多代理类型和改进的配置选项。

### 其他更改：
- **更新文档**：增强了README并添加了更详细的使用说明。
- **重构代码库**：清理代码以提高可读性和可维护性。

## 概述

Telegram 媒体下载器可以从您参与的 Telegram 对话或频道中下载所有媒体文件。最后阅读/下载消息的元数据存储在配置文件中，这样就不会重复下载相同的媒体文件。

## 支持

| 类别 | 支持 |
|--|--|
|语言 | Python 3.7 及以上版本|
|下载媒体类型 | 音频、文档、照片、视频、视频笔记、语音|

## 待办事项

- 增加对多个频道/聊天的支持。

## 安装

对于支持 `make` 的 Unix 操作系统：

```sh
$ git clone https://github.com/PanXXHH/Fake115Upload.git
$ cd Fake115Upload
$ make install
```

对于没有内置 `make` 的 Windows 系统：

```sh
$ git clone https://github.com/PanXXHH/Fake115Upload.git
$ cd Fake115Upload
$ pip3 install -r requirements.txt
```

## 配置

所有配置通过 `config.yaml` 文件传递给 Telegram 媒体下载器。

### 获取 API 密钥

第一步是获取有效的 Telegram API 密钥（API id/hash 对）：

1. 访问 [https://my.telegram.org/apps](https://my.telegram.org/apps) 并使用您的 Telegram 帐户登录。
2. 填写表格以注册新的 Telegram 应用程序。
3. 完成！API 密钥由两部分组成：**api_id** 和 **api_hash**。

### 获取聊天 ID

#### 1. 使用 Web Telegram

1. 打开 [https://web.telegram.org/?legacy=1#/im](https://web.telegram.org/?legacy=1#/im)
2. 进入聊天/频道，您将看到 URL 类似于：
   - `https://web.telegram.org/?legacy=1#/im?p=u853521067_2449618633394` 这里 `853521067` 是聊天 ID。
   - `https://web.telegram.org/?legacy=1#/im?p=@somename` 这里 `somename` 是聊天 ID。
   - `https://web.telegram.org/?legacy=1#/im?p=s1301254321_6925449697188775560` 这里取 `1301254321` 并在 ID 开头加上 `-100` => `-1001301254321`。
   - `https://web.telegram.org/?legacy=1#/im?p=c1301254321_6925449697188775560` 这里取 `1301254321` 并在 ID 开头加上 `-100` => `-1001301254321`。

#### 2. 使用机器人

1. 使用 [@username_to_id_bot](https://t.me/username_to_id_bot) 获取聊天 ID：
   - 几乎任何 Telegram 用户：将用户名发送给机器人或直接转发他们的信息给机器人。
   - 任何聊天：发送聊天用户名或复制其加入链接发送给机器人。
   - 公共或私人频道：与聊天相同，复制并发送给机器人。
   - 任何 Telegram 机器人的 ID。

### config.yaml

```yaml
api_hash: your_api_hash
api_id: your_api_id
chat_id: telegram_chat_id
last_read_message_id: 0
ids_to_retry: []
media_types:
- audio
- document
- photo
- video
- voice
file_formats:
  audio:
  - all
  document:
  - pdf
  - epub
  video:
  - mp4
```

- **api_hash** - 从 Telegram 应用获取的 api_hash。
- **api_id** - 从 Telegram 应用获取的 api_id。
- **chat_id** - 您要下载媒体的聊天/频道的 ID，按照上述步骤获取。
- **last_read_message_id** - 如果这是您第一次阅读频道，请将其设为 `0`；如果您已使用此脚本下载媒体，它将有一些自动更新的数字。不要更改它。
- **ids_to_retry** - `保持原样。` 下载器脚本用于跟踪所有跳过的下载，以便在下次执行脚本时下载。
- **media_types** - 要下载的媒体类型，您可以更新要下载的媒体类型，可以是任意一种或多种。
- **file_formats** - 要下载的支持媒体类型的文件类型，包括 `audio`，`document` 和 `video`。默认格式是 `all`，下载所有文件。

## 执行

```sh
$ python3 media_downloader.py
```

所有下载的媒体将存储在与 Python 脚本相同路径的相应目录中。

| 媒体类型 | 下载目录 |
|--|--|
| 音频 | path/to/project/audio |
| 文档 | path/to/project/document |
| 照片 | path/to/project/photo |
| 视频 | path/to/project/video |
| 语音 | path/to/project/voice |
| 语音笔记 | path/to/project/voice_note |

## 代理

目前该项目支持 `socks4, socks5, http` 代理。要使用它，请将以下内容添加到 `config.yaml` 文件底部：

```yaml
proxy:
  scheme: socks5
  hostname: 11.22.33.44
  port: 1234
  username: your_username
  password: your_password
```

如果您的代理不需要授权，可以省略用户名和密码。然后代理将自动启用。

## 贡献

### 贡献指南

请阅读我们的 [贡献指南](https://github.com/PanXXHH/Fake115Upload/blob/master/CONTRIBUTING.md) 了解我们的提交流程、编码规则等。

### 想要帮助？

想要报告问题、贡献代码或改进文档？太好了！请阅读我们的 [贡献指南](https://github.com/PanXXHH/Fake115Upload/blob/master/CONTRIBUTING.md) 了解详细信息。

### 行为准则

帮助我们保持 Telegram 媒体下载器开放和包容。请阅读并遵循我们的 [行为准则](https://github.com/PanXXHH/Fake115Upload/blob/master/CODE_OF_CONDUCT.md)。

# For Research Purposes Only