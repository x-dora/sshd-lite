# sshd-lite

一个不依赖系统用户数据库的轻量 SSH 服务端，用于以「虚拟 uid」运行的容器。

## 为什么需要它

OpenSSH sshd 和 Dropbear 的每一条认证路径都要经过 `getpwnam`/`getpwuid`：

- 容器以 `/etc/passwd` 中不存在的 uid 运行时（PaaS 平台、OpenShift 的任意 uid 模式、
  `docker run --user 999` 等），**客户端填任何用户名都会认证失败**；
- 这类环境通常也不允许容器内进程写 `/etc/passwd`，所以没有配置层面的绕法；
- dropbear 的第三方补丁（如 clearml 的 `DROPBEAR_CLEARML_FIXED_PASSWORD`）同样绕不开：
  它只是把客户端用户名替换成 `cuserid()` 的结果，而 `cuserid()` 本质仍是
  `getpwuid(geteuid())`，对虚拟 uid 一样返回空——而且该补丁**只覆盖密码认证，不支持公钥**。

sshd-lite 完全跳过用户数据库：认证只比对 `authorized_keys`，登录成功后直接以当前进程的
身份启动 shell。**客户端填什么用户名都可以**，`root`、`user`、`999` 完全等价。

## 特性

- 公钥认证，密钥来自文件或环境变量，支持运行时配置
- 交互式 pty shell 与 `ssh host <command>` 执行（命令交给登录 shell 的 `-c`，支持管道、重定向、`&&`）
- `ssh -L` / `-R` / `-D` 端口转发
- host key 自动生成并可持久化，避免重启后客户端报 host key 变化
- 单一静态二进制，无外部依赖，不需要 tar/xz 解包
- 默认只监听回环地址，由部署方的前置代理对外暴露

## 用法

```bash
# 最小用法：公钥直接给内容，host key 自动生成
SSH_AUTHORIZED_KEYS="ssh-ed25519 AAAAC3Nza... you@laptop" \
SSH_LISTEN=127.0.0.1:2222 \
./sshd-lite
```

```bash
# 从文件读公钥，并持久化 host key
SSH_AUTHORIZED_KEYS_FILE=/opt/ssh/authorized_keys \
SSH_HOST_KEY_FILE=/opt/ssh/host_key \
SSH_LISTEN=127.0.0.1:2222 \
./sshd-lite
```

```bash
# 客户端：用户名随意
ssh -p 2222 root@example.com
ssh -p 2222 user@example.com
```

### 配置项

环境变量与同名命令行参数等价，环境变量优先用于容器部署；命令行参数优先级更高。

| 环境变量 | 参数 | 默认值 | 说明 |
|---|---|---|---|
| `SSH_LISTEN` | `-listen` | `127.0.0.1:2222` | 监听地址 |
| `SSH_AUTHORIZED_KEYS` | `-authorized-keys-inline` | — | 公钥内容，多个用换行或字面量 `\n` 分隔 |
| `SSH_AUTHORIZED_KEYS_FILE` | `-authorized-keys` | — | `authorized_keys` 文件路径 |
| `SSH_HOST_KEY_FILE` | `-host-key` | — | host key 文件；不存在则生成，留空表示每次启动重新生成 |
| `SSH_SHELL` | `-shell` | 自动探测 | 登录后启动的 shell |

`SSH_AUTHORIZED_KEYS` 与 `SSH_AUTHORIZED_KEYS_FILE` 至少提供一个，否则启动失败——
不会起一个谁都进不来的空服务端。

shell 探测顺序：`SSH_SHELL` → `$SHELL` → `/bin/bash` → `/bin/sh`。

## 安全说明

- 认证只看公钥，**没有密码认证**，也不做用户名区分，因此 `authorized_keys` 就是唯一的访问边界，务必妥善保管私钥。
- 默认只监听 `127.0.0.1`。对外暴露时请置于前置代理之后（例如按协议分流的 Caddy layer4），
  不要直接监听 `0.0.0.0`。
- 登录后的权限等同于运行 sshd-lite 的进程权限。

## 构建

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o sshd-lite .
```

## 许可证

MIT
