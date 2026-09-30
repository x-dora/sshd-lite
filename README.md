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
- `ssh -L` / `-R` / `-D` 端口转发；`-R` 的监听地址强制收敛到回环
- `authorized_keys` 支持 `command=`、`from=`、`no-pty`、`no-port-forwarding`、`restrict`
- host key 同时提供 ed25519 与 RSA(3072)，兼顾不支持 ed25519 的老客户端
- host key 可由种子派生：种子放进环境变量即可，容器没有可写持久卷也能保持稳定
- 收到 SIGTERM/SIGINT 时回收全部会话进程组，重启不留孤儿 shell
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

`-version` 打印版本号后退出，启动日志里也会带上它，方便确认节点上装的是哪一版。

### 配置项

环境变量与同名命令行参数等价，环境变量优先用于容器部署；命令行参数优先级更高。

| 环境变量 | 参数 | 默认值 | 说明 |
|---|---|---|---|
| `SSH_LISTEN` | `-listen` | `127.0.0.1:2222` | 监听地址 |
| `SSH_AUTHORIZED_KEYS` | `-authorized-keys-inline` | — | 公钥内容，多个用换行或字面量 `\n` 分隔 |
| `SSH_AUTHORIZED_KEYS_FILE` | `-authorized-keys` | — | `authorized_keys` 文件路径 |
| `SSH_HOST_KEY_FILE` | `-host-key` | — | host key 的落盘位置：既有的 PEM 私钥放这里（RSA 在同路径的 `.rsa`），没有 PEM 时这里会生成同名 `.seed` 种子文件 |
| `SSH_HOST_KEY_SEED` | `-host-key-seed` | — | host key 种子；设置后完全由它派生 host key，不读也不写任何文件 |
| `SSH_SHELL` | `-shell` | 自动探测 | 登录后启动的 shell |

`SSH_AUTHORIZED_KEYS` 与 `SSH_AUTHORIZED_KEYS_FILE` 至少提供一个，否则启动失败——
不会起一个谁都进不来的空服务端。

shell 探测顺序：`SSH_SHELL` → `$SHELL` → `/bin/bash` → `/bin/sh`。

### host key 的来源

按优先级取第一份可用的：

1. `SSH_HOST_KEY_SEED` —— 显式配置的种子，纯内存派生，不读也不写任何文件
2. `SSH_HOST_KEY_FILE` 指向的 PEM 私钥（以前就是这么用的，升级不会换掉身份）
3. `<SSH_HOST_KEY_FILE>.seed` —— 上一次自动生成的随机种子
4. 都没有 —— 生成一颗随机种子写入 3 的路径，再用它派生

所以新部署上，`SSH_HOST_KEY_FILE` 旁边出现的是 `host_key.seed`，而不是私钥文件。

用种子是为了适配**给不了可写持久卷、但环境变量能长期保留**的容器平台：把种子放进
环境变量，重启后 host key 不变，客户端也就不会再报 host key 已改变。种子可以用
`openssl rand -hex 32` 生成，或者直接把 `host_key.seed` 的内容抄进环境变量。

种子**等价于 host key 本身**：猜到种子就能伪造本机 host key 做中间人，所以别用可猜的
字符串（短于 32 字节会告警）。无论走哪条路径，都同时提供 ed25519 与 RSA(3072)。

### 会话环境变量

ssh 会话沿用服务端进程的环境，另外补上：

| 变量 | 说明 |
|---|---|
| `SSH_CONNECTION` | 对端地址（注意：经前置代理转发时是代理的地址，不是真实客户端 IP） |
| `SSH_LOGIN_USER` | 客户端填写的用户名。用户名不参与认证，填什么都等价，所以这里只作信息记录 |
| `USER` / `LOGNAME` | 服务端进程已有的值，或当前进程的真实身份。**不会**被客户端填写的用户名覆盖——`$USER` 被大量脚本信任，任何客户端都能改它等于埋雷 |

### authorized_keys 选项

行首的选项按 OpenSSH 的语义生效：

| 选项 | 行为 |
|---|---|
| `command="…"` | 该公钥只能执行这条命令，覆盖客户端请求的命令 |
| `from="…"` | 限制来源 IP / CIDR，逗号分隔 |
| `no-pty` | 不分配 pty |
| `no-port-forwarding` | 关闭 `-L` / `-R` / `-D` |
| `restrict` | 等价于同时打开上面两项 |
| `no-agent-forwarding`、`no-X11-forwarding`、`no-user-rc` | 所限制的能力 sshd-lite 本来就没有，等同已满足 |

其余选项（`permitopen=`、`environment=`、`expiry-time=` 等）会让**服务启动失败**。
不支持就明说，好过让使用者以为限制已经生效。

`from=` 比较的是 sshd-lite 看到的对端地址。经前置代理转发时那是代理的地址而非真实
客户端 IP，写了 `from=` 会把所有连接都挡在外面——启动时会有一条 WARN 提醒。

## 安全说明

- 认证只看公钥，**没有密码认证**，也不做用户名区分，因此 `authorized_keys` 就是唯一的访问边界，务必妥善保管私钥。
- 默认只监听 `127.0.0.1`。对外暴露时请置于前置代理之后（例如按协议分流的 Caddy layer4），
  不要直接监听 `0.0.0.0`。
- `-R` 反向转发的监听地址强制收敛到回环（等价 OpenSSH 默认的 `GatewayPorts no`）：
  客户端留空时改写为 `127.0.0.1`，显式写 `0.0.0.0` 之类的通配地址会被拒绝。否则
  「默认只绑回环」这个承诺会被一条 `-R` 直接绕过。
- 登录后的权限等同于运行 sshd-lite 的进程权限。

## 构建

版本号取自仓库根目录的 `VERSION`，发布时用 `-ldflags` 注入；直接 `go build` 得到的是 `dev`。

```bash
VERSION="$(tr -d '[:space:]' < VERSION)"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
  -ldflags "-s -w -X main.version=${VERSION}" -o sshd-lite .
```

推 `v<VERSION>` tag 触发 Release 工作流，发布 amd64/arm64 静态二进制与 `checksums.txt`。
`releases/latest/download/<asset>` 始终指向最新一条 release，所以下游不用跟着版本号改；
[rw-node](https://github.com/x-dora/rw-node) 用 `.sshd-lite-version` 钉住具体版本。

## 许可证

MIT
