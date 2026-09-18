// Command sshd-lite 是一个不依赖系统用户数据库的轻量 SSH 服务端。
//
// OpenSSH sshd 与 Dropbear 的每一条认证路径都要经过 getpwnam/getpwuid：当容器以
// /etc/passwd 中不存在的虚拟 uid 运行时（PaaS、OpenShift 的任意 uid 模式等），
// 无论客户端填什么用户名都会认证失败；这类环境通常也不允许写 /etc/passwd，所以
// 没有配置层面的绕法——dropbear 的第三方补丁同样只是把客户端用户名换成
// cuserid()，而后者本质仍是 getpwuid(geteuid())。
//
// sshd-lite 完全跳过用户数据库：认证只比对 authorized_keys，登录成功后直接以当前
// 进程的身份启动 shell，因此客户端填什么用户名都可以。
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/creack/pty"
	"github.com/gliderlabs/ssh"
	"github.com/pkg/sftp"
	gossh "golang.org/x/crypto/ssh"
)

const (
	envListen         = "SSH_LISTEN"
	envHostKey        = "SSH_HOST_KEY_FILE"
	envKeysFile       = "SSH_AUTHORIZED_KEYS_FILE"
	envKeysInline     = "SSH_AUTHORIZED_KEYS"
	envShell          = "SSH_SHELL"
	envIdleTimeout    = "SSH_IDLE_TIMEOUT"
	envMaxTimeout     = "SSH_MAX_TIMEOUT"
	envMaxConnections = "SSH_MAX_CONNECTIONS"
)

// 默认值按 PaaS 容器（内存百来 MiB、CPU 不到一核）取：每个空闲会话都占着一个
// goroutine、一个 pty 和一块缓冲，需要兜底回收；但正常交互和跑得久的长任务
// 不能被误伤，所以空闲超时取得够长，会话最大时长默认不限，连接数上限只拦
// 真正的异常堆积。三项都可以用 0 关掉。
const (
	defaultIdleTimeout    = 30 * time.Minute
	defaultMaxTimeout     = 0
	defaultMaxConnections = 32
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("[sshd-lite] ")

	listen := flag.String("listen", envOr(envListen, "127.0.0.1:2222"),
		"监听地址（env "+envListen+"）")
	hostKeyPath := flag.String("host-key", os.Getenv(envHostKey),
		"host key 文件路径，不存在则生成；留空表示每次启动重新生成（env "+envHostKey+"）")
	keysFile := flag.String("authorized-keys", os.Getenv(envKeysFile),
		"authorized_keys 文件路径（env "+envKeysFile+"）")
	keysInline := flag.String("authorized-keys-inline", os.Getenv(envKeysInline),
		"直接给出公钥内容，多个用换行或字面量 \\n 分隔（env "+envKeysInline+"）")
	shellPath := flag.String("shell", os.Getenv(envShell),
		"登录后启动的 shell（env "+envShell+"）")
	idleTimeout := flag.Duration("idle-timeout", durationEnv(envIdleTimeout, defaultIdleTimeout),
		"会话空闲多久后断开，0 表示不限（env "+envIdleTimeout+"）")
	maxTimeout := flag.Duration("max-timeout", durationEnv(envMaxTimeout, defaultMaxTimeout),
		"单个会话最长存活时间，0 表示不限（env "+envMaxTimeout+"）")
	maxConnections := flag.Int("max-connections", intEnv(envMaxConnections, defaultMaxConnections),
		"并发连接上限，0 表示不限（env "+envMaxConnections+"）")
	flag.Parse()

	signer, err := loadOrCreateHostKey(*hostKeyPath)
	if err != nil {
		log.Fatalf("host key: %v", err)
	}

	keys, err := loadAuthorizedKeys(*keysFile, *keysInline)
	if err != nil {
		log.Fatalf("authorized keys: %v", err)
	}

	shell := resolveShell(*shellPath)

	// 连接计数由 ConnCallback 维护，用包装过的 net.Conn 在 Close 时释放，
	// 这样转发连接、认证中途掉线等异常路径也不会把额度泄漏掉。
	var activeConns atomic.Int64

	server := &ssh.Server{
		Addr:    *listen,
		Handler: sessionHandler(shell),
		// 认证只看公钥，不看用户名——客户端用 root、user 还是 uid 数字都等价。
		PublicKeyHandler: func(_ ssh.Context, key ssh.PublicKey) bool {
			_, ok := keys[string(key.Marshal())]
			return ok
		},
		// ssh -L/-R/-D 是本工具的主要用途之一，默认全部放行；可达性由部署方控制
		// （通常只绑回环，再由前置代理对外暴露）。
		LocalPortForwardingCallback:   func(ssh.Context, string, uint32) bool { return true },
		ReversePortForwardingCallback: func(ssh.Context, string, uint32) bool { return true },

		IdleTimeout: *idleTimeout,
		MaxTimeout:  *maxTimeout,

		// 连接数上限只能靠 ConnCallback 实现（Server 没有对应字段）：返回 nil
		// 即拒绝该连接。超限时先写一行说明再关，否则客户端只会看到连接被重置。
		ConnCallback: func(_ ssh.Context, conn net.Conn) net.Conn {
			if *maxConnections <= 0 {
				return conn
			}
			if activeConns.Add(1) > int64(*maxConnections) {
				activeConns.Add(-1)
				_, _ = fmt.Fprintf(conn, "sshd-lite: 连接数已达上限 %d\r\n", *maxConnections)
				return nil
			}
			return &countedConn{Conn: conn, release: func() { activeConns.Add(-1) }}
		},

		// sftp 子系统必须由本进程实现，不能交给系统二进制：OpenSSH 9.0 起 scp
		// 默认改走 SFTP 协议，而容器以 /etc/passwd 里不存在的 uid 运行时，
		// /usr/bin/scp 和 sftp-server 自己就会在 getpwnam 上失败（实测报
		// "scp: unknown user 999"）。这正是 sshd-lite 要绕开的那个问题。
		SubsystemHandlers: map[string]ssh.SubsystemHandler{
			"sftp": sftpHandler,
		},
	}
	server.AddHostKey(signer)

	log.Printf("listening on %s, shell=%s, %d authorized key(s)", *listen, shell, len(keys))
	log.Printf("idle-timeout=%s max-timeout=%s max-connections=%d (0 = 不限)",
		durationLabel(*idleTimeout), durationLabel(*maxTimeout), *maxConnections)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, net.ErrClosed) {
		log.Fatalf("serve: %v", err)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// durationEnv 解析时长配置：接受 Go duration 字符串（"30m"、"1h30m"）或纯秒数。
// 解析失败只给警告并退回默认值——一处拼错的超时配置不该让服务起不来。
func durationEnv(key string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	if d, err := time.ParseDuration(raw); err == nil && d >= 0 {
		return d
	}
	if secs, err := strconv.Atoi(raw); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second
	}
	log.Printf("WARN: 无法解析 %s=%q，改用默认值 %s", key, raw, durationLabel(fallback))
	return fallback
}

func intEnv(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		log.Printf("WARN: 无法解析 %s=%q，改用默认值 %d", key, raw, fallback)
		return fallback
	}
	return n
}

func durationLabel(d time.Duration) string {
	if d <= 0 {
		return "0"
	}
	return d.String()
}

// countedConn 在连接关闭时释放配额。sync.Once 保证计数不会被减成负数——
// net.Conn 的 Close 允许多次调用，转发链路里也确实会重复关闭。
type countedConn struct {
	net.Conn
	release func()
	once    sync.Once
}

func (c *countedConn) Close() error {
	c.once.Do(c.release)
	return c.Conn.Close()
}

// sftpHandler 在会话上跑一个 SFTP 服务端，供 sftp 与本机 scp（OpenSSH 9.0+
// 默认协议）使用。它直接以当前进程身份读写文件系统，不查用户数据库，所以
// 虚拟 uid 环境下也能正常工作——而系统自带的 scp/sftp-server 会在 getpwnam
// 上直接失败。
func sftpHandler(s ssh.Session) {
	srv, err := sftp.NewServer(s)
	if err != nil {
		fmt.Fprintln(s.Stderr(), "sshd-lite: 无法启动 sftp:", err)
		_ = s.Exit(1)
		return
	}
	defer srv.Close()

	if err := srv.Serve(); err != nil && !errors.Is(err, io.EOF) {
		fmt.Fprintln(s.Stderr(), "sshd-lite: sftp:", err)
		_ = s.Exit(1)
		return
	}
	_ = s.Exit(0)
}

// resolveShell 依次尝试显式配置、用户登录 shell、常见 shell，最后退回 /bin/sh。
func resolveShell(explicit string) string {
	for _, candidate := range []string{explicit, os.Getenv("SHELL"), "/bin/bash", "/bin/sh"} {
		if candidate == "" {
			continue
		}
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	return "/bin/sh"
}

// loadOrCreateHostKey 优先读取既有 host key；缺失时生成 ed25519，并在给出路径时
// 写回磁盘，避免每次重启 host key 变化导致客户端报 host key 已改变。
func loadOrCreateHostKey(path string) (gossh.Signer, error) {
	if path != "" {
		data, err := os.ReadFile(path)
		switch {
		case err == nil:
			signer, err := gossh.ParsePrivateKey(data)
			if err != nil {
				return nil, fmt.Errorf("parse %s: %w", path, err)
			}
			return signer, nil
		case !errors.Is(err, os.ErrNotExist):
			return nil, err
		}
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		return nil, err
	}

	if path != "" {
		if err := writeHostKey(path, priv); err != nil {
			log.Printf("WARN: host key 无法写入 %s: %v（重启后 host key 会变化）", path, err)
		}
	}
	return signer, nil
}

func writeHostKey(path string, priv ed25519.PrivateKey) error {
	block, err := gossh.MarshalPrivateKey(priv, "")
	if err != nil {
		return err
	}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0o600)
}

// loadAuthorizedKeys 从文件或内联内容读取公钥。两者都为空时直接报错，避免起一个
// 谁都进不来的空服务端。
func loadAuthorizedKeys(file, inline string) (map[string]struct{}, error) {
	var raw []byte
	switch {
	case inline != "":
		raw = []byte(strings.ReplaceAll(inline, `\n`, "\n"))
	case file != "":
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		raw = data
	default:
		return nil, errors.New("未提供 authorized keys")
	}

	keys := make(map[string]struct{})
	for len(raw) > 0 {
		pub, _, _, rest, err := gossh.ParseAuthorizedKey(raw)
		if err != nil {
			// 注释与空行由 ParseAuthorizedKey 自行跳过，剩余内容解析失败说明
			// 配置有误，直接报出来比静默忽略更安全。
			if strings.TrimSpace(string(raw)) == "" {
				break
			}
			return nil, fmt.Errorf("解析公钥失败: %w", err)
		}
		keys[string(pub.Marshal())] = struct{}{}
		raw = rest
	}
	if len(keys) == 0 {
		return nil, errors.New("没有解析到可用的公钥")
	}
	return keys, nil
}

func sessionHandler(shell string) ssh.Handler {
	return func(s ssh.Session) {
		if raw := s.RawCommand(); raw != "" {
			runCommand(s, shell, raw)
			return
		}
		runShell(s, shell)
	}
}

func runShell(s ssh.Session, shell string) {
	ptyReq, winCh, hasPty := s.Pty()
	cmd := exec.Command(shell)
	cmd.Env = sessionEnv(s, ptyReq.Term, hasPty)

	if !hasPty {
		cmd.Stdin, cmd.Stdout, cmd.Stderr = s, s, s.Stderr()
		if err := cmd.Run(); err != nil {
			reportExit(s, "shell", err)
		}
		return
	}

	f, err := pty.Start(cmd)
	if err != nil {
		fmt.Fprintln(s.Stderr(), "sshd-lite: 无法分配 pty:", err)
		_ = s.Exit(1)
		return
	}
	defer f.Close()

	go func() {
		for win := range winCh {
			_ = pty.Setsize(f, &pty.Winsize{
				Rows: uint16(win.Height),
				Cols: uint16(win.Width),
			})
		}
	}()
	go func() { _, _ = io.Copy(f, s) }()
	_, _ = io.Copy(s, f)
	_ = cmd.Wait()
}

// runCommand 与 sshd 保持同样的语义：整条命令字符串交给登录 shell 的 -c 执行，
// 这样 `ls | grep x`、`a && b` 这类 shell 语法才能正常工作（直接 exec.Command 拆
// 参数会让分号、管道全部失效）。
func runCommand(s ssh.Session, shell, raw string) {
	cmd := exec.Command(shell, "-c", raw)
	cmd.Env = sessionEnv(s, "", false)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = s, s, s.Stderr()

	if err := cmd.Run(); err != nil {
		reportExit(s, raw, err)
		return
	}
	_ = s.Exit(0)
}

// sessionEnv 沿用服务端进程的环境：容器里没有登录会话那一套初始化，直接用父进程
// 环境最贴近部署方的预期，只补上 TERM 与 SSH 惯例变量。
func sessionEnv(s ssh.Session, term string, hasPty bool) []string {
	env := os.Environ()
	if hasPty && term != "" {
		env = append(env, "TERM="+term)
	}
	if addr := s.RemoteAddr(); addr != nil {
		env = append(env, "SSH_CONNECTION="+addr.String())
	}
	if user := s.User(); user != "" {
		env = append(env, "USER="+user, "LOGNAME="+user)
	}
	return env
}

func reportExit(s ssh.Session, what string, err error) {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		_ = s.Exit(exitErr.ExitCode())
		return
	}
	fmt.Fprintf(s.Stderr(), "sshd-lite: %s: %v\n", what, err)
	_ = s.Exit(127)
}
