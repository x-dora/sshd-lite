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
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/creack/pty"
	"github.com/gliderlabs/ssh"
	"github.com/pkg/sftp"
	gossh "golang.org/x/crypto/ssh"
)

const (
	envListen         = "SSH_LISTEN"
	envHostKey        = "SSH_HOST_KEY_FILE"
	envHostKeySeed    = "SSH_HOST_KEY_SEED"
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
	hostKeySeed := flag.String("host-key-seed", os.Getenv(envHostKeySeed),
		"host key 种子；设置后由它派生 host key，不读写任何文件（env "+envHostKeySeed+"）")
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

	signers, err := loadOrCreateHostKeys(*hostKeyPath, *hostKeySeed)
	if err != nil {
		log.Fatalf("host key: %v", err)
	}

	keys, err := loadAuthorizedKeys(*keysFile, *keysInline)
	if err != nil {
		log.Fatalf("authorized keys: %v", err)
	}
	warnFromRestrictions(keys)

	shell := resolveShell(*shellPath)

	// 连接计数由 ConnCallback 维护，用包装过的 net.Conn 在 Close 时释放，
	// 这样转发连接、认证中途掉线等异常路径也不会把额度泄漏掉。
	var activeConns atomic.Int64

	// 端口转发必须显式注册：gliderlabs 的 DefaultChannelHandlers 只有 "session"、
	// DefaultRequestHandlers 是空 map，不注册的话 -L/-R/-D 一律以
	// "unknown channel type" 被拒，下面两个 Callback 永远轮不到执行。
	fwdHandler := &ssh.ForwardedTCPHandler{}

	server := &ssh.Server{
		Addr:    *listen,
		Handler: sessionHandler(shell),
		// 认证只看公钥，不看用户名——客户端用 root、user 还是 uid 数字都等价。
		// 命中公钥后把那一行的选项挂到连接上下文上，会话与转发都按它来。
		PublicKeyHandler: func(ctx ssh.Context, key ssh.PublicKey) bool {
			opts, ok := keys[string(key.Marshal())]
			if !ok {
				return false
			}
			if !opts.allowsFrom(ctx.RemoteAddr()) {
				log.Printf("拒绝连接：来源 %v 不在该公钥的 from= 列表内", ctx.RemoteAddr())
				return false
			}
			ctx.SetValue(authOptionsKey{}, opts)
			return true
		},
		// 这两个 handler 必须自己塞进去，否则端口转发通道/请求没人应答。
		ChannelHandlers: map[string]ssh.ChannelHandler{
			"session":      ssh.DefaultSessionHandler,
			"direct-tcpip": ssh.DirectTCPIPHandler,
		},
		RequestHandlers: map[string]ssh.RequestHandler{
			"tcpip-forward":        forceLoopbackBind(fwdHandler.HandleSSHRequest),
			"cancel-tcpip-forward": forceLoopbackBind(fwdHandler.HandleSSHRequest),
		},
		// ssh -L/-D 的目标不限，可达性由部署方控制（通常只绑回环，再由前置代理
		// 对外暴露）；被 authorized_keys 的 no-port-forwarding/restrict 关掉时拒绝。
		LocalPortForwardingCallback: func(ctx ssh.Context, _ string, _ uint32) bool {
			return !optionsOf(ctx).noForward
		},
		// -R 的绑定地址由 forceLoopbackBind 收敛到回环，这里只管开关。
		ReversePortForwardingCallback: func(ctx ssh.Context, _ string, _ uint32) bool {
			return !optionsOf(ctx).noForward
		},

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
	for _, signer := range signers {
		server.AddHostKey(signer)
	}

	// 交互式会话跑在 pty 里，而 creack/pty 的 Start 会给子进程 Setsid：每个会话
	// 自成一个会话和进程组，既收不到本进程退出时的 SIGHUP，也不和本进程同组，
	// 容器 init 的进程组转发同样够不着。不显式回收，节点重启就会留下一堆还在跑的
	// shell，所以这里自己接管 SIGTERM/SIGINT。
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		log.Printf("收到 %s，回收 %d 个会话后退出", <-sigCh, sessions.count())
		sessions.terminate()
		_ = server.Close()
	}()

	log.Printf("listening on %s, shell=%s, %d authorized key(s)", *listen, shell, len(keys))
	log.Printf("idle-timeout=%s max-timeout=%s max-connections=%d (0 = 不限)",
		durationLabel(*idleTimeout), durationLabel(*maxTimeout), *maxConnections)
	if err := server.ListenAndServe(); err != nil &&
		!errors.Is(err, net.ErrClosed) && !errors.Is(err, ssh.ErrServerClosed) {
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

// sessionShutdownGrace 是退出时留给会话自行收尾的时间。
const sessionShutdownGrace = 3 * time.Second

// sessionRegistry 记录正在运行的会话进程，用于退出时整组回收。
//
// 登记的是会话进程的 pid，它同时也是该会话的进程组 id：pty 分支由 creack/pty 设
// Setsid 拿到，非 pty 分支由 prepareSession 设 Setpgid 拿到。
type sessionRegistry struct {
	mu   sync.Mutex
	pids map[int]struct{}
}

var sessions = &sessionRegistry{pids: map[int]struct{}{}}

func (r *sessionRegistry) add(pid int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pids[pid] = struct{}{}
}

func (r *sessionRegistry) remove(pid int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.pids, pid)
}

func (r *sessionRegistry) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.pids)
}

// terminate 先 SIGHUP 再 SIGKILL 回收所有会话进程组。只杀会话进程本身是不够的：
// shell 退出未必带走自己的子孙，而且这些会话都自成进程组，父进程组收到的信号
// 传不到它们，只有按组通知才能覆盖到整棵进程树。
func (r *sessionRegistry) terminate() {
	r.mu.Lock()
	pids := make([]int, 0, len(r.pids))
	for pid := range r.pids {
		pids = append(pids, pid)
	}
	r.mu.Unlock()

	if len(pids) == 0 {
		return
	}
	for _, pid := range pids {
		terminateGroup(pid)
	}
	deadline := time.Now().Add(sessionShutdownGrace)
	for time.Now().Before(deadline) {
		if r.count() == 0 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	for _, pid := range pids {
		killGroup(pid)
	}
}

// forceLoopbackBind 把 -R 的绑定地址收敛到回环地址，复刻 OpenSSH 默认的
// GatewayPorts=no 语义：客户端显式写通配地址会被拒，留空（OpenSSH 客户端最常见
// 的写法）则改写成 127.0.0.1——gliderlabs 会把空地址交给 net.Listen(":port")，
// 那等于监听所有接口，和「默认只绑回环」的承诺直接冲突。
//
// 只做 allow/deny 是做不到这一点的（回调拿不到改写结果），所以这里改写请求负载
// 再交给上游 handler；调用方 handleRequests 用的是原来的 req 去 Reply，替换安全。
func forceLoopbackBind(inner ssh.RequestHandler) ssh.RequestHandler {
	return func(ctx ssh.Context, srv *ssh.Server, req *gossh.Request) (bool, []byte) {
		var payload struct {
			BindAddr string
			BindPort uint32
		}
		if err := gossh.Unmarshal(req.Payload, &payload); err != nil {
			return false, nil
		}
		switch {
		case payload.BindAddr == "":
			payload.BindAddr = "127.0.0.1"
		case !isLoopbackHost(payload.BindAddr):
			log.Printf("拒绝 -R 绑定到 %q：只允许回环地址", payload.BindAddr)
			return false, []byte("sshd-lite: 反向转发只允许绑定回环地址")
		}
		normalized := &gossh.Request{
			Type:      req.Type,
			WantReply: req.WantReply,
			Payload:   gossh.Marshal(&payload),
		}
		return inner(ctx, srv, normalized)
	}
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
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

// authOptionsKey 是连接上下文里存放 authorized_keys 选项的键：认证通过时写入，
// 会话处理与端口转发回调再取出来。
type authOptionsKey struct{}

// keyOptions 是 authorized_keys 行首的选项里 sshd-lite 需要落实的部分。
//
// 这些选项以前被整个丢掉了：写了 from= 以为限了来源、写了 command= 以为锁了命令，
// 实际什么都没发生——安全预期落空比不支持更危险。现在能落实的落实，落实不了的
// 启动时直接报错，不留静默失效的余地。
type keyOptions struct {
	command   string       // command=：强制执行的命令，优先于客户端请求的命令
	from      []*net.IPNet // from=：允许的来源，空表示不限
	noPTY     bool         // no-pty / restrict
	noForward bool         // no-port-forwarding / restrict
}

// allowsFrom 判断来源地址是否在 from= 列表内。比较的是 sshd-lite 看到的对端地址：
// 部署在前置代理之后时那是代理的地址，不是真实客户端 IP。
func (o keyOptions) allowsFrom(addr net.Addr) bool {
	if len(o.from) == 0 || addr == nil {
		return true
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, network := range o.from {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func optionsOf(ctx ssh.Context) keyOptions {
	opts, _ := ctx.Value(authOptionsKey{}).(keyOptions)
	return opts
}

// parseKeyOptions 解析一行 authorized_keys 的选项。
func parseKeyOptions(options []string) (keyOptions, error) {
	var opts keyOptions
	for _, raw := range options {
		name, value, _ := strings.Cut(raw, "=")
		switch name {
		case "restrict":
			opts.noPTY, opts.noForward = true, true
		case "no-pty":
			opts.noPTY = true
		case "no-port-forwarding":
			opts.noForward = true
		case "no-agent-forwarding", "no-X11-forwarding", "no-user-rc":
			// 这三项限制的能力 sshd-lite 本来就没有，等同已经满足。
		case "command":
			opts.command = strings.Trim(value, `"`)
		case "from":
			networks, err := parseFromList(strings.Trim(value, `"`))
			if err != nil {
				return keyOptions{}, err
			}
			opts.from = append(opts.from, networks...)
		default:
			return keyOptions{}, fmt.Errorf("不支持 authorized_keys 选项 %q", name)
		}
	}
	return opts, nil
}

func parseFromList(list string) ([]*net.IPNet, error) {
	var networks []*net.IPNet
	for _, item := range strings.Split(list, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if ip := net.ParseIP(item); ip != nil {
			bits := 128
			if ipv4 := ip.To4(); ipv4 != nil {
				ip, bits = ipv4, 32
			}
			networks = append(networks, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		if _, network, err := net.ParseCIDR(item); err == nil {
			networks = append(networks, network)
			continue
		}
		return nil, fmt.Errorf("from= 中的 %q 既不是 IP 也不是 CIDR", item)
	}
	return networks, nil
}

// warnFromRestrictions 提前把 from= 的坑说清楚：它比较的是 sshd-lite 看到的对端
// 地址，经前置代理转发时那是代理的回环地址，写了 from= 会把所有连接都挡在外面。
func warnFromRestrictions(keys map[string]keyOptions) {
	for _, opts := range keys {
		if len(opts.from) > 0 {
			log.Printf("WARN: 有公钥配置了 from= 限制；sshd-lite 只能看到对端地址，" +
				"经前置代理转发时会拒绝所有连接")
			return
		}
	}
}

// loadAuthorizedKeys 从文件或内联内容读取公钥，连同每行的选项一起返回。两者都
// 为空时直接报错，避免起一个谁都进不来的空服务端。
func loadAuthorizedKeys(file, inline string) (map[string]keyOptions, error) {
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

	keys := make(map[string]keyOptions)
	for len(raw) > 0 {
		pub, _, options, rest, err := gossh.ParseAuthorizedKey(raw)
		if err != nil {
			// 注释与空行由 ParseAuthorizedKey 自行跳过，剩余内容解析失败说明
			// 配置有误，直接报出来比静默忽略更安全。
			if strings.TrimSpace(string(raw)) == "" {
				break
			}
			return nil, fmt.Errorf("解析公钥失败: %w", err)
		}
		opts, err := parseKeyOptions(options)
		if err != nil {
			return nil, fmt.Errorf("公钥选项 %v: %w", options, err)
		}
		keys[string(pub.Marshal())] = opts
		raw = rest
	}
	if len(keys) == 0 {
		return nil, errors.New("没有解析到可用的公钥")
	}
	return keys, nil
}

func sessionHandler(shell string) ssh.Handler {
	return func(s ssh.Session) {
		opts := optionsOf(s.Context())
		raw := s.RawCommand()
		// command= 覆盖客户端请求的命令（客户端压根没请求命令时也照样执行它），
		// 与 OpenSSH 的强制命令语义一致。
		if opts.command != "" {
			raw = opts.command
		}
		if raw != "" {
			runCommand(s, shell, raw)
			return
		}
		runShell(s, opts, shell)
	}
}

func runShell(s ssh.Session, opts keyOptions, shell string) {
	ptyReq, winCh, hasPty := s.Pty()
	// no-pty 时按无终端会话处理：命令照跑，只是不分配 pty。
	if opts.noPTY {
		hasPty = false
	}
	cmd := exec.Command(shell)
	cmd.Env = sessionEnv(s, ptyReq.Term, hasPty)

	if !hasPty {
		cmd.Stdin, cmd.Stdout, cmd.Stderr = s, s, s.Stderr()
		runTracked(s, "shell", cmd)
		return
	}

	f, err := pty.Start(cmd)
	if err != nil {
		fmt.Fprintln(s.Stderr(), "sshd-lite: 无法分配 pty:", err)
		_ = s.Exit(1)
		return
	}
	defer f.Close()

	// pty.Start 已经让子进程 Setsid，它自己就是进程组组长，直接按 pid 登记。
	sessions.add(cmd.Process.Pid)
	defer sessions.remove(cmd.Process.Pid)

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

// runTracked 启动命令并登记它的进程组，好在退出时统一回收；启动或等待失败都按
// sshd 的习惯把退出码报给客户端，并把错误原样返回给调用方判断是否已上报。
func runTracked(s ssh.Session, what string, cmd *exec.Cmd) error {
	prepareSession(cmd)
	if err := cmd.Start(); err != nil {
		reportExit(s, what, err)
		return err
	}
	sessions.add(cmd.Process.Pid)
	err := cmd.Wait()
	sessions.remove(cmd.Process.Pid)
	if err != nil {
		reportExit(s, what, err)
	}
	return err
}

// runCommand 与 sshd 保持同样的语义：整条命令字符串交给登录 shell 的 -c 执行，
// 这样 `ls | grep x`、`a && b` 这类 shell 语法才能正常工作（直接 exec.Command 拆
// 参数会让分号、管道全部失效）。
func runCommand(s ssh.Session, shell, raw string) {
	cmd := exec.Command(shell, "-c", raw)
	cmd.Env = sessionEnv(s, "", false)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = s, s, s.Stderr()

	if runTracked(s, raw, cmd) == nil {
		_ = s.Exit(0)
	}
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

	// USER/LOGNAME 不再写客户端填的用户名：那是客户端完全可控的任意字符串，而
	// $USER 是被脚本普遍信任的变量，拿它覆盖真实身份会误导这些脚本（真实 uid 还
	// 可能根本不在 /etc/passwd 里）。父进程设了就保留，否则用本进程的真实身份
	// 兜底；客户端填的名字改用 SSH_LOGIN_USER 暴露，需要时照样读得到。
	if os.Getenv("USER") == "" {
		if name := currentUserName(); name != "" {
			env = append(env, "USER="+name, "LOGNAME="+name)
		}
	}
	if loginUser := s.User(); loginUser != "" {
		env = append(env, "SSH_LOGIN_USER="+loginUser)
	}
	return env
}

// currentUserName 取本进程的真实用户名。容器以虚拟 uid 运行时 /etc/passwd 里没有
// 对应条目，这里就返回空——宁可不设，也不编一个假名字出来。
func currentUserName() string {
	current, err := user.Current()
	if err != nil {
		return ""
	}
	return current.Username
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
