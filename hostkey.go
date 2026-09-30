// host key 的准备与持久化。
//
// 身份来源按优先级取第一份可用的：
//
//  1. SSH_HOST_KEY_SEED        —— 显式配置的种子，纯内存派生，不读也不写任何文件
//  2. SSH_HOST_KEY_FILE        —— 已经存在的私钥文件，原样沿用
//  3. <SSH_HOST_KEY_FILE>.seed —— 上一次生成的随机种子
//  4. 都没有                    —— 生成随机种子写到 3 的路径，再用它派生
//
// 为什么要种子：容器平台常常给不了可写的持久卷，但环境变量能长期保留。把种子放进
// 环境变量，重启后 host key 就不变，客户端也不会再报 host key 已改变；而一颗种子
// 才几十个字符，比把两三份 PEM 塞进环境变量省事得多。
//
// 无论走哪条路径，都同时提供 ed25519 与 RSA(3072)：只给 ed25519 的话，不支持
// ssh-ed25519 的客户端（OpenSSH 6.5 之前、部分嵌入式与路由器客户端、老版本
// PuTTY）会在算法协商阶段直接失败，而报错信息完全指不到 host key 上。
package main

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"strings"

	"golang.org/x/crypto/hkdf"
	gossh "golang.org/x/crypto/ssh"
)

// rsaHostKeyBits 取 3072：2048 对更老的实现更友好，但 3072 各主流客户端都接受，
// 没必要为极少数老实现降强度。
const rsaHostKeyBits = 3072

// rsaPublicExponent 是 RSA 的公开指数，65537 是事实标准。
const rsaPublicExponent = 65537

// primeRounds 是素数判定里 Miller-Rabin 的轮数，和 crypto/rand.Prime 取的一致。
const primeRounds = 20

// seedLength 是新生成种子的字节数，与 ed25519 私钥种子同量级。
const seedLength = 32

// minSeedLength 是种子长度的告警线。种子能推出 host key，短种子等于把 host key
// 交给任何猜得到它的人——中间人攻击正是靠伪造 host key 完成的。
const minSeedLength = 32

// HKDF 的固定 salt 与 info：salt 把 sshd-lite 的派生结果和同一颗种子在其他用途上
// 的派生区分开，info 再把 ed25519 与 RSA 两条推导路径分开。
const (
	seedSalt          = "sshd-lite host key seed v1"
	seedInfoEd25519   = "ed25519"
	seedInfoRSAStream = "rsa key generation stream"
)

// loadOrCreateHostKeys 按上面的优先级取出本进程要提供的全部 host key。
func loadOrCreateHostKeys(path, seed string) ([]gossh.Signer, error) {
	seedPath := ""
	if path != "" {
		seedPath = path + ".seed"
	}

	// 1. 显式给了种子就完全按它来，不碰任何文件——「没有可写持久卷」的部署要的
	//    正是这个行为。
	if seed != "" {
		log.Printf("host key 由 %s 派生", envHostKeySeed)
		return signersFromSeed(seed)
	}

	if path != "" {
		// 2. 旧版本留下的私钥文件优先：升级时不能把已经在用的 host key 换掉。
		signers, found, err := loadPEMHostKeys(path)
		switch {
		case err != nil:
			return nil, err
		case found:
			return signers, nil
		}

		// 3. 上一次生成的种子。
		saved, err := os.ReadFile(seedPath)
		switch {
		case err == nil:
			savedSeed := strings.TrimSpace(string(saved))
			// 空种子会派生出一个人人可算的 host key，这种时候宁可起不来，也不能
			// 静默接受。文件被截断之类的情况就落在这里。
			if savedSeed == "" {
				return nil, fmt.Errorf("%s 是空的；删掉它重新生成，或改用 %s", seedPath, envHostKeySeed)
			}
			log.Printf("host key 由种子文件 %s 派生", seedPath)
			return signersFromSeed(savedSeed)
		case !errors.Is(err, os.ErrNotExist):
			return nil, err
		}
	}

	// 4. 全新部署：生成一颗随机种子并存下来，下次直接复用。
	generated, err := randomSeed()
	if err != nil {
		return nil, err
	}
	if seedPath == "" {
		log.Printf("WARN: 没有可落盘的位置，host key 每次启动都会变化；"+
			"设置 %s 或 %s 可以固定下来", envHostKeySeed, envHostKey)
	} else if writeSeed(seedPath, generated) == nil {
		log.Printf("已生成随机 host key 种子并保存到 %s", seedPath)
	}
	return signersFromSeed(generated)
}

// signersFromSeed 由种子派生两份 host key。推导完全由本文件的代码决定，不受构建
// 环境或标准库版本影响，所以种子就是身份本身：别泄漏，也别设成弱口令。
func signersFromSeed(seed string) ([]gossh.Signer, error) {
	if len(seed) < minSeedLength {
		log.Printf("WARN: host key 种子只有 %d 字节，太短容易被猜到（猜到种子就能伪造本机 host key）；"+
			"建议用 `openssl rand -hex 32` 生成", len(seed))
	}

	edSeed, err := deriveBytes(seed, seedInfoEd25519, ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	edSigner, err := gossh.NewSignerFromKey(ed25519.NewKeyFromSeed(edSeed))
	if err != nil {
		return nil, err
	}
	signers := []gossh.Signer{edSigner}

	// RSA 没有「由种子直接构造私钥」的写法：私钥来自两个随机素数，得自己搜。
	rsaKey, err := deriveRSAHostKey(seed)
	if err != nil {
		log.Printf("WARN: 无法由种子派生 RSA host key: %v（只提供 ed25519 host key，老客户端会连不上）", err)
		return signers, nil
	}
	rsaSigner, err := gossh.NewSignerFromKey(rsaKey)
	if err != nil {
		log.Printf("WARN: 无法由种子派生 RSA host key: %v（只提供 ed25519 host key，老客户端会连不上）", err)
		return signers, nil
	}
	return append(signers, rsaSigner), nil
}

// deriveRSAHostKey 由种子确定性地构造一份 RSA 私钥。
//
// 不能图省事把 HKDF 流直接喂给 rsa.GenerateKey：crypto/internal/rand 会给非默认
// reader 包一层 randutil.MaybeReadByte，而它会用另一个全局随机源掷硬币，决定要不要
// 从调用方的流里多吃一个字节。于是同一条流在两次运行里被消耗的方式不同，派生出的
// 素数也就不一样——这是实测确认过的，不是推测。所以这里自己按标准步骤构造：从种子
// 流取候选奇数、向上找素数、再组装出 n 与 d。
//
// 素性判定用 math/big 的 ProbablyPrime：它的 Miller-Rabin 底数由被判定数自身派生
// （math/big 里是 `rand.NewSource(int64(n[0]))`），所以对同一个数结果确定；再加上
// Baillie-PSW，误判可以忽略。整个推导过程都在本文件里，不依赖标准库的实现细节。
func deriveRSAHostKey(seed string) (*rsa.PrivateKey, error) {
	stream := hkdf.New(sha256.New, []byte(seed), []byte(seedSalt), []byte(seedInfoRSAStream))
	half := rsaHostKeyBits / 2

	p, err := derivePrime(stream, half)
	if err != nil {
		return nil, err
	}
	for {
		q, err := derivePrime(stream, half)
		if err != nil {
			return nil, err
		}
		if q.Cmp(p) == 0 {
			continue
		}
		// 组装不过关（理论上到不了）就换一个 q 继续试。
		if key, err := assembleRSAKey(p, q); err == nil {
			return key, nil
		}
	}
}

// derivePrime 从确定性流里取一个候选奇数，再向上找到第一个素数。
//
// 候选数置满顶两位和最低位，和 crypto/rand.Prime 的做法一致：顶两位保证两个素数
// 相乘后模数正好是 rsaHostKeyBits 位（否则得反复重试），最低位保证是奇数（2 以外
// 只有奇数可能是素数，直接省掉一半候选）。
func derivePrime(stream io.Reader, bits int) (*big.Int, error) {
	buf := make([]byte, bits/8)
	if _, err := io.ReadFull(stream, buf); err != nil {
		return nil, fmt.Errorf("派生素数失败: %w", err)
	}

	candidate := new(big.Int).SetBytes(buf)
	candidate.SetBit(candidate, bits-1, 1) // 最高位
	candidate.SetBit(candidate, bits-2, 1) // 次高位
	candidate.SetBit(candidate, 0, 1)      // 最低位

	two := big.NewInt(2)
	for ; ; candidate.Add(candidate, two) {
		if candidate.ProbablyPrime(primeRounds) {
			return candidate, nil
		}
	}
}

// assembleRSAKey 由两个素数组装出可用的私钥，并交给标准库校验一遍。
func assembleRSAKey(p, q *big.Int) (*rsa.PrivateKey, error) {
	n := new(big.Int).Mul(p, q)
	if n.BitLen() != rsaHostKeyBits {
		return nil, fmt.Errorf("模数位数是 %d，期望 %d", n.BitLen(), rsaHostKeyBits)
	}

	phi := new(big.Int).Mul(
		new(big.Int).Sub(p, big.NewInt(1)),
		new(big.Int).Sub(q, big.NewInt(1)),
	)
	e := big.NewInt(rsaPublicExponent)
	d := new(big.Int).ModInverse(e, phi)
	if d == nil {
		return nil, errors.New("公钥指数与欧拉函数不互素")
	}

	key := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: n, E: rsaPublicExponent},
		D:         d,
		Primes:    []*big.Int{p, q},
	}
	// Validate 会核对素数性、n = p·q、e·d ≡ 1 这些约束，不过关就当这次取值不可用。
	if err := key.Validate(); err != nil {
		return nil, err
	}
	key.Precompute()
	return key, nil
}

// deriveBytes 用 HKDF 从种子推出指定长度的密钥材料。
func deriveBytes(seed, info string, length int) ([]byte, error) {
	out := make([]byte, length)
	if _, err := io.ReadFull(hkdf.New(sha256.New, []byte(seed), []byte(seedSalt), []byte(info)), out); err != nil {
		return nil, fmt.Errorf("派生 host key 失败: %w", err)
	}
	return out, nil
}

// randomSeed 生成一颗随机种子。存成十六进制是为了好打印、好直接粘进环境变量。
func randomSeed() (string, error) {
	buf := make([]byte, seedLength)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// writeSeed 把种子落盘。失败只告警不返回错误：种子写不进去只是重启后 host key
// 会变，不该让服务起不来。
func writeSeed(path, seed string) error {
	if err := os.WriteFile(path, []byte(seed+"\n"), 0o600); err != nil {
		log.Printf("WARN: 种子无法写入 %s: %v（host key 每次启动都会变化；"+
			"可改用 %s 环境变量）", path, err, envHostKeySeed)
		return err
	}
	return nil
}

// loadPEMHostKeys 读取路径上的 PEM 私钥。主 host key 不存在就返回 found=false，
// 交给种子流程接手。
func loadPEMHostKeys(path string) ([]gossh.Signer, bool, error) {
	edSigner, found, err := loadSignerFile(path)
	if err != nil || !found {
		return nil, false, err
	}
	signers := []gossh.Signer{edSigner}

	// 伴生的 RSA 只服务老客户端：读不到就现生成一份，坏掉也只是少一份，两种情况
	// 都不该让服务起不来。
	rsaSigner, found, err := loadSignerFile(path + ".rsa")
	switch {
	case err != nil:
		log.Printf("WARN: %v（只提供 ed25519 host key，老客户端会连不上）", err)
	case found:
		signers = append(signers, rsaSigner)
	default:
		generated, err := createRSAHostKey(path + ".rsa")
		if err != nil {
			log.Printf("WARN: %v（只提供 ed25519 host key，老客户端会连不上）", err)
			break
		}
		signers = append(signers, generated)
	}
	return signers, true, nil
}

func loadSignerFile(path string) (gossh.Signer, bool, error) {
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil, false, nil
	case err != nil:
		return nil, false, err
	}
	signer, err := gossh.ParsePrivateKey(data)
	if err != nil {
		return nil, false, fmt.Errorf("parse %s: %w", path, err)
	}
	return signer, true, nil
}

// createRSAHostKey 生成一份新的 RSA host key，并尽力落盘：写不进去只是重启后会
// 变化，不影响本次启动。
func createRSAHostKey(path string) (gossh.Signer, error) {
	priv, err := rsa.GenerateKey(rand.Reader, rsaHostKeyBits)
	if err != nil {
		return nil, err
	}
	if err := writeHostKey(path, priv); err != nil {
		log.Printf("WARN: host key 无法写入 %s: %v（重启后 host key 会变化）", path, err)
	}
	return gossh.NewSignerFromKey(priv)
}

func writeHostKey(path string, priv crypto.PrivateKey) error {
	block, err := gossh.MarshalPrivateKey(priv, "")
	if err != nil {
		return err
	}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0o600)
}
