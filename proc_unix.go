//go:build !windows

package main

import (
	"os/exec"
	"syscall"
)

// prepareSession 让非 pty 会话自成一个进程组，这样退出时才能按负 pid 整组回收；
// pty 分支由 creack/pty 的 Setsid 完成同样的事，不需要再设一次。
func prepareSession(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}

func terminateGroup(pid int) { _ = syscall.Kill(-pid, syscall.SIGHUP) }

func killGroup(pid int) { _ = syscall.Kill(-pid, syscall.SIGKILL) }
