//go:build windows

package main

import "os/exec"

// Windows 不是本工具的部署目标（目标场景是 Linux 容器与前置代理），这几个函数
// 只负责让包在 Windows 上仍能编译：会话回收退化为什么都不做。

func prepareSession(*exec.Cmd) {}

func terminateGroup(int) {}

func killGroup(int) {}
