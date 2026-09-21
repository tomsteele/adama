//go:build !linux && !darwin

package toolrun

import "os/exec"

func configureProcess(cmd *exec.Cmd) {}
