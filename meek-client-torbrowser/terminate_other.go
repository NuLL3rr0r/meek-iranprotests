// +build !windows

// Process termination code for platforms that have SIGTERM (i.e., not Windows).

package main

import (
	"os/exec"
	"syscall"
	"time"
)

// Terminate a subprocess: first send it SIGTERM; then kill it if that doesn't
// work.
func terminateCmd(cmd *exec.Cmd) error {
	err := cmd.Process.Signal(syscall.SIGTERM)
	ch := make(chan error, 1)
	go func() {
		ch <- cmd.Wait()
	}()
	var err2 error
	select {
	case <-time.After(terminateTimeout):
		err2 = cmd.Process.Kill()
	case err2 = <-ch:
	}
	if err == nil {
		err = err2
	}
	return err
}

// Terminate a PT subprocess: first close its stdin and send it SIGTERM; then
// kill it if that doesn't work.
func terminatePTCmd(cmd *ptCmd) error {
	err := cmd.StdinCloser.Close()
	err2 := terminateCmd(cmd.Cmd)
	if err == nil {
		err = err2
	}
	return err
}
