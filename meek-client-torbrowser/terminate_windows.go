// +build windows

// Process termination code for platforms that don't have SIGTERM (i.e.,
// Windows).

package main

import (
	"os/exec"
	"time"
)

// Terminate a subprocess: on Windows all we can do is kill it.
func terminateCmd(cmd *exec.Cmd) error {
	return cmd.Process.Kill()
}

// Terminate a PT subprocess: first close its stdin; then kill it if that
// doesn't work.
func terminatePTCmd(cmd *ptCmd) error {
	err := cmd.StdinCloser.Close()
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
