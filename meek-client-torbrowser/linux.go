// +build linux
// This file is compiled only on linux. It contains paths used by the linux
// browser bundle.
// http://golang.org/pkg/go/build/#hdr-Build_Constraints

package main

import (
	"os/exec"
	"syscall"
)

const (
	firefoxPath                  = "./firefox"
	firefoxProfilePath           = "TorBrowser/Data/Browser/profile.meek-http-helper"
	torDataDirFirefoxProfilePath = ""
	profileTemplatePath          = ""
)

func osSpecificCommandSetup(cmd *exec.Cmd) {
	// Extra insurance against stray child processes: send SIGTERM when this
	// process terminates. Only works on Linux.
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
}
