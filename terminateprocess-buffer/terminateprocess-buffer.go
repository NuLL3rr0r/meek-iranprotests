// This program simulates support for TOR_PT_EXIT_ON_STDIN_CLOSE for versions of
// tor without it. It sets TOR_PT_EXIT_ON_STDIN_CLOSE=1, then sits between tor
// and a transport plugin and keeps the plugin's stdin open. (Versions of tor
// that do not support TOR_PT_EXIT_ON_STDIN_CLOSE instead close the plugin's
// stdin immediately.)
//
// This is mainly useful on Windows, where, before TOR_PT_EXIT_ON_STDIN_CLOSE,
// tor kills child processes with TerminateProcess, which doesn't give them a
// chance to clean up. When you put this program in between tor and the plugin,
// it is this program that is killed (and has its stdout closed) by
// TerminateProcess. The plugin can then obey TOR_PT_EXIT_ON_STDIN_CLOSE=1,
// notice that its stdin has closed, and exit gracefully.
//
// TOR_PT_EXIT_ON_STDIN_CLOSE:
// https://bugs.torproject.org/15435
package main

import (
	"io"
	"log"
	"os"
	"os/exec"
)

func main() {
	args := os.Args[1:]
	if len(args) < 1 {
		log.Fatalf("%s needs a command to run", os.Args[0])
	}
	err := os.Setenv("TOR_PT_EXIT_ON_STDIN_CLOSE", "1")
	if err != nil {
		log.Fatal(err)
	}
	cmd := exec.Command(args[0], args[1:]...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		log.Fatal(err)
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Start()
	if err != nil {
		log.Fatal(err)
	}
	io.Copy(stdin, os.Stdin)
	err = cmd.Wait()
	if err != nil {
		log.Fatal(err)
	}
}
