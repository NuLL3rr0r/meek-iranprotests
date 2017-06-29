// meek-client-torbrowser is an auxiliary program that helps with connecting
// meek-client to meek-http-helper running in Tor Browser.
//
// Sample usage in torrc (exact paths depend on platform):
// 	ClientTransportPlugin meek exec ./meek-client-torbrowser --log meek-client-torbrowser.log -- ./meek-client --url=https://meek-reflect.appspot.com/ --front=www.google.com --log meek-client.log
// Everything up to "--" is options for this program. Everything following it is
// a meek-client command line. The command line for running firefox is implicit
// and hardcoded in this program.
//
// This program, meek-client-torbrowser, starts a copy of firefox under the
// meek-http-helper profile, which must have configured the meek-http-helper
// extension. This program reads the stdout of firefox, looking for a special
// line with the listening port number of the extension, one that looks like
// "meek-http-helper: listen <address>". The meek-client command is then
// executed as given, except that a --helper option is added that points to the
// port number read from firefox.
//
// This program proxies stdin and stdout to and from meek-client, so it is
// actually meek-client that drives the pluggable transport negotiation with
// tor.
package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

// This magic string is emitted by meek-http-helper.
var helperAddrPattern = regexp.MustCompile(`^meek-http-helper: listen (127\.0\.0\.1:\d+)$`)

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [meek-client-torbrowser args] -- meek-client [meek-client args]\n", os.Args[0])
	flag.PrintDefaults()
}

// Log a call to os.Process.Kill.
func logKill(p *os.Process) error {
	log.Printf("killing PID %d", p.Pid)
	err := p.Kill()
	if err != nil {
		log.Print(err)
	}
	return err
}

// Log a call to os.Process.Signal.
func logSignal(p *os.Process, sig os.Signal) error {
	log.Printf("sending signal %s to PID %d", sig, p.Pid)
	err := p.Signal(sig)
	if err != nil {
		log.Print(err)
	}
	return err
}

func copyFile(srcPath string, mode os.FileMode, destPath string) error {
	inFile, err := os.Open(srcPath)
	if err != nil {
		return err
	}

	defer inFile.Close()
	outFile, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}

	// Always close the destination file before returning.
	defer func() {
		closeErr := outFile.Close()
		if err == nil {
			err = closeErr
		}
	}()

	if _, err = io.Copy(outFile, inFile); err != nil {
		return err
	}
	err = outFile.Sync()
	return err
}

// Make sure that the browser profile exists. If profileTemplatePath is not
// empty, the profile is created and maintained by making a recursive copy of
// all the files and directories under profileTemplatePath. A safe copy is
// done by first copying the profile files into a temporary directory and
// then doing an atomic rename of the temporary directory as the last step.
// To ensure that the profile is up-to-date with respect to the template
// (e.g., after Tor Browser has been updated), the contents of the file
// meek-template-sha256sum.txt within the profile are compared with the
// corresponding template file; if they differ, the profile is deleted and
// recreated.
func prepareBrowserProfile(profilePath string) error {
	_, err := os.Stat(profilePath)
	profileExists := err == nil || os.IsExist(err)

	// If profileTemplatePath is not set, we are running on a platform that
	// expects the profile to already exist.
	if profileTemplatePath == "" {
		if profileExists {
			return nil
		}
		return err
	}

	if profileExists {
		if isBrowserProfileUpToDate(profileTemplatePath, profilePath) {
			return nil
		}

		// Remove outdated meek helper profile.
		log.Printf("removing outdated profile at %s\n", profilePath)
		err = os.RemoveAll(profilePath)
		if err != nil {
			return err
		}
	}

	log.Printf("creating profile by copying files from %s to %s\n", profileTemplatePath, profilePath)
	profileParentPath := filepath.Dir(profilePath)
	err = os.MkdirAll(profileParentPath, os.ModePerm)
	if err != nil {
		return err
	}

	tmpPath, err := ioutil.TempDir(profileParentPath, "tmpMeekProfile")
	if err != nil {
		return err
	}

	err = os.MkdirAll(tmpPath, os.ModePerm)
	if err != nil {
		return err
	}

	// Remove the temporary directory before returning.
	defer func() {
		os.RemoveAll(tmpPath)
	}()

	templatePath, err := filepath.Abs(profileTemplatePath)
	if err != nil {
		return err
	}

	visit := func(path string, info os.FileInfo, err error) error {
		relativePath := strings.TrimPrefix(path, templatePath)
		if relativePath == "" {
			return nil // skip the root directory
		}

		// If relativePath is a directory, create it; if it is a file, copy it.
		destPath := filepath.Join(tmpPath, relativePath)
		if info.IsDir() {
			err = os.MkdirAll(destPath, info.Mode())
		} else {
			err = copyFile(path, info.Mode(), destPath)
		}

		return err
	}

	err = filepath.Walk(templatePath, visit)
	if err != nil {
		return err
	}

	return os.Rename(tmpPath, profilePath)
}

// Return true if the profile is up-to-date with the template.
func isBrowserProfileUpToDate(templatePath string, profilePath string) bool {
	checksumFileName := "meek-template-sha256sum.txt"
	templateChecksumPath := filepath.Join(templatePath, checksumFileName)
	templateData, err := ioutil.ReadFile(templateChecksumPath)
	if err != nil {
		return false
	}
	profileChecksumPath := filepath.Join(profilePath, checksumFileName)
	profileData, err := ioutil.ReadFile(profileChecksumPath)
	if err != nil {
		return false
	}

	return bytes.Equal(templateData, profileData)
}

// Run firefox and return its exec.Cmd and stdout pipe.
func runFirefox() (cmd *exec.Cmd, stdout io.Reader, err error) {
	// Mac OS X needs absolute paths for firefox and for the profile.
	var absFirefoxPath string
	absFirefoxPath, err = filepath.Abs(firefoxPath)
	if err != nil {
		return
	}
	var profilePath string
	var torDataDir = os.Getenv("TOR_BROWSER_TOR_DATA_DIR")
	if torDataDir != "" && torDataDirFirefoxProfilePath != "" {
		profilePath = filepath.Join(torDataDir, torDataDirFirefoxProfilePath)
	} else {
		profilePath, err = filepath.Abs(firefoxProfilePath)
		if err != nil {
			return
		}
	}
	err = prepareBrowserProfile(profilePath)
	if err != nil {
		return
	}

	cmd = exec.Command(absFirefoxPath, "--invisible", "-no-remote", "-profile", profilePath)
	osSpecificCommandSetup(cmd)
	cmd.Stderr = os.Stderr
	stdout, err = cmd.StdoutPipe()
	if err != nil {
		return
	}
	log.Printf("running firefox command %q", cmd.Args)
	err = cmd.Start()
	if err != nil {
		return
	}
	log.Printf("firefox started with pid %d", cmd.Process.Pid)
	return cmd, stdout, nil
}

// Look for the magic meek-http-helper address string in the Reader, and return
// the address it contains. Start a goroutine to continue reading and discarding
// output of the Reader before returning.
func grepHelperAddr(r io.Reader) (string, error) {
	var helperAddr string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if m := helperAddrPattern.FindStringSubmatch(line); m != nil {
			helperAddr = m[1]
			break
		}
	}
	err := scanner.Err()
	if err != nil {
		return "", err
	}
	// Ran out of input before finding the pattern.
	if helperAddr == "" {
		return "", io.EOF
	}
	// Keep reading from the browser to avoid its output buffer filling.
	go io.Copy(ioutil.Discard, r)
	return helperAddr, nil
}

// Run meek-client and return its exec.Cmd.
func runMeekClient(helperAddr string, meekClientCommandLine []string) (cmd *exec.Cmd, err error) {
	meekClientPath := meekClientCommandLine[0]
	args := meekClientCommandLine[1:]
	args = append(args, []string{"--helper", helperAddr}...)
	cmd = exec.Command(meekClientPath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	log.Printf("running meek-client command %q", cmd.Args)
	err = cmd.Start()
	if err != nil {
		return
	}
	log.Printf("meek-client started with pid %d", cmd.Process.Pid)
	return cmd, nil
}

func main() {
	var logFilename string

	flag.Usage = usage
	flag.StringVar(&logFilename, "log", "", "name of log file")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.LUTC)
	if logFilename != "" {
		f, err := os.OpenFile(logFilename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		log.SetOutput(f)
	}

	// By default, writes to file descriptor 1 and 2 when the descriptor has
	// been closed will terminate the program with a SIGPIPE signal. This is
	// a problem because the default log destination is stderr (file
	// descriptor 2). When the parent process (tor) terminates and closes
	// its stderr, any attempt to log will cause us to die, before we can do
	// our own cleanup. Therefore ignore SIGPIPE, causing writes to a closed
	// stderr to return syscall.EPIPE rather than terminate.
	// https://golang.org/pkg/os/signal/#hdr-SIGPIPE
	// https://bugs.torproject.org/20030#comment:6
	signal.Notify(make(chan os.Signal, 1), syscall.SIGPIPE)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM)

	// Unset environment variables that Firefox sets after a restart (as
	// caused by, for example, an update or the installation of an add-on).
	// XRE_PROFILE_PATH, in particular, overrides the -profile option that
	// runFirefox sets, causing Firefox to run with profile.default instead
	// of profile.meek-http-helper, which conflicts with the profile.default
	// that is already running. See https://bugs.torproject.org/13247,
	// particularly #comment:17 and #comment:18. The environment variable
	// names come from
	// https://hg.mozilla.org/mozilla-central/file/cfde3603b020/toolkit/xre/nsAppRunner.cpp#l3941
	var firefoxRestartEnvVars = []string{
		"XRE_PROFILE_PATH",
		"XRE_PROFILE_LOCAL_PATH",
		"XRE_PROFILE_NAME",
		"XRE_START_OFFLINE",
		"NO_EM_RESTART",
		"XUL_APP_FILE",
		"XRE_BINARY_PATH",
	}
	for _, varname := range firefoxRestartEnvVars {
		err := os.Unsetenv(varname)
		if err != nil {
			log.Fatal(err)
		}
	}

	// Start firefox.
	firefoxCmd, stdout, err := runFirefox()
	if err != nil {
		log.Print(err)
		return
	}
	defer logKill(firefoxCmd.Process)

	// Find out the helper's listening address.
	helperAddr, err := grepHelperAddr(stdout)
	if err != nil {
		log.Print(err)
		return
	}

	// Start meek-client with the helper address.
	meekClientCmd, err := runMeekClient(helperAddr, flag.Args())
	if err != nil {
		log.Print(err)
		return
	}
	defer logKill(meekClientCmd.Process)

	if os.Getenv("TOR_PT_EXIT_ON_STDIN_CLOSE") == "1" {
		// This environment variable means we should treat EOF on stdin
		// just like SIGTERM: https://bugs.torproject.org/15435.
		go func() {
			io.Copy(ioutil.Discard, os.Stdin)
			log.Printf("synthesizing SIGTERM because of stdin close")
			sigChan <- syscall.SIGTERM
		}()
	}

	sig := <-sigChan
	log.Printf("sig %s", sig)
	err = logSignal(meekClientCmd.Process, sig)
	if err != nil {
		log.Print(err)
	}

	// If SIGINT, wait for a second SIGINT.
	if sig == syscall.SIGINT {
		sig := <-sigChan
		log.Printf("sig %s", sig)
		err = logSignal(meekClientCmd.Process, sig)
		if err != nil {
			log.Print(err)
		}
	}
}
