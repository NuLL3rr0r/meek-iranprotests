// +build darwin
// This file is compiled only on mac. It contains paths used by the mac
// browser bundle.
// http://golang.org/pkg/go/build/#hdr-Build_Constraints

package main

import "os/exec"

const (
	// During startup of meek-client-torbrowser, the browser profile is
	// created and maintained under a meek-specific directory by making a
	// recursive copy of everything under profileTemplatePath (see
	// https://bugs.torproject.org/18904).
	// If the TOR_BROWSER_TOR_DATA_DIR env var is set, the path for the
	// meek-specific profile directory is constructed by appending
	// torDataDirFirefoxProfilePath to TOR_BROWSER_TOR_DATA_DIR. Otherwise,
	// firefoxProfilePath (a relative path) is used.
	firefoxPath                  = "../firefox"
	torDataDirFirefoxProfilePath = "PluggableTransports/profile.meek-http-helper"
	firefoxProfilePath           = "../../../../TorBrowser-Data/Tor/PluggableTransports/profile.meek-http-helper"
	profileTemplatePath          = "../../Resources/TorBrowser/Tor/PluggableTransports/template-profile.meek-http-helper"
)

func osSpecificCommandSetup(cmd *exec.Cmd) {
	// nothing
}
