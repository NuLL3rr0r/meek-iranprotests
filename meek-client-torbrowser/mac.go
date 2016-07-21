// +build darwin
// This file is compiled only on mac. It contains paths used by the mac
// browser bundle.
// http://golang.org/pkg/go/build/#hdr-Build_Constraints

package main

const (
	// During startup of meek-client-torbrowser, the browser profile is
	// created and maintained under firefoxProfilePath by making a
	// recursive copy of everything under profileTemplatePath.
	// https://bugs.torproject.org/18904
	firefoxPath         = "../firefox"
	firefoxProfilePath  = "../../../../TorBrowser-Data/Tor/PluggableTransports/profile.meek-http-helper"
	profileTemplatePath = "../../Resources/TorBrowser/Tor/PluggableTransports/template-profile.meek-http-helper"
)
