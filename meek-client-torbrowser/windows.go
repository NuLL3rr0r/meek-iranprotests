// +build windows
// This file is compiled only on windows. It contains paths used by the windows
// browser bundle.
// http://golang.org/pkg/go/build/#hdr-Build_Constraints

package main

import (
	"os/exec"
	"path/filepath"

	"golang.org/x/sys/windows/registry"
)

const (
	firefoxPath                  = "./firefox.exe"
	firefoxProfilePath           = "TorBrowser/Data/Browser/profile.meek-http-helper"
	torDataDirFirefoxProfilePath = ""
	profileTemplatePath          = ""
	// The location of the host manifest doesn't matter for windows. Just
	// put it in the same place as on linux.
	// https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Native_manifests#Windows
	helperNativeManifestDir    = "TorBrowser/Data/Browser/.mozilla/native-messaging-hosts"
	helperNativeExecutablePath = "TorBrowser/Tor/PluggableTransports/meek-http-helper.exe"
)

func osSpecificCommandSetup(cmd *exec.Cmd) {
	// nothing
}

func installHelperNativeManifest() error {
	absManifestPath, err := filepath.Abs(filepath.Join(helperNativeManifestDir, nativeAppName+".json"))
	if err != nil {
		return err
	}

	err = writeNativeManifestToFile(helperNativeManifestDir, helperNativeExecutablePath)
	if err != nil {
		return err
	}

	// TODO: Find a way to do this without having to write to the registry.
	// https://bugs.torproject.org/29347#comment:9
	// https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Native_manifests#Windows
	k, _, err := registry.CreateKey(
		registry.CURRENT_USER,
		`SOFTWARE\Mozilla\NativeMessagingHosts\`+nativeAppName,
		registry.WRITE,
	)
	if err != nil {
		return err
	}
	return k.SetStringValue("", absManifestPath)
}
