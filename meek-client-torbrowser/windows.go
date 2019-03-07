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
	registryKey                = `SOFTWARE\Mozilla\NativeMessagingHosts\` + nativeAppName
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

	// On Windows we must set a registry key pointing to the host manifest.
	// We'll attempt to delete the key in uninstallHelperNativeManifest.
	// https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Native_manifests#Windows
	k, _, err := registry.CreateKey(registry.CURRENT_USER, registryKey, registry.WRITE)
	if err != nil {
		return err
	}
	return k.SetStringValue("", absManifestPath)
}

func uninstallHelperNativeManifest() error {
	// Delete the registry key pointing to the host manifest. We don't
	// delete any higher up the tree; e.g. an empty
	// HKEY_CURRENT_USER\SOFTWARE\Mozilla\NativeMessagingHosts will remain
	// even if it was not present before installHelperNativeManifest was
	// called.
	return registry.DeleteKey(registry.CURRENT_USER, registryKey)
}
