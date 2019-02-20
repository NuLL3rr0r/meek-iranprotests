// This code has to do with the native manifest of the meek-http-helper
// WebExtension. The native manifest contains the path to the native executable
// that the WebExtension runs via the native messaging API.
//
// https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Native_messaging#App_manifest

package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
)

// These values need to match the ones in the webextension directory.
const (
	// https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/WebExtensions_and_the_Add-on_ID
	addOnID = "meek-http-helper@bamsoftware.com"
	// This needs to match the value passed to runtime.connectNative in the
	// JavaScript code.
	nativeAppName = "meek.http.helper"
)

// https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Native_manifests#Native_messaging_manifests
type nativeManifestJSON struct {
	Name              string   `json:"name"`
	Description       string   `json:"description"`
	Path              string   `json:"path"`
	Type              string   `json:"type"`
	AllowedExtensions []string `json:"allowed_extensions"`
}

// manifestDir is the directory of the eventual meek.http.helper.json file (the
// manifest itself). nativePath is the path to the native executable that is
// stored inside the manifest.
func writeNativeManifestToFile(manifestDir, nativePath string) error {
	// "On Windows, this may be relative to the manifest itself. On OS X and
	// Linux it must be absolute."
	absNativePath, err := filepath.Abs(nativePath)
	if err != nil {
		return err
	}
	manifest := nativeManifestJSON{
		Name:              nativeAppName,
		Description:       "Native half of meek-http-helper.",
		Path:              absNativePath,
		Type:              "stdio",
		AllowedExtensions: []string{"meek-http-helper@bamsoftware.com"},
	}

	err = os.MkdirAll(manifestDir, 0755)
	if err != nil {
		return err
	}
	// First we'll write the new manifest into a temporary file.
	tmpFile, err := ioutil.TempFile(manifestDir, nativeAppName+".json.tmp.")
	if err != nil {
		return err
	}
	// Write the JSON to the temporary file and rename it to the
	// destination. Wrapped in a lambda to allow early return in case of
	// error.
	err = func() error {
		err = json.NewEncoder(tmpFile).Encode(manifest)
		if err != nil {
			return err
		}
		err = tmpFile.Close()
		if err != nil {
			return err
		}
		return os.Rename(tmpFile.Name(), filepath.Join(manifestDir, nativeAppName+".json"))
	}()
	// If any error occurred during write/close/rename, try to remove the
	// temporary file.
	if err != nil {
		err := os.Remove(tmpFile.Name())
		// Log this error but otherwise ignore it.
		if err != nil {
			log.Print(err)
		}
	}
	return err
}
