// The WebExtension browser–app protocol uses native-endian length prefixes :/
// https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Native_messaging#App_side

package main

import "encoding/binary"

var nativeEndian = binary.LittleEndian
