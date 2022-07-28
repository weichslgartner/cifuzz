// Embed an empty file system if the installer is not getting built.
// The installation bundle should only be present temporarily while building the installer.
// It is not possible to embed an empty bundle directory.

//go:build !installer

package embed

import "embed"

var Bundle embed.FS
