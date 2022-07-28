// Embed the installation bundle if the installer is getting built.
// The installation bundle should only be present temporarily while building the installer.
// It is not possible to embed an empty bundle directory.

//go:build installer

package embed

import "embed"

//go:embed bundle
var Bundle embed.FS
