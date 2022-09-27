package testutil

import (
	"fmt"
	"path/filepath"
	"runtime"

	"github.com/otiai10/copy"
	"github.com/pkg/errors"
)

// BootstrapExampleProjectForTest copies the given example project to a temporary folder
// and changes into that directory.
func BootstrapExampleProjectForTest(prefix, exampleName string) (tempDir string, cleanup func()) { //nolint:nonamedreturns
	tempDir, cleanup = ChdirToTempDir(prefix)

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		panic("runtime.Caller failed")
	}

	basepath := filepath.Dir(thisFile)
	examplePath := filepath.Join(basepath, "..", "..", "examples", exampleName)

	err := copy.Copy(examplePath, tempDir)
	if err != nil {
		panic(fmt.Sprintf("copying %v to %v failed: %+v", examplePath, tempDir, errors.WithStack(err)))
	}

	return tempDir, cleanup
}
