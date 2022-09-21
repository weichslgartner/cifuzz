package testutil

import (
	"path/filepath"
	"runtime"

	"github.com/otiai10/copy"
	"github.com/pkg/errors"

	"code-intelligence.com/cifuzz/util/testutil"
)

// BootstrapExampleProjectForTest copies the given example project to a temporary folder
// and changes into that directory.
func BootstrapExampleProjectForTest(prefix, exampleName string) (string, error) {
	target := testutil.ChdirToTempDir(prefix)

	if _, thisFile, _, ok := runtime.Caller(0); ok {
		basepath := filepath.Dir(thisFile)
		examplePath := filepath.Join(basepath, "..", "..", "examples", exampleName)

		if err := copy.Copy(examplePath, target); err != nil {
			return "", errors.WithStack(err)
		}
		return target, nil
	}

	return "", errors.Errorf("Unable to clone example %s project", exampleName)
}
