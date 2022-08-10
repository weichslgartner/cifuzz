package testutil

import (
	"path/filepath"
	"runtime"

	"github.com/otiai10/copy"
	"github.com/pkg/errors"

	"code-intelligence.com/cifuzz/util/testutil"
)

// Creates a copy of the CMake example project in a temp dir and
// change the working dir to the new path
func ChdirToClonedCmakeExampleProject(prefix string) (string, error) {
	target := testutil.ChdirToTempDir(prefix)

	if _, thisFile, _, ok := runtime.Caller(0); ok {
		basepath := filepath.Dir(thisFile)
		examplePath := filepath.Join(basepath, "..", "..", "examples", "cmake")

		if err := copy.Copy(examplePath, target); err != nil {
			return "", errors.WithStack(err)
		}
		return target, nil
	}

	return "", errors.New("Unable to clone cmake example project")
}
