package testutil

import (
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"runtime"

	"code-intelligence.com/cifuzz/pkg/install"
	"code-intelligence.com/cifuzz/util/fileutil"
)

// RegisterTestDeps ensures that the test calling this function is rerun (despite caching) if any of the files and
// directories (and their recursive contents) under the provided paths change.
func RegisterTestDeps(path ...string) {
	// Workaround for https://github.com/golang/go/issues/53053
	// Explicitly stat all data dirs and files so that the Go test runner picks up the data dependency and knows how to
	// rerun the test if the data dir contents change. Without this explicit recursive walk, changes to files in
	// subdirectories aren't picked up automatically.
	for _, p := range path {
		err := filepath.Walk(p, func(path string, info fs.FileInfo, err error) error {
			if err != nil {
				return err
			}
			_, err = os.Stat(path)
			return err
		})
		if err != nil {
			panic(err)
		}
	}
}

// RegisterTestDepOnCIFuzz registers test dependencies on the cifuzz
// executable and all its dependencies. Go doesn't recognize those
// dependencies on its own in tests which build and execute cifuzz as an
// external command.
func RegisterTestDepOnCIFuzz() {
	var deps []string
	_, b, _, _ := runtime.Caller(0)
	// Note: The number of levels we go up here has to be adjusted if
	// this source file is moved.
	basepath := filepath.Dir(filepath.Dir(filepath.Dir(b)))
	for _, dep := range install.Deps {
		deps = append(deps, filepath.Join(basepath, dep))
	}
	RegisterTestDeps(deps...)
}

// ChdirToTempDir creates and changes the working directory to new tmp dir
func ChdirToTempDir(prefix string) string {
	testTempDir, err := os.MkdirTemp("", prefix)
	if err != nil {
		log.Printf("Failed to create temp dir for tests: %+v", err)
		os.Exit(1)
	}

	err = os.Chdir(testTempDir)
	if err != nil {
		log.Printf("Failed to change working dir for tests: %+v", err)
		fileutil.Cleanup(testTempDir)
		os.Exit(1)
	}

	return testTempDir
}
