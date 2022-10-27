package runfiles

import (
	"os"
	"path/filepath"

	"github.com/pkg/errors"
)

type RunfilesFinder interface {
	CIFuzzIncludePath() (string, error)
	ClangPath() (string, error)
	CMakePath() (string, error)
	CMakePresetsPath() (string, error)
	LLVMCovPath() (string, error)
	LLVMProfDataPath() (string, error)
	LLVMSymbolizerPath() (string, error)
	Minijail0Path() (string, error)
	ProcessWrapperPath() (string, error)
	ReplayerSourcePath() (string, error)
	VSCodeTasksPath() (string, error)
	LogoPath() (string, error)
	MavenPath() (string, error)
	GradlePath() (string, error)
	GradleClasspathScriptPath() (string, error)
	JavaHomePath() (string, error)
}

var Finder RunfilesFinder

func init() {
	// Set the default runfiles finder.
	//
	// If the environment variable CIFUZZ_INSTALL_ROOT is set, we use
	// that as the installation directory, else we assume that the
	// current executable lives in $INSTALL_DIR/bin, so we go up one
	// directory from there and use that as the installation directory.
	installDir, found := os.LookupEnv("CIFUZZ_INSTALL_ROOT")
	if !found || installDir == "" {
		executablePath, err := os.Executable()
		if err != nil {
			panic(errors.WithStack(err))
		}

		installDir, err = filepath.Abs(filepath.Join(filepath.Dir(executablePath), ".."))
		if err != nil {
			panic(errors.WithStack(err))
		}
	}

	Finder = RunfilesFinderImpl{InstallDir: installDir}
}
