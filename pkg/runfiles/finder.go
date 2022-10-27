package runfiles

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/pkg/errors"
)

type RunfilesFinderImpl struct {
	InstallDir string
}

func (f RunfilesFinderImpl) CIFuzzIncludePath() (string, error) {
	return f.findFollowSymlinks("share/cifuzz/include/cifuzz")
}

func (f RunfilesFinderImpl) ClangPath() (string, error) {
	path, err := exec.LookPath("clang")
	return path, errors.WithStack(err)
}

func (f RunfilesFinderImpl) CMakePath() (string, error) {
	path, err := exec.LookPath("cmake")
	return path, errors.WithStack(err)
}

func (f RunfilesFinderImpl) CMakePresetsPath() (string, error) {
	return f.findFollowSymlinks("share/cifuzz/share/CMakePresets.json")
}

func (f RunfilesFinderImpl) LLVMCovPath() (string, error) {
	path, err := exec.LookPath("llvm-cov")
	return path, errors.WithStack(err)
}

func (f RunfilesFinderImpl) LLVMProfDataPath() (string, error) {
	path, err := exec.LookPath("llvm-profdata")
	return path, errors.WithStack(err)
}

func (f RunfilesFinderImpl) LLVMSymbolizerPath() (string, error) {
	path, err := exec.LookPath("llvm-symbolizer")
	return path, errors.WithStack(err)
}

func (f RunfilesFinderImpl) JavaPath() (string, error) {
	os.LookupEnv("JAVA_HOME")
	path, err := exec.LookPath("java")
	return path, errors.WithStack(err)
}

func (f RunfilesFinderImpl) MavenPath() (string, error) {
	path, err := exec.LookPath("mvn")
	return path, errors.WithStack(err)
}

func (f RunfilesFinderImpl) GradlePath() (string, error) {
	path, err := exec.LookPath("gradle")
	return path, errors.WithStack(err)
}

func (f RunfilesFinderImpl) Minijail0Path() (string, error) {
	return f.findFollowSymlinks("bin/minijail0")
}

func (f RunfilesFinderImpl) ProcessWrapperPath() (string, error) {
	return f.findFollowSymlinks("lib/process_wrapper")
}

func (f RunfilesFinderImpl) ReplayerSourcePath() (string, error) {
	return f.findFollowSymlinks("share/cifuzz/src/replayer.c")
}

func (f RunfilesFinderImpl) VSCodeTasksPath() (string, error) {
	return f.findFollowSymlinks("share/cifuzz/share/tasks.json")
}

func (f RunfilesFinderImpl) LogoPath() (string, error) {
	return f.findFollowSymlinks("share/cifuzz/share/logo.png")
}

func (f RunfilesFinderImpl) GradleClasspathScriptPath() (string, error) {
	return f.findFollowSymlinks("share/cifuzz/share/classpath.gradle")
}

// JavaHomePath returns the absolute path to the base directory of the
// default system JDK/JRE. It first looks up JAVA_HOME and then falls back to
// using the java binary in the PATH.
func (f RunfilesFinderImpl) JavaHomePath() (string, error) {
	javaHome := os.Getenv("JAVA_HOME")
	if javaHome != "" {
		return javaHome, nil
	}

	if runtime.GOOS == "darwin" {
		// On some macOS installations, an executable 'java_home' exists
		// which prints the JAVA_HOME of the default installation to stdout
		var outbuf bytes.Buffer
		cmd := exec.Command("/usr/libexec/java_home")
		cmd.Stdout = &outbuf
		err := cmd.Run()
		if err == nil {
			return strings.TrimSpace(outbuf.String()), nil
		}
	}

	javaSymlink, err := exec.LookPath("java")
	if err != nil {
		return "", errors.WithStack(err)
	}
	// The java binary in the PATH, e.g. at /usr/bin/java, is typically a
	// symlink pointing to the actual java binary in the bin subdirectory of the
	// JAVA_HOME.
	javaBinary, err := filepath.EvalSymlinks(javaSymlink)
	if err != nil {
		return "", errors.WithStack(err)
	}
	absoluteJavaBinary, err := filepath.Abs(javaBinary)
	if err != nil {
		return "", errors.WithStack(err)
	}
	return filepath.Dir(filepath.Dir(absoluteJavaBinary)), nil

}

func (f RunfilesFinderImpl) findFollowSymlinks(relativePath string) (string, error) {
	absolutePath := filepath.Join(f.InstallDir, relativePath)

	resolvedPath, err := filepath.EvalSymlinks(absolutePath)
	if err != nil {
		return "", errors.Wrapf(err, "path: %s", absolutePath)
	}
	_, err = os.Stat(resolvedPath)
	if err != nil {
		return "", errors.WithStack(err)
	}

	return resolvedPath, nil
}
