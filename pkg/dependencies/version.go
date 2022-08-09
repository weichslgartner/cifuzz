package dependencies

import (
	"fmt"
	"os/exec"
	"regexp"

	"github.com/Masterminds/semver"
	"github.com/pkg/errors"
)

/*
Note: we ignore the "patch" part of the semver (when parsing the output with regex)
be more lenient when a command returns something like 1.2 instead of 1.2.0
*/

// returns the currently installed clang version
func clangVersion(dep *Dependency) (*semver.Version, error) {
	path, err := dep.finder.ClangPath()
	if err != nil {
		return nil, err
	}

	re := regexp.MustCompile(`(?m)clang version (?P<version>\d+.\d+)$`)
	version, err := parseCommandVersionWithRegex(path, []string{"--version"}, re, dep.Key)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return version, nil
}

// helper for parsing the --version output for different llvm tools,
// for example llvm-cov, llvm-symbolizer
func llvmVersion(path string, dep *Dependency) (*semver.Version, error) {
	re := regexp.MustCompile(`(?m)\s*LLVM version (?P<version>\d+.\d+)$`)

	version, err := parseCommandVersionWithRegex(path, []string{"--version"}, re, dep.Key)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return version, nil
}

func cmakeVersion(dep *Dependency) (*semver.Version, error) {
	path, err := exec.LookPath("cmake")
	if err != nil {
		return nil, errors.WithStack(err)
	}

	re := regexp.MustCompile(`(?m)^\s*cmake version (?P<version>\d+.\d+)$`)
	version, err := parseCommandVersionWithRegex(path, []string{"--version"}, re, dep.Key)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return version, nil
}

// takes a command + args and parses the output with a given regex for a SemVer
func parseCommandVersionWithRegex(cmdPath string, args []string, re *regexp.Regexp, key Key) (*semver.Version, error) {
	cmd := exec.Command(cmdPath, args...)
	output, err := cmd.Output()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	result := re.FindStringSubmatch(string(output))
	if len(result) <= 1 {
		return nil, fmt.Errorf("No matching version string for %s", key)
	}

	version, err := semver.NewVersion(result[1])
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return version, nil
}
