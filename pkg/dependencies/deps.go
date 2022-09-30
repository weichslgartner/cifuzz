package dependencies

import (
	"github.com/Masterminds/semver"
	"github.com/pkg/errors"

	"code-intelligence.com/cifuzz/pkg/log"
	"code-intelligence.com/cifuzz/pkg/runfiles"
)

type Key string

const (
	CLANG           Key = "clang"
	CMAKE           Key = "cmake"
	LLVM_COV        Key = "llvm-cov"
	LLVM_SYMBOLIZER Key = "llvm-symbolizer"
	LLVM_PROFDATA   Key = "llvm-profdata"

	MAVEN  Key = "mvn"
	GRADLE Key = "gradle"

	MESSAGE_VERSION = "cifuzz requires %s %s or higher, have %s"
	MESSAGE_MISSING = "cifuzz requires %s, but it is not installed"
)

// Dependency represents a single dependency
type Dependency struct {
	finder runfiles.RunfilesFinder

	Key        Key
	MinVersion semver.Version
	// these fields are used to implement custom logic to
	// retrieve version or installation information for the
	// specific dependency
	GetVersion func(*Dependency) (*semver.Version, error)
	Installed  func(*Dependency) bool
}

// Compares MinVersion against GetVersion
func (dep *Dependency) CheckVersion() bool {
	currentVersion, err := dep.GetVersion(dep)
	if err != nil {
		log.Warnf("Unable to get current version for %s, message: %v", dep.Key, err)
		// we want to be lenient if we were not able to extract the version
		return true
	}

	if currentVersion.Compare(&dep.MinVersion) == -1 {
		log.Warnf(MESSAGE_VERSION, dep.Key, dep.MinVersion.String(), currentVersion.String())
		return false
	}
	return true
}

func (dep *Dependency) Ok() bool {
	if !dep.Installed(dep) {
		log.Warnf(MESSAGE_MISSING, dep.Key)
		return false
	}

	if !dep.CheckVersion() {
		return false
	}

	return true
}

// helper to easily check against functions from the runfiles.RunfilesFinder interface
func (dep *Dependency) checkFinder(finderFunc func() (string, error)) bool {
	if _, err := finderFunc(); err != nil {
		return false
	}
	return true
}

// Iterates of a list of dependencies and checks if they are fulfilled
func Check(keys []Key, deps Dependencies, finder runfiles.RunfilesFinder) (bool, error) {
	allFine := true
	for _, key := range keys {
		dep, found := deps[key]
		if !found {
			return false, errors.Errorf("Undefined dependency %s", key)
		}

		dep.finder = finder

		if dep.MinVersion.Equal(semver.MustParse("0.0.0")) {
			log.Debugf("Checking dependency: %s ", dep.Key)
		} else {
			log.Debugf("Checking dependency: %s version >= %s", dep.Key, dep.MinVersion.String())
		}

		if !dep.Ok() {
			allFine = false
		}
	}
	return allFine, nil
}
