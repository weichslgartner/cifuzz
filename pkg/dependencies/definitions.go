package dependencies

import (
	"github.com/Masterminds/semver"
	"github.com/pkg/errors"

	"code-intelligence.com/cifuzz/pkg/log"
)

type Dependencies map[Key]*Dependency

var CMakeDeps Dependencies
var MavenDeps Dependencies
var GradleDeps Dependencies

func init() {
	setDefaults()
}

func setDefaults() {
	cmakeDeps, err := Define([]Key{
		CLANG,
		CMAKE,
		LLVM_COV,
		LLVM_PROFDATA,
		LLVM_SYMBOLIZER,
	})
	if err != nil {
		panic("Unable to define cmake dependencies")
	}
	CMakeDeps = cmakeDeps

	mavenDeps, err := Define([]Key{
		JAVA,
		MAVEN,
	})
	if err != nil {
		panic("Unable to define maven dependencies")
	}
	MavenDeps = mavenDeps

	gradleDeps, err := Define([]Key{
		JAVA,
		GRADLE,
	})
	if err != nil {
		panic("Unable to define gradle dependencies")
	}
	GradleDeps = gradleDeps
}

func ResetDefaultsForTestsOnly() {
	setDefaults()
}

// Defines a set of dependencies
func Define(keys []Key) (Dependencies, error) {
	deps := Dependencies{}
	for _, key := range keys {
		if dep, found := all[key]; found {
			// make a copy of the dependency to be able to modify it
			// without side effects, for example in tests
			newDep := dep
			deps[key] = &newDep
			continue
		}
		return nil, errors.Errorf("Unknown dependency %s", key)
	}
	return deps, nil
}

// List of all known dependencies
var all = map[Key]Dependency{
	CLANG: {
		Key:        CLANG,
		MinVersion: *semver.MustParse("11.0.0"),
		GetVersion: func(dep *Dependency) (*semver.Version, error) {
			return clangVersion(dep, clangCheck)
		},
		Installed: func(dep *Dependency) bool {
			return dep.checkFinder(dep.finder.ClangPath)
		},
	},
	CMAKE: {
		Key:        CMAKE,
		MinVersion: *semver.MustParse("3.16.0"),
		GetVersion: cmakeVersion,
		Installed: func(dep *Dependency) bool {
			return dep.checkFinder(dep.finder.CMakePath)
		},
	},
	LLVM_COV: {
		Key:        LLVM_COV,
		MinVersion: *semver.MustParse("11.0.0"),
		GetVersion: func(dep *Dependency) (*semver.Version, error) {
			path, err := dep.finder.LLVMCovPath()
			if err != nil {
				return nil, err
			}
			version, err := llvmVersion(path, dep)
			if err != nil {
				return nil, err
			}
			log.Debugf("Found llvm-cov version %s in PATH: %s", version, path)
			return version, nil
		},
		Installed: func(dep *Dependency) bool {
			return dep.checkFinder(dep.finder.LLVMCovPath)
		},
	},
	LLVM_PROFDATA: {
		Key: LLVM_PROFDATA,
		// llvm-profdata provides no version information
		MinVersion: *semver.MustParse("0.0.0"),
		GetVersion: func(dep *Dependency) (*semver.Version, error) {
			return semver.NewVersion("0.0.0")
		},
		Installed: func(dep *Dependency) bool {
			path, err := dep.finder.LLVMProfDataPath()
			if err != nil {
				return false
			}
			log.Debugf("Found llvm-profdata in PATH: %s", path)
			return true
		},
	},
	LLVM_SYMBOLIZER: {
		Key:        LLVM_SYMBOLIZER,
		MinVersion: *semver.MustParse("11.0.0"),
		GetVersion: func(dep *Dependency) (*semver.Version, error) {
			path, err := dep.finder.LLVMSymbolizerPath()
			if err != nil {
				return nil, err
			}
			version, err := llvmVersion(path, dep)
			if err != nil {
				return nil, err
			}
			log.Debugf("Found llvm-symbolizer version %s in PATH: %s", version, path)
			return version, nil
		},
		Installed: func(dep *Dependency) bool {
			return dep.checkFinder(dep.finder.LLVMSymbolizerPath)
		},
	},
	JAVA: {
		Key:        JAVA,
		MinVersion: *semver.MustParse("8.0.0"),
		GetVersion: javaVersion,
		Installed: func(dep *Dependency) bool {
			return dep.checkFinder(dep.finder.JavaHomePath)
		},
	},
	MAVEN: {
		Key:        MAVEN,
		MinVersion: *semver.MustParse("0.0.0"),
		GetVersion: func(dep *Dependency) (*semver.Version, error) {
			return semver.NewVersion("0.0.0")
		},
		Installed: func(dep *Dependency) bool {
			return dep.checkFinder(dep.finder.MavenPath)
		},
	},
	GRADLE: {
		Key:        GRADLE,
		MinVersion: *semver.MustParse("0.0.0"),
		GetVersion: func(dep *Dependency) (*semver.Version, error) {
			return semver.NewVersion("0.0.0")
		},
		Installed: func(dep *Dependency) bool {
			return dep.checkFinder(dep.finder.GradlePath)
		},
	},
}
