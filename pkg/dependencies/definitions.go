package dependencies

import (
	"github.com/Masterminds/semver"
	"github.com/pkg/errors"
)

type Dependencies map[Key]*Dependency

var Default Dependencies

func init() {
	setDefaults()
}

func setDefaults() {
	deps, err := Define([]Key{
		CLANG,
		CMAKE,
		LLVM_COV,
		LLVM_PROFDATA,
		LLVM_SYMBOLIZER,
	})

	if err != nil {
		panic("Unable to define default dependencies")
	}
	Default = deps
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
		GetVersion: clangVersion,
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
			return llvmVersion(path, dep)
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
			return dep.checkFinder(dep.finder.LLVMProfDataPath)
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
			return llvmVersion(path, dep)
		},
		Installed: func(dep *Dependency) bool {
			return dep.checkFinder(dep.finder.LLVMSymbolizerPath)
		},
	},
}
