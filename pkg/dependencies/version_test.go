package dependencies

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/Masterminds/semver"
	"github.com/stretchr/testify/require"
)

type versionTest struct {
	Want   *semver.Version
	Regex  *regexp.Regexp
	Output string
}

var tests = []versionTest{
	// ---cmake
	{
		Want:  semver.MustParse("3.24.1"),
		Regex: cmakeRegex,
		Output: `cmake version 3.24.1

CMake suite maintained and supported by Kitware (kitware.com/cmake).`,
	},
	{
		Want:   semver.MustParse("3.21.0"),
		Regex:  cmakeRegex,
		Output: `cmake version 3.21.0`,
	},
	// ---clang
	{
		Want:  semver.MustParse("14.0.6"),
		Regex: clangRegex,
		Output: `clang version 14.0.6
Target: x86_64-pc-linux-gnu
Thread model: posix
InstalledDir: /usr/sbin`,
	},
	{
		Want:  semver.MustParse("14.0.6"),
		Regex: clangRegex,
		Output: `Debian clang version 14.0.6-2
Target: x86_64-pc-linux-gnu
Thread model: posix
InstalledDir: /usr/bin`,
	},
	{
		Want:   semver.MustParse("14.0.0"),
		Regex:  clangRegex,
		Output: `foobar clang version 14.0-special`,
	},
	// ---llvm-symbolizer
	{
		Want:  semver.MustParse("14.0.6"),
		Regex: llvmRegex,
		Output: `llvm-symbolizer
LLVM (http://llvm.org/):
  LLVM version 14.0.6
  Optimized build.
  Default target: x86_64-pc-linux-gnu
  Host CPU: znver3`,
	},
	{
		Want:  semver.MustParse("14.0.6"),
		Regex: llvmRegex,
		Output: `llvm-symbolizer
Debian LLVM version 14.0.6

  Optimized build.
  Default target: x86_64-pc-linux-gnu
  Host CPU: skylake`,
	},
}

func TestVersionParsing(t *testing.T) {
	for i, test := range tests {
		key := Key(fmt.Sprintf("version-test-%d", i))
		version, err := extractVersion(test.Output, test.Regex, key)
		require.NoError(t, err)
		require.True(t, version.Equal(test.Want),
			"%s: expected version %s, got %s", key, test.Want.String(), version.String())
	}
}
