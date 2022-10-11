package generator

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/otiai10/copy"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"code-intelligence.com/cifuzz/internal/builder"
	"code-intelligence.com/cifuzz/internal/testutil"
	"code-intelligence.com/cifuzz/pkg/mocks"
)

func TestMain(m *testing.M) {
	viper.Set("verbose", false)

	m.Run()
}

func TestLLVM(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	testCases := map[string]struct {
		format string
	}{
		"lcov": {
			format: "lcov",
		},
		"html": {
			format: "html",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			cwd, err := os.Getwd()
			require.NoError(t, err)
			testdataDir := filepath.Join(cwd, "testdata", "llvm")
			testutil.RegisterTestDeps(testdataDir)

			// get path to shared include
			repoRoot, err := builder.FindProjectDir()
			require.NoError(t, err)
			includePath := filepath.Join(repoRoot, "tools", "cmake", "cifuzz", "include", "cifuzz")

			tmpDir, cleanup := testutil.ChdirToTempDir("llvm-coverage-gen")
			defer cleanup()

			// copy testdata project to tmp directory
			err = copy.Copy(testdataDir, tmpDir)
			require.NoError(t, err)

			// mock finderMock to use include dir from repository
			finderMock := &mocks.RunfilesFinderMock{}
			finderMock.On("CIFuzzIncludePath").Return(includePath, nil)
			finderMock.On("LLVMProfDataPath").Return("llvm-profdata", nil)
			finderMock.On("LLVMCovPath").Return("llvm-cov", nil)

			var bOut bytes.Buffer
			outBuf := io.Writer(&bOut)
			var bErr bytes.Buffer
			errBuf := io.Writer(&bErr)

			testLLVM := &LLVMCoverageGenerator{
				OutputFormat: tc.format,
				BuildSystem:  "other",
				BuildCommand: "make clean && make $FUZZ_TEST",
				UseSandbox:   false,
				FuzzTest:     "my_fuzz_test",
				ProjectDir:   tmpDir,
				StdOut:       outBuf,
				StdErr:       errBuf,
				finder:       finderMock,
			}

			reportPath, err := testLLVM.Generate()
			require.NoError(t, err)

			assert.FileExists(t, reportPath)
			assert.True(t, strings.HasSuffix(reportPath, tc.format))
			assert.Contains(t, bOut.String(), "src/explore_me.cpp")
			assert.Contains(t, bOut.String(), "my_fuzz_test.cpp")
		})
	}
}
