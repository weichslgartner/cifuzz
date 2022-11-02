package replayer

import (
	"bytes"
	_ "embed"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"code-intelligence.com/cifuzz/internal/testutil"
	"code-intelligence.com/cifuzz/util/fileutil"
)

//go:embed src/replayer.c
var replayerSrc []byte

//go:embed testdata/fuzz_target.c
var fuzzTargetSrc []byte

type compilerCase struct {
	compiler                    string
	flags                       []string
	outputFlags                 []string
	disableFuzzerInitializeFlag string
	compileOnlyAsCppFlags       []string
}

// clang-cl is almost fully compatible with MSVC (cl.exe), but doesn't seem to support ASan and the /Za flag.
var clangCl = compilerCase{
	"clang-cl",
	[]string{
		"/W4",
		// Treat warnings as errors.
		"/WX",
		// Enable additional security warnings.
		"/sdl",
	},
	[]string{"/Fe%s"},
	"/DDISABLE_FUZZER_INITIALIZE",
	[]string{"/TP", "/c"},
}

var msvc = compilerCase{
	"cl",
	append([]string{
		// Enable additional portability checks. The even stricter /Za flag is incompatible with windows.h itself.
		"/permissive-",
		// Required when using /external with older versions of MSVC.
		"/experimental:external",
		// Disable warnings originating from system includes, which would otherwise be treated as errors.
		"/external:W0",
		"/fsanitize=address",
		// Signal to the replayer that it is being built with sanitizers.
		"-DCIFUZZ_HAS_SANITIZER",
		// Sanitizer runtimes have to be linked manually on Windows:
		// https://devblogs.microsoft.com/cppblog/addresssanitizer-asan-for-windows-with-msvc/
		"/wholearchive:clang_rt.asan-x86_64.lib",
		// Using ASan without debug symbols may result in a warning, which would be fatal due to /WX.
		"/Zi",
	}, clangCl.flags...),
	clangCl.outputFlags,
	clangCl.disableFuzzerInitializeFlag,
	clangCl.compileOnlyAsCppFlags,
}

var clang = compilerCase{
	"clang",
	[]string{
		"-Wall",
		"-Wextra",
		"-Werror",
		"-Wconversion",
		// Add debug info to make ASan and UBSan findings more useful.
		"-g",
		"-fsanitize=address,undefined",
		// Signal to the replayer that it is being built with sanitizers.
		"-DCIFUZZ_HAS_SANITIZER",
		// Make UBSan findings assertable by aborting.
		"-fsanitize-undefined-trap-on-error",
		// Disable compiler-specific extensions and use the C90 standard.
		"-ansi",
	},
	[]string{"-o", "%s"},
	"-DDISABLE_FUZZER_INITIALIZE",
	[]string{"-xc++", "-c"},
}

// MinGW lacks ASan and UBSan, but is otherwise compatible with Unix gcc.
var mingw = compilerCase{
	"gcc",
	[]string{
		"-Wall",
		"-Wextra",
		"-Wconversion",
		"-pedantic",
		"-pedantic-errors",
		"-Werror",
		"-ansi",
	},
	[]string{"-o", "%s"},
	"-DDISABLE_FUZZER_INITIALIZE",
	[]string{"-xc++", "-c"},
}

// On Unix, gcc supports ASan and UBSan.
var gcc = compilerCase{
	"gcc",
	append([]string{
		// Add debug info to make ASan and UBSan findings more useful.
		"-g",
		"-fsanitize=address,undefined",
		// Signal to the replayer that it is being built with sanitizers.
		"-DCIFUZZ_HAS_SANITIZER",
		// Make UBSan findings assertable by aborting.
		"-fsanitize-undefined-trap-on-error",
	}, mingw.flags...),
	mingw.outputFlags,
	mingw.disableFuzzerInitializeFlag,
	mingw.compileOnlyAsCppFlags,
}

type runCase struct {
	name       string
	inputs     []any
	normalExit bool
}

var baseRunCases = []runCase{
	{
		"no files",
		[]any{},
		true,
	},
	{
		"single file",
		[]any{"foo"},
		true,
	},
	{
		"multiple files",
		[]any{"foo", "bar"},
		true,
	},
	{
		"single empty directory",
		[]any{[]string{}},
		true,
	},
	{
		"single directory with single file",
		[]any{[]string{"foo"}},
		true,
	},
	{
		"single directory with multiple files",
		[]any{[]string{"foo", "bar", "baz"}},
		true,
	},
	{
		"multiple directories",
		[]any{[]string{"foo", "bar"}, []string{}, []string{"baz"}},
		true,
	},
	{
		"directories and files",
		[]any{[]string{"foo", "bar"}, "baz", []string{"baz"}, "bob"},
		true,
	},
	{
		"assert",
		[]any{"foo", "assert", "bar"},
		false,
	},
	{
		"assert in directory",
		[]any{[]string{"foo", "bar"}, []string{"assert"}, "never_executed"},
		false,
	},
	{
		"non-zero return value",
		[]any{"foo", "return", "bar"},
		false,
	},
}

var asanRunCase = runCase{
	"ASan finding",
	[]any{"foo", "asan", "bar"},
	false,
}

var ubsanRunCase = runCase{
	"UBSan finding",
	[]any{"foo", "ubsan", "bar"},
	false,
}

var baseTempDir string

func TestMain(m *testing.M) {
	var err error
	// Intentionally include a space here to test that we don't break on it.
	baseTempDir, err = os.MkdirTemp("", "cifuzz replayer")
	if err != nil {
		log.Fatalf("Failed to create temp dir for tests: %+v", err)
	}
	defer fileutil.Cleanup(baseTempDir)
	m.Run()
}

func TestIntegration_Replayer_WithMsvc(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	if runtime.GOOS != "windows" {
		t.Skip("MSVC is only available on Windows")
	}
	t.Parallel()
	testutil.RegisterTestDeps("src", "testdata")

	// MSVC (cl.exe) does not support UBSan.
	subtestCompileAndRunWithFuzzerInitialize(t, &msvc, append(baseRunCases, asanRunCase))
	subtestCompileAndRunWithoutFuzzerInitialize(t, &msvc)
	subtestCompileAsCpp(t, &msvc)
}

func TestIntegration_Replayer_WithClangCl(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	if runtime.GOOS != "windows" {
		t.Skip("clang-cl is only available on Windows")
	}
	t.Parallel()
	testutil.RegisterTestDeps("src", "testdata")

	// clang-cl does not seem to support sanitizers.
	// CI runs fail with the error referenced in https://github.com/llvm/llvm-project/issues/52728.
	subtestCompileAndRunWithFuzzerInitialize(t, &clangCl, baseRunCases)
	subtestCompileAndRunWithoutFuzzerInitialize(t, &clangCl)
	subtestCompileAsCpp(t, &clangCl)
}

func TestIntegration_Replayer_WithClang(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	if runtime.GOOS == "windows" {
		t.Skip("clang on Windows is covered by the clang-cl test")
	}
	t.Parallel()
	testutil.RegisterTestDeps("src", "testdata")

	subtestCompileAndRunWithFuzzerInitialize(t, &clang, append(baseRunCases, asanRunCase, ubsanRunCase))
	subtestCompileAndRunWithoutFuzzerInitialize(t, &clang)
	subtestCompileAsCpp(t, &clang)
}

func TestIntegration_Replayer_WithGcc(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	if runtime.GOOS == "windows" {
		t.Skip("gcc on Windows is covered by the MinGW test")
	}
	t.Parallel()
	testutil.RegisterTestDeps("src", "testdata")

	subtestCompileAndRunWithFuzzerInitialize(t, &gcc, append(baseRunCases, asanRunCase, ubsanRunCase))
	subtestCompileAndRunWithoutFuzzerInitialize(t, &gcc)
	subtestCompileAsCpp(t, &gcc)
}

func TestIntegration_Replayer_WithMingw(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	if runtime.GOOS != "windows" {
		t.Skip("MinGW is only available on Windows")
	}
	t.Parallel()
	testutil.RegisterTestDeps("src", "testdata")

	// MinGW does not support sanitizers.
	subtestCompileAndRunWithFuzzerInitialize(t, &mingw, baseRunCases)
	subtestCompileAndRunWithoutFuzzerInitialize(t, &mingw)
	subtestCompileAsCpp(t, &mingw)
}

func TestIntegration_Replayer_WithNoAsserts(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	t.Parallel()
	testutil.RegisterTestDeps("src", "testdata")

	tempDir, err := os.MkdirTemp(baseTempDir, "")
	require.NoError(t, err)

	if runtime.GOOS == "windows" {
		compileReplayer(t, tempDir, clangCl.compiler, clangCl.outputFlags, append([]string{"/DNDEBUG"}, clangCl.flags...)...)
	} else {
		compileReplayer(t, tempDir, clang.compiler, clang.outputFlags, append([]string{"-DNDEBUG"}, clang.flags...)...)
	}
}

func TestIntegration_Replayer_WithoutArgsRunsSeedCorpus(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	t.Parallel()
	testutil.RegisterTestDeps("src", "testdata")

	tempDir, err := os.MkdirTemp(baseTempDir, "")
	require.NoError(t, err)

	var replayerPath string
	if runtime.GOOS == "windows" {
		replayerPath = compileReplayer(t, tempDir, msvc.compiler, msvc.outputFlags, msvc.flags...)
	} else {
		replayerPath = compileReplayer(t, tempDir, clang.compiler, clang.outputFlags, clang.flags...)
	}

	// Create a seed corpus directory with the correct name next to the replayer binary.
	seedCorpusDir := strings.TrimSuffix(replayerPath, ".exe") + "_inputs"
	err = os.Mkdir(seedCorpusDir, 0700)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(seedCorpusDir, "some_entry"), []byte("seed_corpus_entry"), 0700)
	require.NoError(t, err)

	stdoutLines, _, err := runReplayer(t, tempDir, replayerPath)
	require.NoError(t, err)
	require.ElementsMatch(
		t,
		[]string{fmt.Sprintf("init(1,%s)", replayerPath), "''", "'seed_corpus_entry'"},
		stdoutLines,
	)
}

func subtestCompileAndRunWithFuzzerInitialize(t *testing.T, cc *compilerCase, rcs []runCase) {
	t.Run("WithFuzzerInitialize", func(t *testing.T) {
		t.Parallel()

		tempDir, err := os.MkdirTemp(baseTempDir, "")
		require.NoError(t, err)

		replayer := compileReplayer(t, tempDir, cc.compiler, cc.outputFlags, cc.flags...)

		for _, rc := range rcs {
			// Capture loop variable in goroutine, see https://gist.github.com/posener/92a55c4cd441fc5e5e85f27bca008721.
			rc := rc
			t.Run(rc.name, func(t *testing.T) {
				t.Parallel()

				expectedStdoutLines := []string{
					// Assert that LLVMFuzzerInitialize has been executed.
					fmt.Sprintf("init(%d,%s)", len(rc.inputs)+1 /* argc */, replayer /* argv[0] */),
				}
				// If no inputs are specified explicitly, the replayer runs the empty input.
				if len(rc.inputs) == 0 {
					expectedStdoutLines = append(expectedStdoutLines, "''")
				}
			outer_loop:
				for _, inputs := range rc.inputs {
					if str, ok := inputs.(string); ok {
						// For the purpose of output assertions, we can treat a file just like a directory
						// containing a single file.
						inputs = []string{str}
					}
					inputs, ok := inputs.([]string)
					require.True(t, ok, "Elements of test case inputs must be either string or []string")
					for _, input := range inputs {
						// The output of the fuzz target ends with the first crash, so don't include the magic
						// inputs and any subsequent ones in the expected output.
						if input == "asan" || input == "ubsan" || input == "assert" || input == "return" {
							break outer_loop
						}
						expectedStdoutLines = append(expectedStdoutLines, fmt.Sprintf("'%s'", input))
					}
				}

				stdoutLines, stderr, err := runReplayer(t, tempDir, replayer, rc.inputs...)
				if rc.normalExit {
					var exitErr *exec.ExitError
					if errors.As(err, &exitErr) {
						require.NoError(t, err, string(exitErr.Stderr))
					} else {
						require.NoError(t, err)
					}

					assert.Contains(t, stderr, "passed")
					assert.Contains(t, stderr, fmt.Sprintf("%d inputs", len(expectedStdoutLines)-1))
				} else {
					require.Error(t, err)
					require.IsType(t, &exec.ExitError{}, err, err.Error())

					assert.Contains(t, stderr, "failed on input")
					if runtime.GOOS == "linux" {
						// Assert the reproduction command on Linux.
						assert.Contains(t, stderr, replayer)
					}
				}
				// Directory traversal order is unspecified, so only compare the set of elements.
				assert.ElementsMatch(t, expectedStdoutLines, stdoutLines)
			})
		}
	})
}

func subtestCompileAndRunWithoutFuzzerInitialize(t *testing.T, cc *compilerCase) {
	t.Run("WithoutFuzzerInitialize", func(t *testing.T) {
		t.Parallel()

		tempDir, err := os.MkdirTemp(baseTempDir, "")
		require.NoError(t, err)

		replayer := compileReplayer(t, tempDir, cc.compiler, cc.outputFlags, append(
			[]string{cc.disableFuzzerInitializeFlag},
			cc.flags...,
		)...)

		stdoutLines, stderr, err := runReplayer(t, tempDir, replayer, "foo", "bar")
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			require.NoError(t, err, string(exitErr.Stderr))
		} else {
			require.NoError(t, err)
		}
		assert.Equal(t, []string{"'foo'", "'bar'"}, stdoutLines)
		assert.Contains(t, stderr, "2 inputs")
	})
}

func subtestCompileAsCpp(t *testing.T, cc *compilerCase) {
	t.Run("CompileAsC++", func(t *testing.T) {
		tempDir, err := os.MkdirTemp(baseTempDir, "")
		require.NoError(t, err)

		reproducerSrcFile := filepath.Join(tempDir, "replayer.cpp")
		err = os.WriteFile(reproducerSrcFile, replayerSrc, 0700)
		require.NoError(t, err)

		var args []string
		args = append(args, cc.compileOnlyAsCppFlags...)
		args = append(args, cc.flags...)
		args = append(args, reproducerSrcFile)
		c := exec.Command(cc.compiler, args...)
		// Emit additional compiler outputs into a test-exclusive directory.
		c.Dir = tempDir
		out, err := c.CombinedOutput()
		require.NoErrorf(t, err, "Failed to execute %q: %+v\n%s", c.String(), err, string(out))
	})
}

// compileReplayer returns the path to the resulting executable.
func compileReplayer(t *testing.T, tempDir string, compiler string, outputFlags []string, flags ...string) string {
	tempDir, err := os.MkdirTemp(tempDir, "")
	require.NoError(t, err)

	reproducerSrcFile := filepath.Join(tempDir, "replayer.c")
	err = os.WriteFile(reproducerSrcFile, replayerSrc, 0700)
	require.NoError(t, err)
	fuzzTargetSrcFile := filepath.Join(tempDir, "fuzz_target.c")
	err = os.WriteFile(fuzzTargetSrcFile, fuzzTargetSrc, 0700)
	require.NoError(t, err)

	outBasename := "replayer"
	if runtime.GOOS == "windows" {
		outBasename += ".exe"
	}
	outFile := filepath.Join(tempDir, outBasename)
	var args []string
	args = append(args, flags...)
	for _, outputFlag := range outputFlags {
		if strings.Contains(outputFlag, "%s") {
			args = append(args, fmt.Sprintf(outputFlag, outFile))
		} else {
			args = append(args, outputFlag)
		}
	}
	args = append(args, reproducerSrcFile, fuzzTargetSrcFile)
	c := exec.Command(compiler, args...)
	// Emit additional compiler outputs into a test-exclusive directory.
	c.Dir = tempDir
	out, err := c.CombinedOutput()
	require.NoErrorf(t, err, "Failed to execute %q: %+v\n%s", c.String(), err, string(out))

	return outFile
}

func runReplayer(t *testing.T, baseTempDir string, replayerPath string, inputs ...any) ([]string, string, error) {
	var inputPaths []string
	for _, input := range inputs {
		if fileContent, ok := input.(string); ok {
			inputPaths = append(inputPaths, createInputFile(t, baseTempDir, fileContent))
		} else if fileContents, ok := input.([]string); ok {
			tempDir, err := os.MkdirTemp(baseTempDir, "input-dir")
			require.NoError(t, err)
			for _, fileContent := range fileContents {
				createInputFile(t, tempDir, fileContent)
			}
			inputPaths = append(inputPaths, tempDir)
		} else {
			t.Fatalf("Unexpected type of parameter 'inputs': %s", reflect.TypeOf(inputs).String())
		}
	}

	c := exec.Command(replayerPath, inputPaths...)
	stdout, stderr, err := outputWithStderr(c)
	// Split on both \r\n (Windows) and \n (Unix) after removing trailing newlines.
	stdoutLines := strings.Split(strings.ReplaceAll(strings.TrimSpace(string(stdout)), "\r\n", "\n"), "\n")
	return stdoutLines, string(stderr), err
}

// outputWithStderr behaves like cmd.Output, but additionally always returns stderr.
func outputWithStderr(cmd *exec.Cmd) (stdout []byte, stderr []byte, err error) { //nolint:nonamedreturns
	stderrBuf := &bytes.Buffer{}
	cmd.Stderr = stderrBuf
	stdout, err = cmd.Output()
	stderr = stderrBuf.Bytes()
	// Also store stderr in the ExitError in case of failure to remain compatible with cmd.Output.
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		exitErr.Stderr = stderr
		err = exitErr
	}
	return
}

func createInputFile(t *testing.T, dir, content string) string {
	tempFile, err := os.CreateTemp(dir, "input")
	require.NoError(t, err)
	_, err = tempFile.WriteString(content)
	require.NoError(t, err)
	err = tempFile.Close()
	require.NoError(t, err)
	return tempFile.Name()
}
