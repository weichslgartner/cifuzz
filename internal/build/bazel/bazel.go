package bazel

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"

	"code-intelligence.com/cifuzz/internal/build"
	"code-intelligence.com/cifuzz/internal/cmdutils"
	"code-intelligence.com/cifuzz/pkg/log"
)

type BuilderOptions struct {
	ProjectDir string
	Engine     string
	NumJobs    uint
	Stdout     io.Writer
	Stderr     io.Writer
	TempDir    string
	Verbose    bool
}

func (opts *BuilderOptions) Validate() error {
	// Check that the project dir is set
	if opts.ProjectDir == "" {
		return errors.New("ProjectDir is not set")
	}

	// Check that the project dir exists and can be accessed
	_, err := os.Stat(opts.ProjectDir)
	if err != nil {
		return errors.WithStack(err)
	}

	// Check that the TempDir is set. This is not set by the user, so
	// we panic if it's not set
	if opts.TempDir == "" {
		panic("TempDir is not set")
	}

	if opts.Engine != "libfuzzer" {
		panic(fmt.Sprintf("Invalid engine %q", opts.Engine))
	}

	return nil
}

type Builder struct {
	*BuilderOptions
	env []string
}

func NewBuilder(opts *BuilderOptions) (*Builder, error) {
	err := opts.Validate()
	if err != nil {
		return nil, err
	}

	b := &Builder{BuilderOptions: opts}

	b.env, err = build.CommonBuildEnv()
	if err != nil {
		return nil, err
	}

	return b, nil
}

// Build builds the specified fuzz tests with bazel. It expects labels
// of "*_bin" targets of the cc_fuzz_test rule provided by rules_fuzzing:
// https://github.com/bazelbuild/rules_fuzzing/blob/master/docs/cc-fuzzing-rules.md#cc_fuzz_test
//
// TODO: Unfortunately, the cc_fuzz_test rule currently doesn't
// support combining sanitizers, so we can't build with both ASan
// and UBSan. Therefore, we only build with ASan and plan to upstream
// support for combining sanitizers.
func (b *Builder) Build(fuzzTests []string) (map[string]*build.Result, error) {
	var err error

	// The BuildDir field of the build results is expected to be a
	// parent directory of all the artifacts, so that a single minijail
	// binding allows access to all artifacts in the sandbox.
	// When building via bazel, the "output_base" directory contains
	// all artifacts, so we use that as the BuildDir.
	cmd := exec.Command("bazel", "info", "output_base")
	out, err := cmd.Output()
	if err != nil {
		// It's expected that bazel might fail due to user configuration,
		// so we print the error without the stack trace.
		err = cmdutils.WrapExecError(err, cmd)
		log.Error(err)
		return nil, cmdutils.ErrSilent
	}
	buildDir := strings.TrimSpace(string(out))
	fuzzScript := filepath.Join(b.TempDir, "fuzz.sh")

	// To avoid part of the loading and/or analysis phase to rerun, we
	// use the same flags for all bazel commands (except for those which
	// are not supported by all bazel commands we use).
	flags := []string{
		"--repo_env=CC",
		"--repo_env=CXX",
		// Don't use the LLVM from Xcode
		"--repo_env=BAZEL_USE_CPP_ONLY_TOOLCHAIN=1",
	}
	if b.NumJobs != 0 {
		flags = append(flags, "--jobs", fmt.Sprint(b.NumJobs))
	}

	// Flags which should only be used for bazel run because they are
	// not supported by the other bazel commands we use
	runFlags := []string{
		// Build with debug symbols
		"-c", "opt", "--copt", "-g",
		// Build with libFuzzer
		"--@rules_fuzzing//fuzzing:cc_engine=@rules_fuzzing//fuzzing/engines:libfuzzer",
		"--@rules_fuzzing//fuzzing:cc_engine_instrumentation=libfuzzer",
		// Build with ASan instrumentation
		"--@rules_fuzzing//fuzzing:cc_engine_sanitizer=asan",
		"--verbose_failures",
		"--script_path=" + fuzzScript,
	}
	args := []string{"run"}
	args = append(args, flags...)
	args = append(args, runFlags...)
	args = append(args, fuzzTests...)

	cmd = exec.Command("bazel", args...)
	// Redirect the build command's stdout to stderr to only have
	// reports printed to stdout
	cmd.Stdout = b.Stderr
	cmd.Stderr = b.Stderr
	cmd.Env = b.env
	log.Debugf("Command: %s", cmd.String())
	err = cmd.Run()
	if err != nil {
		// It's expected that bazel might fail due to user configuration,
		// so we print the error without the stack trace.
		err = cmdutils.WrapExecError(err, cmd)
		log.Error(err)
		return nil, cmdutils.ErrSilent
	}

	// Assemble the build results
	results := make(map[string]*build.Result)

	for _, fuzzTest := range fuzzTests {
		// For bazel, we expect the seed corpus in the directory which
		// defines the fuzz test bazel target.
		// To get the seed corpus path, we first get a canonical form of
		// the fuzz test target's label via `bazel query`
		args := append([]string{"query"}, flags...)
		args = append(args, fuzzTest)
		cmd = exec.Command("bazel", args...)
		log.Debugf("Command: %s", cmd.String())
		out, err := cmd.Output()
		if err != nil {
			// It's expected that bazel might fail due to user configuration,
			// so we print the error without the stack trace.
			err = cmdutils.WrapExecError(err, cmd)
			log.Error(err)
			return nil, cmdutils.ErrSilent
		}
		fuzzTestLabel := strings.TrimSpace(string(out))

		// Create a canonical name from the label, which is a valid path
		// to a file inside the same directory as the BUILD file and:
		// * Doesn't contain any leading '//'
		// * Doesn't contain the "_bin" suffix
		// * Has ':' replaced with '/' (because ':' is not allowed in
		//   filenames on Windows)
		canonicalName := strings.TrimPrefix(fuzzTestLabel, "//")
		canonicalName = strings.TrimSuffix(canonicalName, "_bin")
		canonicalName = strings.ReplaceAll(canonicalName, ":", "/")

		// Use the canonical name to construct the path of the seed corpus
		relSeedCorpus := filepath.Join(strings.Split(canonicalName, "/")...) + "_inputs"
		seedCorpus := filepath.Join(b.ProjectDir, relSeedCorpus)

		// Use the canonical name to construct the path of the generated corpus
		parent := filepath.Join(b.ProjectDir, ".cifuzz-corpus")
		generatedCorpus := filepath.Join(parent, filepath.Join(strings.Split(canonicalName, "/")...))

		results[fuzzTest] = &build.Result{
			Executable:      fuzzScript,
			GeneratedCorpus: generatedCorpus,
			SeedCorpus:      seedCorpus,
			BuildDir:        buildDir,
			Engine:          b.Engine,
			Sanitizers:      []string{"address"},
		}
	}

	return results, nil
}
