package run

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"

	"code-intelligence.com/cifuzz/pkg/cmdutils"
	"code-intelligence.com/cifuzz/pkg/dialog"
	"code-intelligence.com/cifuzz/pkg/report"
	"code-intelligence.com/cifuzz/pkg/runner/libfuzzer"
	"code-intelligence.com/cifuzz/util/envutil"
	"code-intelligence.com/cifuzz/util/stringutil"
)

type runOptions struct {
	fs *afero.Afero

	buildCommand   string
	fuzzTest       string
	seedsDirs      []string
	dictionary     string
	engineArgs     []string
	fuzzTargetArgs []string
	timeout        time.Duration
	useSandbox     bool
}

func (opts *runOptions) validate() error {
	// Check if the seed dirs exist and can be accessed
	for _, d := range opts.seedsDirs {
		_, err := opts.fs.Stat(d)
		if err != nil {
			err = errors.WithStack(err)
			dialog.Error(err, err.Error())
			return cmdutils.WrapSilentError(err)
		}
	}

	if opts.dictionary != "" {
		// Check if the dictionary exists and can be accessed
		_, err := opts.fs.Stat(opts.dictionary)
		if err != nil {
			err = errors.WithStack(err)
			dialog.Error(err, err.Error())
			return cmdutils.WrapSilentError(err)
		}
	}

	return nil
}

type runCmd struct {
	*cobra.Command
	opts *runOptions
}

func New(fs *afero.Afero) *cobra.Command {
	opts := &runOptions{fs: fs}

	cmd := &cobra.Command{
		Use:   "run",
		Short: "Build and run a fuzz test",
		// TODO: Write long description (easier once we support more
		//       than just the fallback mode).
		Long: "",
		Args: cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return opts.validate()
		},
		RunE: func(c *cobra.Command, args []string) error {
			cmd := runCmd{c, opts}
			return cmd.run()
		},
	}

	cmd.Flags().StringVar(&opts.buildCommand, "build-command", "", "The command to build the fuzz test. Example: \"make clean && make my-fuzz-test\"")
	cmd.Flags().StringVarP(&opts.fuzzTest, "fuzz-test", "f", "", "Path where the fuzz test executable can be found after running the build command.")
	cmd.Flags().StringArrayVarP(&opts.seedsDirs, "seeds-dir", "s", nil, "Directory containing sample inputs for the code under test.\nSee https://llvm.org/docs/LibFuzzer.html#corpus and\nhttps://aflplus.plus/docs/fuzzing_in_depth/#a-collecting-inputs.")
	cmd.Flags().StringVar(&opts.dictionary, "dict", "", "A file containing input language keywords or other interesting byte sequences.\nSee https://llvm.org/docs/LibFuzzer.html#dictionaries and\nhttps://github.com/AFLplusplus/AFLplusplus/blob/stable/dictionaries/README.md.")
	cmd.Flags().StringArrayVar(&opts.engineArgs, "engine-arg", nil, "Command-line argument to pass to the fuzzing engine.\nSee https://llvm.org/docs/LibFuzzer.html#options and\nhttps://www.mankier.com/8/afl-fuzz.")
	cmd.Flags().StringArrayVar(&opts.fuzzTargetArgs, "fuzz-target-arg", nil, "Command-line argument to pass to the fuzz target.")
	cmd.Flags().DurationVar(&opts.timeout, "timeout", 0, "Maximum time in seconds to run the fuzz test. The default is to run indefinitely.")
	cmd.Flags().BoolVar(&opts.useSandbox, "sandbox", true, "By default, fuzz tests are executed in a sandbox to prevent accidental damage to the system.\nUse --sandbox=false to run the fuzz test unsandboxed.")
	cmdutils.MarkFlagsRequired(cmd, "build-command", "seeds-dir", "fuzz-test")

	return cmd
}

func (c *runCmd) run() error {
	err := c.buildFuzzTest()
	if err != nil {
		return err
	}

	err = c.runFuzzTest()
	if err != nil {
		return err
	}

	return nil
}

func (c *runCmd) buildFuzzTest() error {
	env, err := buildEnv()
	if err != nil {
		return err
	}

	// Run the build command
	cmd := exec.Command("/bin/sh", "-c", c.opts.buildCommand)
	cmd.Stdout = c.OutOrStdout()
	cmd.Stderr = c.ErrOrStderr()
	cmd.Env = env
	err = cmd.Run()
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func (c *runCmd) runFuzzTest() error {
	runnerOpts := &libfuzzer.RunnerOptions{
		FuzzTarget:          c.opts.fuzzTest,
		SeedsDir:            c.opts.seedsDirs[0],
		AdditionalSeedsDirs: c.opts.seedsDirs[1:],
		Dictionary:          c.opts.dictionary,
		EngineArgs:          c.opts.engineArgs,
		FuzzTargetArgs:      c.opts.fuzzTargetArgs,
		ReportHandler:       &reportHandler{},
		Timeout:             c.opts.timeout,
		UseMinijail:         c.opts.useSandbox,
	}
	runner := libfuzzer.NewRunner(runnerOpts)
	return runner.Run(context.Background())
}

func buildEnv() ([]string, error) {
	var err error

	// Prepare the build environment
	env := os.Environ()

	// Set the C/C++ compiler to clang/clang++, which is needed to build
	// a libfuzzer binary via `-fsanitize=fuzzer`.
	env, err = envutil.Setenv(env, "CC", "clang")
	if err != nil {
		return nil, err
	}
	env, err = envutil.Setenv(env, "CXX", "clang++")
	if err != nil {
		return nil, err
	}

	// Set CFLAGS and CXXFLAGS. Note that these flags must not contain
	// spaces, because the environment variables are space separated.
	// TODO: These flags were copied from ci-build, we should explain
	//       for each why we use it
	flags := []string{
		// Common flags
		"-g",
		"-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION",
		// Flags used to build with libFuzzer
		"-fno-omit-frame-pointer",
		"-fsanitize=fuzzer-no-link",
		"-Og",
		"-gline-tables-only",
		"-fsanitize-coverage=indirect-calls,trace-cmp,trace-div,trace-gep",
		// Flags used to build with ASan
		"-fsanitize=address,undefined",
		"-fno-sanitize=function,vptr",
		"-fsanitize-recover=address",
		"-fsanitize-address-use-after-scope",
	}
	env, err = envutil.Setenv(env, "CFLAGS", strings.Join(flags, " "))
	if err != nil {
		return nil, err
	}
	env, err = envutil.Setenv(env, "CXXFLAGS", strings.Join(flags, " "))
	if err != nil {
		return nil, err
	}

	// Users should pass the environment variable FUZZ_TEST_LDFLAGS to
	// the linker command building the fuzz test. For libfuzzer, we set
	// it to "-fsanitize=fuzzer" to build a libfuzzer binary.
	env, err = envutil.Setenv(env, "FUZZ_TEST_LDFLAGS", "-fsanitize=fuzzer")
	if err != nil {
		return nil, err
	}

	// TODO: ci-build sets ASAN_OPTIONS to "detect_leaks=0:verify_asan_link_order=0".
	//       Should we do the same? If so, should we override these
	//       settings or not (allowing the user to set the environment
	//       variable themself).

	return env, nil
}

type reportHandler struct{}

func (s *reportHandler) Handle(report *report.Report) error {
	jsonString, err := stringutil.ToJsonString(report)
	if err != nil {
		return err
	}
	fmt.Println(jsonString)
	return nil
}
