package coverage

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/pkg/browser"
	"github.com/pkg/errors"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"code-intelligence.com/cifuzz/internal/build"
	"code-intelligence.com/cifuzz/internal/build/cmake"
	"code-intelligence.com/cifuzz/internal/build/other"
	"code-intelligence.com/cifuzz/internal/cmdutils"
	"code-intelligence.com/cifuzz/internal/completion"
	"code-intelligence.com/cifuzz/internal/config"
	"code-intelligence.com/cifuzz/pkg/coverage"
	"code-intelligence.com/cifuzz/pkg/dependencies"
	"code-intelligence.com/cifuzz/pkg/log"
	"code-intelligence.com/cifuzz/pkg/minijail"
	"code-intelligence.com/cifuzz/pkg/runfiles"
	"code-intelligence.com/cifuzz/util/envutil"
	"code-intelligence.com/cifuzz/util/executil"
	"code-intelligence.com/cifuzz/util/fileutil"
	"code-intelligence.com/cifuzz/util/stringutil"
)

type coverageOptions struct {
	OutputFormat   string   `mapstructure:"format"`
	OutputPath     string   `mapstructure:"output"`
	BuildSystem    string   `mapstructure:"build-system"`
	BuildCommand   string   `mapstructure:"build-command"`
	NumBuildJobs   uint     `mapstructure:"build-jobs"`
	SeedCorpusDirs []string `mapstructure:"seed-corpus-dirs"`
	FuzzTestArgs   []string `mapstructure:"fuzz-test-args"`
	UseSandbox     bool     `mapstructure:"use-sandbox"`

	ProjectDir string
	fuzzTest   string
}

func supportedOutputFormats() []string {
	return []string{"html", "lcov"}
}

func (opts *coverageOptions) validate() error {
	var err error

	if !stringutil.Contains(supportedOutputFormats(), opts.OutputFormat) {
		msg := `Flag "format" must be html or lcov`
		return cmdutils.WrapIncorrectUsageError(errors.New(msg))
	}

	opts.SeedCorpusDirs, err = cmdutils.ValidateSeedCorpusDirs(opts.SeedCorpusDirs)
	if err != nil {
		log.Error(err, err.Error())
		return cmdutils.ErrSilent
	}

	if opts.BuildSystem == "" {
		opts.BuildSystem, err = config.DetermineBuildSystem(opts.ProjectDir)
		if err != nil {
			return err
		}
	} else {
		err = config.ValidateBuildSystem(opts.BuildSystem)
		if err != nil {
			return err
		}
	}

	// To build with other build systems, a build command must be provided
	if opts.BuildSystem == config.BuildSystemOther && opts.BuildCommand == "" {
		msg := `Flag 'build-command' must be set when using the build system type 'other'`
		return cmdutils.WrapIncorrectUsageError(errors.New(msg))
	}

	return nil
}

type coverageCmd struct {
	*cobra.Command
	opts   *coverageOptions
	tmpDir string
}

func New() *cobra.Command {
	opts := &coverageOptions{}
	var bindFlags func()

	cmd := &cobra.Command{
		Use:   "coverage [flags] <fuzz test>",
		Short: "Generate a coverage report for a fuzz test",
		Long: `Generate a coverage report for a fuzz test

Open a browser displaying the source code with coverage information:

    cifuzz coverage <fuzz test>

Write out an HTML file instead of launching a browser:

    cifuzz coverage --output coverage.html <fuzz test>

Write out an lcov trace file:

    cifuzz coverage --format=lcov <fuzz test>


`,
		ValidArgsFunction: completion.ValidFuzzTests,
		Args:              cobra.ExactArgs(1),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			// Bind viper keys to flags. We can't do this in the New
			// function, because that would re-bind viper keys which
			// were bound to the flags of other commands before.
			bindFlags()
			cmdutils.ViperMustBindPFlag("format", cmd.Flags().Lookup("format"))
			cmdutils.ViperMustBindPFlag("output", cmd.Flags().Lookup("output"))

			err := config.FindAndParseProjectConfig(opts)
			if err != nil {
				log.Errorf(err, "Failed to parse cifuzz.yaml: %v", err.Error())
				return cmdutils.WrapSilentError(err)
			}

			opts.fuzzTest = args[0]
			return opts.validate()
		},
		RunE: func(c *cobra.Command, args []string) error {
			cmd := coverageCmd{Command: c, opts: opts}
			return cmd.run()
		},
	}

	// Note: If a flag should be configurable via cifuzz.yaml as well,
	// bind it to viper in the PreRunE function.
	bindFlags = cmdutils.AddFlags(cmd,
		cmdutils.AddBuildCommandFlag,
		cmdutils.AddBuildJobsFlag,
		cmdutils.AddFuzzTestArgFlag,
		cmdutils.AddProjectDirFlag,
		cmdutils.AddSeedCorpusFlag,
		cmdutils.AddUseSandboxFlag,
	)
	cmd.Flags().StringP("format", "f", "html", "Output format of the coverage report (html/lcov).")
	cmd.Flags().StringP("output", "o", "", "Output path of the coverage report.")

	return cmd
}

func (c *coverageCmd) run() error {
	depsOk, err := c.checkDependencies()
	if err != nil {
		return err
	}
	if !depsOk {
		return dependencies.Error()
	}

	var baseTmpDir string
	if c.opts.UseSandbox {
		baseTmpDir = minijail.OutputDir
		err = os.MkdirAll(baseTmpDir, 0700)
		if err != nil {
			return err
		}
	}
	c.tmpDir, err = os.MkdirTemp(baseTmpDir, "coverage-")
	if err != nil {
		return err
	}
	defer fileutil.Cleanup(c.tmpDir)

	buildResult, err := c.buildFuzzTest()
	if err != nil {
		return err
	}

	err = c.runFuzzTest(buildResult)
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && c.opts.UseSandbox {
			return cmdutils.WrapCouldBeSandboxError(err)
		}
		return err
	}

	err = c.indexRawProfile(buildResult.Executable)
	if err != nil {
		return err
	}

	lcovReportSummary, err := c.lcovReportSummary(buildResult.Executable, buildResult.RuntimeDeps)
	if err != nil {
		return err
	}
	coverage.ParseLcov(lcovReportSummary).PrintTable(c.OutOrStderr())

	switch c.opts.OutputFormat {
	case "html":
		err = c.generateHTMLReport(buildResult.Executable, buildResult.RuntimeDeps)
		if err != nil {
			return err
		}

	case "lcov":
		err = c.generateLcovReport(buildResult.Executable, buildResult.RuntimeDeps)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *coverageCmd) buildFuzzTest() (*build.Result, error) {
	log.Infof("Building %s", pterm.Style{pterm.Reset, pterm.FgLightBlue}.Sprint(c.opts.fuzzTest))

	if c.opts.BuildSystem == config.BuildSystemCMake {
		builder, err := cmake.NewBuilder(&cmake.BuilderOptions{
			ProjectDir: c.opts.ProjectDir,
			Engine:     "libfuzzer",
			Sanitizers: []string{"coverage"},
			Parallel: cmake.ParallelOptions{
				Enabled: viper.IsSet("build-jobs"),
				NumJobs: c.opts.NumBuildJobs,
			},
			Stdout: c.OutOrStdout(),
			Stderr: c.ErrOrStderr(),
			// We want the runtime deps in the build result because we
			// pass them to the llvm-cov command.
			FindRuntimeDeps: true,
		})
		if err != nil {
			return nil, err
		}
		err = builder.Configure()
		if err != nil {
			return nil, err
		}
		buildResults, err := builder.Build([]string{c.opts.fuzzTest})
		if err != nil {
			return nil, err
		}
		return buildResults[c.opts.fuzzTest], nil
	} else if c.opts.BuildSystem == config.BuildSystemOther {
		if runtime.GOOS == "windows" {
			return nil, errors.New("CMake is the only supported build system on Windows")
		}
		builder, err := other.NewBuilder(&other.BuilderOptions{
			BuildCommand: c.opts.BuildCommand,
			Engine:       "libfuzzer",
			Sanitizers:   []string{"coverage"},
			Stdout:       c.OutOrStdout(),
			Stderr:       c.ErrOrStderr(),
		})
		if err != nil {
			return nil, err
		}
		buildResult, err := builder.Build(c.opts.fuzzTest)
		if err != nil {
			return nil, err
		}
		return buildResult, nil
	} else {
		return nil, errors.Errorf("Unsupported build system \"%s\"", c.opts.BuildSystem)
	}
}

func (c *coverageCmd) runFuzzTest(buildResult *build.Result) error {
	log.Infof("Running %s on corpus", pterm.Style{pterm.Reset, pterm.FgLightBlue}.Sprint(c.opts.fuzzTest))
	log.Debugf("Executable: %s", buildResult.Executable)

	// Use user-specified seed corpus dirs (if any), the default seed
	// corpus (if it exists), and the generated corpus (if it exists).
	corpusDirs := c.opts.SeedCorpusDirs
	exists, err := fileutil.Exists(buildResult.SeedCorpus)
	if err != nil {
		return err
	}
	if exists {
		corpusDirs = append(corpusDirs, buildResult.SeedCorpus)
	}
	generatedCorpusDir := cmdutils.GeneratedCorpusDir(c.opts.ProjectDir, c.opts.fuzzTest)
	exists, err = fileutil.Exists(generatedCorpusDir)
	if err != nil {
		return err
	}
	if exists {
		corpusDirs = append(corpusDirs, generatedCorpusDir)
	}

	// Ensure that symlinks are resolved to be able to add minijail
	// bindings for the corpus dirs.
	for i, dir := range corpusDirs {
		corpusDirs[i], err = filepath.EvalSymlinks(dir)
		if err != nil {
			return errors.WithStack(err)
		}
	}

	// The environment we run the binary in
	var binaryEnv []string
	binaryEnv, err = envutil.Setenv(binaryEnv, "LLVM_PROFILE_FILE",
		c.rawProfilePattern(supportsLlvmProfileContinuousMode(buildResult.Executable)))
	if err != nil {
		return err
	}
	binaryEnv, err = envutil.Setenv(binaryEnv, "NO_CIFUZZ", "1")
	if err != nil {
		return err
	}

	// The environment we run minijail in
	wrapperEnv := os.Environ()

	dirWithEmptyFile, err := os.MkdirTemp("", "cifuzz-coverage-*")
	if err != nil {
		return errors.WithStack(err)
	}
	err = fileutil.Touch(filepath.Join(dirWithEmptyFile, "empty_file"))
	if err != nil {
		return err
	}
	defer fileutil.Cleanup(dirWithEmptyFile)

	emptyDir, err := os.MkdirTemp("", "cifuzz-coverage-*")
	if err != nil {
		return errors.WithStack(err)
	}
	defer fileutil.Cleanup(emptyDir)

	// libFuzzer's merge mode never runs the empty input, whereas regular fuzzing runs and the replayer always try the
	// empty input first. To achieve consistent behavior, manually run the empty input, ignoring any crashes. runFuzzer
	// always logs any error we encounter.
	// This line is responsible for empty inputs being skipped:
	// https://github.com/llvm/llvm-project/blob/c7c0ce7d9ebdc0a49313bc77e14d1e856794f2e0/compiler-rt/lib/fuzzer/FuzzerIO.cpp#L127
	_ = c.runFuzzer(buildResult.Executable, []string{"-runs=0"}, []string{dirWithEmptyFile}, binaryEnv, wrapperEnv)

	// We use libFuzzer's crash-resistant merge mode to merge all corpus directories into an empty directory, which
	// makes libFuzzer go over all inputs in a subprocess that is restarted in case it crashes. With LLVM's continuous
	// mode (see rawProfilePattern) and since the LLVM coverage information is automatically appended to the existing
	// .profraw file, we collect complete coverage information even if the target crashes on an input in the corpus.
	return c.runFuzzer(buildResult.Executable, []string{"-merge=1"}, append([]string{emptyDir}, corpusDirs...), binaryEnv, wrapperEnv)
}

func (c *coverageCmd) runFuzzer(executable string, preCorpusArgs []string, corpusDirs []string, binaryEnv []string, wrapperEnv []string) error {
	args := []string{executable}
	args = append(args, preCorpusArgs...)
	args = append(args, corpusDirs...)
	if len(c.opts.FuzzTestArgs) > 0 {
		args = append(append(args, "--"), c.opts.FuzzTestArgs...)
	}

	if c.opts.UseSandbox {
		bindings := []*minijail.Binding{
			// The fuzz target must be accessible
			{Source: executable},
		}

		for _, dir := range corpusDirs {
			bindings = append(bindings, &minijail.Binding{Source: dir})
		}

		// Set up Minijail
		mj, err := minijail.NewMinijail(&minijail.Options{
			Args:     args,
			Bindings: bindings,
			Env:      binaryEnv,
		})
		if err != nil {
			return err
		}
		defer mj.Cleanup()

		// Use the command which runs the fuzz test via minijail
		args = mj.Args
	} else {
		// We don't use minijail, so we can merge the binary and wrapper
		// environment
		for key, value := range envutil.ToMap(binaryEnv) {
			var err error
			wrapperEnv, err = envutil.Setenv(wrapperEnv, key, value)
			if err != nil {
				return err
			}
		}
	}

	cmd := executil.Command(args[0], args[1:]...)
	cmd.Env = wrapperEnv

	errStream := &bytes.Buffer{}
	if viper.GetBool("verbose") {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	} else if c.opts.UseSandbox {
		cmd.Stderr = minijail.NewOutputFilter(errStream)
	} else {
		cmd.Stderr = errStream
	}

	log.Debugf("Command: %s", strings.Join(stringutil.QuotedStrings(cmd.Args), " "))
	err := cmd.Run()
	if err != nil {
		// Print the stderr output of the fuzzer to provide users with
		// the context of this error even without verbose mode.
		if !viper.GetBool("verbose") {
			log.Print(errStream.String())
		}
		// It's expected that the fuzz test executable might fail, so we
		// print the error without the stack trace.
		err = cmdutils.WrapExecError(err, cmd.Cmd)
		log.Error(err)
		return cmdutils.ErrSilent
	}
	return err
}

func (c *coverageCmd) indexRawProfile(fuzzTestExecutable string) error {
	rawProfileFiles, err := c.rawProfileFiles()
	if err != nil {
		return err
	}
	if len(rawProfileFiles) == 0 {
		// The rawProfilePattern parameter only governs whether we add "%c",
		// which doesn't affect the actual raw profile location.
		return errors.Errorf("%s did not generate .profraw files at %s", fuzzTestExecutable, c.rawProfilePattern(false))
	}

	llvmProfData, err := runfiles.Finder.LLVMProfDataPath()
	if err != nil {
		return err
	}

	args := append([]string{"merge", "-sparse", "-o", c.indexedProfilePath(fuzzTestExecutable)}, rawProfileFiles...)
	cmd := exec.Command(llvmProfData, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	log.Debugf("Command: %s", strings.Join(stringutil.QuotedStrings(cmd.Args), " "))
	err = cmd.Run()
	if err != nil {
		return cmdutils.WrapExecError(errors.WithStack(err), cmd)
	}
	return nil
}

func (c *coverageCmd) generateHTMLReport(executable string, runtimeDeps []string) error {
	args := []string{"show", "-format=html"}
	ignoreCifuzzIncludesArgs, err := c.getIgnoreCifuzzIncludesArgs()
	if err != nil {
		return err
	}
	args = append(args, ignoreCifuzzIncludesArgs...)
	report, err := c.runLlvmCov(args, executable, runtimeDeps)
	if err != nil {
		return err
	}

	outputPath := c.opts.OutputPath
	if c.opts.OutputPath == "" {
		// If no output path is specified, we create the output in a
		// temporary directory.
		outputDir, err := os.MkdirTemp("", "coverage-")
		if err != nil {
			return errors.WithStack(err)
		}
		outputPath = filepath.Join(outputDir, c.defaultReportName(executable, c.opts.OutputFormat))
	}

	err = os.WriteFile(outputPath, []byte(report), 0644)
	if err != nil {
		return errors.WithStack(err)
	}

	// Open the browser if no output path was specified
	if c.opts.OutputPath == "" {
		// try to open the report in the browser ...
		err := c.openReport(outputPath)
		if err != nil {
			//... if this fails print the file URI
			log.Debug(err)
			err = c.printReportURI(outputPath)
			if err != nil {
				return err
			}
		}
	} else {
		log.Successf("Created coverage HTML report: %s", outputPath)
		err = c.printReportURI(outputPath)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *coverageCmd) runLlvmCov(args []string, fuzzTestExecutable string, runtimeDeps []string) (string, error) {
	llvmCov, err := runfiles.Finder.LLVMCovPath()
	if err != nil {
		return "", err
	}

	// Add all runtime dependencies of the fuzz test to the binaries
	// processed by llvm-cov to include them in the coverage report
	args = append(args, "-instr-profile="+c.indexedProfilePath(fuzzTestExecutable))
	args = append(args, fuzzTestExecutable)
	if archArg, err := c.archFlagIfNeeded(fuzzTestExecutable); err != nil {
		return "", err
	} else if archArg != "" {
		args = append(args, archArg)
	}
	for _, path := range runtimeDeps {
		args = append(args, "-object="+path)
		if archArg, err := c.archFlagIfNeeded(path); err != nil {
			return "", err
		} else if archArg != "" {
			args = append(args, archArg)
		}
	}

	cmd := exec.Command(llvmCov, args...)
	cmd.Stderr = os.Stderr
	log.Debugf("Command: %s", strings.Join(stringutil.QuotedStrings(cmd.Args), " "))
	output, err := cmd.Output()
	if err != nil {
		return "", cmdutils.WrapExecError(errors.WithStack(err), cmd)
	}
	return string(output), nil
}

func (c *coverageCmd) generateLcovReport(executable string, runtimeDeps []string) error {
	args := []string{"export", "-format=lcov"}
	ignoreCifuzzIncludesArgs, err := c.getIgnoreCifuzzIncludesArgs()
	if err != nil {
		return err
	}
	args = append(args, ignoreCifuzzIncludesArgs...)
	report, err := c.runLlvmCov(args, executable, runtimeDeps)
	if err != nil {
		return err
	}

	outputPath := c.opts.OutputPath
	if c.opts.OutputPath == "" {
		// If no output path is specified, we create the output in the
		// current working directory. We don't create it in a temporary
		// directory like we do for HTML reports, because we can't open
		// the lcov report in a browser, so the command is only useful
		// if the lcov report is accessible after it was created.
		outputPath = c.defaultReportName(executable, c.opts.OutputFormat)
	}

	err = os.WriteFile(outputPath, []byte(report), 0644)
	if err != nil {
		return errors.WithStack(err)
	}

	log.Successf("Created lcov trace file: %s", outputPath)
	return nil
}

func (c *coverageCmd) lcovReportSummary(fuzzTestExecutable string, runtimeDeps []string) (string, error) {
	args := []string{"export", "-format=lcov", "-summary-only"}
	ignoreCifuzzIncludesArgs, err := c.getIgnoreCifuzzIncludesArgs()
	if err != nil {
		return "", err
	}
	args = append(args, ignoreCifuzzIncludesArgs...)
	output, err := c.runLlvmCov(args, fuzzTestExecutable, runtimeDeps)
	if err != nil {
		return "", err
	}

	return output, nil
}

func (c *coverageCmd) getIgnoreCifuzzIncludesArgs() ([]string, error) {
	cifuzzIncludePath, err := runfiles.Finder.CIFuzzIncludePath()
	if err != nil {
		return nil, err
	}
	return []string{"-ignore-filename-regex=" + regexp.QuoteMeta(cifuzzIncludePath) + "/.*"}, nil
}

func (c *coverageCmd) rawProfilePattern(supportsContinuousMode bool) string {
	// Use "%m" instead of a fixed path to support coverage of shared
	// libraries: Each executable or library generates its own profile
	// file, all of which we have to merge in the end. By using "%m",
	// the profile is written to a unique file for each executable and
	// shared library.
	// Use "%c", if supported, which expands out to nothing, to enable the
	// continuous mode in which the .profraw is mmaped and thus kept in sync with
	// the counters in the instrumented code even when it crashes.
	// https://clang.llvm.org/docs/SourceBasedCodeCoverage.html#running-the-instrumented-program
	basePattern := "%m.profraw"
	if supportsContinuousMode {
		basePattern = "%c" + basePattern
	}
	return filepath.Join(c.tmpDir, basePattern)
}

func (c *coverageCmd) rawProfileFiles() ([]string, error) {
	files, err := filepath.Glob(filepath.Join(c.tmpDir, "*.profraw"))
	return files, errors.WithStack(err)
}

func (c *coverageCmd) indexedProfilePath(fuzzTestExecutable string) string {
	return filepath.Join(c.tmpDir, filepath.Base(fuzzTestExecutable)+".profdata")
}

func (c *coverageCmd) defaultReportName(fuzzTestExecutable string, outputFormat string) string {
	return filepath.Base(fuzzTestExecutable) + ".coverage." + outputFormat
}

func (c *coverageCmd) openReport(reportPath string) error {
	// ignore output of browser package
	browser.Stdout = io.Discard
	browser.Stderr = io.Discard
	err := browser.OpenFile(reportPath)
	return errors.WithStack(err)
}

func (c *coverageCmd) printReportURI(reportPath string) error {
	absReportPath, err := filepath.Abs(reportPath)
	if err != nil {
		return errors.WithStack(err)
	}
	reportUri := fmt.Sprintf("file://%s", filepath.ToSlash(absReportPath))
	log.Infof("To view the report, open this URI in a browser:\n\n   %s\n\n", reportUri)
	return nil
}

func (c *coverageCmd) checkDependencies() (bool, error) {
	deps := []dependencies.Key{
		dependencies.CLANG, dependencies.LLVM_SYMBOLIZER, dependencies.LLVM_COV, dependencies.LLVM_PROFDATA,
	}
	if c.opts.BuildSystem == config.BuildSystemCMake {
		deps = append(deps, dependencies.CMAKE)
	}
	return dependencies.Check(deps, dependencies.Default, runfiles.Finder)
}

// Returns an llvm-cov -arch flag indicating the preferred architecture of the given object on macOS, where objects can
// be "universal", that is, contain versions for multiple architectures.
func (c *coverageCmd) archFlagIfNeeded(object string) (string, error) {
	if runtime.GOOS != "darwin" {
		// Only macOS uses universal binaries that bundle multiple architectures.
		return "", nil
	}
	var cifuzzCpu macho.Cpu
	if runtime.GOARCH == "amd64" {
		cifuzzCpu = macho.CpuAmd64
	} else {
		cifuzzCpu = macho.CpuArm64
	}
	fatFile, fatErr := macho.OpenFat(object)
	if fatErr == nil {
		defer fatFile.Close()
		var fallbackCpu macho.Cpu
		for _, arch := range fatFile.Arches {
			// Give preference to the architecture matching that of the cifuzz binary.
			if arch.Cpu == cifuzzCpu {
				return cpuToArchFlag(arch.Cpu)
			}
			if arch.Cpu == macho.CpuAmd64 || arch.Cpu == macho.CpuArm64 {
				fallbackCpu = arch.Cpu
			}
		}
		return cpuToArchFlag(fallbackCpu)
	}
	file, err := macho.Open(object)
	if err == nil {
		defer file.Close()
		return cpuToArchFlag(file.Cpu)
	}
	return "", errors.Errorf("failed to parse Mach-O file %q: %q (as universal binary), %q", object, fatErr, err)
}

func cpuToArchFlag(cpu macho.Cpu) (string, error) {
	switch cpu {
	case macho.CpuArm64:
		return "-arch=arm64", nil
	case macho.CpuAmd64:
		return "-arch=x86_64", nil
	default:
		return "", errors.Errorf("unsupported architecture: %s", cpu.String())
	}
}

func supportsLlvmProfileContinuousMode(binary string) bool {
	if runtime.GOOS == "darwin" {
		// No compile-time flags are required on macOS.
		return true
	}
	if runtime.GOOS != "linux" {
		// We do not know the level of support for platforms other than Linux
		// and macOS.
		return false
	}
	// On Linux, we need to parse the symbols of the binary to check whether it
	// has been built with the required compile-time flags
	// (-mllvm -runtime-counter-relocation).
	file, err := elf.Open(binary)
	if err != nil {
		log.Warnf("Failed to parse %s as an ELF file: %s", binary, err)
		// Continuous mode is best-effort, do not fail on "weird" binaries.
		return false
	}
	symbols, err := file.Symbols()
	if err != nil {
		log.Warnf("Failed to read ELF symbols from %s: %s", binary, err)
		return false
	}
	var biasVarAddress uint64
	var biasDefaultVarAddress uint64
	for _, symbol := range symbols {
		if symbol.Name == "__llvm_profile_counter_bias" {
			biasVarAddress = symbol.Value
		} else if symbol.Name == "__llvm_profile_counter_bias_default" {
			biasDefaultVarAddress = symbol.Value
		}
	}
	// Check taken from:
	// https://github.com/llvm/llvm-project/blob/846709b287abe541fcad42e5a54d37a41dae3f67/compiler-rt/lib/profile/InstrProfilingFile.c#L574
	return biasVarAddress != 0 && biasVarAddress != biasDefaultVarAddress
}
