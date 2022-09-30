package coverage

import (
	"fmt"
	"io"
	"path/filepath"

	"github.com/pkg/browser"
	"github.com/pkg/errors"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"

	"code-intelligence.com/cifuzz/internal/cmd/coverage/generator"
	"code-intelligence.com/cifuzz/internal/cmdutils"
	"code-intelligence.com/cifuzz/internal/completion"
	"code-intelligence.com/cifuzz/internal/config"
	"code-intelligence.com/cifuzz/pkg/dependencies"
	"code-intelligence.com/cifuzz/pkg/log"
	"code-intelligence.com/cifuzz/pkg/runfiles"
	"code-intelligence.com/cifuzz/util/stringutil"
)

type coverageOptions struct {
	OutputFormat   string   `mapstructure:"format"`
	OutputPath     string   `mapstructure:"output"`
	BuildSystem    string   `mapstructure:"build-system"`
	BuildCommand   string   `mapstructure:"build-command"`
	NumBuildJobs   uint     `mapstructure:"build-jobs"`
	SeedCorpusDirs []string `mapstructure:"seed-corpus-dirs"`
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
	opts *coverageOptions
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

	log.Infof("Building %s", pterm.Style{pterm.Reset, pterm.FgLightBlue}.Sprint(c.opts.fuzzTest))

	var reportPath string
	switch c.opts.BuildSystem {
	case config.BuildSystemCMake,
		config.BuildSystemOther:

		gen := &generator.LLVMCoverageGenerator{
			OutputFormat:   c.opts.OutputFormat,
			OutputPath:     c.opts.OutputPath,
			BuildSystem:    c.opts.BuildSystem,
			BuildCommand:   c.opts.BuildCommand,
			NumBuildJobs:   c.opts.NumBuildJobs,
			SeedCorpusDirs: c.opts.SeedCorpusDirs,
			UseSandbox:     c.opts.UseSandbox,
			FuzzTest:       c.opts.fuzzTest,
			ProjectDir:     c.opts.ProjectDir,
			StdOut:         c.OutOrStdout(),
			StdErr:         c.OutOrStderr(),
		}
		reportPath, err = gen.Generate()
	default:
		return errors.Errorf("Unsupported build system \"%s\"", c.opts.BuildSystem)
	}
	if err != nil {
		return err
	}

	switch c.opts.OutputFormat {
	case "html":
		return c.handleHTMLReport(reportPath)
	case "lcov":
		log.Successf("Created coverage lcov report: %s", reportPath)
		return nil
	default:
		return errors.Errorf("Unsupported output format")
	}

}

func (c *coverageCmd) handleHTMLReport(reportPath string) error {
	// Open the browser if no output path was specified
	if c.opts.OutputPath == "" {
		// try to open the report in the browser ...
		err := c.openReport(reportPath)
		if err != nil {
			//... if this fails print the file URI
			log.Debug(err)
			err = c.printReportURI(reportPath)
			if err != nil {
				return err
			}
		}
	} else {
		log.Successf("Created coverage HTML report: %s", reportPath)
		err := c.printReportURI(reportPath)
		if err != nil {
			return err
		}
	}
	return nil
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
	return dependencies.Check(deps, dependencies.CMakeDeps, runfiles.Finder)
}
