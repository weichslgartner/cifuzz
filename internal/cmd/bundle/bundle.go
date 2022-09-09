package bundle

import (
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"code-intelligence.com/cifuzz/internal/bundler"
	"code-intelligence.com/cifuzz/internal/completion"
	"code-intelligence.com/cifuzz/internal/config"
	"code-intelligence.com/cifuzz/pkg/cmdutils"
	"code-intelligence.com/cifuzz/pkg/log"
)

func New() *cobra.Command {
	return newWithOptions(&bundler.Opts{})
}

func newWithOptions(opts *bundler.Opts) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bundle [flags] [<fuzz test>]...",
		Short: "Bundles fuzz tests into an archive",
		Long: `Bundles all runtime artifacts required by the given fuzz tests into
a self-contained archive that can be executed by a remote fuzzing worker.
If no fuzz tests are specified all fuzz tests are added to the bundle.`,
		ValidArgsFunction: completion.ValidFuzzTests,
		Args:              cobra.ArbitraryArgs,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			// Bind viper keys to flags. We can't do this in the New
			// function, because that would re-bind viper keys which
			// were bound to the flags of other commands before.
			cmdutils.ViperMustBindPFlag("build-jobs", cmd.Flags().Lookup("build-jobs"))
			cmdutils.ViperMustBindPFlag("dict", cmd.Flags().Lookup("dict"))
			cmdutils.ViperMustBindPFlag("engine-args", cmd.Flags().Lookup("engine-arg"))
			cmdutils.ViperMustBindPFlag("fuzz-test-args", cmd.Flags().Lookup("fuzz-test-arg"))
			cmdutils.ViperMustBindPFlag("seed-corpus-dirs", cmd.Flags().Lookup("seed-corpus"))
			cmdutils.ViperMustBindPFlag("timeout", cmd.Flags().Lookup("timeout"))
			cmdutils.ViperMustBindPFlag("branch", cmd.Flags().Lookup("branch"))
			cmdutils.ViperMustBindPFlag("commit", cmd.Flags().Lookup("commit"))

			projectDir, err := config.ParseProjectConfig(opts)
			if err != nil {
				log.Errorf(err, "Failed to parse cifuzz.yaml: %v", err.Error())
				return cmdutils.WrapSilentError(err)
			}
			opts.ProjectDir = projectDir

			if opts.BuildSystem != config.BuildSystemCMake {
				return errors.New("cifuzz bundle currently only supports CMake projects")
			}
			opts.FuzzTests = args
			return opts.Validate()
		},
		RunE: func(c *cobra.Command, args []string) error {
			opts.Stdout = c.OutOrStdout()
			opts.Stderr = c.OutOrStderr()
			return bundler.NewBundler(opts).Bundle()
		},
	}

	cmd.Flags().Uint("build-jobs", 0, "Maximum number of concurrent processes to use when building.\nIf argument is omitted the native build tool's default number is used.\nOnly available when the build system is CMake.")
	cmd.Flags().Lookup("build-jobs").NoOptDefVal = "0"
	// TODO(afl): Also link to https://github.com/AFLplusplus/AFLplusplus/blob/stable/dictionaries/README.md
	cmd.Flags().String("dict", "", "A `file` containing input language keywords or other interesting byte sequences.\nSee https://llvm.org/docs/LibFuzzer.html#dictionaries.")
	// TODO(afl): Also link to https://www.mankier.com/8/afl-fuzz
	cmd.Flags().StringArray("engine-arg", nil, "Command-line `argument` to pass to the fuzzing engine.\nSee https://llvm.org/docs/LibFuzzer.html#options.")
	cmd.Flags().StringArray("fuzz-test-arg", nil, "Command-line `argument` to pass to the fuzz test.")
	// TODO(afl): Also link to https://aflplus.plus/docs/fuzzing_in_depth/#a-collecting-inputs
	cmd.Flags().StringArrayP("seed-corpus", "s", nil, "A `directory` containing sample inputs for the code under test.\nSee https://llvm.org/docs/LibFuzzer.html#corpus.")
	cmd.Flags().Duration("timeout", 0, "Maximum time to run the fuzz test, e.g. \"30m\", \"1h\". The default is to run indefinitely.")
	cmd.Flags().StringVarP(&opts.OutputPath, "output", "o", "", "Output path of the artifact (.tar.gz)")
	cmd.Flags().StringVar(&opts.Branch, "branch", "", "Branch name to get used instead of the default detecting mechanism. Used in bundle config to identify code revision.")
	cmd.Flags().StringVar(&opts.Commit, "commit", "", "Commit to get used instead of default detecing mechanism. Used in bundle config to identify code revision.")

	return cmd
}
