package bundle

import (
	"os"
	"runtime"
	"strings"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"code-intelligence.com/cifuzz/internal/bundler"
	"code-intelligence.com/cifuzz/internal/cmdutils"
	"code-intelligence.com/cifuzz/internal/completion"
	"code-intelligence.com/cifuzz/internal/config"
	"code-intelligence.com/cifuzz/pkg/log"
)

func New() *cobra.Command {
	return newWithOptions(&bundler.Opts{})
}

func newWithOptions(opts *bundler.Opts) *cobra.Command {
	var bindFlags func()
	cmd := &cobra.Command{
		Use:   "bundle [flags] [<fuzz test>]...",
		Short: "Bundles fuzz tests into an archive",
		Long: `Bundles all runtime artifacts required by the given fuzz tests into
a self-contained archive that can be executed by a remote fuzzing server.
If no fuzz tests are specified all fuzz tests are added to the bundle.`,
		ValidArgsFunction: completion.ValidFuzzTests,
		Args:              cobra.ArbitraryArgs,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			// Bind viper keys to flags. We can't do this in the New
			// function, because that would re-bind viper keys which
			// were bound to the flags of other commands before.
			bindFlags()

			// Fail early if the platform is not supported. Creating the
			// bundle actually works on all platforms, but the backend
			// currently only supports running a bundle on Linux, so the
			// user can't do anything useful with a bundle created on
			// other platforms.
			//
			// We set CIFUZZ_BUNDLE_ON_UNSUPPORTED_PLATFORMS in tests to
			// still be able to test that creating the bundle works on
			// all platforms.
			if os.Getenv("CIFUZZ_BUNDLE_ON_UNSUPPORTED_PLATFORMS") == "" && runtime.GOOS != "linux" {
				system := strings.ToTitle(runtime.GOOS)
				if runtime.GOOS == "darwin" {
					system = "macOS"
				}
				err := errors.Errorf(`Creating a bundle is currently only supported on Linux. If you are
interested in using this feature on %s, please file an issue at
https://github.com/CodeIntelligenceTesting/cifuzz/issues`, system)
				log.Print(err.Error())
				return cmdutils.WrapSilentError(err)
			}

			err := config.FindAndParseProjectConfig(opts)
			if err != nil {
				log.Errorf(err, "Failed to parse cifuzz.yaml: %v", err.Error())
				return cmdutils.WrapSilentError(err)
			}

			if opts.BuildSystem != config.BuildSystemCMake {
				err = errors.New("'cifuzz bundle' currently only supports CMake projects")
				log.Error(err)
				return cmdutils.WrapSilentError(err)
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

	bindFlags = cmdutils.AddFlags(cmd,
		cmdutils.AddBranchFlag,
		cmdutils.AddBuildJobsFlag,
		cmdutils.AddCommitFlag,
		cmdutils.AddDictFlag,
		cmdutils.AddEngineArgFlag,
		cmdutils.AddEnvFlag,
		cmdutils.AddFuzzTestArgFlag,
		cmdutils.AddProjectDirFlag,
		cmdutils.AddSeedCorpusFlag,
		cmdutils.AddTimeoutFlag,
	)
	cmd.Flags().StringVarP(&opts.OutputPath, "output", "o", "", "Output path of the artifacts archive (.tar.gz)")

	return cmd
}
