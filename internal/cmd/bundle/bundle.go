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
	"code-intelligence.com/cifuzz/util/sliceutil"
)

type options struct {
	bundler.Opts `mapstructure:",squash"`
}

func (opts *options) Validate() error {
	if !sliceutil.Contains([]string{config.BuildSystemBazel, config.BuildSystemCMake, config.BuildSystemOther}, opts.BuildSystem) {
		err := errors.Errorf(`Creating a bundle is currently not supported for %[1]s projects. If you
are interested in using this feature with %[1]s, please file an issue at
https://github.com/CodeIntelligenceTesting/cifuzz/issues`, strings.ToTitle(opts.BuildSystem))
		log.Print(err.Error())
		return cmdutils.WrapSilentError(err)
	}

	return opts.Opts.Validate()
}

func New() *cobra.Command {
	return newWithOptions(&options{})
}

func newWithOptions(opts *options) *cobra.Command {
	var bindFlags func()
	cmd := &cobra.Command{
		Use:   "bundle [flags] [<fuzz test>]...",
		Short: "Bundles fuzz tests into an archive",
		Long: `Bundles all runtime artifacts required by the given fuzz tests into
a self-contained archive (bundle) that can be executed by a remote
fuzzing server.

The usage of this command depends on the build system configured for the
project:

 * For CMake, <fuzz test> is the name of the fuzz test as defined in the
   'add_fuzz_test' command in your CMakeLists.txt. Command completion for
   the <fuzz test> argument works if the fuzz test has been built before
   or after running 'cifuzz reload'. The '--build-command' flag is ignored.
   If no fuzz tests are specified, all fuzz tests are added to the bundle.

 * For other build systems, a command which builds the fuzz test executable
   must be provided via the '--build-command' flag or the 'build-command'
   setting in cifuzz.yaml. In this case, <fuzz test> is the path to the
   fuzz test executable created by the build command. The value specified
   for <fuzz test> is available to the build command in the FUZZ_TEST
   environment variable. Example:

       echo "build-command: make clean && make \$FUZZ_TEST" >> cifuzz.yaml
       cifuzz bundle my_fuzz_test

   Alternatively, <fuzz test> can be the name of the fuzz test executable,
   which will then be searched for recursively in the current directory.`,
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

			opts.FuzzTests = args
			return opts.Validate()
		},
		RunE: func(c *cobra.Command, args []string) error {
			opts.Stdout = c.OutOrStdout()
			opts.Stderr = c.OutOrStderr()
			return bundler.NewBundler(&opts.Opts).Bundle()
		},
	}

	bindFlags = cmdutils.AddFlags(cmd,
		cmdutils.AddBranchFlag,
		cmdutils.AddBuildCommandFlag,
		cmdutils.AddBuildJobsFlag,
		cmdutils.AddCommitFlag,
		cmdutils.AddDictFlag,
		cmdutils.AddDockerImageFlag,
		cmdutils.AddEngineArgFlag,
		cmdutils.AddEnvFlag,
		cmdutils.AddProjectDirFlag,
		cmdutils.AddSeedCorpusFlag,
		cmdutils.AddTimeoutFlag,
	)
	cmd.Flags().StringVarP(&opts.OutputPath, "output", "o", "", "Output path of the bundle (.tar.gz)")

	return cmd
}
