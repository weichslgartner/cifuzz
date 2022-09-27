package bundle

import (
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
			cmdutils.ViperMustBindPFlag("build-jobs", cmd.Flags().Lookup("build-jobs"))
			cmdutils.ViperMustBindPFlag("dict", cmd.Flags().Lookup("dict"))
			cmdutils.ViperMustBindPFlag("engine-args", cmd.Flags().Lookup("engine-arg"))
			cmdutils.ViperMustBindPFlag("fuzz-test-args", cmd.Flags().Lookup("fuzz-test-arg"))
			cmdutils.ViperMustBindPFlag("seed-corpus-dirs", cmd.Flags().Lookup("seed-corpus"))
			cmdutils.ViperMustBindPFlag("timeout", cmd.Flags().Lookup("timeout"))
			cmdutils.ViperMustBindPFlag("branch", cmd.Flags().Lookup("branch"))
			cmdutils.ViperMustBindPFlag("commit", cmd.Flags().Lookup("commit"))

			projectDir, err := config.FindAndParseProjectConfig(opts)
			if err != nil {
				log.Errorf(err, "Failed to parse cifuzz.yaml: %v", err.Error())
				return cmdutils.WrapSilentError(err)
			}
			opts.ProjectDir = projectDir

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

	cmdutils.AddBundleFlags(cmd)
	cmd.Flags().StringVarP(&opts.OutputPath, "output", "o", "", "Output path of the artifact (.tar.gz)")
	cmd.Flags().StringVar(&opts.Branch, "branch", "", "Branch name to use in the artifacts config. By default, the currently checked out git branch is used.")
	cmd.Flags().StringVar(&opts.Commit, "commit", "", "Commit to use in the artifacts config. By default, the head of the currently checked out git branch is used.")

	return cmd
}
