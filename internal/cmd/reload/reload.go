package run

import (
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"code-intelligence.com/cifuzz/internal/build/cmake"
	"code-intelligence.com/cifuzz/internal/config"
	"code-intelligence.com/cifuzz/pkg/dependencies"
	"code-intelligence.com/cifuzz/pkg/runfiles"
)

// TODO: The reload command allows to reload the fuzz test names used
//       for autocompletion from the cmake config. It's only meant as a
//       temporary solution until we find a better solution.
type reloadCmd struct {
	*cobra.Command

	config *config.Config
}

func New(projectConfig *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "reload [flags]",
		Short: "Reload fuzz test metadata",
		// TODO: Write long description
		Long: "",
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, args []string) error {
			cmd := reloadCmd{Command: c, config: projectConfig}
			return cmd.run()
		},
	}
	return cmd
}

func (c *reloadCmd) run() error {
	depsOk, err := c.checkDependencies()
	if err != nil {
		return err
	}
	if !depsOk {
		return dependencies.Error()
	}

	if c.config.BuildSystem == config.BuildSystemCMake {
		return c.reloadCMake()
	} else if c.config.BuildSystem == config.BuildSystemOther {
		// Nothing to reload for other build system
		return nil
	} else {
		return errors.Errorf("Unsupported build system \"%s\"", c.config.BuildSystem)
	}
}

func (c *reloadCmd) reloadCMake() error {
	// TODO: Make these configurable
	engine := "libfuzzer"
	sanitizers := []string{"address", "undefined"}

	builder, err := cmake.NewBuilder(&cmake.BuilderOptions{
		ProjectDir: c.config.ProjectDir,
		Engine:     engine,
		Sanitizers: sanitizers,
		Stdout:     c.OutOrStdout(),
		Stderr:     c.ErrOrStderr(),
	})
	if err != nil {
		return err
	}

	err = builder.Configure()
	if err != nil {
		return err
	}
	return nil
}

func (c *reloadCmd) checkDependencies() (bool, error) {
	deps := []dependencies.Key{}
	if c.config.BuildSystem == config.BuildSystemCMake {
		deps = append(deps, []dependencies.Key{dependencies.CLANG, dependencies.CMAKE}...)
	}
	return dependencies.Check(deps, dependencies.Default, runfiles.Finder)
}
