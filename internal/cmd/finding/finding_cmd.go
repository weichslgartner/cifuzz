package finding

import (
	"fmt"
	"os"
	"strings"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"code-intelligence.com/cifuzz/internal/completion"
	"code-intelligence.com/cifuzz/internal/config"
	"code-intelligence.com/cifuzz/pkg/cmdutils"
	"code-intelligence.com/cifuzz/pkg/finding"
	"code-intelligence.com/cifuzz/pkg/log"
	"code-intelligence.com/cifuzz/util/stringutil"
)

type options struct {
	PrintJSON bool `mapstructure:"print-json"`
}

type findingCmd struct {
	*cobra.Command
	opts *options
}

func New() *cobra.Command {
	opts := &options{}
	cmd := &cobra.Command{
		Use:               "finding",
		Aliases:           []string{"findings"},
		Short:             "List and show findings",
		Args:              cobra.MaximumNArgs(1),
		ValidArgsFunction: completion.ValidFindings,
		PreRun: func(cmd *cobra.Command, args []string) {
			// Bind viper keys to flags. We can't do this in the New
			// function, because that would re-bind viper keys which
			// were bound to the flags of other commands before.
			cmdutils.ViperMustBindPFlag("print-json", cmd.Flags().Lookup("json"))
		},
		RunE: func(c *cobra.Command, args []string) error {
			cmd := findingCmd{Command: c, opts: opts}
			return cmd.run(args)
		},
	}

	// Note: If a flag should be configurable via cifuzz.yaml as well,
	//       bind it to viper in the PreRun function.
	cmd.Flags().BoolVar(&opts.PrintJSON, "json", false, "Print output as JSON")

	return cmd
}

func (cmd *findingCmd) run(args []string) error {
	projectDir, err := config.FindProjectDir()
	if errors.Is(err, os.ErrNotExist) {
		// The project directory doesn't exist, this is an expected
		// error, so we print it and return a silent error to avoid
		// printing a stack trace
		log.Error(err, fmt.Sprintf("%s\nUse 'cifuzz init' to set up a project for use with cifuzz.", err.Error()))
		return cmdutils.ErrSilent
	}
	if err != nil {
		return err
	}

	if len(args) == 0 {
		// If called without arguments, `cifuzz findings` lists the
		// findings
		findings, err := finding.ListFindings(projectDir)
		if err != nil {
			return err
		}

		if cmd.opts.PrintJSON {
			s, err := stringutil.ToJsonString(findings)
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), s)
			return nil
		}

		if len(findings) == 0 {
			log.Print("This project doesn't have any findings yet")
			return nil
		}
		for _, f := range findings {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), f.Name)
		}
		return nil
	}

	// If called with one argument, `cifuzz finding <finding name>`
	// prints the information available for the specified finding
	findingName := args[0]
	f, err := finding.LoadFinding(projectDir, findingName)
	if finding.IsNotExistError(err) {
		log.Errorf(err, "Finding %s does not exist", findingName)
		return cmdutils.WrapSilentError(err)
	}
	if err != nil {
		return err
	}

	if cmd.opts.PrintJSON {
		s, err := stringutil.ToJsonString(f)
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), s)
	} else {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), strings.Join(f.Logs, "\n"))
	}

	return nil
}
