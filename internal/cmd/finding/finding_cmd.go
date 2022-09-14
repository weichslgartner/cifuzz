package finding

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/pkg/errors"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"

	"code-intelligence.com/cifuzz/internal/cmdutils"
	"code-intelligence.com/cifuzz/internal/completion"
	"code-intelligence.com/cifuzz/internal/config"
	"code-intelligence.com/cifuzz/pkg/finding"
	"code-intelligence.com/cifuzz/pkg/log"
	"code-intelligence.com/cifuzz/util/stringutil"
)

type options struct {
	PrintJSON bool `mapstructure:"print-json"`
	ShowAll   bool
}

type findingCmd struct {
	*cobra.Command
	opts *options
}

func New() *cobra.Command {
	opts := &options{}
	cmd := &cobra.Command{
		Use:               "finding [name]",
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
	cmd.Flags().BoolVar(&opts.ShowAll, "all", false, "Show all findings")

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

	if cmd.opts.ShowAll {
		findings, err := finding.ListFindings(projectDir)
		if err != nil {
			return err
		}

		if len(findings) == 0 {
			log.Print("This project doesn't have any findings yet")
			return nil
		}

		for _, f := range findings {
			err = cmd.printFinding(f)
			if err != nil {
				return err
			}
			// Print a newline to separate the findings
			_, _ = fmt.Fprintln(cmd.OutOrStdout())
		}
		return nil
	}

	if len(args) == 0 {
		// If called without arguments, `cifuzz findings` lists short
		// descriptions of all findings
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

		w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 1, ' ', 0)
		for _, f := range findings {
			_, _ = fmt.Fprintln(w, f.Name, "\t", strings.Join(f.ShortDescriptionColumns(), "\t"))
		}
		err = w.Flush()
		if err != nil {
			return errors.WithStack(err)
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
	return cmd.printFinding(f)
}

func (cmd *findingCmd) printFinding(f *finding.Finding) error {
	if cmd.opts.PrintJSON {
		s, err := stringutil.ToJsonString(f)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(cmd.OutOrStdout(), s)
		if err != nil {
			return err
		}
	} else {
		s := pterm.Style{pterm.Reset, pterm.Bold}.Sprint(f.ShortDescriptionWithName())
		s += fmt.Sprintf("\nDate: %s\n", f.CreatedAt)
		s += fmt.Sprintf("\n  %s\n", strings.Join(f.Logs, "\n  "))
		_, err := fmt.Fprintf(cmd.OutOrStdout(), s)
		if err != nil {
			return err
		}
	}
	return nil
}
