package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	initCmd "github.com/CodeIntelligenceTesting/cifuzz/pkg/cmd/init"
	"github.com/CodeIntelligenceTesting/cifuzz/pkg/cmdutil"
)

func init() {
	viper.SetEnvPrefix("CIFUZZ")
	viper.AutomaticEnv()
}

func NewRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use: "cifuzz",
		// Tell cobra to not automatically print the usage message when
		// an error is returned. We print the usage message ourselves
		// when an IncorrectUsageError is returned.
		SilenceUsage: true,
	}

	cmd.AddCommand(initCmd.Cmd)

	return cmd
}

func main() {
	rootCmd := NewRootCmd()
	cmd, err := rootCmd.ExecuteC()
	if err != nil {
		var incorrectUsageError *cmdutil.IncorrectUsageError
		if errors.As(err, &incorrectUsageError) {
			_, _ = fmt.Fprintln(os.Stderr, cmd.UsageString())
		}

		os.Exit(1)
	}
}
