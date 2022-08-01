package main

import (
	"os"
	"path/filepath"

	"github.com/spf13/pflag"

	"code-intelligence.com/cifuzz/pkg/install"
	"code-intelligence.com/cifuzz/pkg/log"
	"code-intelligence.com/cifuzz/tools/install/bundler/embed"
)

func main() {
	flags := pflag.NewFlagSet("cifuzz installer", pflag.ExitOnError)
	installDir := flags.StringP("install-dir", "i", "~/cifuzz", "The directory to install cifuzz in")
	helpRequested := flags.BoolP("help", "h", false, "")

	if err := flags.Parse(os.Args); err != nil {
		log.Error(err, err.Error())
		os.Exit(1)
	}

	if *helpRequested {
		log.Printf("Usage of cifuzz installer:")
		flags.PrintDefaults()
		os.Exit(0)
	}

	fs := &embed.Bundle
	if err := install.ExtractBundle(*installDir, fs); err != nil {
		log.Error(err, err.Error())
		os.Exit(1)
	}

	binDir := filepath.Join(*installDir, "bin")
	install.PrintPathInstructions(binDir)
}
