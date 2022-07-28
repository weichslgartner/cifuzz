package main

import (
	"os"
	"path/filepath"

	"github.com/spf13/pflag"

	"code-intelligence.com/cifuzz/pkg/install"
	"code-intelligence.com/cifuzz/pkg/log"
)

func main() {
	flags := pflag.NewFlagSet("bundler", pflag.ExitOnError)
	version := flags.StringP("version", "v", "dev", "the target version of cifuzz")
	helpRequested := flags.BoolP("help", "h", false, "")

	if err := flags.Parse(os.Args); err != nil {
		log.Error(err, err.Error())
		os.Exit(1)
	}

	if *helpRequested {
		log.Print("Usage of bundler:")
		flags.PrintDefaults()
		os.Exit(0)
	}

	projectDir, err := install.FindProjectDir()
	if err != nil {
		log.Error(err, err.Error())
		os.Exit(1)
	}
	targetDir := filepath.Join(projectDir, "tools", "install", "bundler", "embed", "bundle")
	if err = os.RemoveAll(targetDir); err != nil {
		log.Error(err, err.Error())
		os.Exit(1)
	}

	opts := install.Options{
		Version:   *version,
		TargetDir: targetDir,
	}

	bundler, err := install.NewInstallationBundler(opts)
	if err != nil {
		log.Error(err, err.Error())
		os.Exit(1)
	}

	if err = bundler.BuildCIFuzzAndDeps(); err != nil {
		log.Error(err, err.Error())
		os.Exit(1)
	}
}
