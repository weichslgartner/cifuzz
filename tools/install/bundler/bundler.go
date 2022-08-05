package main

import (
	"os"
	"path/filepath"
	"runtime"

	"github.com/spf13/pflag"

	"code-intelligence.com/cifuzz/pkg/install"
	"code-intelligence.com/cifuzz/pkg/log"
)

func main() {
	flags := pflag.NewFlagSet("bundler", pflag.ExitOnError)
	version := flags.StringP("version", "v", "dev", "the target version of cifuzz")
	goos := flags.String("goos", runtime.GOOS, "cross compilation OS, defaults to runtime.GOOS")
	goarch := flags.String("goarch", runtime.GOARCH, "cross compilation GOARCH, defaults to runtime.GOARCH")
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
		GOOS:      *goos,
		GOARCH:    *goarch,
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
