package glogutil

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/pkg/errors"
	"github.com/spf13/pflag"

	"code-intelligence.com/cifuzz/util/sliceutil"
	"code-intelligence.com/cifuzz/util/stringutil"
)

var glogFlagNames = []string{
	"alsologtostderr",
	"log_backtrace_at",
	"log_dir",
	"logtostderr",
	"stderrthreshold",
	"v",
	"vmodule",
}

// We use log instead of glog in this package for logging before glog
// was set up completely.
var logger = log.New(os.Stderr, "", log.Lshortfile)

var glogSetupOnce sync.Once

// SetupGlog sets up various things for an improved glog UX:
// * Set up glog flags from environment variables and vice versa.
// * Add glog flags to the default pflag command-line flags, to allow
//   the caller to use the pflag package instead of the flag package.
// * Mark flags we don't want to expose to users as hidden in pflag.
func SetupGlog() error {
	// We call an unexported function here because in this package, we
	// use the log package for logging (because glog is not set up yet)
	// and we set the call depth so that all the stack frames from this
	// package are removed and the log message includes the file and
	// line number of the caller.
	// This only works if there are always the same number of stack
	// frames above all log statements, so we call this unexported
	// function here which can also be called by other exported
	// functions in this package.
	return setupGlog()
}

func setupGlog() error {
	var err error

	// Add glog flags to the default pflag command-line flags, to allow
	// the caller to use the pflag package instead of the flag package.
	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)

	// Set up glog flags from environment variables and vice versa
	glogSetupOnce.Do(func() {
		// Set up glog flags from GLOG_ env vars
		err = setGlogFlagsFromEnv()
		if err != nil {
			return
		}
		// Set GLOG_ env vars for all currently set glog flags. This allows
		// commands called by us to use the same glog settings as we do (
		// when they also call SetupGlog()).
		err = setGlogEnvVarsFromArgs()
		if err != nil {
			return
		}
	})
	if err != nil {
		return err
	}

	// Mark flags we want to support but not expose to users as hidden.
	// Those are "vmodule" and "log_backtrace_at", which can be useful
	// for debugging, but require knowledge about the source files, so
	// they are not useful for our users. Note that this will only hide
	// them when the caller uses pflag, because the flag package doesn't
	// support hidden flags.
	hiddenFlags := []string{"vmodule", "log_backtrace_at"}
	for _, name := range hiddenFlags {
		err = pflag.CommandLine.MarkHidden(name)
		if err != nil {
			return err
		}
	}

	// Avoid glog printing "ERROR: logging before flag.Parse"
	_ = flag.CommandLine.Parse([]string{})

	return nil
}

// SetupGlogAlwaysPrintToStderr does the same as SetupGlog, but it also:
// * configures glog to always print to stderr (and never to a log file)
// * removes all the glog flags related to logging to files
func SetupGlogAlwaysPrintToStderr() error {
	err := useReducedGlogFlagSet()
	if err != nil {
		return err
	}

	return setupGlog()
}

func useReducedGlogFlagSet() error {
	var err error

	// Create a new empty flag set
	flags := flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	// Copy the glog flags we want to support to the new flag set
	flag.CommandLine.VisitAll(func(f *flag.Flag) {
		switch f.Name {
		// Flags we want to support
		case "v":
			flags.Var(f.Value, f.Name, "verbosity level")
		case "vmodule", "log_backtrace_at":
			flags.Var(f.Value, f.Name, f.Usage)
		// Always log to stderr
		case "logtostderr":
			err = f.Value.Set("true")
			return
		}
	})
	if err != nil {
		return err
	}

	// Overwrite the default flag set, to remove the flags which glog
	// added in its init() method
	flag.CommandLine = flags

	return nil
}

func getGlogFlagSet() *pflag.FlagSet {
	// Create a new empty flag set
	flags := pflag.NewFlagSet(os.Args[0], pflag.ExitOnError)

	// Copy the glog flags we want to support to the new flag set
	flag.CommandLine.VisitAll(func(f *flag.Flag) {
		if sliceutil.Contains(glogFlagNames, f.Name) {
			flags.AddGoFlag(f)
		}
	})
	return flags
}

func getGlogArgs() []string {
	var args []string
	glogFlags := getGlogFlagSet()
	// Parse all glog flags from the provided arguments and ignore
	// other flags
	glogFlags.ParseErrorsWhitelist = pflag.ParseErrorsWhitelist{UnknownFlags: true}
	// Don't parse --help and -h because that would cause the Parse()
	// function to print the usage message for the glog flags and then
	// call os.Exit(0).
	argsWithoutHelpFlag := stringutil.SubtractSlices(os.Args[1:], []string{"--help", "-h", "-help", "--h"})
	// Ignore errors; glogFlags is set for ExitOnError.
	_ = glogFlags.Parse(argsWithoutHelpFlag)
	glogFlags.VisitAll(func(f *pflag.Flag) {
		if f.Changed && sliceutil.Contains(glogFlagNames, f.Name) {
			args = append(args, f.Name+"="+f.Value.String())
		}
	})
	return args
}

// SetupGlogWithVerbosity sets up glog flags for increased verbosity and
// then calls SetupGlog.
func SetupGlogWithVerbosity(level uint8) (err error) {
	if err = flag.Set("stderrthreshold", "0"); err != nil {
		return errors.WithStack(err)
	}
	if err = flag.Set("v", strconv.Itoa(int(level))); err != nil {
		return errors.WithStack(err)
	}
	return setupGlog()
}

func setGlogFlagsFromEnv() (err error) {
	for _, envvar := range os.Environ() {
		if !strings.HasPrefix(envvar, "GLOG_") {
			continue
		}
		a := strings.SplitN(envvar, "=", 2)
		name, value := a[0], a[1]
		if value == "" {
			continue
		}
		name = strings.TrimPrefix(name, "GLOG_")
		name = strings.ToLower(name)
		// We can use pflag.CommandLine here because we added
		// flag.CommandLine to pflag.CommandLine above.
		err = pflag.CommandLine.Set(name, value)
		// Some of our tools support other glog flags than other tools,
		// so it's expected that some flags can't be passed. We don't
		// want to fail in that case, so we only print the error.
		if err != nil {
			// Commented out because it's too noisy
			//logger.Output(7, fmt.Sprintf("Ignoring glog flag: %s", err.Error()))
		} else {
			logger.Output(7, fmt.Sprintf("Set glog flag -%s=%s", name, value))
		}
	}
	return nil
}

// Gets the currently set GLOG environment variables in the form
// "key=value"
func GlogEnvVars() []string {
	var res []string
	for _, envvar := range os.Environ() {
		if strings.HasPrefix(envvar, "GLOG_") {
			res = append(res, envvar)
		}
	}
	return res
}

// Sets GLOG environment variables from the glog arguments
func setGlogEnvVarsFromArgs() error {
	var err error
	args := getGlogArgs()
	for _, arg := range args {
		var key, val string
		a := strings.SplitN(arg, "=", 2)
		switch len(a) {
		case 1:
			key, val = a[0], "1"
		case 2:
			key, val = a[0], a[1]
		default:
			return errors.Errorf("Invalid glog arg %q", arg)
		}

		err = os.Setenv("GLOG_"+key, val)
		if err != nil {
			return errors.WithStack(err)
		}
		logger.Output(7, fmt.Sprintf("Set %s=%s", "GLOG_"+key, val))
	}
	return nil
}
