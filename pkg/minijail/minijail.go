package main

// A small wrapper around minijail.
// We use a separate tool to call minijail via syscall.Exec() because:
// * Sometimes, for a reason unknown to me, when called via
//   exec.Command(), minijail doesn't print anything to stderr, while
//   it does when called via syscall.Exec().
// * It allows fuzzer_monitor to kill minijail by sending signals to its
//   child process (i.e. the one started for this program).

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/golang/glog"
	"github.com/pkg/errors"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"golang.org/x/sys/unix"

	minijail "code-intelligence.com/cifuzz/pkg/minijail/pkg"
	"code-intelligence.com/cifuzz/util/fileutil"
	"code-intelligence.com/cifuzz/util/glogutil"
	"code-intelligence.com/cifuzz/util/runfileutil"
	"code-intelligence.com/cifuzz/util/stringutil"
)

var fixedMinijailArgs = []string{
	// Most of these args are the same as the ones clusterfuzz sets in
	// their minijail wrapper:
	// https://github.com/google/clusterfuzz/blob/4f8020c4c7ce73c1da0e68f04943af30bb5f0b32/src/clusterfuzz/_internal/system/minijail.py
	//
	// In contrast to clusterfuzz, we don't set "-T static", but do
	// preload libminijailpreload.so, to prevent circumvention of the
	// seccomp filters, as described in the minijail manual:
	// https://google.github.io/minijail/minijail0.1.html
	//
	"-U", "-m", // Quote from clusterfuzz:
	// root (uid 0 in namespace) -> USER.
	// The reason for this is that minijail does setresuid(0, 0, 0) before doing a
	// chroot, which means uid 0 needs access to the chroot dir (owned by USER).
	//
	// Note that we also run fuzzers as uid 0 (but with no capabilities in
	// permitted/effective/inherited sets which *should* mean there"s nothing
	// special about it). This is because the uid running the fuzzer also need
	// access to things owned by USER (fuzzer binaries, supporting files), and USER
	// can only be mapped once.
	"-M",      // Map current gid to root
	"-c", "0", // drop all capabilities.
	"-n", // no_new_privs
	"-v", // mount namespace
	"-p", // PID namespace
	"-l", // IPC namespace
	"-I", // Run jailed process as init.
	// Mount procfs read-only
	"-k", "proc,/proc,proc," + strconv.Itoa(unix.MS_RDONLY),
	// Mount a tmpfs on /dev/shm to allow using shared memory.
	"-k", "tmpfs,/dev/shm,tmpfs," + strconv.Itoa(unix.MS_NOSUID|unix.MS_NODEV|unix.MS_STRICTATIME) + ",mode=1777",
	// Added by us, to log to stderr
	"--logging=stderr",
}

var defaultBindings = []*minijail.Binding{
	// The second value specifies whether the binding is read-only (0)
	// or read-write (1).
	{Source: "/lib"},
	{Source: "/lib32"},
	{Source: "/lib64"},
	{Source: "/usr/lib"},
	{Source: "/usr/lib32"},
	// Added by us
	{Source: minijail.OutputDir, Writable: minijail.ReadWrite},
	// We allow access to /dev/null and /dev/urandom because AFL needs
	// access to them and some fuzz targets might as well (for example
	// our lighttpd example fuzz target).
	// They have to be mounted read-write, else minijail fails with
	// libminijail[1]: cannot bind-remount: [...] Operation not permitted
	{Source: "/dev/null", Writable: minijail.ReadWrite},
	{Source: "/dev/urandom", Writable: minijail.ReadWrite},
	// We allow access to /etc/passwd and /etc/group because some fuzz
	// targets (for example nginx) will fail if they can't obtain the
	// UID and GID for a specified user and group (specifying a UID
	// instead doesn't seem to be supported by nginx).
	{Source: "/etc/passwd"},
	{Source: "/etc/group"},
}

func runMinijail(fuzzerArgs []string) error {
	// Evaluate symlinks in the fuzzer path
	fuzzer, err := filepath.EvalSymlinks(fuzzerArgs[0])
	if err != nil {
		return errors.WithStack(err)
	}
	fuzzerArgs[0] = fuzzer

	// --------------------------
	// --- Create directories ---
	// --------------------------
	// Create chroot directory
	chrootDir, err := fileutil.TempDir("minijail-chroot-")
	if err != nil {
		return err
	}
	defer fileutil.Cleanup(chrootDir)

	// Create output directory
	err = os.MkdirAll(minijail.OutputDir, 0700)
	if err != nil {
		return errors.WithStack(err)
	}

	// Create /tmp, /proc directories.
	for _, dir := range []string{"/proc", "/tmp"} {
		err = os.MkdirAll(filepath.Join(chrootDir, dir), 0o755)
		if err != nil {
			return errors.WithStack(err)
		}
	}

	// Create /dev/shm which is required to allow using shared memory
	err = os.MkdirAll(filepath.Join(chrootDir, "/dev/shm"), 0o755)
	if err != nil {
		return errors.WithStack(err)
	}

	// ----------------------------
	// --- Set up minijail args ---
	// ----------------------------
	minijailPath, err := runfileutil.FindFollowSymlinks("minijail/minijail_make/bin/minijail0")
	if err != nil {
		return err
	}
	minijailArgs := append([]string{minijailPath}, fixedMinijailArgs...)

	if os.Getenv(minijail.DebugEnvVarName) != "" {
		glog.Warningf("Running minijail in debug mode, this is NOT SAFE FOR PRODUCTION!")
		// This causes minijail to not use preload hooking, which
		// sometimes results in better error messages, so it can be
		// useful for debugging but shouldn't be used in production
		minijailArgs = append(minijailArgs, "-T", "static", "--ambient")
	} else {
		// Set path to libminijailpreload.so
		libminijailpreloadRunfilePath := "minijail/minijail_make/lib/libminijailpreload.so"
		libminijailpreload, err := runfileutil.FindFollowSymlinks(libminijailpreloadRunfilePath)
		if err != nil {
			return err
		}
		minijailArgs = append(minijailArgs, "--preload-library="+libminijailpreload)
	}

	// Change root filesystem to the chroot directory. See pivot_root(2).
	minijailArgs = append(minijailArgs, "-P", chrootDir)

	// -----------------------
	// --- Set up bindings ---
	// -----------------------
	bindings := defaultBindings

	// We expect the current working directory to be the artifacts
	// directory, which should be accessible to the fuzz target, so we
	// add a binding for it.
	// Some fuzz targets (e.g. the one for nginx) write to the working
	// directory, which is why we mount it read-write. We decided that
	// this is fine on CIFUZZ-1192.
	workdir, err := os.Getwd()
	if err != nil {
		return errors.WithStack(err)
	}
	bindings = append(bindings, &minijail.Binding{Source: workdir, Writable: minijail.ReadWrite})

	// Add binding for the fuzzer executable
	bindings = append(bindings, &minijail.Binding{Source: fuzzer})

	// Add llvm to bindings
	llvmDir, err := runfileutil.FindDirFollowSymlinks("llvm", "bin/llvm-symbolizer")
	if err != nil {
		return err
	}
	bindings = append(bindings, &minijail.Binding{Source: llvmDir})

	// Add binding for process_wrapper. process_wrapper changes the
	// working directory and sets environment variables and then
	// executes the specified command.
	processWrapperPath, err := runfileutil.FindFollowSymlinks("code_intelligence/cifuzz/pkg/minijail/process_wrapper/process_wrapper")
	if err != nil {
		return err
	}
	bindings = append(bindings, &minijail.Binding{Source: processWrapperPath})

	// Add additional bindings from the environment variable
	additionalBindings := os.Getenv(minijail.BindingsEnvVarName)
	for _, s := range strings.Split(additionalBindings, ":") {
		if s == "" {
			continue
		}
		binding, err := minijail.BindingFromString(s)
		if err != nil {
			return err
		}
		bindings = append(bindings, binding)
	}

	// Add bindings from flags
	for _, s := range viper.GetStringSlice(minijail.BindingFlag) {
		b, err := minijail.BindingFromString(s)
		if err != nil {
			return err
		}
		bindings = append(bindings, b)
	}

	// Create the bindings
	for _, binding := range bindings {
		if binding.Target == "" {
			binding.Target = binding.Source
		}
		// Skip if the source doesn't exist
		exists, err := fileutil.Exists(binding.Source)
		if err != nil {
			return err
		}
		if !exists {
			continue
		}

		// Create the destination
		if fileutil.IsDir(binding.Source) {
			err = os.MkdirAll(filepath.Join(chrootDir, binding.Target), 0o755)
			if err != nil {
				return errors.WithStack(err)
			}
		} else {
			err = os.MkdirAll(filepath.Join(chrootDir, filepath.Dir(binding.Target)), 0o755)
			if err != nil {
				return errors.WithStack(err)
			}
			err = fileutil.Touch(filepath.Join(chrootDir, binding.Target))
			if err != nil {
				return err
			}
		}

		minijailArgs = append(minijailArgs, "-b", binding.String())
	}

	// -----------------------------------
	// --- Set up process wrapper args ---
	// -----------------------------------
	// The process wrapper changes the working directory inside the
	// sandbox to the first argument
	processWrapperArgs := []string{processWrapperPath, workdir}

	// The process wrapper sets environment variables inside the sandbox
	// to the remaining arguments until the first "--", so we pass
	// variables from the --env flags
	processWrapperArgs = append(processWrapperArgs, viper.GetStringSlice(minijail.EnvFlag)...)

	// --------------------
	// --- Run minijail ---
	// --------------------
	var env []string
	args := stringutil.JoinSlices("--", minijailArgs, processWrapperArgs, fuzzerArgs)

	// When CI_DEBUG_MINIJAIL_SLEEP_FOREVER is set, instead of executing
	// the actual command, we store it in the CMD environment variable
	// and start a shell to allow debugging issues interactively.
	if os.Getenv("CI_DEBUG_MINIJAIL_SLEEP_FOREVER") != "" {
		_ = os.MkdirAll(filepath.Join(chrootDir, "bin"), 0o755)
		minijailArgs = append(minijailArgs, "-b", "/bin")
		processWrapperArgs = append(processWrapperArgs, "CMD="+strings.Join(fuzzerArgs, " "))
		args = stringutil.JoinSlices("--", minijailArgs, processWrapperArgs, []string{"/bin/sh"})
	}

	glog.Infof("Command: %s", strings.Join(stringutil.QuotedStrings(args), " "))
	err = syscall.Exec(args[0], args, env)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func run(args []string) error {
	help := pflag.BoolP("help", "h", false, "Print usage")
	// The double backtick in the usage string avoids that the type name
	// "StringArray" is printed in the usage. Instead, we document the
	// expected format via the NoOptDefVal attribute.
	pflag.StringArrayP(minijail.EnvFlag, "e", nil,
		"``Set environment variables inside the sandbox. Example: -e FOO=BAR")
	pflag.Lookup(minijail.EnvFlag).NoOptDefVal = "<key>=<val>"
	pflag.StringArrayP(minijail.BindingFlag, "b", nil,
		"``Bind <src> to <dest> in chroot, writable if <writable> is 1. Example: -b /foo,/bar,1")
	pflag.Lookup(minijail.BindingFlag).NoOptDefVal = "<src>[,[dest][,<writeable>]]"

	err := glogutil.SetupGlogAlwaysPrintToStderr()
	if err != nil {
		return err
	}

	err = viper.BindPFlags(pflag.CommandLine)
	if err != nil {
		return err
	}

	err = pflag.CommandLine.Parse(args[1:])
	if err != nil {
		return err
	}

	pflag.Usage = func() {
		_, _ = fmt.Fprintf(os.Stderr, "Usage: %s [<option>...] -- <program> [<arg>...]\n%s", args[0], pflag.CommandLine.FlagUsages())
	}

	if *help {
		pflag.Usage()
		return nil
	}

	if pflag.NArg() < 1 {
		pflag.Usage()
		return fmt.Errorf("error: %s requires least one argument", args[0])
	}

	err = runMinijail(pflag.Args())
	if err != nil {
		return err
	}

	return nil
}

func main() {
	err := run(os.Args)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%+v\n", err)
		os.Exit(1)
	}
}
