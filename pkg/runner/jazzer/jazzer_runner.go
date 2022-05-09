package jazzer

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/pkg/errors"

	minijail "code-intelligence.com/cifuzz/pkg/minijail/pkg"
	"code-intelligence.com/cifuzz/pkg/runner/libfuzzer"
	"code-intelligence.com/cifuzz/util/envutil"
	"code-intelligence.com/cifuzz/util/runfileutil"
	"code-intelligence.com/cifuzz/util/stringutil"
)

// List of non-open-sourced hooks that should be used for Java API fuzzing.
var customHooks = []string{
	"com.code_intelligence.jazzer.sanitizers.FileIOHooks",
	"com.code_intelligence.jazzer.sanitizers.SQLHooks",
}

type RunnerOptions struct {
	LibfuzzerOptions              *libfuzzer.RunnerOptions
	AutofuzzTarget                string
	TargetClass                   string
	ClassPaths                    []string
	InstrumentationPackageFilters []string
}

func (options *RunnerOptions) ValidateOptions() error {
	err := options.LibfuzzerOptions.ValidateOptions()
	if err != nil {
		return err
	}

	if options.AutofuzzTarget == "" && options.TargetClass == "" {
		return errors.New("Either a autofuzz target or a target class must be specified")
	}
	if options.AutofuzzTarget != "" && options.TargetClass != "" {
		return errors.New("Only specify either an autofuzz target or a target class")
	}

	return nil
}

type Runner struct {
	*RunnerOptions
	*libfuzzer.Runner
}

func NewRunner(options *RunnerOptions) *Runner {
	libfuzzerRunner := libfuzzer.NewRunner(options.LibfuzzerOptions)
	libfuzzerRunner.SupportJazzer = true
	return &Runner{options, libfuzzerRunner}
}

func (r *Runner) Run(ctx context.Context) error {
	var err error

	var driverPath string
	driverPath, err = runfileutil.FindFollowSymlinks("jazzer/driver/jazzer_driver")
	if err != nil {
		return err
	}
	agentPath, err := runfileutil.FindFollowSymlinks("jazzer/agent/jazzer_agent_deploy.jar")
	if err != nil {
		return err
	}
	additionalSanitizersPath, err := runfileutil.FindFollowSymlinks("code_intelligence/pkg/web_app/agents/java/runtime_sanitizers_only_deploy.jar")
	if err != nil {
		return err
	}

	args := []string{driverPath}

	// ----------------------
	// --- Jazzer options ---
	// ----------------------
	if r.AutofuzzTarget != "" {
		args = append(args, "--autofuzz="+r.AutofuzzTarget)
	} else {
		args = append(args, "--target_class="+r.TargetClass)
	}

	classpathWithInternalTools := append(r.ClassPaths, additionalSanitizersPath)
	args = append(args, fmt.Sprintf("--cp=%s", strings.Join(classpathWithInternalTools, ":")))

	args = append(args, "--agent_path="+agentPath)
	args = append(args, instrumentorAgentArgs(r.InstrumentationPackageFilters)...)

	// -------------------------
	// --- libfuzzer options ---
	// -------------------------
	// Tell libfuzzer to exit after the timeout
	timeoutSeconds := strconv.FormatInt(int64(r.Timeout.Seconds()), 10)
	args = append(args, "-max_total_time="+timeoutSeconds)

	// Tell libfuzzer which dictionary it should use
	if r.Dictionary != "" {
		args = append(args, "-dict="+r.Dictionary)
	}

	// Add user-specified Jazzer/libfuzzer options
	args = append(args, r.EngineArgs...)

	// For Jazzer, we increase the default OOM limit further away from the JVM's maximum heap size of 1800 MB to
	// prevent spurious OOMs, which abort a fuzzing run.
	if !stringutil.ContainsStringWithPrefix(r.EngineArgs, "-rss_limit_mb=") {
		args = append(args, "-rss_limit_mb=3000")
	}

	// Tell libfuzzer which corpus directory it should use
	args = append(args, r.SeedsDir)

	// -----------------------------
	// --- fuzz target arguments ---
	// -----------------------------
	if len(r.FuzzTargetArgs) > 0 {
		// separate the Jazzer/libfuzzer arguments and fuzz target
		// arguments with a "--"
		args = append(args, "--")
		args = append(args, r.FuzzTargetArgs...)
	}
	// -----------------------------

	// The environment we run the fuzzer in
	fuzzerEnv, err := r.FuzzerEnvironment()
	if err != nil {
		return err
	}

	// The environment we run our minijail wrapper in
	wrapperEnv := os.Environ()

	if r.UseMinijail {
		jazzerArgs := args

		// Execute Jazzer via minijail
		minijailPath, err := runfileutil.FindFollowSymlinks("code_intelligence/cifuzz/pkg/minijail/minijail_/minijail")
		if err != nil {
			return err
		}
		minijailArgs := []string{minijailPath}

		// TODO(adrian): I couldn't find out what this option does
		//args = append(args, "--reproducer_path="+minijail.OutputDir)

		// Add bindings
		bindings := []minijail.Binding{
			// The Jazzer agent must be accessible
			{Source: agentPath},
			// The first corpus directory must be writable, because
			// libfuzzer writes new test inputs to it
			{Source: r.SeedsDir, Writable: minijail.ReadWrite},
			// The additional sanitizers jar must be accessible
			{Source: additionalSanitizersPath},
		}

		// Add bindings for the Java dependencies
		for _, p := range r.ClassPaths {
			bindings = append(bindings, minijail.Binding{Source: p})
		}

		// Add binding for the system JDK and pass it to minijail.
		javaHome, err := runfileutil.FindSystemJavaHome()
		if err != nil {
			return err
		}
		bindings = append(bindings, minijail.Binding{Source: javaHome})

		for _, b := range bindings {
			minijailArgs = append(minijailArgs, "--"+minijail.BindingFlag+"="+b.String())
		}

		// Pass environment variables via --env flags
		for _, e := range fuzzerEnv {
			minijailArgs = append(minijailArgs, "--"+minijail.EnvFlag+"="+e)
		}

		args = append(append(minijailArgs, "--"), jazzerArgs...)
	} else {
		// We don't use minijail, so we can set the environment
		// variables for the fuzzer in the wrapper environment
		for key, value := range envutil.ToMap(fuzzerEnv) {
			wrapperEnv, err = envutil.Setenv(wrapperEnv, key, value)
			if err != nil {
				return err
			}
		}
	}

	return r.RunLibfuzzerAndReport(ctx, args, wrapperEnv)
}

func (r *Runner) FuzzerEnvironment() ([]string, error) {
	// Get fuzzer environment from the libfuzzer runner
	env, err := r.Runner.FuzzerEnvironment()
	if err != nil {
		return nil, err
	}

	// Set JAVA_HOME
	javaHome, err := runfileutil.FindSystemJavaHome()
	if err != nil {
		return nil, err
	}
	env, err = envutil.Setenv(env, "JAVA_HOME", javaHome)
	if err != nil {
		return nil, err
	}

	// Enable more verbose logging for Jazzer's libjvm.so search process.
	env, err = envutil.Setenv(env, "RULES_JNI_TRACE", "1")
	if err != nil {
		return nil, err
	}

	return env, nil
}

func instrumentorAgentArgs(instrumentationPackageFilters []string) []string {
	// add arguments for the instrumentation agent:
	// instrumentation_includes - Specifies a list of glob patterns for classes that should be instrumented with fuzzing
	//		instrumentation.
	// custom_hooks - A list of classes which contain methods with hook annotations.
	instrumentationAgentArgs := []string{
		"--custom_hooks=" + strings.Join(customHooks, ":"),
	}
	if len(instrumentationPackageFilters) > 0 {
		instrumentationAgentArgs = append(instrumentationAgentArgs,
			"--instrumentation_includes="+strings.Join(instrumentationPackageFilters, ":"))
	}
	return instrumentationAgentArgs
}
