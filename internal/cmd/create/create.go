package create

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"golang.org/x/exp/maps"

	"code-intelligence.com/cifuzz/internal/cmdutils"
	"code-intelligence.com/cifuzz/internal/config"
	"code-intelligence.com/cifuzz/pkg/dependencies"
	"code-intelligence.com/cifuzz/pkg/dialog"
	"code-intelligence.com/cifuzz/pkg/log"
	"code-intelligence.com/cifuzz/pkg/runfiles"
	"code-intelligence.com/cifuzz/pkg/stubs"
)

type createOpts struct {
	BuildSystem string `mapstructure:"build-system"`

	outputPath string
	testType   config.FuzzTestType
}

type createCmd struct {
	*cobra.Command

	opts *createOpts
}

// map of supported test types -> label:value
var supportedTestTypes = map[string]string{
	"C/C++": string(config.CPP),
	"Java":  string(config.JAVA),
}

func New() *cobra.Command {
	return newWithOptions(&createOpts{})
}

func newWithOptions(opts *createOpts) *cobra.Command {
	createCmd := &cobra.Command{
		Use:   fmt.Sprintf("create [%s]", strings.Join(maps.Values(supportedTestTypes), "|")),
		Short: "Create a new fuzz test",
		Long: `Creates a new templated fuzz test source file in the current directory.
After running this command, you should edit the created file in order to
make it call the functions you want to fuzz. You can then execute the
fuzz test via 'cifuzz run'.`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 {
				opts.testType = config.FuzzTestType(args[0])
			}

			err := config.FindAndParseProjectConfig(opts)
			if err != nil {
				log.Errorf(err, "Failed to parse cifuzz.yaml: %v", err.Error())
				return cmdutils.WrapSilentError(err)
			}

			return nil
		},
		RunE: func(c *cobra.Command, args []string) error {
			cmd := createCmd{
				Command: c,
				opts:    opts,
			}
			return cmd.run()
		},
		Args:      cobra.MatchAll(cobra.MaximumNArgs(1), cobra.OnlyValidArgs),
		ValidArgs: maps.Values(supportedTestTypes),
	}

	createCmd.Flags().StringVarP(&opts.outputPath, "output", "o", "", "File path of new fuzz test")

	return createCmd
}

func (c *createCmd) run() error {
	var err error
	// get test type
	if c.opts.testType == "" {
		c.opts.testType, err = c.getTestType()
		if err != nil {
			return err
		}
	}
	log.Debugf("Selected fuzz test type: %s", c.opts.testType)

	if c.opts.outputPath == "" {
		c.opts.outputPath, err = stubs.FuzzTestFilename(c.opts.testType)
		if err != nil {
			return err
		}
	}
	log.Debugf("Output path: %s", c.opts.outputPath)

	// we ignore the first value, as this command has no actual
	// dependencies and we just want to give recommendations
	// instead of letting the command fail
	if _, err := c.checkDependencies(); err != nil {
		return err
	}

	// create stub
	err = stubs.Create(c.opts.outputPath, c.opts.testType)
	if err != nil {
		log.Errorf(err, "Failed to create fuzz test stub %s: %s", c.opts.outputPath, err.Error())
		return cmdutils.ErrSilent
	}

	// show success message
	log.Successf("Created fuzz test stub %s", c.opts.outputPath)
	log.Print(`
Note: Fuzz tests can be put anywhere in your repository, but it makes sense
to keep them close to the tested code - just like regular unit tests.`)

	c.printBuildSystemInstructions()

	return nil
}

// getTestType returns the test type (selected by argument or input dialog)
func (c *createCmd) getTestType() (config.FuzzTestType, error) {
	userSelectedType, err := dialog.Select("Select type of the fuzz test", supportedTestTypes)
	if err != nil {
		return "", errors.WithStack(err)
	}
	return config.FuzzTestType(userSelectedType), nil
}

func (c *createCmd) printBuildSystemInstructions() {
	filename := filepath.Base(c.opts.outputPath)
	// Printing build system instructions is best-effort: Do not fail on errors.
	switch c.opts.BuildSystem {
	case config.BuildSystemBazel:
		log.Printf(`
Define a bazel target for the fuzz test by adding the following to the
BUILD.bazel file:

    load("@rules_fuzzing//fuzzing:cc_defs.bzl", "cc_fuzz_test")

    cc_fuzz_test(
        name = "%s",
        srcs = ["%s"],
        corpus = glob(
            ["my_fuzz_test_inputs/**"],
            allow_empty = True,
        ),
        deps = ["@cifuzz"],
    )

`, strings.TrimSuffix(filename, filepath.Ext(filename)), filename)
	case config.BuildSystemCMake:
		log.Printf(`
Create a CMake target for the fuzz test as follows - it behaves just like
a regular add_executable(...):

    add_fuzz_test(%s %s)

`, strings.TrimSuffix(filename, filepath.Ext(filename)), filename)

	case config.BuildSystemOther:
		log.Printf(`
It seems like you're not using a build system which cifuzz has special
integration support for, so you'll have to configure your build system
yourself in order to build the fuzz test and specify the command which
produces the fuzz test executable via the '--build-command' flag or the
'build-command' option in the cifuzz.yaml. See 'cifuzz run --help' for
more information about the build command.

The FUZZ_TEST_CLFAGS and FUZZ_TEST_LDFLAGS environment variables are
set by cifuzz when building the fuzz test, please make sure that
$FUZZ_TEST_CLFAGS is passed as a command-line argument to the compiler
and $FUZZ_TEST_LDFLAGS to the linker.`)
	}
}

func (c *createCmd) checkDependencies() (bool, error) {
	deps := []dependencies.Key{}

	switch c.opts.testType {
	case config.CPP:
		deps = append(deps, dependencies.CLANG)
	}

	switch c.opts.BuildSystem {
	case config.BuildSystemCMake:
		deps = append(deps, dependencies.CMAKE)
	}

	return dependencies.Check(deps, dependencies.Default, runfiles.Finder)
}
