package create

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/exp/maps"

	"code-intelligence.com/cifuzz/internal/config"
	"code-intelligence.com/cifuzz/pkg/cmdutils"
	"code-intelligence.com/cifuzz/pkg/dependencies"
	"code-intelligence.com/cifuzz/pkg/dialog"
	"code-intelligence.com/cifuzz/pkg/log"
	"code-intelligence.com/cifuzz/pkg/runfiles"
	"code-intelligence.com/cifuzz/pkg/stubs"
)

type createOpts struct {
	outputPath string
	testType   config.FuzzTestType
}

type createCmd struct {
	*cobra.Command

	opts   *createOpts
	config *config.Config
}

// map of supported test types -> label:value
var supportedTestTypes = map[string]string{
	"C/C++": string(config.CPP),
}

func New(projectConfig *config.Config) *cobra.Command {
	opts := &createOpts{}

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
			return nil
		},
		RunE: func(c *cobra.Command, args []string) error {
			cmd := createCmd{
				Command: c,
				opts:    opts,
				config:  projectConfig,
			}
			return cmd.run()
		},
		Args:      cobra.MatchAll(cobra.MaximumNArgs(1), cobra.OnlyValidArgs),
		ValidArgs: maps.Values(supportedTestTypes),
	}

	createCmd.Flags().StringVarP(&opts.outputPath, "output", "o", "", "File path of new fuzz test")

	return createCmd
}

func (c *createCmd) run() (err error) {
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

	return
}

// getTestType returns the test type (selected by argument or input dialog)
func (c *createCmd) getTestType() (config.FuzzTestType, error) {
	userSelectedType, err := dialog.Select("Select type of the fuzz test", supportedTestTypes)
	if err != nil {
		fmt.Printf("%+v \n", err)
		return "", cmdutils.ErrSilent
	}
	return config.FuzzTestType(userSelectedType), nil
}

func (c *createCmd) printBuildSystemInstructions() {
	filename := filepath.Base(c.opts.outputPath)
	// Printing build system instructions is best-effort: Do not fail on errors.
	if c.config.BuildSystem == config.BuildSystemCMake {
		log.Printf(`
Create a CMake target for the fuzz test as follows - it behaves just like
a regular add_executable(...):

    add_fuzz_test(%s %s)

`, strings.TrimSuffix(filename, filepath.Ext(filename)), filename)
	}
}

func (c *createCmd) checkDependencies() (bool, error) {
	deps := []dependencies.Key{}
	if c.opts.testType == config.CPP {
		deps = append(deps, dependencies.CLANG)
	}
	if c.config.BuildSystem == config.BuildSystemCMake {
		deps = append(deps, dependencies.CMAKE)
	}
	return dependencies.Check(deps, dependencies.Default, runfiles.Finder)
}
