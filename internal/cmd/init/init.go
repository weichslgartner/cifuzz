package init

import (
	"os"
	"path/filepath"

	copy2 "github.com/otiai10/copy"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"code-intelligence.com/cifuzz/internal/config"
	"code-intelligence.com/cifuzz/pkg/cmdutils"
	"code-intelligence.com/cifuzz/pkg/log"
	"code-intelligence.com/cifuzz/pkg/runfiles"
	"code-intelligence.com/cifuzz/util/fileutil"
)

type cmdOpts struct {
}

func New() *cobra.Command {
	opts := &cmdOpts{}
	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Set up a project for use with cifuzz",
		Long: `This command sets up a project for use with cifuzz, creating a
'cifuzz.yaml' config file.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(cmd, args, opts)
		},
	}

	cmdutils.DisableConfigCheck(initCmd)

	return initCmd
}

func run(cmd *cobra.Command, args []string, opts *cmdOpts) (err error) {
	cwd, err := os.Getwd()
	if err != nil {
		return errors.WithStack(err)
	}
	log.Debugf("Using current working directory: %s", cwd)

	configpath, err := config.CreateProjectConfig(cwd)
	if err != nil {
		// explicitly inform the user about an existing config file
		if errors.Is(err, os.ErrExist) && configpath != "" {
			log.Warnf("Config already exists in %s", configpath)
			err = cmdutils.ErrSilent
		}
		log.Error(err, "Failed to create config")
		return err
	}
	log.Successf("Configuration saved in %s", configpath)

	setUpAndMentionBuildSystemIntegrations(cwd)

	log.Print(`
Use 'cifuzz create' to create your first fuzz test.`)
	return
}

func setUpAndMentionBuildSystemIntegrations(cwd string) {
	// Printing build system instructions is best-effort: Do not fail on errors.
	cfg, err := config.ReadProjectConfig(cwd)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Debug(err)
		}
		return
	}
	if cfg.BuildSystem == config.BuildSystemCMake {
		log.Print(`
Enable fuzz testing in your CMake project by adding the following lines
to the top-level CMakeLists.txt before any add_subdirectory(...),
add_library(...) or add_executable(...) calls:

    find_package(cifuzz)
    enable_fuzz_testing()`)
		cmakePresetsSrc, err := runfiles.Finder.CMakePresetsPath()
		if err != nil {
			return
		}
		cmakePresetsDst := filepath.Join(cwd, "CMakeUserPresets.json")
		hasPresets, err := fileutil.Exists(cmakePresetsDst)
		if err != nil {
			return
		}
		if !hasPresets {
			// Situation: The user doesn't have a CMake user preset set up and
			// may thus be unaware of this functionality. Create one and tell
			// them about it.
			err = copy2.Copy(cmakePresetsSrc, cmakePresetsDst)
			if err != nil {
				return
			}
			log.Printf(`
CMakeUserPresets.json has been created to provide integration with IDEs
such as CLion and Visual Studio Code. This file should not be checked
in to version control systems. To learn more about CMake presets, visit:

    https://github.com/microsoft/vscode-cmake-tools/blob/main/docs/cmake-presets.md
    https://www.jetbrains.com/help/clion/cmake-presets.html`)
		} else {
			// Situation: The user does have a CMake user preset set up, so we
			// assume them to know about the benefits. We don't want to edit the
			// preset ourselves, so let them know how they can add the presets
			// themselves.
			log.Printf(`
Add the CMake presets contained in the following file to your
CMakeUserPresets.json to be able to run regression tests and measure
code coverage right from your IDE:

    %s`, cmakePresetsSrc)
		}
	}
}
