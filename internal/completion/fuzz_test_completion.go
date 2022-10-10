package completion

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/mattn/go-zglob"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"code-intelligence.com/cifuzz/internal/cmdutils"
	"code-intelligence.com/cifuzz/internal/config"
	"code-intelligence.com/cifuzz/pkg/log"
)

// ValidFuzzTests can be used as a cobra ValidArgsFunction that completes fuzz test names.
func ValidFuzzTests(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	// Change the directory if the `--directory` flag was set
	err := cmdutils.Chdir()
	if err != nil {
		log.Error(err, err.Error())
		return nil, cobra.ShellCompDirectiveError
	}

	// Read the project config to figure out the build system
	conf := struct {
		BuildSystem string `mapstructure:"build-system"`
		ProjectDir  string `mapstructure:"project-dir"`
	}{}
	err = config.FindAndParseProjectConfig(&conf)
	if err != nil {
		log.Error(err, err.Error())
		return nil, cobra.ShellCompDirectiveError
	}

	switch conf.BuildSystem {
	case config.BuildSystemCMake:
		return validCMakeFuzzTests(conf.ProjectDir)
	case config.BuildSystemMaven, config.BuildSystemGradle:
		return validJavaFuzzTests(toComplete, conf.ProjectDir)
	case config.BuildSystemOther:
		// For other build systems, the <fuzz test> argument must be
		// the path to the fuzz test executable, so we use file
		// completion here (which is only useful if the executable has
		// been built before, but that's still better than no completion
		// support)
		return nil, cobra.ShellCompDirectiveDefault
	default:
		err := errors.Errorf("Unsupported build system \"%s\"", conf.BuildSystem)
		log.Error(err, err.Error())
		return nil, cobra.ShellCompDirectiveError
	}
}

func validCMakeFuzzTests(projectDir string) ([]string, cobra.ShellCompDirective) {
	matches, err := zglob.Glob(projectDir + "/.cifuzz-build/**/.cifuzz/fuzz_tests/*")
	if err != nil {
		log.Error(err, err.Error())
		return nil, cobra.ShellCompDirectiveError
	}
	var res []string
	for _, match := range matches {
		res = append(res, filepath.Base(match))
	}
	return res, cobra.ShellCompDirectiveNoFileComp
}

func validJavaFuzzTests(toComplete string, projectDir string) ([]string, cobra.ShellCompDirective) {
	var res []string

	testDir := filepath.Join(projectDir, "src", "test", "java")
	completionPrefix := filepath.Join(
		testDir,
		strings.ReplaceAll(toComplete, ".", string(os.PathSeparator)),
	)

	err := filepath.WalkDir(testDir, func(path string, d fs.DirEntry, err error) error {
		if !strings.HasPrefix(path, completionPrefix) {
			return nil
		}

		if !d.IsDir() {
			if filepath.Ext(path) != ".java" {
				return nil
			}

			bytes, err := os.ReadFile(path)
			if err != nil {
				return err
			}

			match, err := regexp.MatchString(`@FuzzTest|fuzzerTestOneInput\(`, string(bytes))
			if err != nil {
				return err
			}
			if match == true {
				classPath, err := filepath.Rel(testDir, path)
				if err != nil {
					return err
				}

				className := strings.TrimSuffix(filepath.Base(path), ".java")
				classPath = filepath.Join(filepath.Dir(classPath), className)
				classPath = strings.ReplaceAll(classPath, string(os.PathSeparator), ".")

				res = append(res, classPath)
			}
		}

		return nil
	})
	if err != nil {
		log.Error(err, err.Error())
		return nil, cobra.ShellCompDirectiveError
	}

	return res, cobra.ShellCompDirectiveNoFileComp
}
