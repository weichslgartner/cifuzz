//go:build installer

package main

import (
	"embed"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/otiai10/copy"
	"github.com/pkg/errors"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"code-intelligence.com/cifuzz/internal/installer"
	"code-intelligence.com/cifuzz/pkg/log"
	"code-intelligence.com/cifuzz/util/fileutil"
)

//go:embed build
var buildFiles embed.FS

func main() {
	flags := pflag.NewFlagSet("cifuzz installer", pflag.ExitOnError)
	installDir := flags.StringP("install-dir", "i", "~/cifuzz", "The directory to install cifuzz in")
	helpRequested := flags.BoolP("help", "h", false, "")
	flags.Bool("verbose", false, "Print verbose output")
	viper.BindPFlag("verbose", flags.Lookup("verbose"))

	if err := flags.Parse(os.Args); err != nil {
		log.Error(err, err.Error())
		os.Exit(1)
	}

	if *helpRequested {
		log.Printf("Usage of cifuzz installer:")
		flags.PrintDefaults()
		os.Exit(0)
	}

	if err := ExtractEmbeddedFiles(*installDir, &buildFiles); err != nil {
		log.Error(err, err.Error())
		os.Exit(1)
	}

	binDir := filepath.Join(*installDir, "bin")
	PrintPathInstructions(binDir)
}

func PrintPathInstructions(binDir string) {
	log.Success("Installation successful")

	if runtime.GOOS == "windows" {
		// TODO: On Windows, users generally don't expect having to fiddle with their PATH. We should update it for
		//       them, but that requires asking for admin access.
		log.Notef(`Please add the following directory to your PATH:
	%s
If you haven't already done so.
`, binDir)
	} else {
		log.Notef(`Please add the following to ~/.profile or ~/.bash_profile:
    export PATH="$PATH:%s"
If you haven't already done so.
`, binDir)
	}
}

// ExtractEmbeddedFiles extracts the embedded files that were built by
// the cifuzz builder into targetDir and registers the CMake package
func ExtractEmbeddedFiles(targetDir string, files *embed.FS) error {
	// List of files which have to be made executable
	executableFiles := []string{
		"bin/cifuzz",
		"bin/minijail0",
		"lib/process_wrapper",
	}

	targetDir, err := validateTargetDir(targetDir)
	if err != nil {
		return err
	}

	buildFS, err := fs.Sub(files, "build")
	if err != nil {
		return errors.WithStack(err)
	}

	// Extract files from the build directory
	err = fs.WalkDir(buildFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return errors.WithStack(err)
		}

		if !d.IsDir() {
			targetDir := filepath.Dir(filepath.Join(targetDir, path))
			err = os.MkdirAll(targetDir, 0755)
			if err != nil {
				return errors.WithStack(err)
			}

			content, err := fs.ReadFile(buildFS, path)
			if err != nil {
				return errors.WithStack(err)
			}

			fileName := filepath.Join(targetDir, d.Name())
			err = os.WriteFile(fileName, content, 0644)
			if err != nil {
				return errors.WithStack(err)
			}

			// Make required files executable
			for _, executableFile := range executableFiles {
				if executableFile == path {
					err = os.Chmod(fileName, 0755)
					if err != nil {
						return errors.WithStack(err)
					}
				}
			}
		}

		return nil
	})
	if err != nil {
		return err
	}

	// Install the autocompletion script for the current shell (if the
	// shell is supported)
	cifuzzPath := filepath.Join(targetDir, "bin", "cifuzz")
	switch filepath.Base(os.Getenv("SHELL")) {
	case "bash":
		err = installBashCompletionScript(cifuzzPath)
	case "zsh":
		err = installZshCompletionScript(cifuzzPath)
	case "fish":
		err = installFishCompletionScript(cifuzzPath)
	}
	if err != nil {
		return err
	}

	if runtime.GOOS != "windows" && os.Getuid() == 0 {
		// On non-Windows systems, CMake doesn't have the concept of a system
		// package registry. Instead, install the package into the well-known
		// prefix /usr/local using the following relative search path:
		// /(lib/|lib|share)/<name>*/(cmake|CMake)/
		// See:
		// https://cmake.org/cmake/help/latest/command/find_package.html#config-mode-search-procedure
		// https://gitlab.kitware.com/cmake/cmake/-/blob/5ed9232d781ccfa3a9fae709e12999c6649aca2f/Modules/Platform/UnixPaths.cmake#L30)
		cmakeSrc := filepath.Join(targetDir, "share", "cifuzz")
		cmakeDest := "/usr/local/share/cifuzz"
		err = copy.Copy(cmakeSrc, cmakeDest)
		if err != nil {
			return errors.WithStack(err)
		}
	}

	// The CMake package registry entry has to point directly to the directory
	// containing the CIFuzzConfig.cmake file rather than any valid prefix for
	// the config mode search procedure.
	dirForRegistry := filepath.Join(targetDir, "share", "cifuzz", "cmake")
	return installer.RegisterCMakePackage(dirForRegistry)
}

func installBashCompletionScript(cifuzzPath string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		var dir string
		if os.Getuid() == 0 {
			// We run as root, so we put the completion script into the
			// system-wide completions directory
			dir = "/etc/bash_completion.d"
		} else {
			// We run as non-root, so install the script to the user's
			// completions directory
			// See https://github.com/scop/bash-completion/tree/2.9#installation
			if os.Getenv("XDG_DATA_HOME") != "" {
				dir = os.Getenv("XDG_DATA_HOME") + "/bash-completion/completions"
			} else {
				dir = os.Getenv("HOME") + "/.local/share/bash-completion/completions"
			}
		}
		err := os.MkdirAll(dir, 0755)
		if err != nil {
			return errors.WithStack(err)
		}
		cmd = exec.Command("bash", "-c", "'"+cifuzzPath+"' completion bash > \""+dir+"/cifuzz\"")
	case "darwin":
		cmd = exec.Command("bash", "-c", "'"+cifuzzPath+"' completion bash > \"$(brew --prefix)/etc/bash_completion.d/cifuzz\"")
	}
	cmd.Stderr = os.Stderr
	log.Printf("Command: %s", cmd.String())
	err := cmd.Run()
	return errors.WithStack(err)
}

func installZshCompletionScript(cifuzzPath string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		// We try to read $ZDOTDIR/.zshrc or ~/.zshrc here in order to
		// store the completion script in the correct directory.
		// When run as non-root, it's expected that ~/.zshrc sets
		// $fpath[1] to a directory in the user's home directory, which
		// allows us to write to it.
		// When run as root, it's expected that /root/.zshrc doesn't
		// exist, which leaves $fpath[1] at the default which is below
		// /etc.
		cmd = exec.Command("zsh", "-c", ". ${ZDOTDIR:-${HOME}}/.zshrc 2>/dev/null; '"+cifuzzPath+"' completion zsh > \"${fpath[1]}/_cifuzz\"")
	case "darwin":
		cmd = exec.Command("zsh", "-c", "'"+cifuzzPath+"' completion zsh > \"$(brew --prefix)/share/zsh/site-functions/_cifuzz\"")
	default:
		return nil
	}
	cmd.Stderr = os.Stderr
	log.Printf("Command: %s", cmd.String())
	err := cmd.Run()
	return errors.WithStack(err)
}

func installFishCompletionScript(cifuzzPath string) error {
	var dir string
	// Choose the correct directory for the completion script.
	// See https://fishshell.com/docs/current/completions.html#where-to-put-completions
	if os.Getuid() == 0 {
		// We run as root, so we put the completion script into the
		// system-wide completions directory
		dir = "/usr/share/fish/vendor_completions.d"
	} else {
		// We run as non-root, so install the script to the user's
		// completions directory
		if os.Getenv("XDG_DATA_HOME") != "" {
			dir = os.Getenv("XDG_DATA_HOME") + "/fish/vendor_completions.d"
		} else {
			dir = os.Getenv("HOME") + "/.local/share/fish/vendor_completions.d"
		}
	}
	err := os.MkdirAll(dir, 0755)
	if err != nil {
		return errors.WithStack(err)
	}

	cmd := exec.Command("fish", "-c", "'"+cifuzzPath+"' completion fish > \""+dir+"/cifuzz.fish\"")
	cmd.Stderr = os.Stderr
	log.Printf("Command: %s", cmd.String())
	err = cmd.Run()
	return errors.WithStack(err)
}

func validateTargetDir(installDir string) (string, error) {
	var err error

	if strings.HasPrefix(installDir, "~") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", errors.WithStack(err)
		}
		installDir = home + strings.TrimPrefix(installDir, "~")
	}

	if installDir == "" {
		installDir, err = os.MkdirTemp("", "cifuzz-install-dir-")
		if err != nil {
			return "", errors.WithStack(err)
		}
	} else {
		installDir, err = filepath.Abs(installDir)
		if err != nil {
			return "", errors.WithStack(err)
		}

		exists, err := fileutil.Exists(installDir)
		if err != nil {
			return "", err
		}
		if exists {
			return "", errors.Errorf("Install directory '%s' already exists. Please remove it to continue.", installDir)
		}
	}

	return installDir, nil
}
