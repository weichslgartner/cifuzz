package maven

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"

	"code-intelligence.com/cifuzz/internal/build"
	"code-intelligence.com/cifuzz/internal/cmdutils"
	"code-intelligence.com/cifuzz/pkg/log"
	"code-intelligence.com/cifuzz/util/fileutil"
)

type ParallelOptions struct {
	Enabled bool
	NumJobs uint
}

type BuilderOptions struct {
	ProjectDir string
	Parallel   ParallelOptions
	Stdout     io.Writer
	Stderr     io.Writer
}

func (opts *BuilderOptions) Validate() error {
	// Check that the project dir is set
	if opts.ProjectDir == "" {
		return errors.New("ProjectDir is not set")
	}
	// Check that the project dir exists and can be accessed
	_, err := os.Stat(opts.ProjectDir)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

type Builder struct {
	*BuilderOptions
}

func NewBuilder(opts *BuilderOptions) (*Builder, error) {
	err := opts.Validate()
	if err != nil {
		return nil, err
	}

	b := &Builder{BuilderOptions: opts}

	return b, err
}

func (b *Builder) Build(targetClass string) (*build.Result, error) {
	var flags []string
	if b.Parallel.Enabled {
		flags = append(flags, "-T")
		if b.Parallel.NumJobs != 0 {
			flags = append(flags, fmt.Sprint(b.Parallel.NumJobs))
		} else {
			// Use one thread per cpu core
			flags = append(flags, "1C")
		}
	}

	args := append(flags, "test-compile")

	cmd := exec.Command("mvn", args...)
	// Redirect the command's stdout to stderr to only have
	// reports printed to stdout
	cmd.Stdout = b.Stderr
	cmd.Stderr = b.Stderr
	cmd.Dir = b.ProjectDir
	log.Debugf("Working directory: %s", cmd.Dir)
	log.Debugf("Command: %s", cmd.String())
	err := cmd.Run()
	if err != nil {
		// It's expected that maven might fail due to user configuration,
		// so we print the error without the stack trace.
		err = cmdutils.WrapExecError(err, cmd)
		log.Error(err)
		return nil, cmdutils.ErrSilent
	}

	deps, err := b.getDependencies()
	if err != nil {
		return nil, err
	}
	seedCorpus := build.JazzerSeedCorpus(targetClass, b.ProjectDir)
	result := &build.Result{
		SeedCorpus:  seedCorpus,
		RuntimeDeps: deps,
	}

	return result, nil
}

func (b *Builder) getDependencies() ([]string, error) {
	tempDir, err := os.MkdirTemp("", "cifuzz-maven-dependencies-*")
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer fileutil.Cleanup(tempDir)

	outputPath := filepath.Join(tempDir, "cp")
	outputFlag := "-Dmdep.outputFile=" + outputPath
	cmd := exec.Command(
		"mvn",
		"dependency:build-classpath",
		outputFlag,
	)
	// Redirect the command's stdout to stderr to only have
	// reports printed to stdout
	cmd.Stdout = b.Stderr
	cmd.Stderr = b.Stderr
	cmd.Dir = b.ProjectDir
	log.Debugf("Working directory: %s", cmd.Dir)
	log.Debugf("Command: %s", cmd.String())
	err = cmd.Run()
	if err != nil {
		// It's expected that maven might fail due to user configuration,
		// so we print the error without the stack trace.
		err = cmdutils.WrapExecError(err, cmd)
		log.Error(err)
		return nil, cmdutils.ErrSilent
	}

	bytes, err := os.ReadFile(outputPath)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	deps := strings.Split(string(bytes), string(os.PathListSeparator))
	// Append local dependencies which are not listed by "mvn dependency:build-classpath"
	localDeps := []string{"classes", "test-classes", "resource", "test-resource"}
	for _, dep := range localDeps {
		deps = append(deps, filepath.Join(b.ProjectDir, "target", dep))
	}

	return deps, nil
}
