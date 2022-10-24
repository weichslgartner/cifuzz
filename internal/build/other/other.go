package other

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/pkg/errors"

	"code-intelligence.com/cifuzz/internal/build"
	"code-intelligence.com/cifuzz/internal/cmdutils"
	"code-intelligence.com/cifuzz/pkg/dependencies"
	"code-intelligence.com/cifuzz/pkg/log"
	"code-intelligence.com/cifuzz/pkg/runfiles"
	"code-intelligence.com/cifuzz/util/envutil"
	"code-intelligence.com/cifuzz/util/fileutil"
)

type BuilderOptions struct {
	ProjectDir   string
	BuildCommand string
	Engine       string
	Sanitizers   []string

	RunfilesFinder runfiles.RunfilesFinder
	Stdout         io.Writer
	Stderr         io.Writer
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

	if opts.RunfilesFinder == nil {
		opts.RunfilesFinder = runfiles.Finder
	}

	return nil
}

type Builder struct {
	*BuilderOptions
	env      []string
	buildDir string
	finder   runfiles.RunfilesFinder
}

func NewBuilder(opts *BuilderOptions) (*Builder, error) {
	err := opts.Validate()
	if err != nil {
		return nil, err
	}

	b := &Builder{BuilderOptions: opts}

	// Create a temporary build directory
	b.buildDir, err = os.MkdirTemp("", "cifuzz-build-")
	if err != nil {
		return nil, err
	}

	b.env, err = build.CommonBuildEnv()
	if err != nil {
		return nil, err
	}

	// Set CFLAGS, CXXFLAGS, LDFLAGS, and FUZZ_TEST_LDFLAGS which must
	// be passed to the build commands by the build system.
	switch opts.Engine {
	case "libfuzzer":
		if len(opts.Sanitizers) == 1 && opts.Sanitizers[0] == "coverage" {
			err = b.setCoverageEnv()
			break
		}
		for _, sanitizer := range opts.Sanitizers {
			if sanitizer != "address" && sanitizer != "undefined" {
				panic(fmt.Sprintf("Invalid sanitizer for engine %q: %q", opts.Engine, sanitizer))
			}
		}
		err = b.setLibFuzzerEnv()
	default:
		panic(fmt.Sprintf("Invalid engine %q", opts.Engine))
	}
	if err != nil {
		return nil, err
	}

	return b, nil
}

// Build builds the specified fuzz test with CMake
func (b *Builder) Build(fuzzTest string) (*build.Result, error) {
	var err error
	defer fileutil.Cleanup(b.buildDir)

	// Let the build command reference the fuzz test (base)name.
	buildCommandEnv, err := envutil.Setenv(b.env, "FUZZ_TEST", fuzzTest)
	if err != nil {
		return nil, err
	}

	// Run the build command
	cmd := exec.Command("/bin/sh", "-c", b.BuildCommand)
	// Redirect the build command's stdout to stderr to only have
	// reports printed to stdout
	cmd.Stdout = b.Stdout
	cmd.Stderr = b.Stderr
	cmd.Env = buildCommandEnv
	log.Debugf("Command: %s", cmd.String())
	err = cmd.Run()
	if err != nil {
		// It's expected that the build command might fail, so we print
		// the error without the stack trace.
		err = cmdutils.WrapExecError(err, cmd)
		log.Error(err)
		return nil, cmdutils.ErrSilent
	}

	executable, err := b.findFuzzTestExecutable(fuzzTest)
	if err != nil {
		return nil, err
	}
	if executable == "" {
		err := errors.Errorf("Could not find executable for fuzz test %q", fuzzTest)
		log.Error(err)
		return nil, cmdutils.WrapSilentError(err)
	}

	// For the build system type "other", we expect the default seed corpus next
	// to the fuzzer executable.
	seedCorpus, err := fileutil.CanonicalPath(executable + "_inputs")
	if err != nil {
		return nil, err
	}
	runtimeDeps, err := b.findSharedLibraries(fuzzTest)
	if err != nil {
		return nil, err
	}
	wd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	buildDir, err := fileutil.CanonicalPath(wd)
	if err != nil {
		return nil, err
	}
	generatedCorpus := filepath.Join(b.ProjectDir, ".cifuzz-corpus", fuzzTest)
	return &build.Result{
		Executable:      executable,
		GeneratedCorpus: generatedCorpus,
		SeedCorpus:      seedCorpus,
		BuildDir:        buildDir,
		Engine:          b.Engine,
		Sanitizers:      b.Sanitizers,
		RuntimeDeps:     runtimeDeps,
	}, nil
}

func (b *Builder) setLibFuzzerEnv() error {
	var err error

	// Set CFLAGS and CXXFLAGS
	cflags := build.LibFuzzerCFlags()
	b.env, err = envutil.Setenv(b.env, "CFLAGS", strings.Join(cflags, " "))
	if err != nil {
		return err
	}
	b.env, err = envutil.Setenv(b.env, "CXXFLAGS", strings.Join(cflags, " "))
	if err != nil {
		return err
	}

	ldflags := []string{
		// ----- Flags used to build with ASan -----
		// Link ASan and UBSan runtime
		"-fsanitize=address,undefined",
	}
	b.env, err = envutil.Setenv(b.env, "LDFLAGS", strings.Join(ldflags, " "))
	if err != nil {
		return err
	}

	// Users should pass the environment variable FUZZ_TEST_CFLAGS to the
	// compiler command building the fuzz test.
	cifuzzIncludePath, err := b.RunfilesFinder.CIFuzzIncludePath()
	if err != nil {
		return err
	}
	b.env, err = envutil.Setenv(b.env, "FUZZ_TEST_CFLAGS", "'-I"+cifuzzIncludePath+"'")
	if err != nil {
		return err
	}

	// Users should pass the environment variable FUZZ_TEST_LDFLAGS to
	// the linker command building the fuzz test. For libfuzzer, we set
	// it to "-fsanitize=fuzzer" to build a libfuzzer binary.
	b.env, err = envutil.Setenv(b.env, "FUZZ_TEST_LDFLAGS", "-fsanitize=fuzzer")
	if err != nil {
		return err
	}

	return nil
}

func (b *Builder) setCoverageEnv() error {
	var err error

	// Set CFLAGS and CXXFLAGS. Note that these flags must not contain
	// spaces, because the environment variables are space separated.
	//
	// Note: Keep in sync with tools/cmake/CIFuzz/share/CIFuzz/CIFuzzFunctions.cmake
	cc := envutil.Getenv(b.env, "CC")
	clangVersion, err := dependencies.ClangVersion(cc)
	if err != nil {
		log.Warnf("Failed to determine version of %q: %v", cc, err)
	}
	cflags := build.CoverageCFlags(clangVersion)

	b.env, err = envutil.Setenv(b.env, "CFLAGS", strings.Join(cflags, " "))
	if err != nil {
		return err
	}
	b.env, err = envutil.Setenv(b.env, "CXXFLAGS", strings.Join(cflags, " "))
	if err != nil {
		return err
	}

	ldflags := []string{
		// ----- Flags used to link in coverage runtime -----
		"-fprofile-instr-generate",
	}
	b.env, err = envutil.Setenv(b.env, "LDFLAGS", strings.Join(ldflags, " "))
	if err != nil {
		return err
	}

	// Users should pass the environment variable FUZZ_TEST_CFLAGS to the
	// compiler command building the fuzz test.
	cifuzzIncludePath, err := b.RunfilesFinder.CIFuzzIncludePath()
	if err != nil {
		return err
	}
	b.env, err = envutil.Setenv(b.env, "FUZZ_TEST_CFLAGS", "'-I"+cifuzzIncludePath+"'")
	if err != nil {
		return err
	}

	// Users should pass the environment variable FUZZ_TEST_LDFLAGS to
	// the linker command building the fuzz test. We use it to link in libFuzzer
	// in coverage builds to use its crash-resistant merge feature.
	b.env, err = envutil.Setenv(b.env, "FUZZ_TEST_LDFLAGS", "-fsanitize=fuzzer")
	if err != nil {
		return err
	}

	return nil
}

func (b *Builder) findFuzzTestExecutable(fuzzTest string) (string, error) {
	if exists, _ := fileutil.Exists(fuzzTest); exists {
		return fileutil.CanonicalPath(fuzzTest)
	}

	var executable string
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return errors.WithStack(err)
		}
		if info.IsDir() {
			return nil
		}
		if runtime.GOOS == "windows" {
			if info.Name() == fuzzTest+".exe" {
				executable = path
			}
		} else {
			// As a heuristic, verify that the executable candidate has some
			// executable bit set - it may not be sufficient to actually execute
			// it as the current user.
			if info.Name() == fuzzTest && (info.Mode()&0111 != 0) {
				executable = path
			}
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	// No executable was found, we handle this error in the caller
	if executable == "" {
		return "", nil
	}
	return fileutil.CanonicalPath(executable)
}

var sharedLibraryRegex = regexp.MustCompile(`^.+\.((so)|(dylib))(\.\d\w*)*$`)

func (b *Builder) findSharedLibraries(fuzzTest string) ([]string, error) {
	// TODO: Only return those libraries which are actually used, and which
	//       might live outside of the project directory, by parsing the
	//       shared object dependencies of the executable (we could use
	//       cmake for that or do it ourselves in Go).
	var sharedObjects []string
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return errors.WithStack(err)
		}
		if info.IsDir() {
			return nil
		}
		// Ignore shared objects in .dSYM directories, to avoid llvm-cov
		// failing with:
		//
		//    Failed to load coverage: Unsupported coverage format version
		//
		if strings.Contains(path, "dSYM") {
			return nil
		}
		if sharedLibraryRegex.MatchString(info.Name()) {
			canonicalPath, err := fileutil.CanonicalPath(path)
			if err != nil {
				return err
			}
			sharedObjects = append(sharedObjects, canonicalPath)
		}
		return nil
	})
	return sharedObjects, err
}
