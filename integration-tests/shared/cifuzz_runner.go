package shared

import (
	"bufio"
	"context"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"code-intelligence.com/cifuzz/util/executil"
)

type CIFuzzRunner struct {
	CIFuzzPath      string
	DefaultWorkDir  string
	DefaultFuzzTest string
}

type CommandOptions struct {
	WorkDir string
	Env     []string
	Args    []string
}

// Command runs "cifuzz <command> <args>" and returns any indented lines
// which the command prints to stdout (which we expect to be lines which
// should be added to some source or config file).
func (r *CIFuzzRunner) Command(t *testing.T, command string, opts *CommandOptions) []string {
	t.Helper()

	if opts == nil {
		opts = &CommandOptions{}
	}

	var args []string
	// Empty command means that the root command should be executed
	if command != "" {
		args = append(args, command)
	}
	args = append(args, opts.Args...)

	if opts.WorkDir == "" {
		opts.WorkDir = r.DefaultWorkDir
	}

	cmd := executil.Command(r.CIFuzzPath, args...)
	cmd.Dir = opts.WorkDir
	stderrPipe, err := cmd.StderrTeePipe(os.Stderr)
	defer stderrPipe.Close()
	require.NoError(t, err)

	t.Logf("Command: %s", cmd.String())
	err = cmd.Run()
	require.NoError(t, err)

	scanner := bufio.NewScanner(stderrPipe)
	var linesToAdd []string
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "    ") {
			linesToAdd = append(linesToAdd, strings.TrimSpace(scanner.Text()))
		}
	}

	return linesToAdd
}

type RunOptions struct {
	FuzzTest string
	WorkDir  string
	Env      []string
	Args     []string

	ExpectedOutputs              []*regexp.Regexp
	TerminateAfterExpectedOutput bool
}

func (r *CIFuzzRunner) Run(t *testing.T, opts *RunOptions) {
	t.Helper()

	if opts.Env == nil {
		opts.Env = os.Environ()
	}

	if opts.WorkDir == "" {
		opts.WorkDir = r.DefaultWorkDir
	}

	if opts.FuzzTest == "" {
		opts.FuzzTest = r.DefaultFuzzTest
	}

	runCtx, closeRunCtx := context.WithCancel(context.Background())
	defer closeRunCtx()
	args := append([]string{"run", "-v", opts.FuzzTest,
		"--no-notifications",
		"--engine-arg=-seed=1",
		"--engine-arg=-runs=1000000"},
		opts.Args...)
	cmd := executil.CommandContext(
		runCtx,
		r.CIFuzzPath,
		args...,
	)
	cmd.Dir = opts.WorkDir
	cmd.Env = opts.Env
	stdoutPipe, err := cmd.StdoutTeePipe(os.Stdout)
	require.NoError(t, err)
	stderrPipe, err := cmd.StderrTeePipe(os.Stderr)
	require.NoError(t, err)

	// Terminate the cifuzz process when we receive a termination signal
	// (else the test won't stop). An alternative would be to run the
	// command in the foreground, via syscall.SysProcAttr.Foreground,
	// but that's not supported on Windows.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)
	go func() {
		s := <-sigs
		t.Logf("Received %s", s.String())
		err = cmd.TerminateProcessGroup()
		require.NoError(t, err)
	}()

	t.Logf("Command: %s", cmd.String())
	err = cmd.Start()
	require.NoError(t, err)

	waitErrCh := make(chan error)
	// Wait for the command to exit in a go routine, so that below
	// we can cancel waiting when the context is done
	go func() {
		waitErrCh <- cmd.Wait()
	}()

	// Check that the output contains the expected output
	var seenExpectedOutputs int
	lenExpectedOutputs := len(opts.ExpectedOutputs)
	mutex := sync.Mutex{}

	routines := errgroup.Group{}
	routines.Go(func() error {
		// cifuzz progress messages go to stdout.
		scanner := bufio.NewScanner(stdoutPipe)
		for scanner.Scan() {
			mutex.Lock()
			var remainingExpectedOutputs []*regexp.Regexp
			for _, expectedOutput := range opts.ExpectedOutputs {
				if expectedOutput.MatchString(scanner.Text()) {
					seenExpectedOutputs += 1
				} else {
					remainingExpectedOutputs = append(remainingExpectedOutputs, expectedOutput)
				}
			}
			opts.ExpectedOutputs = remainingExpectedOutputs
			if seenExpectedOutputs == lenExpectedOutputs && opts.TerminateAfterExpectedOutput {
				err = cmd.TerminateProcessGroup()
				require.NoError(t, err)
			}
			mutex.Unlock()
		}
		err = stdoutPipe.Close()
		require.NoError(t, err)
		return nil
	})

	routines.Go(func() error {
		// Fuzzer output goes to stderr.
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			mutex.Lock()
			var remainingExpectedOutputs []*regexp.Regexp
			for _, expectedOutput := range opts.ExpectedOutputs {
				if expectedOutput.MatchString(scanner.Text()) {
					seenExpectedOutputs += 1
				} else {
					remainingExpectedOutputs = append(remainingExpectedOutputs, expectedOutput)
				}
			}
			opts.ExpectedOutputs = remainingExpectedOutputs
			if seenExpectedOutputs == lenExpectedOutputs && opts.TerminateAfterExpectedOutput {
				err = cmd.TerminateProcessGroup()
				require.NoError(t, err)
			}
			mutex.Unlock()
		}
		err = stderrPipe.Close()
		require.NoError(t, err)
		return nil
	})

	select {
	case waitErr := <-waitErrCh:

		err = routines.Wait()
		require.NoError(t, err)

		seen := seenExpectedOutputs == lenExpectedOutputs
		if seen && opts.TerminateAfterExpectedOutput && executil.IsTerminatedExitErr(waitErr) {
			return
		}
		require.NoError(t, waitErr)
	case <-runCtx.Done():
		require.NoError(t, runCtx.Err())
	}

	seen := seenExpectedOutputs == lenExpectedOutputs
	require.True(t, seen, "Did not see %q in fuzzer output", opts.ExpectedOutputs)
}
