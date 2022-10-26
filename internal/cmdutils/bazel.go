package cmdutils

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/pkg/errors"

	"code-intelligence.com/cifuzz/pkg/log"
)

func EvaluateBazelTargetPatterns(patterns []string) ([]string, error) {
	var fuzzTestLabels []string

	multiPattern := patterns[0]
	for _, pattern := range patterns[1:] {
		if strings.HasPrefix(pattern, "-") {
			multiPattern += " " + pattern
		} else {
			multiPattern += " +" + pattern
		}
	}

	args := []string{
		"query",
		fmt.Sprintf("kind(fuzzing_regression_test, attr(generator_function, cc_fuzz_test, %s))", multiPattern),
	}
	cmd := exec.Command("bazel", args...)
	cmd.Stderr = os.Stderr
	log.Debugf("Command: %s", cmd.String())
	out, err := cmd.Output()
	if err != nil {
		// It's expected that bazel might fail due to user configuration,
		// so we print the error without the stack trace.
		err = WrapExecError(errors.WithStack(err), cmd)
		log.Error(err)
		return nil, ErrSilent
	}
	lines := strings.Split(strings.ReplaceAll(strings.TrimSpace(string(out)), "\r\n", "\n"), "\n")
	for _, line := range lines {
		label := strings.TrimSpace(line)
		if label != "" {
			fuzzTestLabels = append(fuzzTestLabels, label)
		}
	}

	return fuzzTestLabels, nil
}
