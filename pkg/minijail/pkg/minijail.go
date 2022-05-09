package minijail

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pkg/errors"

	"code-intelligence.com/cifuzz/util/envutil"
)

const (
	OutputDir = "/tmp/minijail-out"

	EnvPrefix = "CIFUZZ_MINIJAIL_"

	DebugEnvVarName    = EnvPrefix + "DEBUG"
	BindingsEnvVarName = EnvPrefix + "BINDINGS"

	BindingFlag = "bind"
	EnvFlag     = "env"
)

type WritableOption int

const (
	ReadOnly WritableOption = iota
	ReadWrite
)

type Binding struct {
	Source   string
	Target   string
	Writable WritableOption
}

func (b *Binding) String() string {
	if b.Target == "" {
		b.Target = b.Source
	}
	if b.Writable == ReadWrite {
		return fmt.Sprintf("%s,%s,1", b.Source, b.Target)
	}
	// Don't use a short form if the source or target contain a comma,
	// which would be interpreted as separators by minijail.
	if strings.ContainsRune(b.Source, ',') || strings.ContainsRune(b.Target, ',') {
		return fmt.Sprintf("%s,%s,0", b.Source, b.Target)
	}
	if b.Source != b.Target {
		return fmt.Sprintf("%s,%s", b.Source, b.Target)
	}
	return b.Source
}

func BindingFromString(s string) (*Binding, error) {
	tokens := strings.SplitN(s, ",", 3)
	switch len(tokens) {
	case 1:
		return &Binding{Source: tokens[0], Target: tokens[0], Writable: 0}, nil
	case 2:
		return &Binding{Source: tokens[0], Target: tokens[1], Writable: 0}, nil
	case 3:
		writable, err := strconv.Atoi(tokens[2])
		if err != nil {
			return nil, errors.WithStack(err)
		}
		return &Binding{Source: tokens[0], Target: tokens[1], Writable: WritableOption(writable)}, nil
	}
	return nil, errors.Errorf("Bad binding: %s", s)
}

// Deprecated: Use AddMinijailBindingToEnv instead, which doesn't use os.Setenv.
// TODO(adrian): AddMinijailBindingDeprecated will be removed once all adapters are
//               rewritten (CIFUZZ-1289).
func AddMinijailBindingDeprecated(path string, writable WritableOption) error {
	binding, err := getMinijailBinding(path, writable)
	if err != nil {
		return err
	}

	bindings := os.Getenv(BindingsEnvVarName)
	if bindings == "" {
		bindings = binding
	} else {
		bindings += ":" + binding
	}

	err = os.Setenv(BindingsEnvVarName, bindings)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func AddMinijailBindingToEnv(env []string, binding *Binding) ([]string, error) {
	bindings := envutil.Getenv(env, BindingsEnvVarName)
	if bindings == "" {
		bindings = binding.Source
	} else {
		bindings += ":" + binding.String()
	}

	env, err := envutil.Setenv(env, BindingsEnvVarName, bindings)
	if err != nil {
		return nil, err
	}

	return env, nil
}

func getMinijailBinding(path string, writable WritableOption) (string, error) {
	src, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", errors.WithStack(err)
	}
	writableStr := "0"
	if writable == ReadWrite {
		writableStr = "1"
	}
	return fmt.Sprintf("%s,%s,%s", src, path, writableStr), nil
}
