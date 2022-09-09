package integration_tests

import (
	"runtime"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	builder2 "code-intelligence.com/cifuzz/internal/builder"
	"code-intelligence.com/cifuzz/pkg/runfiles"
)

var builder *builder2.CIFuzzBuilder
var installOnce sync.Once
var installMutex sync.Mutex

func TestWithAndWithoutMinijail(t *testing.T, f func(t *testing.T, disableMinijail bool)) {
	t.Run("WithoutMinijail", func(t *testing.T) {
		t.Parallel()
		f(t, true)
	})
	t.Run("WithMinijail", func(t *testing.T) {
		// we support minijail for linux only
		if runtime.GOOS != "linux" {
			t.Skip()
		}
		t.Parallel()

		installMutex.Lock()
		installOnce.Do(func() {
			err := builder.BuildMinijail()
			require.NoError(t, err)
			err = builder.BuildProcessWrapper()
			require.NoError(t, err)
		})
		installMutex.Unlock()

		runfiles.Finder = runfiles.RunfilesFinderImpl{InstallDir: builder.TargetDir}

		f(t, false)
	})
}
