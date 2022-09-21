package maven

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	builderPkg "code-intelligence.com/cifuzz/internal/builder"
	"code-intelligence.com/cifuzz/internal/testutil"
	"code-intelligence.com/cifuzz/util/fileutil"
)

func TestIntegration_Maven(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	// Create installation builder
	installDir := testutil.InstallCifuzzInTemp(t)
	cifuzz := builderPkg.CIFuzzExecutablePath(filepath.Join(installDir, "bin"))

	// Copy testdata
	projectDir := testutil.CopyTestdataDir(t, "maven")
	defer fileutil.Cleanup(projectDir)

	// Execute the init command
	output := testutil.RunCommand(t, projectDir, cifuzz, []string{"init"})
	assert.FileExists(t, filepath.Join(projectDir, "cifuzz.yaml"))
	testutil.AddLinesToFileAtBreakPoint(t, filepath.Join(projectDir, "pom.xml"), output, "    </dependencies>", false)

	// TODO: execute create and run command
}
