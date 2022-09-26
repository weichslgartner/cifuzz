package gradle

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	builderPkg "code-intelligence.com/cifuzz/internal/builder"
	"code-intelligence.com/cifuzz/internal/testutil"
	"code-intelligence.com/cifuzz/util/fileutil"
)

func TestIntegration_Gradle(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	// Create installation builder
	installDir := testutil.InstallCifuzzInTemp(t)
	cifuzz := builderPkg.CIFuzzExecutablePath(filepath.Join(installDir, "bin"))

	// Copy testdata
	projectDir := testutil.CopyTestdataDir(t, "gradle")
	defer fileutil.Cleanup(projectDir)

	// Execute the init command
	output := testutil.RunCommand(t, projectDir, cifuzz, []string{"init"})
	assert.FileExists(t, filepath.Join(projectDir, "cifuzz.yaml"))
	testutil.AddLinesToFileAtBreakPoint(t, filepath.Join(projectDir, "build.gradle"), output, "dependencies", true)

	// Execute the create command
	outputPath := filepath.Join("src", "MyClassFuzzTest.java")
	testutil.RunCommand(t, projectDir, cifuzz, []string{"create", "java", "--output", outputPath})

	// Check that the fuzz test was created in the correct directory
	fuzzTestPath := filepath.Join(projectDir, outputPath)
	require.FileExists(t, fuzzTestPath)

	// Check that the findings command doesn't list any findings yet
	findings := testutil.GetFindings(t, cifuzz, projectDir)
	require.Empty(t, findings)

	// TODO: execute run command
}
