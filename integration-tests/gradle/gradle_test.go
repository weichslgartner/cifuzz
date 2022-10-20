package gradle

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"code-intelligence.com/cifuzz/integration-tests/shared"
	builderPkg "code-intelligence.com/cifuzz/internal/builder"
	"code-intelligence.com/cifuzz/util/fileutil"
)

func TestIntegration_Gradle(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	// Create installation builder
	installDir := shared.InstallCIFuzzInTemp(t)
	cifuzz := builderPkg.CIFuzzExecutablePath(filepath.Join(installDir, "bin"))

	// Copy testdata
	projectDir := shared.CopyTestdataDir(t, "gradle")
	defer fileutil.Cleanup(projectDir)

	cifuzzRunner := shared.CIFuzzRunner{
		CIFuzzPath:     cifuzz,
		DefaultWorkDir: projectDir,
	}

	// Execute the init command
	linesToAdd := cifuzzRunner.Command(t, "init", nil)
	assert.FileExists(t, filepath.Join(projectDir, "cifuzz.yaml"))
	shared.AddLinesToFileAtBreakPoint(t, filepath.Join(projectDir, "build.gradle"), linesToAdd, "dependencies", true)

	// Execute the create command
	outputPath := filepath.Join("src", "MyClassFuzzTest.java")
	cifuzzRunner.Command(t, "create", &shared.CommandOptions{
		Args: []string{"java", "--output", outputPath}},
	)

	// Check that the fuzz test was created in the correct directory
	fuzzTestPath := filepath.Join(projectDir, outputPath)
	require.FileExists(t, fuzzTestPath)

	// Check that the findings command doesn't list any findings yet
	findings := shared.GetFindings(t, cifuzz, projectDir)
	require.Empty(t, findings)

	// TODO: execute run command
}
