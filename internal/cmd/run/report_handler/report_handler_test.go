package report_handler

import (
	"bytes"
	"io"
	"os"
	"testing"
	"time"

	"github.com/gookit/color"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"code-intelligence.com/cifuzz/internal/cmd/run/report_handler/metrics"
	"code-intelligence.com/cifuzz/pkg/finding"
	"code-intelligence.com/cifuzz/pkg/log"
	"code-intelligence.com/cifuzz/pkg/report"
	"code-intelligence.com/cifuzz/util/fileutil"
	"code-intelligence.com/cifuzz/util/testutil"
)

var logOutput io.ReadWriter
var testDir string

func TestMain(m *testing.M) {
	// Disable color for this test to allow comparing strings without
	// having to add color to them
	color.Disable()

	logOutput = bytes.NewBuffer([]byte{})
	log.Output = logOutput

	testDir = testutil.ChdirToTempDir("report-handler-test-")
	defer fileutil.Cleanup(testDir)

	m.Run()
}

func TestReportHandler_EmptyCorpus(t *testing.T) {
	h, err := NewReportHandler(&ReportHandlerOptions{ProjectDir: testDir})
	require.NoError(t, err)

	initStartedReport := &report.Report{
		Status:   report.RunStatus_INITIALIZING,
		NumSeeds: 0,
	}
	err = h.Handle(initStartedReport)
	require.NoError(t, err)
	checkOutput(t, logOutput, "Starting from an empty corpus")
	require.True(t, h.initFinished)
}

func TestReportHandler_NonEmptyCorpus(t *testing.T) {
	h, err := NewReportHandler(&ReportHandlerOptions{ProjectDir: testDir})
	require.NoError(t, err)

	initStartedReport := &report.Report{
		Status:   report.RunStatus_INITIALIZING,
		NumSeeds: 1,
	}
	err = h.Handle(initStartedReport)
	require.NoError(t, err)
	checkOutput(t, logOutput, "Initializing fuzzer with")

	initFinishedReport := &report.Report{Status: report.RunStatus_RUNNING}
	err = h.Handle(initFinishedReport)
	require.NoError(t, err)
	checkOutput(t, logOutput, "Successfully initialized fuzzer")
}

func TestReportHandler_Metrics(t *testing.T) {
	h, err := NewReportHandler(&ReportHandlerOptions{ProjectDir: testDir})
	require.NoError(t, err)

	printerOut := bytes.NewBuffer([]byte{})
	h.printer.(*metrics.LinePrinter).BasicTextPrinter.Writer = printerOut

	metricsReport := &report.Report{
		Status: report.RunStatus_RUNNING,
		Metric: &report.FuzzingMetric{
			Timestamp:           time.Now(),
			ExecutionsPerSecond: 1234,
			Features:            12,
		},
	}
	err = h.Handle(metricsReport)
	require.NoError(t, err)
	checkOutput(t, printerOut, metrics.MetricsToString(metricsReport.Metric))
}

func TestReportHandler_Finding(t *testing.T) {
	h, err := NewReportHandler(&ReportHandlerOptions{ProjectDir: testDir, SeedCorpusDir: "seed_corpus"})
	require.NoError(t, err)

	// create an input file
	testfile := "crash_123_test"
	err = os.WriteFile(testfile, []byte("TEST"), 0644)
	require.NoError(t, err)

	findingReport := &report.Report{
		Status: report.RunStatus_RUNNING,
		Finding: &finding.Finding{
			InputFile: testfile,
		},
	}
	err = h.Handle(findingReport)
	require.NoError(t, err)

	expectedOutputs := []string{"NEW", findingReport.Finding.Name}
	checkOutput(t, logOutput, expectedOutputs...)
}

func TestReportHandler_PrintJSON(t *testing.T) {
	h, err := NewReportHandler(&ReportHandlerOptions{ProjectDir: testDir, PrintJSON: true})
	require.NoError(t, err)

	jsonOut := bytes.NewBuffer([]byte{})
	h.jsonOutput = jsonOut

	findingLogs := []string{"Oops", "The program crashed"}
	findingReport := &report.Report{
		Status: report.RunStatus_RUNNING,
		Finding: &finding.Finding{
			Logs: findingLogs,
		},
	}
	err = h.Handle(findingReport)
	require.NoError(t, err)
	checkOutput(t, jsonOut, findingLogs...)
}

func TestReportHandler_GenerateName(t *testing.T) {
	h, err := NewReportHandler(&ReportHandlerOptions{ProjectDir: testDir, PrintJSON: true})
	require.NoError(t, err)

	findingLogs := []string{"Oops", "The program crashed"}
	findingReport := &report.Report{
		Status: report.RunStatus_RUNNING,
		Finding: &finding.Finding{
			Logs:      findingLogs,
			InputData: []byte("123"),
		},
	}
	err = h.Handle(findingReport)
	require.NoError(t, err)
	assert.Equal(t, "nifty_liskov", findingReport.Finding.Name)
}

func checkOutput(t *testing.T, r io.Reader, s ...string) {
	output, err := io.ReadAll(r)
	require.NoError(t, err)
	for _, str := range s {
		require.Contains(t, string(output), str)
	}
}
