package shared

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"code-intelligence.com/cifuzz/util/stringutil"
)

type MockServer struct {
	Address           string
	ArtifactsUploaded bool
	RunStarted        bool
}

func StartMockServer(t *testing.T, projectName, artifactsName string) *MockServer {
	server := &MockServer{}

	handleUpload := func(w http.ResponseWriter, req *http.Request) {
		_, err := io.ReadAll(req.Body)
		require.NoError(t, err)
		_, err = fmt.Fprintf(w, `{"display-name": "test-artifacts", "resource-name": "%s"}`, artifactsName)
		require.NoError(t, err)
		server.ArtifactsUploaded = true
	}

	handleStartRun := func(w http.ResponseWriter, req *http.Request) {
		_, err := io.ReadAll(req.Body)
		require.NoError(t, err)
		_, err = fmt.Fprintf(w, `{"name": "test-campaign-run-123"}`)
		require.NoError(t, err)
		server.RunStarted = true
	}

	handleDefault := func(w http.ResponseWriter, req *http.Request) {
		require.Fail(t, "Unexpected request", stringutil.PrettyString(req))
	}

	mux := http.NewServeMux()
	mux.HandleFunc(fmt.Sprintf("/v2/projects/%s/artifacts/import", projectName), handleUpload)
	mux.HandleFunc(fmt.Sprintf("/v1/%s:run", artifactsName), handleStartRun)
	mux.HandleFunc("/", handleDefault)

	listener, err := net.Listen("tcp4", ":0")
	require.NoError(t, err)

	server.Address = fmt.Sprintf("http://127.0.0.1:%d", listener.Addr().(*net.TCPAddr).Port)

	go func() {
		err = http.Serve(listener, mux)
		require.NoError(t, err)
	}()

	return server
}
