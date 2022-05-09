package testutil

import (
	"log"
	"os"

	"code-intelligence.com/cifuzz/util/glogutil"
)

// SetupGlog sets up glog flags from env vars and enables logging to
// stderr.
// You still have to call flag.Parse() after calling SetupGlog().
func SetupGlog() {
	// Also log to stderr
	err := os.Setenv("GLOG_alsologtostderr", "1")
	if err != nil {
		log.Fatalf("%+v", err)
	}

	// If not set already, set the GLOG_v env var to 2, to enable
	// moderately verbose logging in tests
	if os.Getenv("GLOG_v") == "" && os.Getenv("GLOG_V") == "" {
		err = os.Setenv("GLOG_v", "2")
		if err != nil {
			log.Fatalf("%+v", err)
		}
	}

	// Set up glog
	err = glogutil.SetupGlog()
	if err != nil {
		log.Fatalf("%+v", err)
	}
}
