package desktop

import (
	"os"
	"runtime"

	"github.com/gen2brain/beeep"

	"code-intelligence.com/cifuzz/pkg/log"
)

// Notify sends a desktop notification, but only when the
// programm is running in a desktop environment
func Notify(title, body string) {

	// just skip notifications when running in CI/CD
	if os.Getenv("CI") != "" {
		return
	}

	onWindows := runtime.GOOS == "windows"
	hasDisplay := os.Getenv("DISPLAY") != ""

	if hasDisplay || onWindows {
		err := beeep.Notify(title, body, "")
		if err != nil {
			// no more error handling as sending notifications is not that critial
			log.Debugf("unable to send desktop notification (%s): %v", title, err)
		}
	}
}
