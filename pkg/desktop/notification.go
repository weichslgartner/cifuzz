package desktop

import (
	"flag"
	"os"
	"runtime"

	"github.com/gen2brain/beeep"
	"github.com/spf13/viper"

	"code-intelligence.com/cifuzz/pkg/log"
)

// Notify sends a desktop notification, but only when the
// program is running in a desktop environment
func Notify(title, body string) {

	// just skip notifications when running in CI/CD, user set
	// no-notifications flag or the program is executed by go test
	if os.Getenv("CI") != "" ||
		viper.GetBool("no-notifications") ||
		flag.Lookup("test.v") != nil {
		return
	}

	onWindows := runtime.GOOS == "windows"
	onMac := runtime.GOOS == "darwin"
	hasDisplayOnLinux := os.Getenv("DISPLAY") != ""

	if hasDisplayOnLinux || onWindows || onMac {
		err := beeep.Notify(title, body, "")
		if err != nil {
			// no more error handling as sending notifications is not that critical
			log.Debugf("unable to send desktop notification (%s): %v", title, err)
		}
	}
}
