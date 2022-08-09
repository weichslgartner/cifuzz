package dependencies

import (
	"code-intelligence.com/cifuzz/pkg/cmdutils"
	"code-intelligence.com/cifuzz/pkg/log"
)

func Error() error {
	log.Error(nil, `Unable to run command due to missing/invalid dependencies.
For installation instruction see:`)
	log.Info("\thttps://github.com/CodeIntelligenceTesting/cifuzz#installation")

	return cmdutils.ErrSilent
}
