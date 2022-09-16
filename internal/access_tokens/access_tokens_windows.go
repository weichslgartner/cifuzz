package access_tokens

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"strings"

	"github.com/pkg/errors"

	"code-intelligence.com/cifuzz/pkg/log"
)

var dpName = "cifuzz-access-tokens"
var accessTokensFilePath = "%LocalAppData%/cifuzz/access_tokens.json"

func init() {
	// Expand the %LocalAppData% environment variable in the access tokens file path
	localAppDataDir = os.Getenv("LocalAppData")
	if localAppDataDir == "" {
		err = errors.New("environment variable %LocalAppData% not set")
		log.Error(err)
	}
	accessTokensFilePath = strings.Replace(accessTokensFilePath, "%LocalAppData%", localAppDataDir, 1)

	var err error
	bytes, err := ioutil.ReadFile(accessTokensFilePath)
	if err != nil && os.IsNotExist(err) {
		// The access tokens file doesn't exist, so we initialize the
		// access tokens with an empty map
		accessTokens = map[string]string{}
		return
	}
	if err != nil {
		log.Errorf(err, "Error reading access tokens file: %v", err.Error())
	}
	err = json.Unmarshal(bytes, &accessTokens)
	if err != nil {
		log.Errorf(err, "Error parsing access tokens: %v", err.Error())
	}
}

func Set(target, token string) error {
	// TODO: We don't use gRPC in cifuzz
	// Note: We used to try to canonicalize the target by parsing it as
	// as URL, but that does not work for all names supported by gRPC,
	// see https://github.com/grpc/grpc/blob/master/doc/naming.md
	accessTokens[target] = token

	bytes, err := json.MarshalIndent(accessTokens, "", "  ")
	if err != nil {
		return errors.WithStack(err)
	}

	// Write the JSON to file
	err = writeLockedDownFile(accessTokensFilePath, true, bytes)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}
