package access_tokens

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/pkg/errors"

	"code-intelligence.com/cifuzz/pkg/log"
)

var accessTokens map[string]string

var accessTokensFilePath = "$HOME/.config/cifuzz/access_tokens.json"

func init() {
	// Expand the $HOME environment variable in the access tokens file path
	accessTokensFilePath = os.ExpandEnv(accessTokensFilePath)

	var err error
	bytes, err := os.ReadFile(accessTokensFilePath)
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
	// Ensure that the parent directory exists
	err := os.MkdirAll(filepath.Dir(accessTokensFilePath), 0755)
	if err != nil {
		return errors.WithStack(err)
	}

	accessTokens[target] = token

	// Convert the access tokens to JSON
	bytes, err := json.MarshalIndent(accessTokens, "", "  ")
	if err != nil {
		return errors.WithStack(err)
	}

	// Write the JSON to file
	err = os.WriteFile(accessTokensFilePath, bytes, 0600)
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func Get(target string) string {
	return accessTokens[target]
}
