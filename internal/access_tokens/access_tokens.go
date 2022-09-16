package access_tokens

var accessTokens map[string]string

func Get(target string) string {
	return accessTokens[target]
}
