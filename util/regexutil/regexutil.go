package regexutil

import "regexp"

// FindNamedGroupsMatch finds a match using a regex with named groups and returns
// a map representing the values of the sub-matches as key-value pairs
func FindNamedGroupsMatch(regexp *regexp.Regexp, text string) (map[string]string, bool) {
	if match := regexp.FindStringSubmatch(text); match != nil {
		result := make(map[string]string)
		for i, name := range regexp.SubexpNames() {
			if i != 0 && name != "" {
				result[name] = match[i]
			}
		}
		return result, true
	}
	return nil, false
}
