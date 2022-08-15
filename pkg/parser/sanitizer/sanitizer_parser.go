package sanitizer

import (
	"regexp"

	"code-intelligence.com/cifuzz/pkg/finding"
	"code-intelligence.com/cifuzz/util/regexutil"
)

var (
	errorPattern = regexp.MustCompile(
		`==\d+==\s*(ERROR|WARNING):.*Sanitizer:\s(?P<error_type>.+)`,
	)
	runtimeErrorStartPattern = regexp.MustCompile(
		`\S+ runtime error: (?P<error_type>[^:]+)`,
	)
)

func ParseAsFinding(line string) *finding.Finding {
	finding := parseAsRuntimeReport(line)
	if finding != nil {
		return finding
	}

	finding = parseAsErrorReport(line)
	if finding != nil {
		return finding
	}

	return nil
}

func parseAsErrorReport(log string) *finding.Finding {
	result, found := regexutil.FindNamedGroupsMatch(errorPattern, log)
	if found {
		return &finding.Finding{
			Type:    finding.ErrorType_CRASH, // aka Vulnerability
			Details: result["error_type"],
			Logs:    []string{log},
		}
	}

	return nil
}

func parseAsRuntimeReport(log string) *finding.Finding {
	result, found := regexutil.FindNamedGroupsMatch(runtimeErrorStartPattern, log)
	if !found {
		return nil
	}
	return &finding.Finding{
		Type:    finding.ErrorType_RUNTIME_ERROR,
		Details: "undefined behaviour: " + result["error_type"],
		Logs:    []string{log},
	}
}
