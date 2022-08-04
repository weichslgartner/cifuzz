package coverage

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseLcov(t *testing.T) {
	report := `SF:bar.cpp
FNH:2
FNF:21
BRH:1
BRF:23
LH:100
LF:200
end_of_record
SF:foo.cpp
FNH:1
FNF:1
BRH:9
BRF:10
LH:50
LF:50
end_of_record
`
	summary := ParseLcov(report)

	assert.Len(t, summary.Files, 2)
	assert.Equal(t, 3, summary.Total.FunctionsHit)
	assert.Equal(t, 22, summary.Total.FunctionsFound)
	assert.Equal(t, 10, summary.Total.BranchesHit)
	assert.Equal(t, 33, summary.Total.BranchesFound)
	assert.Equal(t, 150, summary.Total.LinesHit)
	assert.Equal(t, 250, summary.Total.LinesFound)

	assert.Equal(t, 2, summary.Files[0].Coverage.FunctionsHit)
	assert.Equal(t, 21, summary.Files[0].Coverage.FunctionsFound)
	assert.Equal(t, 1, summary.Files[0].Coverage.BranchesHit)
	assert.Equal(t, 23, summary.Files[0].Coverage.BranchesFound)
	assert.Equal(t, 100, summary.Files[0].Coverage.LinesHit)
	assert.Equal(t, 200, summary.Files[0].Coverage.LinesFound)

	assert.Equal(t, 1, summary.Files[1].Coverage.FunctionsHit)
	assert.Equal(t, 1, summary.Files[1].Coverage.FunctionsFound)
	assert.Equal(t, 9, summary.Files[1].Coverage.BranchesHit)
	assert.Equal(t, 10, summary.Files[1].Coverage.BranchesFound)
	assert.Equal(t, 50, summary.Files[1].Coverage.LinesHit)
	assert.Equal(t, 50, summary.Files[1].Coverage.LinesFound)
}

func TestParseLcov_MissingSectionEnd(t *testing.T) {
	report := `SF:bar.cpp
FNH:2
FNF:21
SF:foo.cpp
FNH:1
FNF:1
`
	summary := ParseLcov(report)

	assert.Len(t, summary.Files, 2)
	assert.Equal(t, 3, summary.Total.FunctionsHit)
	assert.Equal(t, 22, summary.Total.FunctionsFound)
	assert.Equal(t, 2, summary.Files[0].Coverage.FunctionsHit)
	assert.Equal(t, 21, summary.Files[0].Coverage.FunctionsFound)
	assert.Equal(t, 1, summary.Files[1].Coverage.FunctionsHit)
	assert.Equal(t, 1, summary.Files[1].Coverage.FunctionsFound)
}

func TestParseLcov_IgnoredKey(t *testing.T) {
	report := `TN:test
SF:bar.cpp
FN:1,hello
FNH:2
FNF:21
end_of_record
`

	summary := ParseLcov(report)
	assert.Equal(t, 2, summary.Files[0].Coverage.FunctionsHit)
	assert.Equal(t, 21, summary.Files[0].Coverage.FunctionsFound)
}

func TestParseLcov_InvalidKey(t *testing.T) {
	report := `SF:bar.cpp
123
FNH:2
FNF:21
FOO:::
end_of_record
`

	summary := ParseLcov(report)
	assert.Equal(t, 2, summary.Files[0].Coverage.FunctionsHit)
	assert.Equal(t, 21, summary.Files[0].Coverage.FunctionsFound)
}

func TestParseLcov_InvalidValue(t *testing.T) {
	report := `SF:foo.cpp
FNH:foo
end_of_record
`

	summary := ParseLcov(report)
	assert.Equal(t, 0, summary.Files[0].Coverage.FunctionsHit)
}

func TestParseLcov_Empty(t *testing.T) {
	report := ""
	summary := ParseLcov(report)
	assert.Len(t, summary.Files, 0)
	assert.Empty(t, summary.Total.BranchesFound)
	assert.Empty(t, summary.Total.LinesFound)
	assert.Empty(t, summary.Total.FunctionsFound)
}
