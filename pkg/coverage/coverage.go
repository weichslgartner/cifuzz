package coverage

type CoverageSummary struct {
	Total *Coverage
	Files []*FileCoverage
}

type FileCoverage struct {
	Filename string
	Coverage *Coverage
}

type Coverage struct {
	FunctionsFound int
	FunctionsHit   int
	BranchesFound  int
	BranchesHit    int
	LinesFound     int
	LinesHit       int
}
