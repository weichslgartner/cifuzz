package config

type FuzzTestType string

const (
	CPP  FuzzTestType = "cpp"
	JAVA FuzzTestType = "java"
)

type Engine string

const (
	LIBFUZZER Engine = "libfuzzer"
)
