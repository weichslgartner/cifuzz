package cmdutil

import "fmt"

// IncorrectUsageError is an error caused by incorrect usage of the
// command-line flags or arguments. When handling an IncorrectUsageError,
// cifuzz prints the usage message.
type IncorrectUsageError struct {
	err error
}

func IncorrectUsageErrorf(format string, args ...interface{}) error {
	return IncorrectUsageErrorWrap(fmt.Errorf(format, args...))
}

func IncorrectUsageErrorWrap(err error) error {
	return &IncorrectUsageError{err}
}

func (e *IncorrectUsageError) Error() string {
	return e.err.Error()
}

func (e *IncorrectUsageError) Unwrap() error {
	return e.err
}
