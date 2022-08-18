package finding

import "github.com/pkg/errors"

// A NotExistError indicates that the specified finding does not exist
type NotExistError struct {
	err error
}

func (e NotExistError) Error() string {
	return e.err.Error()
}

func (e NotExistError) Unwrap() error {
	return e.err
}

// WrapNotExistError wraps an existing error into a
// NotExistError to hint on disabling the sandbox when the error
// is handled.
func WrapNotExistError(err error) error {
	return &NotExistError{err}
}

func IsNotExistError(err error) bool {
	var notExistErr *NotExistError
	return errors.As(err, &notExistErr)
}

// A AlreadyExistsError indicates that the specified finding already
// exists
type AlreadyExistsError struct {
	err error
}

func (e AlreadyExistsError) Error() string {
	return e.err.Error()
}

func (e AlreadyExistsError) Unwrap() error {
	return e.err
}

// WrapAlreadyExistsError wraps an existing error into a
// AlreadyExistsError to hint on disabling the sandbox when the error
// is handled.
func WrapAlreadyExistsError(err error) error {
	return &AlreadyExistsError{err}
}

func IsAlreadyExistsError(err error) bool {
	var alreadyExistsErr *AlreadyExistsError
	return errors.As(err, &alreadyExistsErr)
}
