package finding

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/otiai10/copy"
	"github.com/pkg/errors"

	"code-intelligence.com/cifuzz/pkg/log"
)

const nameCrashingInput = "crashing-input"
const nameJsonFile = "finding.json"
const nameFindingDir = ".cifuzz-findings"

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

type Finding struct {
	Name               string        `json:"name,omitempty"`
	Type               ErrorType     `json:"type,omitempty"`
	InputData          []byte        `json:"input_data,omitempty"`
	Logs               []string      `json:"logs,omitempty"`
	Details            string        `json:"details,omitempty"`
	HumanReadableInput string        `json:"human_readable_input,omitempty"`
	MoreDetails        *ErrorDetails `json:"more_details,omitempty"`
	Tag                uint64        `json:"tag,omitempty"`
	ShortDescription   string        `json:"short_description,omitempty"`
	InputFile          string
}

type ErrorType string

// These constants must have this exact value (in uppercase) to be able
// to parse JSON-marshalled reports as protobuf reports which use an
// enum for this field.
const (
	ErrorType_UNKNOWN_ERROR     ErrorType = "UNKNOWN_ERROR"
	ErrorType_COMPILATION_ERROR ErrorType = "COMPILATION_ERROR"
	ErrorType_CRASH             ErrorType = "CRASH"
	ErrorType_WARNING           ErrorType = "WARNING"
	ErrorType_RUNTIME_ERROR     ErrorType = "RUNTIME_ERROR"
)

type ErrorDetails struct {
	Id       string    `json:"id,omitempty"`
	Name     string    `json:"name,omitempty"`
	Severity *Severity `json:"severity,omitempty"`
}

type Severity struct {
	Description string  `json:"description,omitempty"`
	Score       float32 `json:"score,omitempty"`
}

func (f *Finding) GetDetails() string {
	if f != nil {
		return f.Details
	}
	return ""
}

// GetInputFile returns the path where the finding's input file can be
// found. Note that the InputFile field contains the path to the input
// file relative to the project directory. The GetInputFile therefore
// receives the project directory as an argument and returns the
// absolute path to the input file.
func (f *Finding) GetInputFile(projectDir string) string {
	if f != nil {
		return filepath.Join(projectDir, f.InputFile)
	}
	return ""
}

func (f *Finding) Save(projectDir string) error {
	findingDir := filepath.Join(projectDir, nameFindingDir, f.Name)

	if err := os.MkdirAll(findingDir, 0755); err != nil {
		return errors.WithStack(err)
	}

	if f.InputFile != "" {
		if err := f.moveInputFile(projectDir, findingDir); err != nil {
			return err
		}
	}

	if err := f.saveJson(findingDir); err != nil {
		return err
	}

	return nil
}

func (f *Finding) saveJson(findingDir string) error {
	bytes, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return errors.WithStack(err)
	}

	jsonPath := filepath.Join(findingDir, nameJsonFile)
	if err := os.WriteFile(jsonPath, bytes, 0644); err != nil {
		return errors.WithStack(err)
	}

	return nil
}

// move the input file to a new location and update
// the finding and the logs
func (f *Finding) moveInputFile(projectDir, findingDir string) error {
	newPath := filepath.Join(findingDir, nameCrashingInput)

	// We don't use os.Rename to avoid errors when source and target
	// are not on the same mounted filesystem.
	// We don't use f.GetInputFile because before moveInputFile is
	// called, the InputFile field might not actually contain a path
	// relative to the project directory.
	if err := copy.Copy(f.InputFile, newPath); err != nil {
		return errors.WithStack(err)
	}
	if err := os.Remove(f.InputFile); err != nil {
		return errors.WithStack(err)
	}

	// Replace the old filename in the finding logs. Replace it with the
	// relative path to not leak the directory structure of the current
	// user in the finding logs (which might be shared with others).
	cwd, err := os.Getwd()
	if err != nil {
		return errors.WithStack(err)
	}
	relPath, err := filepath.Rel(cwd, newPath)
	if err != nil {
		return errors.WithStack(err)
	}
	for i, line := range f.Logs {
		f.Logs[i] = strings.ReplaceAll(line, f.InputFile, relPath)
	}
	log.Debugf("moved input file from %s to %s", f.InputFile, newPath)

	// The path in the InputFile field is expected to be relative to the
	// project directory
	pathRelativeToProjectDir, err := filepath.Rel(projectDir, newPath)
	if err != nil {
		return errors.WithStack(err)
	}
	f.InputFile = pathRelativeToProjectDir
	return nil
}

// ListFindings parses the JSON files of all findings and returns the
// result.
func ListFindings(projectDir string) ([]*Finding, error) {
	findingsDir := filepath.Join(projectDir, nameFindingDir)
	entries, err := os.ReadDir(findingsDir)
	if os.IsNotExist(err) {
		return []*Finding{}, nil
	}
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var res []*Finding
	for _, e := range entries {
		f, err := LoadFinding(projectDir, e.Name())
		if err != nil {
			return nil, err
		}
		res = append(res, f)
	}

	return res, nil
}

// LoadFinding parses the JSON file of the specified finding and returns
// the result.
// If the specified finding does not exist, a NotExistError is returned.
func LoadFinding(projectDir, findingName string) (*Finding, error) {
	findingDir := filepath.Join(projectDir, nameFindingDir, findingName)
	jsonPath := filepath.Join(findingDir, nameJsonFile)
	bytes, err := os.ReadFile(jsonPath)
	if os.IsNotExist(err) {
		return nil, WrapNotExistError(err)
	}
	if err != nil {
		return nil, errors.WithStack(err)
	}
	var f Finding
	err = json.Unmarshal(bytes, &f)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return &f, nil
}
