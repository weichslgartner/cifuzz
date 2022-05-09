package report

import (
	"time"
)

type Handler interface {
	Handle(report *Report) error
}

type Report struct {
	Status  RunStatus      `json:"status,omitempty"`
	Metric  *FuzzingMetric `json:"metric,omitempty"`
	Finding *Finding       `json:"finding,omitempty"`
}

func (x *Report) GetFinding() *Finding {
	if x != nil {
		return x.Finding
	}
	return nil
}

type RunStatus int32

const (
	RunStatus_RUNSTATUS_UNSPECIFIED      RunStatus = 0
	RunStatus_PENDING                    RunStatus = 1
	RunStatus_COMPILING                  RunStatus = 2
	RunStatus_RUNNING                    RunStatus = 3
	RunStatus_STOPPED                    RunStatus = 4
	RunStatus_FAILED                     RunStatus = 5
	RunStatus_SUCCEEDED                  RunStatus = 6
	RunStatus_UNKNOWN                    RunStatus = 7
	RunStatus_INITIALIZING               RunStatus = 8
	RunStatus_FAILED_TO_START            RunStatus = 9
	RunStatus_WAITING_FOR_FUZZING_AGENTS RunStatus = 10
)

type FuzzingMetric struct {
	Timestamp                time.Time `json:"timestamp,omitempty"`
	ExecutionsPerSecond      int32     `json:"executions_per_second,omitempty"`
	Features                 int32     `json:"features,omitempty"`
	CorpusSize               int32     `json:"corpus_size,omitempty"`
	SecondsSinceLastCoverage uint64    `json:"seconds_since_last_coverage,omitempty"`
	TotalExecutions          uint64    `json:"total_executions,omitempty"`
	Edges                    int32     `json:"edges,omitempty"`
	SecondsSinceLastEdge     uint64    `json:"seconds_since_last_edge,omitempty"`
}

type Finding struct {
	Type               ErrorType     `json:"type,omitempty"`
	InputData          []byte        `json:"input_data,omitempty"`
	Logs               []string      `json:"logs,omitempty"`
	Details            string        `json:"details,omitempty"`
	HumanReadableInput string        `json:"human_readable_input,omitempty"`
	MoreDetails        *ErrorDetails `json:"more_details,omitempty"`
	Tag                uint64        `json:"tag,omitempty"`
	ShortDescription   string        `json:"short_description,omitempty"`
}

func (x *Finding) GetDetails() string {
	if x != nil {
		return x.Details
	}
	return ""
}

type ErrorType int32

const (
	ErrorType_UNKNOWN_ERROR     ErrorType = 0
	ErrorType_COMPILATION_ERROR ErrorType = 1
	ErrorType_CRASH             ErrorType = 2
	ErrorType_WARNING           ErrorType = 3
	ErrorType_RUNTIME_ERROR     ErrorType = 4
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
