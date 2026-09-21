package sdk

import (
	"encoding/json"
	"time"
)

const ToolBucket = "ADAMA_TOOLS"

type toolUnavailableError struct{ error }

func (e toolUnavailableError) Unwrap() error { return e.error }

// ToolUnavailable records a shared installation/configuration fault. Every
// replica stops executing that tool until an operator resumes it after repair.
func ToolUnavailable(err error) error {
	if err == nil {
		return nil
	}
	return toolUnavailableError{err}
}

type ToolFailure struct {
	Tool   string    `json:"tool"`
	Reason string    `json:"reason"`
	At     time.Time `json:"at"`
}

func (b *Bus) pauseTool(tool, reason string) error {
	raw, _ := json.Marshal(ToolFailure{Tool: tool, Reason: reason, At: time.Now().UTC()})
	ctx, cancel := operationContext()
	defer cancel()
	_, err := b.Tools.Put(ctx, tool, raw)
	return err
}
