// Package toolrun preserves subprocess failure and partial stdout separately.
package toolrun

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"adama/sdk"
)

func Run(ctx context.Context, binary string, args []string, stdin io.Reader) ([]byte, error) {
	cmd := exec.CommandContext(ctx, binary, args...)
	configureProcess(cmd)
	cmd.Stdin = stdin
	cmd.WaitDelay = 2 * time.Second
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	return out, Failure(ctx, binary, err, stderr.Bytes())
}

func Failure(ctx context.Context, binary string, err error, stderr []byte) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err == nil {
		return nil
	}
	text := strings.TrimSpace(string(stderr))
	if len(text) > 4096 {
		text = text[len(text)-4096:]
	}
	failure := fmt.Errorf("%s: %w: %s", binary, err, text)
	var startup *exec.Error
	if errors.As(err, &startup) {
		return sdk.ToolUnavailable(failure)
	}
	lower := strings.ToLower(text)
	for _, marker := range []string{"unknown flag", "unknown shorthand flag", "flag provided but not defined", "unrecognized option", "invalid option", "chrome browser is not installed", "could not create runner"} {
		if strings.Contains(lower, marker) {
			return sdk.ToolUnavailable(failure)
		}
	}
	// An unclassified nonzero exit is terminal. Do not guess that replaying
	// the same command will repair it.
	return failure
}
