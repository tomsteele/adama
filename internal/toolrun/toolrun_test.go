package toolrun

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
)

func TestExitFailurePreservesPartialStdout(t *testing.T) {
	out, err := Run(context.Background(), "sh", []string{"-c", "printf 'partial output'; printf 'fatal error' >&2; exit 2"}, nil)
	if string(out) != "partial output" || err == nil || !strings.Contains(err.Error(), "fatal error") {
		t.Fatalf("%q %v", out, err)
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 2 {
		t.Fatalf("lost exit status %v", err)
	}
}

func TestCanceledProcessDoesNotReportSuccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Run(ctx, "sh", []string{"-c", "exit 0"}, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("%v", err)
	}
}
