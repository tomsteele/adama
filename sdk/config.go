package sdk

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Defaults bound executions independently of JetStream delivery counts. A
// delivery waiting for another replica's lease does not consume an attempt.
func (c Config) defaults() (Config, error) {
	if c.AckWait == 0 {
		c.AckWait = 5 * time.Minute
	}
	ints := []struct {
		key   string
		dst   *int
		value int
	}{
		{"ADAMA_MAX_ATTEMPTS", &c.MaxAttempts, 3},
		{"ADAMA_MAX_PUBLISH_ATTEMPTS", &c.MaxPublishAttempts, 5},
		{"ADAMA_MAX_PENDING", &c.MaxPending, 32},
	}
	for _, item := range ints {
		if *item.dst != 0 {
			continue
		}
		*item.dst = item.value
		if raw := os.Getenv(item.key); raw != "" {
			v, err := strconv.Atoi(raw)
			if err != nil || v < 1 {
				return c, fmt.Errorf("%s must be a positive integer", item.key)
			}
			*item.dst = v
		}
	}
	durations := []struct {
		key   string
		dst   *time.Duration
		value time.Duration
	}{
		{"ADAMA_TASK_TIMEOUT", &c.TaskTimeout, c.AckWait},
		{"ADAMA_RETRY_WINDOW", &c.RetryWindow, 24 * time.Hour},
		{"ADAMA_RETRY_DELAY", &c.RetryDelay, 10 * time.Second},
		{"ADAMA_LEASE_DURATION", &c.LeaseDuration, 30 * time.Second},
		{"ADAMA_SHUTDOWN_GRACE", &c.ShutdownGrace, 5 * time.Second},
	}
	for _, item := range durations {
		if *item.dst != 0 {
			continue
		}
		*item.dst = item.value
		if raw := os.Getenv(item.key); raw != "" {
			v, err := time.ParseDuration(raw)
			if err != nil || v <= 0 {
				return c, fmt.Errorf("%s must be a positive duration", item.key)
			}
			*item.dst = v
		}
	}
	if c.MaxAttempts < 1 || c.MaxPublishAttempts < 1 || c.MaxPending < 1 || c.AckWait <= 0 || c.TaskTimeout <= 0 || c.RetryWindow <= 0 || c.RetryDelay <= 0 || c.LeaseDuration < 3*time.Millisecond || c.ShutdownGrace <= 0 {
		return c, fmt.Errorf("invalid worker limits")
	}
	return c, nil
}

type retryableError struct{ error }

// Retryable opts a plausibly transient failure into the finite execution
// budget. Ordinary errors (including malformed output) are terminal by default.
func Retryable(err error) error {
	if err == nil {
		return nil
	}
	return retryableError{err}
}
func (e retryableError) Unwrap() error { return e.error }
