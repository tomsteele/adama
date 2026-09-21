package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"adama/event"
	"adama/internal/toolrun"
	"adama/sdk"
)

const ctlURL = "https://ctl.shodan.io/api/v1/domain/%s/hostnames"

var client = &http.Client{Timeout: 30 * time.Second}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err := sdk.Run(ctx, sdk.Config{
		RequiredTools: []string{"dnsx"},
		Name:          "ctl",
		Kinds:         []event.Kind{event.KindDomain},
		Handle: func(ctx context.Context, ev event.Event) ([]event.Event, error) {
			body, err := fetch(ctx, ev.Value)
			if err != nil {
				return nil, err
			}
			evs, err := parseHostnames(body, ev.Value)
			if err != nil {
				return nil, err
			}
			evs, err = resolving(ctx, evs)
			slog.Info("ctl", "domain", ev.Value, "names", len(evs))
			return evs, err
		},
	})
	if err != nil && ctx.Err() == nil {
		slog.Error("run", "err", err)
		os.Exit(1)
	}
}

func fetch(ctx context.Context, domain string) ([]byte, error) {
	u := fmt.Sprintf(ctlURL, url.PathEscape(domain))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "adama")
	resp, err := client.Do(req)
	if err != nil {
		return nil, sdk.Retryable(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, sdk.Retryable(err)
	}
	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("ctl %d", resp.StatusCode)
		if resp.StatusCode == 429 || resp.StatusCode >= 500 {
			err = sdk.Retryable(err)
		}
		return nil, err
	}
	return body, nil
}

func resolving(ctx context.Context, evs []event.Event) ([]event.Event, error) {
	if len(evs) == 0 {
		return evs, nil
	}
	var b strings.Builder
	for _, ev := range evs {
		b.WriteString(ev.Value)
		b.WriteByte('\n')
	}
	out, runErr := toolrun.Run(ctx, "dnsx", []string{"-silent", "-a", "-aaaa", "-json"}, strings.NewReader(b.String()))
	resolved, parseErr := keepResolved(evs, out)
	return resolved, errors.Join(runErr, parseErr)
}
