package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"adama/event"
	"adama/sdk"
)

const ctlURL = "https://ctl.shodan.io/api/v1/domain/%s/hostnames"

var client = &http.Client{Timeout: 30 * time.Second}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err := sdk.Run(ctx, sdk.Config{
		Name:  "ctl",
		Kinds: []event.Kind{event.KindDomain},
		Handle: func(ctx context.Context, ev event.Event) ([]event.Event, error) {
			body, err := fetch(ctx, ev.Value)
			if err != nil {
				return nil, err
			}
			evs := parseHostnames(body, ev.Value)
			slog.Info("ctl", "domain", ev.Value, "names", len(evs))
			return evs, nil
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
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ctl %d", resp.StatusCode)
	}
	return body, nil
}
