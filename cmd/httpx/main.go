package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"adama/event"
	"adama/sdk"
)

func main() {
	path := os.Getenv("HTTPX_PROFILE")
	if path == "" {
		path = "profiles/httpx.yaml"
	}
	p, err := loadProfile(path)
	if err != nil {
		slog.Error("profile", "err", err)
		os.Exit(2)
	}
	dir := os.Getenv("SCREENSHOT_DIR")
	if dir == "" {
		dir = "screenshots"
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err = sdk.Run(ctx, sdk.Config{
		Name:    p.Name,
		Kinds:   p.kinds(),
		AckWait: p.ackWait(),
		Handle: func(ctx context.Context, ev event.Event) ([]event.Event, error) {
			args := append(append([]string{}, p.HttpxArgs...), "-u", ev.Value, "-srd", dir)
			out, stderr, err := runHttpx(ctx, args)
			if err != nil && chromeMissing(stderr) {
				args = stripShot(args)
				slog.Warn("httpx retry without screenshot")
				out, stderr, err = runHttpx(ctx, args)
			}
			if err != nil {
				slog.Warn("httpx exit", "err", err, "stderr", string(stderr))
			}
			results, err := parseResults(out)
			if err != nil {
				return nil, err
			}
			var events []event.Event
			for _, r := range results {
				shot := toEvent(ev, r)
				slog.Info("httpx", "url", shot.Value, "host", shot.Host, "status", shot.Meta["status_code"])
				events = append(events, shot)
			}
			return events, nil
		},
	})
	if err != nil && ctx.Err() == nil {
		slog.Error("run", "err", err)
		os.Exit(1)
	}
}
