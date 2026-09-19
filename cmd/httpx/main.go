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
			r, ok, err := parseResult(out)
			if err != nil || !ok {
				return nil, err
			}
			shot := toEvent(ev, r)
			slog.Info("httpx", "url", shot.Value, "status", shot.Meta["status_code"], "title", shot.Meta["title"])
			return []event.Event{shot}, nil
		},
	})
	if err != nil && ctx.Err() == nil {
		slog.Error("run", "err", err)
		os.Exit(1)
	}
}
