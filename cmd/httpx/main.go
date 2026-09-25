package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"adama/event"
	"adama/internal/browsercapture"
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
		RequiredTools: []string{"httpx", browsercapture.ChromePath()},
		Name:          p.Name,
		Evidence:      "screenshot",
		Kinds:         p.kinds(),
		AckWait:       p.ackWait(),
		Handle: func(ctx context.Context, ev event.Event) ([]event.Event, error) {
			return scan(ctx, p, dir, ev)
		},
	})
	if err != nil && ctx.Err() == nil {
		slog.Error("run", "err", err)
		os.Exit(1)
	}
}
