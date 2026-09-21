package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"adama/event"
	"adama/internal/asurl"
	"adama/sdk"
)

func main() {
	path := os.Getenv("NUCLEI_PROFILE")
	if path == "" {
		path = "profiles/nuclei.yaml"
	}
	p, err := loadProfile(path)
	if err != nil {
		slog.Error("profile", "err", err)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err = sdk.Run(ctx, sdk.Config{
		RequiredTools: []string{"nuclei"},
		Name:          p.Name,
		Kinds:         p.kinds(),
		AckWait:       p.ackWait(),
		TaskTimeout:   p.taskTimeout(),
		Filter:        sdk.Any(sdk.Not(sdk.FieldIn("kind", string(event.KindService))), sdk.Not(asurl.WebServiceRule())),
		Handle: func(ctx context.Context, ev event.Event) ([]event.Event, error) {
			return scan(ctx, p, ev)
		},
	})
	if err != nil && ctx.Err() == nil {
		slog.Error("run", "err", err)
		os.Exit(1)
	}
}
