package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"adama/event"
	"adama/internal/toolrun"
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
		Handle: func(ctx context.Context, ev event.Event) ([]event.Event, error) {
			u, ok := target(ev)
			if !ok {
				slog.Info("nuclei skip", "kind", ev.Kind, "value", ev.Value)
				return nil, nil
			}
			args := append(append([]string{}, p.NucleiArgs...), "-u", u)
			out, runErr := toolrun.Run(ctx, "nuclei", args, nil)
			evs, err := parseHits(out, ev)
			slog.Info("nuclei", "target", u, "findings", len(evs))
			return evs, errors.Join(runErr, err)
		},
	})
	if err != nil && ctx.Err() == nil {
		slog.Error("run", "err", err)
		os.Exit(1)
	}
}
