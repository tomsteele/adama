package main

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"adama/event"
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
		Name:    p.Name,
		Kinds:   p.kinds(),
		AckWait: p.ackWait(),
		Handle: func(ctx context.Context, ev event.Event) ([]event.Event, error) {
			u, ok := target(ev)
			if !ok {
				slog.Info("nuclei skip", "kind", ev.Kind, "value", ev.Value)
				return nil, nil
			}
			args := append(append([]string{}, p.NucleiArgs...), "-u", u)
			out, err := exec.CommandContext(ctx, "nuclei", args...).Output()
			if err != nil {
				if x, ok := err.(*exec.ExitError); ok {
					slog.Warn("nuclei exit", "err", err, "stderr", string(x.Stderr))
				} else {
					return nil, err
				}
			}
			evs := parseHits(out, ev)
			slog.Info("nuclei", "target", u, "findings", len(evs))
			return evs, nil
		},
	})
	if err != nil && ctx.Err() == nil {
		slog.Error("run", "err", err)
		os.Exit(1)
	}
}
