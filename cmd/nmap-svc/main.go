package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"adama/event"
	"adama/internal/nmapx"
	"adama/internal/toolrun"
	"adama/sdk"
)

func main() {
	path := os.Getenv("NMAP_PROFILE")
	if path == "" {
		path = "profiles/nmap-svc.yaml"
	}
	p, err := nmapx.LoadProfile(path)
	if err != nil {
		slog.Error("profile", "err", err)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err = sdk.Run(ctx, sdk.Config{
		RequiredTools: []string{"nmap"},
		Name:          p.Name,
		Evidence:      "service identification",
		Kinds:         p.EventKinds(),
		AckWait:       p.Ack(),
		Handle: func(ctx context.Context, ev event.Event) ([]event.Event, error) {
			host, port := ev.TargetHost(), ev.Port
			if host == "" || port == 0 {
				return nil, nil
			}
			args := append(p.Args(ev), "-p", strconv.Itoa(port), "-oX", "-", host)
			out, runErr := toolrun.Run(ctx, "nmap", args, nil)
			runErr = errors.Join(runErr, nmapx.CompletionError(out))
			svcs, err := nmapx.ParseServices(out)
			if err != nil {
				return nil, errors.Join(runErr, err)
			}
			slog.Info("nmap-svc", "target", ev.Value, "services", len(svcs), "scripts", scriptCount(svcs))
			return nmapx.ServiceEvents(ev, svcs), runErr
		},
	})
	if err != nil && ctx.Err() == nil {
		slog.Error("run", "err", err)
		os.Exit(1)
	}
}

func scriptCount(svcs []nmapx.Svc) int {
	n := 0
	for _, s := range svcs {
		n += len(s.Scripts)
	}
	return n
}
