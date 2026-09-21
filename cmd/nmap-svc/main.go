package main

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"

	"adama/event"
	"adama/internal/nmapx"
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
		Name:    p.Name,
		Kinds:   p.EventKinds(),
		AckWait: p.Ack(),
		Handle: func(ctx context.Context, ev event.Event) ([]event.Event, error) {
			host, port := ev.TargetHost(), ev.Port
			if host == "" || port == 0 {
				return nil, nil
			}
			args := append(p.Args(ev), "-p", strconv.Itoa(port), "-oX", "-", host)
			out, err := exec.CommandContext(ctx, "nmap", args...).Output()
			if err != nil {
				if x, ok := err.(*exec.ExitError); ok {
					slog.Warn("nmap-svc exit", "err", err, "stderr", string(x.Stderr))
				} else {
					return nil, err
				}
			}
			svcs, err := nmapx.ParseServices(out)
			if err != nil {
				return nil, err
			}
			slog.Info("nmap-svc", "target", ev.Value, "services", len(svcs), "scripts", scriptCount(svcs))
			return nmapx.ServiceEvents(ev, svcs), nil
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
