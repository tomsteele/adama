package main

import (
	"context"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"adama/event"
	"adama/sdk"
)

func main() {
	dir := os.Getenv("SCREENSHOT_DIR")
	if dir == "" {
		dir = "screenshots"
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err := sdk.Run(ctx, sdk.Config{
		Name:  "gowitness",
		Kinds: []event.Kind{event.KindPort},
		Handle: func(ctx context.Context, ev event.Event) ([]event.Event, error) {
			host := ev.Meta["host"]
			port := ev.Meta["port"]
			if port != "80" && port != "443" {
				return nil, nil
			}
			u := urlFor(host, port)
			cmd := exec.CommandContext(ctx, "gowitness", "scan", "single", "--url", u, "--screenshot-path", dir, "--driver", "gorod", "--write-none")
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				return nil, err
			}
			out := event.Event{Kind: event.KindScreenshot, Value: u, Meta: map[string]string{"host": host, "port": port}}
			attachShot(dir, u, &out)
			return []event.Event{out}, nil
		},
	})
	if err != nil && ctx.Err() == nil {
		slog.Error("run", "err", err)
		os.Exit(1)
	}
}

func urlFor(host, port string) string {
	h := host
	if ip, err := netip.ParseAddr(host); err == nil && ip.Is6() {
		h = "[" + host + "]"
	}
	if port == "443" {
		return "https://" + h
	}
	return "http://" + h
}
