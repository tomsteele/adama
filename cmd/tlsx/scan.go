package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"adama/event"
	"adama/internal/toolrun"
)

func scan(ctx context.Context, ev event.Event) ([]event.Event, error) {
	// Consume every open port, but leave unsupported transports visibly failed.
	// TLS over TCP is not evidence that the corresponding UDP service was tested.
	if ev.Proto != event.TCP {
		return nil, fmt.Errorf("tlsx does not support transport %q at %s; endpoint was not scanned", ev.Proto, ev.Value)
	}
	u, err := event.PortValue(ev.TargetHost(), ev.Port)
	if err != nil {
		return nil, fmt.Errorf("invalid tlsx target: %w", err)
	}
	args := []string{"-u", u, "-san", "-cn", "-silent", "-nc", "-json"}
	if ev.Name != "" && ev.NameRole == event.NameRequested {
		args = append(args, "-sni", ev.Name)
	}
	out, runErr := toolrun.Run(ctx, "tlsx", args, nil)
	evs, err := parseTLSX(out, ev)
	slog.Info("tlsx", "target", ev.Value, "names", len(evs))
	return evs, errors.Join(runErr, err)
}
