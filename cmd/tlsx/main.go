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
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err := sdk.Run(ctx, sdk.Config{
		RequiredTools: []string{"tlsx"},
		Name:          "tlsx",
		Kinds:         []event.Kind{event.KindPort},
		Handle:        scan,
	})
	if err != nil && ctx.Err() == nil {
		slog.Error("run", "err", err)
		os.Exit(1)
	}
}
