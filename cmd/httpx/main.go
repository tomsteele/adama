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
		RequiredTools: screenshotTools(p.HttpxArgs),
		Name:          p.Name,
		Evidence:      "screenshot",
		Kinds:         p.kinds(),
		AckWait:       p.ackWait(),
		Handle: func(ctx context.Context, ev event.Event) ([]event.Event, error) {
			args := append(append([]string{}, p.HttpxArgs...), "-u", ev.Value, "-srd", dir)
			out, runErr := toolrun.Run(ctx, "httpx", args, nil)
			results, parseErr := parseResults(out)
			err := errors.Join(runErr, parseErr)
			events, outcomeErr := screenshotEvents(ev, results)
			return events, errors.Join(err, outcomeErr)
		},
	})
	if err != nil && ctx.Err() == nil {
		slog.Error("run", "err", err)
		os.Exit(1)
	}
}

func screenshotTools(args []string) []string {
	tools := []string{"httpx"}
	for _, arg := range args {
		if arg == "-system-chrome" {
			chrome := os.Getenv("CHROME_PATH")
			if chrome == "" {
				chrome = "chromium-browser"
			}
			tools = append(tools, chrome)
			break
		}
	}
	return tools
}
