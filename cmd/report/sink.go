package main

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"adama/event"
)

var httpc = &http.Client{Timeout: 15 * time.Second}

func deliver(ctx context.Context, url, file string, ev event.Event) error {
	raw, err := ev.Bytes()
	if err != nil {
		return err
	}
	if url != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		res, err := httpc.Do(req)
		if err != nil {
			return err
		}
		defer res.Body.Close()
		if res.StatusCode < 200 || res.StatusCode > 299 {
			return fmt.Errorf("report api %s", res.Status)
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(file, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = f.Write(append(raw, '\n')); err != nil {
		return err
	}
	return writeHTML(file)
}

func kinds() []event.Kind {
	s := os.Getenv("REPORT_KINDS")
	if s == "" {
		return []event.Kind{event.KindScreenshot, event.KindService}
	}
	var out []event.Kind
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, event.Kind(p))
		}
	}
	return out
}
