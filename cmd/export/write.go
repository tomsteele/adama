package main

import (
	"os"
	"path/filepath"

	"adama/event"
)

func appendJSONL(file string, ev event.Event) error {
	raw, err := ev.Bytes()
	if err != nil {
		return err
	}
	line := append(raw, '\n')
	if file == "-" {
		_, err = os.Stdout.Write(line)
		return err
	}
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(file, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(line)
	if err != nil {
		return err
	}
	return f.Sync()
}
