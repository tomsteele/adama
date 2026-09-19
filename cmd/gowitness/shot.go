package main

import (
	"os"
	"path/filepath"
	"strings"

	"adama/event"
)

func gowitnessFile(dir, u string) string {
	base := strings.NewReplacer("://", "---", "/", "").Replace(u)
	return filepath.Join(dir, base+".jpeg")
}

func attachShot(dir, u string, ev *event.Event) {
	b, err := os.ReadFile(gowitnessFile(dir, u))
	if err != nil {
		return
	}
	ev.Data = b
	ev.MediaType = "image/jpeg"
}
