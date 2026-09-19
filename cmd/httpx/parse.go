package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"adama/event"
)

type result struct {
	URL             string          `json:"url"`
	Title           string          `json:"title"`
	WebServer       string          `json:"webserver"`
	ContentType     string          `json:"content_type"`
	Method          string          `json:"method"`
	Host            string          `json:"host"`
	Path            string          `json:"path"`
	Scheme          string          `json:"scheme"`
	Location        string          `json:"location"`
	FinalURL        string          `json:"final_url"`
	StatusCode      int             `json:"status_code"`
	ContentLength   int             `json:"content_length"`
	Failed          bool            `json:"failed"`
	Port            string          `json:"port"`
	Technologies    []string        `json:"tech"`
	CDN             bool            `json:"cdn"`
	CDNName         string          `json:"cdn_name"`
	Jarm            string          `json:"jarm"`
	Favicon         string          `json:"favicon"`
	A               []string        `json:"a"`
	AAAA            []string        `json:"aaaa"`
	CNames          []string        `json:"cname"`
	ScreenshotBytes []byte          `json:"screenshot_bytes"`
	ScreenshotPath  string          `json:"screenshot_path"`
	ASN             json.RawMessage `json:"asn"`
}

func runHttpx(ctx context.Context, args []string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, "httpx", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	return out, stderr.Bytes(), err
}

func chromeMissing(stderr []byte) bool {
	s := string(stderr)
	return strings.Contains(s, "chrome browser is not installed") ||
		strings.Contains(s, "Could not create runner")
}

func stripShot(args []string) []string {
	skipNext := 0
	var out []string
	for _, a := range args {
		if skipNext > 0 {
			skipNext--
			continue
		}
		switch a {
		case "-ss", "-screenshot", "-system-chrome", "-no-screenshot-full-page",
			"-esb", "-exclude-screenshot-bytes":
			continue
		case "-ho", "-headless-options", "-st", "-screenshot-timeout", "-sid", "-screenshot-idle":
			skipNext = 1
			continue
		}
		out = append(out, a)
	}
	return out
}

func firstJSON(b []byte) []byte {
	i := bytes.IndexByte(b, '{')
	if i < 0 {
		return nil
	}
	j := bytes.IndexByte(b[i:], '\n')
	if j < 0 {
		return bytes.TrimSpace(b[i:])
	}
	return bytes.TrimSpace(b[i : i+j])
}

func parseResult(stdout []byte) (result, bool, error) {
	line := firstJSON(stdout)
	if len(line) == 0 {
		return result{}, false, nil
	}
	var r result
	if err := json.Unmarshal(line, &r); err != nil {
		return result{}, false, err
	}
	if r.Failed && r.StatusCode == 0 && len(r.ScreenshotBytes) == 0 && r.ScreenshotPath == "" {
		return result{}, false, nil
	}
	return r, true, nil
}

func toEvent(in event.Event, r result) event.Event {
	ev := event.Event{
		Kind:  event.KindScreenshot,
		Value: in.Value,
		Meta:  map[string]string{},
	}
	if r.URL != "" {
		ev.Value = r.URL
	}
	copyMeta(ev.Meta, in.Meta, "host", "port", "name", "product")
	put(ev.Meta, "title", r.Title)
	put(ev.Meta, "webserver", r.WebServer)
	put(ev.Meta, "content_type", r.ContentType)
	put(ev.Meta, "method", r.Method)
	put(ev.Meta, "path", r.Path)
	put(ev.Meta, "scheme", r.Scheme)
	put(ev.Meta, "location", r.Location)
	put(ev.Meta, "final_url", r.FinalURL)
	put(ev.Meta, "jarm", r.Jarm)
	put(ev.Meta, "favicon", r.Favicon)
	put(ev.Meta, "cdn_name", r.CDNName)
	put(ev.Meta, "tech", event.JoinMetaList(r.Technologies))
	put(ev.Meta, "a", event.JoinMetaList(r.A))
	put(ev.Meta, "aaaa", event.JoinMetaList(r.AAAA))
	put(ev.Meta, "cname", event.JoinMetaList(r.CNames))
	if r.StatusCode != 0 {
		ev.Meta["status_code"] = strconv.Itoa(r.StatusCode)
	}
	if r.ContentLength != 0 {
		ev.Meta["content_length"] = strconv.Itoa(r.ContentLength)
	}
	if r.Port != "" {
		ev.Meta["port"] = r.Port
	}
	if r.Host != "" && ev.Meta["host"] == "" {
		ev.Meta["host"] = r.Host
	}
	if r.CDN {
		ev.Meta["cdn"] = "true"
	}
	asnMeta(r.ASN, ev.Meta)
	attachShot(&ev, r)
	return ev
}

func attachShot(ev *event.Event, r result) {
	b := r.ScreenshotBytes
	if len(b) == 0 && r.ScreenshotPath != "" {
		b, _ = os.ReadFile(r.ScreenshotPath)
	}
	if len(b) == 0 {
		return
	}
	ev.Data = b
	ev.MediaType = mediaType(b)
}

func mediaType(b []byte) string {
	if bytes.HasPrefix(b, []byte{0x89, 'P', 'N', 'G'}) {
		return "image/png"
	}
	return "image/jpeg"
}

func put(m map[string]string, k, v string) {
	if v != "" {
		m[k] = v
	}
}

func copyMeta(dst, src map[string]string, keys ...string) {
	for _, k := range keys {
		put(dst, k, src[k])
	}
}

func asnMeta(raw json.RawMessage, m map[string]string) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return
	}
	if raw[0] == '"' {
		var s string
		if json.Unmarshal(raw, &s) == nil {
			put(m, "asn", s)
		}
		return
	}
	var o struct {
		Number  string `json:"as_number"`
		Name    string `json:"as_name"`
		Country string `json:"as_country"`
	}
	if json.Unmarshal(raw, &o) != nil {
		return
	}
	put(m, "asn", o.Number)
	put(m, "as_name", o.Name)
	put(m, "as_country", o.Country)
}
