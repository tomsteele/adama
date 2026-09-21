package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"adama/event"
)

type result struct {
	Timestamp       time.Time       `json:"timestamp"`
	URL             string          `json:"url"`
	Title           string          `json:"title"`
	WebServer       string          `json:"webserver"`
	ContentType     string          `json:"content_type"`
	Method          string          `json:"method"`
	Host            string          `json:"host"`
	HostIP          string          `json:"host_ip"`
	SNI             string          `json:"sni"`
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

// parseResults retains every address/scheme result returned by the tool.
func parseResults(stdout []byte) ([]result, error) {
	var out []result
	sc := bufio.NewScanner(bytes.NewReader(stdout))
	sc.Buffer(make([]byte, 64*1024), 16<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		r, ok, err := parseResult(line)
		if err != nil {
			return nil, fmt.Errorf("httpx result: %w", err)
		}
		if ok {
			out = append(out, r)
		}
	}
	return out, sc.Err()
}

func toEvent(in event.Event, r result) event.Event {
	ev := event.Event{
		SchemaVersion: event.SchemaVersion,
		Kind:          event.KindScreenshot,
		Value:         in.Value,
		Meta:          map[string]string{},
	}
	if r.URL != "" {
		ev.Value = r.URL
	}
	ev.Probe = "http-screenshot"
	ev.Observed = r.Timestamp
	ev.Target, _ = event.URLTarget(ev.Value)
	ip, _ := event.CanonIP(r.HostIP)
	if ip == "" {
		ip, _ = event.CanonIP(r.Host)
	}
	if ip != "" {
		ev.Host = ip
	}
	if r.SNI != "" {
		ev.SNI = r.SNI
	}
	// HTTPX's connected IP identifies its HTTP probe, not an independently
	// redirected browser navigation. Preserve that boundary explicitly.
	ev.Meta["endpoint_evidence"] = "http_probe"
	if r.FinalURL != "" {
		initial, _ := url.Parse(ev.Value)
		final, err := url.Parse(r.FinalURL)
		if err == nil && initial != nil && !strings.EqualFold(initial.Host, final.Host) {
			ev.Meta["redirect_endpoint"] = "unverified"
		}
	}
	ev.TLS = strings.HasPrefix(ev.URL, "https://")
	ev.Service = "http"
	// Never copy an ancestor's IP, product, or port over the response identity.
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
	ev.Info = map[string]string{}
	for k, v := range ev.Meta {
		ev.Info[k] = v
	}
	if len(ev.Data) == 0 {
		ev.Info["screenshot_status"] = "missing"
	} else {
		ev.Info["screenshot_status"] = "captured"
	}
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
