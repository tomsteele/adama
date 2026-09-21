package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"adama/event"
)

type nucleiHit struct {
	Timestamp        time.Time       `json:"timestamp"`
	TemplateID       string          `json:"template-id"`
	MatcherName      json.RawMessage `json:"matcher-name"`
	ExtractedResults []string        `json:"extracted-results"`
	CurlCommand      string          `json:"curl-command"`
	Type             string          `json:"type"`
	IP               string          `json:"ip"`
	MatchedAt        string          `json:"matched-at"`
	Info             struct {
		Name        string   `json:"name"`
		Severity    string   `json:"severity"`
		Description string   `json:"description"`
		Tags        []string `json:"tags"`
	} `json:"info"`
}

func parseHits(stdout []byte, in event.Event) ([]event.Event, error) {
	var evs []event.Event
	sc := bufio.NewScanner(bytes.NewReader(stdout))
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var hit nucleiHit
		if line[0] != '{' {
			continue
		}
		if err := json.Unmarshal(line, &hit); err != nil {
			return nil, fmt.Errorf("nuclei result: %w", err)
		}
		if hit.TemplateID == "" {
			return nil, fmt.Errorf("nuclei result missing template ID")
		}
		t := findingTarget(hit, in)
		ev := event.Event{
			SchemaVersion: event.SchemaVersion,
			Kind:          event.KindFinding,
			Value:         "nuclei/" + hit.TemplateID + "/" + in.Value,
			Target:        t,
			Probe:         hit.TemplateID,
			Observed:      hit.Timestamp,
			TLS:           strings.HasPrefix(t.URL, "https://") || hit.Type == "ssl",
			Meta: map[string]string{
				"template":    hit.TemplateID,
				"name":        hit.Info.Name,
				"severity":    hit.Info.Severity,
				"description": hit.Info.Description,
				"tags":        event.JoinMetaList(hit.Info.Tags),
				"matcher":     rawString(hit.MatcherName),
				"extracted":   event.JoinMetaList(hit.ExtractedResults),
				"curl":        hit.CurlCommand,
				"type":        hit.Type,
				"ip":          hit.IP,
				"matched_at":  hit.MatchedAt,
				"url":         in.Value,
				"host":        t.Host,
			},
		}
		ev.Info = map[string]string{}
		for k, v := range ev.Meta {
			ev.Info[k] = v
		}
		evs = append(evs, ev)
	}
	return evs, sc.Err()
}

func findingTarget(hit nucleiHit, in event.Event) event.Target {
	var t event.Target
	switch hit.Type {
	case "http", "headless", "websocket":
		u := hit.MatchedAt
		if u == "" {
			u = in.Value
		}
		t, _ = event.URLTarget(u)
	case "ssl", "tcp", "network":
		t = in.Target
		t.Host = "" // The scanner's IP below is authoritative.
		fromURL, urlErr := event.URLTarget(hit.MatchedAt)
		if hit.Type == "ssl" && urlErr == nil {
			t = fromURL
		} else if h, p, err := event.SplitHostPort(hit.MatchedAt); err == nil {
			t.Port = p
			if ip, err := event.CanonIP(h); err == nil {
				t.Host = ip
			} else {
				t.Name, t.NameRole = event.CanonFQDN(h), event.NameRequested
			}
		}
		if hit.Type == "ssl" {
			t.Proto = event.TCP
		}
	}
	if ip, err := event.CanonIP(hit.IP); err == nil {
		t.Host = ip
	}
	return t
}

func rawString(raw json.RawMessage) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	if raw[0] == '"' {
		var s string
		if json.Unmarshal(raw, &s) == nil {
			return s
		}
	}
	var ss []string
	if json.Unmarshal(raw, &ss) == nil {
		return strings.Join(ss, ",")
	}
	return string(raw)
}
