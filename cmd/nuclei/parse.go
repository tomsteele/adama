package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"

	"adama/event"
)

type nucleiHit struct {
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

func parseHits(stdout []byte, in event.Event) []event.Event {
	var evs []event.Event
	sc := bufio.NewScanner(bytes.NewReader(stdout))
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var hit nucleiHit
		if err := json.Unmarshal(line, &hit); err != nil || hit.TemplateID == "" {
			continue
		}
		evs = append(evs, event.Event{
			Kind:  event.KindFinding,
			Value: "nuclei/" + hit.TemplateID + "/" + in.Value,
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
				"host":        in.Meta["host"],
				"product":     in.Meta["product"],
			},
		})
	}
	return evs
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
