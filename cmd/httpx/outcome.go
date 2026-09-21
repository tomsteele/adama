package main

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"adama/event"
)

func screenshotEvents(in event.Event, results []result) ([]event.Event, error) {
	if len(results) == 0 {
		return nil, errors.New("httpx returned no successful screenshot")
	}
	var events []event.Event
	var problems []error
	for _, r := range results {
		shot := toEvent(in, r)
		if len(shot.Data) == 0 {
			problems = append(problems, fmt.Errorf("screenshot missing for %s: %s", shot.Value, shot.Info["screenshot_error"]))
		}
		if in.Host != "" && shot.Host != in.Host {
			shot.Info["requested_endpoint_status"] = "mismatch"
			problems = append(problems, fmt.Errorf("HTTPX responding IP %q does not establish requested backend %s", shot.Host, in.Host))
		}
		if !sameURL(in.Value, shot.Value) {
			shot.Info["requested_url_status"] = "mismatch"
			problems = append(problems, fmt.Errorf("HTTPX result URL %q does not establish requested URL %q", shot.Value, in.Value))
		}
		events = append(events, shot)
	}
	return events, errors.Join(problems...)
}

func sameURL(a, b string) bool {
	x, err := event.URLTarget(a)
	if err != nil {
		return false
	}
	y, err := event.URLTarget(b)
	if err != nil {
		return false
	}
	u, _ := url.Parse(a)
	v, _ := url.Parse(b)
	path := func(u *url.URL) string {
		if u.EscapedPath() == "" {
			return "/"
		}
		return u.EscapedPath()
	}
	return strings.EqualFold(u.Scheme, v.Scheme) && strings.EqualFold(u.Hostname(), v.Hostname()) &&
		x.Port == y.Port && path(u) == path(v) && u.RawQuery == v.RawQuery
}
