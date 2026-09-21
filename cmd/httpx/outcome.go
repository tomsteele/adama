package main

import (
	"errors"
	"fmt"

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
		events = append(events, shot)
	}
	return events, errors.Join(problems...)
}
