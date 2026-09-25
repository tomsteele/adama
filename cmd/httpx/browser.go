package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"adama/event"
	"adama/internal/browsercapture"
)

func hopTarget(h browsercapture.Hop) (event.Target, error) {
	t, err := event.URLTarget(h.URL)
	if err != nil {
		return t, err
	}
	ip, err := event.CanonIP(h.Host)
	if err != nil {
		return t, fmt.Errorf("browser response has no peer IP for %s", h.URL)
	}
	if t.Host != "" && t.Host != ip || t.Port != h.Port {
		return t, fmt.Errorf("browser peer disagrees with URL endpoint for %s", h.URL)
	}
	t.Host = ip
	return t, nil
}

func browserEvents(in event.Event, probes []result, capture browsercapture.Capture, limit int) ([]event.Event, error) {
	var out []event.Event
	var problems []error
	chain, _ := json.Marshal(capture.Hops)
	depth, err := redirectDepth(in)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for i, hop := range capture.Hops {
		target, err := hopTarget(hop)
		if err != nil {
			problems = append(problems, err)
			continue
		}
		if i == 0 {
			if !sameURL(in.Value, hop.URL) || in.Host != "" && in.Host != target.Host {
				problems = append(problems, fmt.Errorf("browser initial response does not establish requested endpoint %s at %s", in.Value, in.Host))
			}
			continue
		}
		if depth+i > limit {
			problems = append(problems, fmt.Errorf("redirect discovery limit exceeded"))
			break
		}
		key := target.Host + "/" + target.URL
		if seen[key] || sameURL(in.Value, hop.URL) && in.Host == target.Host {
			continue
		}
		seen[key] = true
		out = append(out, event.Event{SchemaVersion: event.SchemaVersion, Kind: event.KindURL, Value: target.URL,
			Target: target, Probe: "browser-redirect", TLS: strings.HasPrefix(target.URL, "https://"),
			Meta: map[string]string{"redirect_depth": strconv.Itoa(depth + i)},
			Info: map[string]string{"endpoint_evidence": "browser_document", "initial_url": in.Value, "redirect_chain": string(chain), "status_code": strconv.FormatInt(hop.Status, 10)},
		})
	}
	if len(capture.Hops) == 0 {
		return out, errors.Join(append(problems, fmt.Errorf("browser returned no verified screenshot"))...)
	}
	last := capture.Hops[len(capture.Hops)-1]
	target, err := hopTarget(last)
	if err != nil {
		return out, errors.Join(append(problems, err)...)
	}
	if len(capture.PNG) == 0 {
		// Preserve the responses already observed before a broken redirect or
		// loop. This is a failed screenshot attempt, never image evidence.
		diagnostic := toEvent(in, result{URL: last.URL, HostIP: last.Host, StatusCode: int(last.Status)})
		diagnostic.Info["endpoint_evidence"] = "browser_document"
		diagnostic.Meta["endpoint_evidence"] = "browser_document"
		diagnostic.Info["initial_url"], diagnostic.Info["redirect_chain"] = in.Value, string(chain)
		out = append([]event.Event{diagnostic}, out...)
		return out, errors.Join(append(problems, fmt.Errorf("browser returned no verified screenshot"))...)
	}
	finalTarget, err := event.URLTarget(capture.URL)
	if err != nil {
		return out, errors.Join(append(problems, err)...)
	}
	responseURL, _ := url.Parse(last.URL)
	finalURL, _ := url.Parse(capture.URL)
	// Same-document fragments/history changes keep the document's endpoint.
	if !strings.EqualFold(responseURL.Host, finalURL.Host) || responseURL.Scheme != finalURL.Scheme {
		return out, errors.Join(append(problems, fmt.Errorf("browser screenshot URL differs from final response authority"))...)
	}
	finalTarget.Host = target.Host
	// Preserve the address-bar fragment/history state for the final URL task.
	for i := range out {
		if out[i].Value == last.URL && out[i].Host == target.Host {
			out[i].Value, out[i].Target = capture.URL, finalTarget
			out[i].Info["response_url"] = last.URL
		}
	}
	shot := toEvent(in, result{URL: capture.URL, Title: capture.Title, HostIP: target.Host, Port: strconv.Itoa(target.Port),
		StatusCode: int(last.Status), ContentType: last.ContentType, WebServer: last.Server, Timestamp: capture.Observed, ScreenshotBytes: capture.PNG})
	shot.Target = finalTarget
	shot.Info["endpoint_evidence"], shot.Info["browser_endpoint_evidence"] = "browser_document", "cdp_response"
	shot.Meta["endpoint_evidence"] = "browser_document"
	shot.Info["initial_url"], shot.Info["initial_host"] = in.Value, capture.Hops[0].Host
	shot.Info["final_url"], shot.Info["response_url"] = capture.URL, last.URL
	shot.Info["redirect_chain"], shot.Info["redirect_count"] = string(chain), strconv.Itoa(len(capture.Hops)-1)
	// Probe fingerprints belong to their own response, not a redirected page.
	for i, probe := range probes {
		prefix := "probe_"
		if i > 0 {
			prefix = fmt.Sprintf("probe_%d_", i+1)
		}
		observed := toEvent(in, probe)
		for key, value := range observed.Info {
			if strings.HasPrefix(key, "screenshot_") {
				continue
			}
			shot.Info[prefix+key] = value
		}
		shot.Info[prefix+"url"], shot.Info[prefix+"host"] = observed.URL, observed.Host
	}
	if len(shot.Data) == 0 {
		problems = append(problems, fmt.Errorf("browser screenshot is not a valid PNG"))
	}
	if len(problems) > 0 {
		shot.Info["requested_endpoint_status"] = "unverified"
	}
	out = append([]event.Event{shot}, out...)
	return out, errors.Join(problems...)
}
