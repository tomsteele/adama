package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"adama/event"
)

type requestSummary struct {
	Total, Failed      int
	FirstError         string
	OffEndpoint        int
	FirstEndpointError string
	DNS                bool
}

func readTrace(path string, in event.Event) (requestSummary, error) {
	f, err := os.Open(path)
	if err != nil {
		return requestSummary{}, fmt.Errorf("nuclei request evidence: %w", err)
	}
	defer f.Close()
	return parseTrace(f, in)
}

func parseTrace(r io.Reader, in event.Event) (requestSummary, error) {
	var summary requestSummary
	d := json.NewDecoder(r)
	for {
		var record struct {
			Template string  `json:"template"`
			Type     string  `json:"type"`
			Error    *string `json:"error"`
			Input    string  `json:"input"`
		}
		if err := d.Decode(&record); err == io.EOF {
			break
		} else if err != nil {
			return summary, fmt.Errorf("nuclei request log: %w", err)
		}
		if record.Error == nil || record.Template == "" || record.Type == "" {
			return summary, fmt.Errorf("incomplete nuclei request log record")
		}
		summary.Total++
		summary.DNS = summary.DNS || record.Type == "dns"
		if in.Kind == event.KindService && *record.Error == "none" {
			if err := serviceRequestEndpoint(record.Type, record.Input, in); err != nil {
				summary.OffEndpoint++
				if summary.FirstEndpointError == "" {
					summary.FirstEndpointError = err.Error()
					if len(summary.FirstEndpointError) > 1024 {
						summary.FirstEndpointError = summary.FirstEndpointError[:1024]
					}
				}
			}
		}
		if *record.Error != "none" {
			summary.Failed++
			if summary.FirstError == "" {
				summary.FirstError = record.Template + ": " + *record.Error
				if len(summary.FirstError) > 1024 {
					summary.FirstError = summary.FirstError[:1024]
				}
			}
		}
	}
	if summary.Total == 0 {
		return summary, fmt.Errorf("nuclei produced no request execution evidence")
	}
	var err error
	if summary.Failed > 0 {
		err = fmt.Errorf("nuclei: %d of %d logged requests failed; first: %s", summary.Failed, summary.Total, summary.FirstError)
	}
	if summary.OffEndpoint > 0 {
		err = errors.Join(err, fmt.Errorf("nuclei: %d successful requests do not establish requested service coverage; first: %s", summary.OffEndpoint, summary.FirstEndpointError))
	}
	return summary, err
}

// Check the scanner's reported request endpoint even for successful non-matches.
// This is request-log evidence, not packet-level verification: SSL logs can
// report the original input, and arbitrary JavaScript does not identify its
// actual transport. Neither may be treated as evidence for a UDP service.
func serviceRequestEndpoint(kind, address string, in event.Event) error {
	if (kind != "tcp" && kind != "network" && kind != "ssl") || in.Proto != event.TCP {
		return fmt.Errorf("%s request cannot establish coverage of %s service", kind, in.Proto)
	}
	host, port, err := event.SplitHostPort(strings.TrimPrefix(address, "tls://"))
	if err != nil {
		return fmt.Errorf("%s request has no usable endpoint: %q", kind, address)
	}
	if port != in.Port || !strings.EqualFold(host, in.Target.Authority()) {
		return fmt.Errorf("%s request used %s, expected %s:%d/%s", kind, address, in.Target.Authority(), in.Port, in.Proto)
	}
	return nil
}
