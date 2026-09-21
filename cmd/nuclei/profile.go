package main

import (
	"fmt"
	"os"
	"slices"
	"time"

	"adama/event"

	"gopkg.in/yaml.v3"
)

type profile struct {
	// These describe this profile's service probes, not a global routing table.
	// Unsupported inputs remain failed work instead of disappearing from coverage.
	ServiceTransports []event.Protocol `yaml:"service_transports"`
	Name              string           `yaml:"name"`
	Kinds             []string         `yaml:"kinds"`
	NucleiArgs        []string         `yaml:"nuclei_args"`
	BoundArgs         []string         `yaml:"bound_args"`
	TraceArgs         []string         `yaml:"trace_args"`
	Resolvers         []string         `yaml:"resolvers"`
	TaskTimeout       string           `yaml:"task_timeout"`
	AckWait           string           `yaml:"ack_wait"`
}

func loadProfile(path string) (profile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return profile{}, err
	}
	var p profile
	if err := yaml.Unmarshal(b, &p); err != nil {
		return profile{}, err
	}
	if p.Name == "" || len(p.Kinds) == 0 || len(p.NucleiArgs) == 0 {
		return profile{}, fmt.Errorf("profile %s: need name, kinds, nuclei_args", path)
	}
	if p.TaskTimeout != "" {
		if d, err := time.ParseDuration(p.TaskTimeout); err != nil || d <= 0 {
			return profile{}, fmt.Errorf("profile %s: task_timeout must be a positive duration", path)
		}
	}
	if slices.Contains(p.Kinds, string(event.KindService)) && len(p.ServiceTransports) == 0 {
		return profile{}, fmt.Errorf("profile %s: service inputs need service_transports", path)
	}
	for _, proto := range p.ServiceTransports {
		if proto != event.TCP && proto != event.UDP {
			return profile{}, fmt.Errorf("profile %s: invalid service transport %q", path, proto)
		}
	}
	return p, nil
}

func (p profile) taskTimeout() time.Duration {
	d, _ := time.ParseDuration(p.TaskTimeout)
	return d
}

func (p profile) kinds() []event.Kind {
	out := make([]event.Kind, len(p.Kinds))
	for i, k := range p.Kinds {
		out[i] = event.Kind(k)
	}
	return out
}

func (p profile) ackWait() time.Duration {
	d, err := time.ParseDuration(p.AckWait)
	if err != nil || d == 0 {
		return 20 * time.Minute
	}
	return d
}
