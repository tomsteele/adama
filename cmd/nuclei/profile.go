package main

import (
	"fmt"
	"os"
	"time"

	"adama/event"

	"gopkg.in/yaml.v3"
)

type profile struct {
	Name       string   `yaml:"name"`
	Kinds      []string `yaml:"kinds"`
	NucleiArgs []string `yaml:"nuclei_args"`
	AckWait    string   `yaml:"ack_wait"`
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
	return p, nil
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
