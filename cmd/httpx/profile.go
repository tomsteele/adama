package main

import (
	"fmt"
	"os"
	"time"

	"adama/event"
	"adama/internal/browsercapture"

	"gopkg.in/yaml.v3"
)

type profile struct {
	Name      string                `yaml:"name"`
	Kinds     []string              `yaml:"kinds"`
	HttpxArgs []string              `yaml:"httpx_args"`
	BoundArgs []string              `yaml:"bound_args"`
	Resolvers []string              `yaml:"resolvers"`
	AckWait   string                `yaml:"ack_wait"`
	Browser   browsercapture.Config `yaml:"browser"`
}

func loadProfile(path string) (profile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return profile{}, err
	}
	p := profile{Browser: browsercapture.Config{MaxRedirects: 10}}
	if err := yaml.Unmarshal(b, &p); err != nil {
		return profile{}, err
	}
	if p.Name == "" || len(p.Kinds) == 0 || len(p.HttpxArgs) == 0 {
		return profile{}, fmt.Errorf("profile %s: need name, kinds, httpx_args", path)
	}
	if err := p.Browser.Validate(); err != nil {
		return profile{}, fmt.Errorf("profile %s: %w", path, err)
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
		return 5 * time.Minute
	}
	return d
}
