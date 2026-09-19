package nmapx

import (
	"fmt"
	"os"
	"time"

	"adama/event"

	"gopkg.in/yaml.v3"
)

type Profile struct {
	Name     string   `yaml:"name"`
	Kinds    []string `yaml:"kinds"`
	NmapArgs []string `yaml:"nmap_args"`
	AckWait  string   `yaml:"ack_wait"`
}

func LoadProfile(path string) (Profile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Profile{}, err
	}
	var p Profile
	if err := yaml.Unmarshal(b, &p); err != nil {
		return Profile{}, err
	}
	if p.Name == "" || len(p.Kinds) == 0 || len(p.NmapArgs) == 0 {
		return Profile{}, fmt.Errorf("profile %s: need name, kinds, nmap_args", path)
	}
	return p, nil
}

func (p Profile) EventKinds() []event.Kind {
	out := make([]event.Kind, len(p.Kinds))
	for i, k := range p.Kinds {
		out[i] = event.Kind(k)
	}
	return out
}

func (p Profile) Ack() time.Duration {
	d, err := time.ParseDuration(p.AckWait)
	if err != nil || d == 0 {
		return 5 * time.Minute
	}
	return d
}
