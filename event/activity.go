package event

import (
	"encoding/json"
	"time"
)

const ActivitySubject = "adama.activity"

// Activity is ephemeral bus status. Not a Kind; not on EVENTS.
type Activity struct {
	Action  string    `json:"action"`
	Tool    string    `json:"tool"`
	Kind    Kind      `json:"kind"`
	Value   string    `json:"value"`
	Scope   string    `json:"scope,omitempty"`
	Reason  string    `json:"reason,omitempty"`
	Emitted int       `json:"emitted,omitempty"`
	Elapsed string    `json:"elapsed,omitempty"`
	At      time.Time `json:"at"`
}

func (a Activity) Bytes() ([]byte, error) { return json.Marshal(a) }

func DecodeActivity(b []byte) (Activity, error) {
	var a Activity
	err := json.Unmarshal(b, &a)
	return a, err
}

func (a Activity) Key() string {
	k := a.Tool + "/" + string(a.Kind) + "/" + a.Value
	if a.Scope != "" {
		k += "/" + a.Scope
	}
	return k
}
