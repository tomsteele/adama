package sdk

import (
	"fmt"
	"slices"
	"strconv"

	"adama/event"
)

// Rule is a serializable predicate over canonical event fields. The zero rule
// accepts everything. Workers and offline coverage evaluate the same predicate;
// there is no separate implementation or list of tool-specific predicates.
type Rule struct {
	All     []Rule   `json:"all,omitempty"`
	Any     []Rule   `json:"any,omitempty"`
	Not     *Rule    `json:"not,omitempty"`
	Field   string   `json:"field,omitempty"`
	Values  []string `json:"values,omitempty"`
	Present bool     `json:"present,omitempty"`
}

func All(rules ...Rule) Rule                      { return Rule{All: rules} }
func Any(rules ...Rule) Rule                      { return Rule{Any: rules} }
func Not(rule Rule) Rule                          { return Rule{Not: &rule} }
func FieldIn(field string, values ...string) Rule { return Rule{Field: field, Values: values} }
func Has(field string) Rule                       { return Rule{Field: field, Present: true} }

func BoundNameRule() Rule {
	return All(Has("host"), Has("name"), FieldIn("name_role", string(event.NameRequested), string(event.NameDNSA), string(event.NameDNSAAAA)))
}

func ruleField(ev event.Event, field string) (string, bool) {
	switch field {
	case "kind":
		return string(ev.Kind), true
	case "source":
		return ev.Source, true
	case "value":
		return ev.Value, true
	case "host":
		return ev.Host, true
	case "name":
		return ev.Name, true
	case "name_role":
		return string(ev.NameRole), true
	case "port":
		if ev.Port == 0 {
			return "", true
		}
		return strconv.Itoa(ev.Port), true
	case "proto":
		return string(ev.Proto), true
	case "service":
		return ev.Service, true
	case "url":
		return ev.URL, true
	case "sni":
		return ev.SNI, true
	case "http_host":
		return ev.HTTPHost, true
	case "tls":
		return strconv.FormatBool(ev.TLS), true
	case "alive":
		return strconv.FormatBool(event.Live(ev)), true
	default:
		return "", false
	}
}

func (r Rule) Match(ev event.Event) bool {
	switch {
	case r.All != nil:
		return !slices.ContainsFunc(r.All, func(child Rule) bool { return !child.Match(ev) })
	case r.Any != nil:
		return slices.ContainsFunc(r.Any, func(child Rule) bool { return child.Match(ev) })
	case r.Not != nil:
		return !r.Not.Match(ev)
	case r.Field != "":
		value, ok := ruleField(ev, r.Field)
		return ok && ((r.Present && value != "") || (!r.Present && slices.Contains(r.Values, value)))
	default:
		return true
	}
}

func (r Rule) Validate() error { return r.validate(0) }
func (r Rule) validate(depth int) error {
	if depth > 16 {
		return fmt.Errorf("input rule exceeds nesting limit")
	}
	modes := 0
	for _, yes := range []bool{r.All != nil, r.Any != nil, r.Not != nil, r.Field != ""} {
		if yes {
			modes++
		}
	}
	if modes > 1 {
		return fmt.Errorf("input rule must use exactly one of all, any, not, field")
	}
	if r.Field == "" && (r.Present || r.Values != nil) {
		return fmt.Errorf("input rule values/present need a field")
	}
	if r.Field != "" {
		if _, ok := ruleField(event.Event{}, r.Field); !ok {
			return fmt.Errorf("unknown input rule field %q", r.Field)
		}
		if r.Present == (len(r.Values) > 0) {
			return fmt.Errorf("input rule field needs either present or nonempty values")
		}
	}
	if (r.All != nil && len(r.All) == 0) || (r.Any != nil && len(r.Any) == 0) {
		return fmt.Errorf("input rule all/any must not be empty")
	}
	if len(r.All)+len(r.Any) > 64 {
		return fmt.Errorf("too many input rule branches")
	}
	for _, group := range [][]Rule{r.All, r.Any} {
		for _, child := range group {
			if err := child.validate(depth + 1); err != nil {
				return err
			}
		}
	}
	if r.Not != nil {
		return r.Not.validate(depth + 1)
	}
	return nil
}
