package main

import (
	"net/url"
	"strings"

	"adama/event"
)

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
