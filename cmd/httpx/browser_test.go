package main

import (
	"context"
	"strings"
	"testing"

	"adama/event"
	"adama/internal/browsercapture"
)

func TestBrowserRedirectIdentityAndProbeDetails(t *testing.T) {
	in := event.Event{Kind: event.KindURL, Value: "http://initial.example/", Target: event.Target{Host: "192.0.2.1"}, Meta: map[string]string{"redirect_depth": "2"}}
	capture := browsercapture.Capture{URL: "https://final.example:8443/Final?Token=AbC#Section", Title: "Final", PNG: screenshotPNG(t), Hops: []browsercapture.Hop{
		{URL: in.Value, Host: in.Host, Port: 80, Status: 302},
		{URL: "http://middle.example/", Host: "192.0.2.2", Port: 80, Status: 301},
		{URL: "https://final.example:8443/Final?Token=AbC", Host: "2001:db8::3", Port: 8443, Status: 200},
	}}
	out, err := browserEvents(in, []result{{URL: in.Value, HostIP: in.Host, Title: "Initial", Technologies: []string{"initial-tech"}}}, capture, 10)
	if err != nil || len(out) != 3 {
		t.Fatalf("%+v %v", out, err)
	}
	shot := out[0]
	if shot.Host != "2001:db8::3" || shot.Name != "final.example" || shot.Port != 8443 || shot.URL != capture.URL || !shot.TLS {
		t.Fatalf("wrong final endpoint %+v", shot.Target)
	}
	if shot.Info["title"] != "Final" || shot.Info["probe_title"] != "Initial" || shot.Info["tech"] != "" || shot.Info["probe_tech"] != "initial-tech" {
		t.Fatal(shot.Info)
	}
	if out[1].Meta["redirect_depth"] != "3" || out[2].Meta["redirect_depth"] != "4" || out[2].Value != capture.URL {
		t.Fatal("lost redirect budget or fragment")
	}
	for _, ev := range out {
		if _, err := ev.Canonical(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestBrowserRequiresResponseAndImageEvidence(t *testing.T) {
	for _, name := range []string{"missing image", "invalid image", "missing peer", "wrong initial peer", "wrong initial URL", "wrong final authority", "wrong peer port", "no responses"} {
		t.Run(name, func(t *testing.T) {
			in := event.Event{Kind: event.KindURL, Value: "https://initial.example/", Target: event.Target{Host: "192.0.2.1"}}
			c := browsercapture.Capture{URL: in.Value, PNG: screenshotPNG(t), Hops: []browsercapture.Hop{{URL: in.Value, Host: in.Host, Port: 443, Status: 200}}}
			switch name {
			case "missing image":
				c.PNG = nil
			case "invalid image":
				c.PNG = []byte("invalid")
			case "missing peer":
				c.Hops[0].Host = ""
			case "wrong initial peer":
				c.Hops[0].Host = "192.0.2.2"
			case "wrong initial URL":
				c.Hops[0].URL = "https://other.example/"
			case "wrong final authority":
				c.URL = "https://other.example/"
			case "wrong peer port":
				c.Hops[0].Port = 8443
			case "no responses":
				c.Hops = nil
			}
			out, err := browserEvents(in, nil, c, 10)
			if err == nil {
				t.Fatal("unverified screenshot completed")
			}
			for _, ev := range out {
				if _, err := ev.Canonical(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestRedirectBudgetSurvivesNewQueueTasks(t *testing.T) {
	in := event.Event{Kind: event.KindURL, Value: "http://initial.example/", Target: event.Target{Host: "192.0.2.1"}, Meta: map[string]string{"redirect_depth": "2"}}
	c := browsercapture.Capture{Hops: []browsercapture.Hop{
		{URL: in.Value, Host: in.Host, Port: 80, Status: 302},
		{URL: "http://next.example/", Host: "192.0.2.2", Port: 80, Status: 200},
	}}
	out, err := browserEvents(in, nil, c, 2)
	if err == nil {
		t.Fatal("budget reset")
	}
	for _, ev := range out {
		if ev.Kind == event.KindURL {
			t.Fatal("created work beyond redirect budget")
		}
	}
	t.Setenv("PATH", t.TempDir())
	in.Meta["redirect_depth"] = "3"
	_, err = scan(context.Background(), profile{Browser: browsercapture.Config{MaxRedirects: 2}}, t.TempDir(), in)
	if err == nil || !strings.Contains(err.Error(), "redirect discovery limit") {
		t.Fatalf("scanner launched beyond budget: %v", err)
	}
}
