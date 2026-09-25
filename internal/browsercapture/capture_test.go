package browsercapture

import (
	"context"
	"testing"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
)

func TestOnlyMainDocumentEstablishesScreenshotIdentity(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	n := &navigation{frame: "main", limit: 2, changed: make(chan struct{}, 1), abort: cancel}
	n.listen(&network.EventRequestWillBeSent{FrameID: "main", LoaderID: "document", Type: network.ResourceTypeDocument})
	for _, frame := range []cdp.FrameID{"iframe", "main"} {
		kind := network.ResourceTypeDocument
		if frame == "main" {
			kind = network.ResourceTypeImage
		}
		n.listen(&network.EventResponseReceived{FrameID: frame, LoaderID: "document", Type: kind, Response: &network.Response{URL: "http://other.example/", RemoteIPAddress: "192.0.2.2", RemotePort: 80}})
	}
	n.listen(&network.EventResponseReceived{FrameID: "main", LoaderID: "document", Type: network.ResourceTypeDocument, Response: &network.Response{URL: "https://actual.example/", RemoteIPAddress: "[2001:db8::1]", RemotePort: 443, Status: 200}})
	n.listen(&page.EventLifecycleEvent{FrameID: "iframe", LoaderID: "document", Name: "load"})
	if n.loaded || len(n.hops) != 1 || n.hops[0].Host != "2001:db8::1" {
		t.Fatalf("wrong document state %+v", n.hops)
	}
	n.listen(&page.EventLifecycleEvent{FrameID: "main", LoaderID: "document", Name: "load"})
	if !n.loaded || ctx.Err() != nil {
		t.Fatal("main document not complete")
	}
}

func TestRepeatedNavigationHasFiniteBudget(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	n := &navigation{frame: "main", limit: 2, changed: make(chan struct{}, 1), abort: cancel}
	for i := 0; i < 3; i++ {
		n.listen(&network.EventRequestWillBeSent{FrameID: "main", Type: network.ResourceTypeDocument})
		if ctx.Err() != nil {
			t.Fatal("legitimate reload rejected before budget")
		}
	}
	n.listen(&network.EventRequestWillBeSent{FrameID: "main", Type: network.ResourceTypeDocument})
	if n.err == nil || context.Cause(ctx) != n.err {
		t.Fatal("redirect limit did not stop navigation")
	}
}
