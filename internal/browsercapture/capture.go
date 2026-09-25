// Package browsercapture observes the main document's responses in the same
// Chromium session that produces the screenshot. Subresources and frames do not
// establish the screenshot's endpoint.
package browsercapture

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"adama/event"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
)

type Config struct {
	Args         []string `yaml:"args"`
	BoundArgs    []string `yaml:"bound_args"`
	Timeout      string   `yaml:"timeout"`
	Idle         string   `yaml:"idle"`
	MaxRedirects int      `yaml:"max_redirects"`
	Width        int64    `yaml:"width"`
	Height       int64    `yaml:"height"`
	FullPage     bool     `yaml:"full_page"`
}

func (c Config) durations() (time.Duration, time.Duration, error) {
	if c.Timeout == "" {
		c.Timeout = "30s"
	}
	if c.Idle == "" {
		c.Idle = "1s"
	}
	timeout, err := time.ParseDuration(c.Timeout)
	if err != nil || timeout <= 0 {
		return 0, 0, fmt.Errorf("browser timeout must be a positive duration")
	}
	idle, err := time.ParseDuration(c.Idle)
	if err != nil || idle < 0 || idle >= timeout {
		return 0, 0, fmt.Errorf("browser idle must be nonnegative and shorter than timeout")
	}
	return timeout, idle, nil
}

func (c Config) Validate() error {
	_, _, err := c.durations()
	if err != nil {
		return err
	}
	if c.MaxRedirects < 0 || c.Width < 0 || c.Height < 0 {
		return fmt.Errorf("browser redirect limit and dimensions cannot be negative")
	}
	return nil
}

func ChromePath() string {
	if path := os.Getenv("CHROME_PATH"); path != "" {
		return path
	}
	return "chromium-browser"
}

// Hop is one main-document response, including HTTP redirects and documents
// which subsequently navigate through JavaScript or meta refresh.
type Hop struct {
	URL         string `json:"url"`
	Host        string `json:"host,omitempty"`
	Port        int    `json:"port,omitempty"`
	Status      int64  `json:"status_code"`
	Location    string `json:"location,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	Server      string `json:"server,omitempty"`
}

type Capture struct {
	Hops       []Hop
	URL, Title string
	PNG        []byte
	Observed   time.Time
}

type navigation struct {
	mu       sync.Mutex
	frame    cdp.FrameID
	loader   cdp.LoaderID
	loaded   bool
	requests int
	version  int
	hops     []Hop
	err      error
	changed  chan struct{}
	limit    int
	abort    context.CancelCauseFunc
}

func (n *navigation) listen(raw any) {
	n.mu.Lock()
	defer n.mu.Unlock()
	changed := false
	switch e := raw.(type) {
	case *network.EventRequestWillBeSent:
		if e.Type != network.ResourceTypeDocument || e.FrameID != n.frame {
			return
		}
		if e.RedirectResponse != nil {
			n.hops = append(n.hops, responseHop(e.RedirectResponse))
		}
		n.requests++
		n.version++
		n.loader, n.loaded = e.LoaderID, false
		changed = true
		if n.requests > n.limit+1 {
			n.err = fmt.Errorf("browser redirect loop or limit exceeded (%d redirects)", n.limit)
			n.abort(n.err)
		}
	case *network.EventResponseReceived:
		if e.Type != network.ResourceTypeDocument || e.FrameID != n.frame || e.LoaderID != n.loader {
			return
		}
		n.hops = append(n.hops, responseHop(e.Response))
		n.version++
		changed = true
	case *page.EventLifecycleEvent:
		if e.FrameID != n.frame || e.LoaderID != n.loader || e.Name != "load" {
			return
		}
		n.loaded = true
		changed = true
	case *page.EventNavigatedWithinDocument:
		if e.FrameID != n.frame {
			return
		}
		n.version++
		changed = true
	}
	if changed {
		select {
		case n.changed <- struct{}{}:
		default:
		}
	}
}

func responseHop(r *network.Response) Hop {
	ip, _ := event.CanonIP(strings.Trim(r.RemoteIPAddress, "[]"))
	h := Hop{URL: r.URL, Host: ip, Port: int(r.RemotePort), Status: r.Status, ContentType: r.MimeType}
	for key, value := range r.Headers {
		switch strings.ToLower(key) {
		case "location":
			h.Location = fmt.Sprint(value)
		case "server":
			h.Server = fmt.Sprint(value)
		}
	}
	return h
}

func (n *navigation) settle(ctx context.Context, idle time.Duration) error {
	timer := time.NewTimer(idle)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-n.changed:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(idle)
		case <-timer.C:
			n.mu.Lock()
			loaded := n.loaded
			n.mu.Unlock()
			if loaded {
				return nil
			}
			// A main-document load must finish before its quiet period can end.
		}
	}
}

func Run(ctx context.Context, cfg Config, rawURL, boundIP string) (out Capture, err error) {
	timeout, idle, err := cfg.durations()
	if err != nil {
		return out, err
	}
	ctx, cancelTimeout := context.WithTimeout(ctx, timeout)
	defer cancelTimeout()
	ctx, cancelRun := context.WithCancelCause(ctx)
	defer cancelRun(nil)
	options := append([]chromedp.ExecAllocatorOption{}, chromedp.DefaultExecAllocatorOptions[:]...)
	options = append(options, chromedp.ExecPath(ChromePath()))
	args := append([]string{}, cfg.Args...)
	u, err := url.Parse(rawURL)
	if err != nil {
		return out, err
	}
	if boundIP != "" && u.Hostname() != boundIP {
		if len(cfg.BoundArgs) == 0 {
			return out, fmt.Errorf("browser needs bound_args for named backend")
		}
		literal := boundIP
		if strings.Contains(literal, ":") {
			literal = "[" + literal + "]"
		}
		r := strings.NewReplacer("{name}", u.Hostname(), "{ip}", literal)
		for _, arg := range cfg.BoundArgs {
			args = append(args, r.Replace(arg))
		}
	}
	for _, arg := range args {
		key, value, hasValue := strings.Cut(strings.TrimLeft(arg, "-"), "=")
		if hasValue {
			options = append(options, chromedp.Flag(key, value))
		} else {
			options = append(options, chromedp.Flag(key, true))
		}
	}
	alloc, cancelAlloc := chromedp.NewExecAllocator(ctx, options...)
	defer cancelAlloc()
	browser, cancelBrowser := chromedp.NewContext(alloc, chromedp.WithErrorf(func(format string, args ...any) {
		message := fmt.Sprintf(format, args...)
		// Older Chromium emits a string in an unused ExtraInfo cookie field.
		// Its main-document response event (including peer IP) is unaffected.
		if strings.Contains(message, "could not unmarshal event") && strings.Contains(message, "cookiePartitionKey") {
			return
		}
		slog.Warn("browser protocol", "error", message)
	}))
	defer cancelBrowser()
	if err := chromedp.Run(browser); err != nil {
		return out, err
	}
	var tree *page.FrameTree
	if err := chromedp.Run(browser, chromedp.ActionFunc(func(ctx context.Context) error {
		var err error
		tree, err = page.GetFrameTree().Do(ctx)
		return err
	})); err != nil {
		return out, err
	}
	n := &navigation{frame: tree.Frame.ID, changed: make(chan struct{}, 1), limit: cfg.MaxRedirects, abort: cancelRun}
	chromedp.ListenTarget(browser, func(raw any) {
		n.listen(raw)
		if _, ok := raw.(*page.EventJavascriptDialogOpening); ok {
			// Dialogs must not block navigation. CDP actions cannot execute
			// synchronously inside the event listener.
			go func() { _ = chromedp.Run(browser, page.HandleJavaScriptDialog(true)) }()
		}
	})
	defer func() {
		n.mu.Lock()
		if err != nil || out.Hops == nil {
			out.Hops = append([]Hop(nil), n.hops...)
		}
		if n.err != nil {
			err = n.err
		}
		n.mu.Unlock()
		if err != nil {
			out.PNG = nil
		}
	}()
	width, height := cfg.Width, cfg.Height
	if width == 0 {
		width = 1080
	}
	if height == 0 {
		height = 1920
	}
	err = chromedp.Run(browser, network.Enable(), network.SetCacheDisabled(true), network.SetBypassServiceWorker(true),
		page.SetLifecycleEventsEnabled(true), chromedp.EmulateViewport(width, height), chromedp.Navigate(rawURL))
	if err != nil {
		return out, fmt.Errorf("browser navigate: %w", err)
	}
	if err := n.settle(browser, idle); err != nil {
		return out, fmt.Errorf("browser settle: %w", err)
	}
	// Stop script-driven navigation while taking the image. A before/after
	// document check also rejects a network navigation that was already in flight.
	err = chromedp.Run(browser, chromedp.Title(&out.Title), emulation.SetScriptExecutionDisabled(true))
	if err != nil {
		return out, fmt.Errorf("browser pause scripts: %w", err)
	}
	n.mu.Lock()
	version, loaded := n.version, n.loaded
	n.mu.Unlock()
	if !loaded {
		return out, fmt.Errorf("browser navigation changed before screenshot")
	}
	var before, after string
	actions := []chromedp.Action{documentURL(&before)}
	if cfg.FullPage {
		actions = append(actions, chromedp.FullScreenshot(&out.PNG, 100))
	} else {
		actions = append(actions, chromedp.ActionFunc(func(ctx context.Context) error {
			var err error
			out.PNG, err = page.CaptureScreenshot().WithCaptureBeyondViewport(false).Do(ctx)
			return err
		}))
	}
	actions = append(actions, documentURL(&after))
	if err := chromedp.Run(browser, actions...); err != nil {
		return out, fmt.Errorf("browser screenshot: %w", err)
	}
	n.mu.Lock()
	stable := version == n.version && n.loaded
	out.Hops = append([]Hop(nil), n.hops...)
	n.mu.Unlock()
	if !stable || before != after {
		return out, fmt.Errorf("browser navigation changed during screenshot")
	}
	out.URL, out.Observed = after, time.Now().UTC()
	return out, nil
}

// Read the frame URL without executing page JavaScript during capture.
func documentURL(dest *string) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		tree, err := page.GetFrameTree().Do(ctx)
		if err == nil {
			*dest = tree.Frame.URL + tree.Frame.URLFragment
		}
		return err
	})
}
