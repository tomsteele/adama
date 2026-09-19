package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"sync"
	"syscall"

	"adama/event"
	"adama/sdk"

	"github.com/nats-io/nats.go"
)

func main() {
	addr := os.Getenv("WATCH_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	nc, err := nats.Connect(sdk.NATSURL())
	if err != nil {
		slog.Error("nats", "err", err)
		os.Exit(1)
	}
	defer nc.Close()

	st := newStore()
	_, err = nc.Subscribe(event.ActivitySubject, func(m *nats.Msg) {
		a, err := event.DecodeActivity(m.Data)
		if err != nil {
			slog.Error("decode", "err", err)
			return
		}
		st.apply(a)
		slog.Info(a.Action, "tool", a.Tool, "kind", a.Kind, "value", a.Value, "reason", a.Reason, "emitted", a.Emitted, "elapsed", a.Elapsed)
	})
	if err != nil {
		slog.Error("subscribe", "err", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(page)
	})
	mux.HandleFunc("/state", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(st.snapshot())
	})
	srv := &http.Server{Addr: addr, Handler: mux}
	go func() {
		slog.Info("watch", "addr", addr, "subject", event.ActivitySubject)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("http", "err", err)
		}
	}()
	<-ctx.Done()
	_ = srv.Shutdown(context.Background())
}

type snapshot struct {
	Running []event.Activity `json:"running"`
	Recent  []event.Activity `json:"recent"`
}

type store struct {
	mu     sync.Mutex
	run    map[string]event.Activity
	recent []event.Activity
}

func newStore() *store { return &store{run: map[string]event.Activity{}} }

func (s *store) apply(a event.Activity) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch a.Action {
	case "start":
		s.run[a.Key()] = a
	case "done", "error":
		delete(s.run, a.Key())
	}
	s.recent = append([]event.Activity{a}, s.recent...)
	if len(s.recent) > 200 {
		s.recent = s.recent[:200]
	}
}

func (s *store) snapshot() snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := snapshot{Recent: append([]event.Activity{}, s.recent...)}
	for _, a := range s.run {
		out.Running = append(out.Running, a)
	}
	sort.Slice(out.Running, func(i, j int) bool {
		if out.Running[i].At.Equal(out.Running[j].At) {
			return out.Running[i].Key() < out.Running[j].Key()
		}
		return out.Running[i].At.Before(out.Running[j].At)
	})
	return out
}

// ponytail: 1s poll; SSE if many browsers
var page = []byte(`<!doctype html>
<meta charset="utf-8">
<title>adama watch</title>
<style>
body{font-family:sans-serif;max-width:56rem;margin:2rem auto;padding:0 1rem}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:.35rem .5rem;border-bottom:1px solid #ddd;font-variant-numeric:tabular-nums}
.mono{font-family:ui-monospace,monospace;font-size:.9rem}
.skip{color:#888}.error{color:#a00}.done{color:#060}
#idle{color:#888}
</style>
<h1>adama</h1>
<h2>running</h2>
<table><thead><tr><th>tool</th><th>kind</th><th>value</th><th>for</th></tr></thead>
<tbody id="run"></tbody></table>
<p id="idle">nothing running</p>
<h2>recent</h2>
<table><thead><tr><th>time</th><th></th><th>tool</th><th>kind</th><th>value</th><th></th></tr></thead>
<tbody id="log"></tbody></table>
<script>
function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function ago(t){
  const ms=Date.now()-new Date(t).getTime();
  if(ms<1000) return Math.max(0,ms)+'ms';
  if(ms<60000) return Math.floor(ms/1000)+'s';
  return Math.floor(ms/60000)+'m'+String(Math.floor((ms%60000)/1000)).padStart(2,'0')+'s';
}
function extra(a){
  const p=[];
  if(a.elapsed) p.push(a.elapsed);
  if(a.emitted) p.push(a.emitted+' emitted');
  if(a.reason) p.push(a.reason);
  if(a.scope) p.push(a.scope);
  return p.join(' · ');
}
async function tick(){
  const s=await (await fetch('/state')).json();
  const run=s.running||[], recent=s.recent||[];
  document.getElementById('idle').style.display=run.length?'none':'';
  document.getElementById('run').innerHTML=run.map(a=>
    '<tr><td>'+esc(a.tool)+'</td><td>'+esc(a.kind)+'</td><td class="mono">'+esc(a.value)+'</td><td>'+esc(ago(a.at))+'</td></tr>'
  ).join('');
  document.getElementById('log').innerHTML=recent.map(a=>
    '<tr class="'+esc(a.action)+'"><td>'+esc(new Date(a.at).toISOString().slice(11,19))+'</td><td>'+esc(a.action)+'</td><td>'+esc(a.tool)+'</td><td>'+esc(a.kind)+'</td><td class="mono">'+esc(a.value)+'</td><td>'+esc(extra(a))+'</td></tr>'
  ).join('');
}
setInterval(tick,1000); tick();
</script>
`)
