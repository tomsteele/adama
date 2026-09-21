package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"os"
	"path/filepath"

	"adama/event"
)

var reportTmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"detail": func(ev event.Event, key string) string {
		if value, ok := ev.Info[key]; ok {
			return value
		}
		return ev.Meta[key]
	},
	"img": func(media string, data []byte) template.URL {
		if len(data) == 0 {
			return ""
		}
		if media == "" {
			media = "image/jpeg"
		}
		return template.URL("data:" + media + ";base64," + base64.StdEncoding.EncodeToString(data))
	},
}).Parse(`<!doctype html>
<meta charset="utf-8">
<title>adama</title>
<style>
body{font-family:sans-serif;max-width:52rem;margin:2rem auto;padding:0 1rem}
section{border-top:1px solid #ddd;padding:1rem 0}
img{max-width:100%;border:1px solid #eee}
dt{font-weight:600} dd{margin:0 0 .4rem 0}
</style>
<h1>adama</h1>
{{range .}}
<section>
<h2>{{.Kind}} {{.Value}}</h2>
<p>{{.Source}} · {{.Observed.UTC.Format "2006-01-02 15:04:05"}}Z
{{if eq .Kind "service"}}{{with detail . "product"}} — {{.}}{{end}}{{with detail . "version"}} {{.}}{{end}}{{end}}
{{if eq .Kind "finding"}}{{with detail . "severity"}} — {{.}}{{end}}{{end}}</p>
<dl>
{{if .Host}}<dt>IP</dt><dd>{{.Host}}</dd>{{end}}
{{if .Name}}<dt>Hostname</dt><dd>{{.Name}} ({{.NameRole}})</dd>{{end}}
{{if .Proto}}<dt>Protocol</dt><dd>{{.Proto}}{{if .Port}} / {{.Port}}{{end}}</dd>{{end}}
{{if .URL}}<dt>URL</dt><dd>{{.URL}}</dd>{{end}}
{{if .Service}}<dt>Service</dt><dd>{{.Service}}{{if .TLS}} over TLS{{end}}</dd>{{end}}
{{if .Probe}}<dt>Probe</dt><dd>{{.Probe}}</dd>{{end}}
{{if .RunID}}<dt>Run</dt><dd>{{.RunID}}</dd>{{end}}
{{if .ScanID}}<dt>Scan</dt><dd>{{.ScanID}}</dd>{{end}}
{{if .Input}}<dt>Input</dt><dd>{{.Input.Kind}} {{.Input.Value}}{{if .Input.Host}} at {{.Input.Host}}{{end}}</dd>{{end}}
{{if .Info}}{{range $k, $v := .Info}}<dt>{{$k}}</dt><dd>{{$v}}</dd>{{end}}
{{else}}{{range $k, $v := .Meta}}<dt>{{$k}}</dt><dd>{{$v}}</dd>{{end}}{{end}}
</dl>
{{if eq .Kind "screenshot"}}
  {{if .Data}}<p><img src="{{img .MediaType .Data}}" alt="{{.Value}}"></p>{{else}}<p>no image</p>{{end}}
{{end}}
</section>
{{else}}
<p>no events yet</p>
{{end}}
`))

func writeHTML(jsonl string) error {
	evs, err := readJSONL(jsonl)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	if err := reportTmpl.Execute(&buf, evs); err != nil {
		return err
	}
	html := filepath.Join(filepath.Dir(jsonl), "report.html")
	f, err := os.CreateTemp(filepath.Dir(jsonl), ".report-*.html")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(buf.Bytes()); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(0o644); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), html)
}

func readJSONL(path string) ([]event.Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []event.Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var ev event.Event
		if err := json.Unmarshal(line, &ev); err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	return out, sc.Err()
}
