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
<p>{{.Source}} · {{.Observed.UTC.Format "2006-01-02 15:04:05"}}Z</p>
{{if eq .Kind "screenshot"}}
  {{if .Data}}<p><img src="{{img .MediaType .Data}}" alt="{{.Value}}"></p>{{else}}<p>no image</p>{{end}}
{{else}}
<dl>
{{range $k, $v := .Meta}}<dt>{{$k}}</dt><dd>{{$v}}</dd>{{end}}
</dl>
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
	return os.WriteFile(html, buf.Bytes(), 0o644)
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
