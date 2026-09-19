package nmapx

import "testing"

func TestLoadProfile(t *testing.T) {
	p, err := LoadProfile("../../profiles/nmap-full.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "nmap-full" || len(p.Kinds) != 1 || p.Kinds[0] != "ip" {
		t.Fatalf("%+v", p)
	}
	if p.Ack().Hours() != 2 {
		t.Fatalf("ack %s", p.Ack())
	}

	q, err := LoadProfile("../../profiles/nmap-quick.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if q.Name != "nmap-quick" || len(q.Kinds) != 2 {
		t.Fatalf("%+v", q)
	}

	h, err := LoadProfile("../../profiles/nmap-http.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if h.Name != "nmap-http" || len(h.Kinds) != 2 || len(h.NmapArgs) < 4 {
		t.Fatalf("%+v", h)
	}

	d, err := LoadProfile("../../profiles/nmap-discover.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if d.Name != "nmap-discover" || len(d.Kinds) != 3 {
		t.Fatalf("%+v", d)
	}

	s, err := LoadProfile("../../profiles/nmap-svc.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if s.Name != "nmap-svc" || s.Kinds[0] != "port" {
		t.Fatalf("%+v", s)
	}
}
