package nmapx

import (
	"strings"
	"testing"
)

func TestCompletionRejectsMissingExitFailureAndHostTimeout(t *testing.T) {
	for _, tc := range []struct{ xml, want string }{
		{`<nmaprun/>`, "no completion record"},
		{`<nmaprun><runstats><finished exit="error" errormsg="probe failed"/></runstats></nmaprun>`, "probe failed"},
		{`<nmaprun><host timedout="true"><address addr="192.0.2.1" addrtype="ipv4"/></host><runstats><finished exit="success"/></runstats></nmaprun>`, "192.0.2.1 timed out"},
		{`<unexpected/>`, "nmaprun"},
	} {
		if err := CompletionError([]byte(tc.xml)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("false completion for %s: %v", tc.xml, err)
		}
	}
	if err := CompletionError([]byte(`<nmaprun><runstats><finished exit="success"/></runstats></nmaprun>`)); err != nil {
		t.Fatal(err)
	}
}

func TestTimeoutStillPreservesConfirmedOpenPorts(t *testing.T) {
	raw := []byte(`<nmaprun><host timedout="true"><address addr="192.0.2.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>`)
	if err := CompletionError(raw); err == nil {
		t.Fatal("host timeout marked complete")
	}
	scans, err := ParseXML(raw)
	if err != nil || len(scans) != 1 || len(scans[0].Ports) != 1 || scans[0].Ports[0].Port != 443 {
		t.Fatalf("lost partial evidence: %+v %v", scans, err)
	}
}
