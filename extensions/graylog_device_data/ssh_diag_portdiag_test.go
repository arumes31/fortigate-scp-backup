package graylogdevicedata

import "testing"

// TestValidDiagName is a security test: the switch/port names reach an SSH CLI
// command, so anything with whitespace, newlines or shell/CLI metacharacters
// must be rejected before interpolation (no command injection).
func TestValidDiagName(t *testing.T) {
	valid := []string{"port1", "port48", "SW-CORE01", "EX_ACCESS.03", "S424EP0000000002"}
	for _, s := range valid {
		if !ValidDiagName(s) {
			t.Errorf("expected %q to be valid", s)
		}
	}
	invalid := []string{
		"", "port1 port2", "port1;reboot", "port1\ndiagnose sys reboot",
		"port1|cat", "port1$(x)", "port1`x`", "port1&", "a b", "port1 ",
		"../etc", "port1\t", "sw name",
	}
	for _, s := range invalid {
		if ValidDiagName(s) {
			t.Errorf("expected %q to be REJECTED (injection risk)", s)
		}
	}
}

func TestCleanDiagOutput(t *testing.T) {
	raw := "diagnose switch-controller switch-info port-stats SW-CORE01 port1\n" +
		"\n" +
		"Vdom: root\n" +
		"Port(port1) is HW Admin up, SW Admin up, line protocol is up\n" +
		"full-duplex, 1000 Mb/s\n" +
		"\n" +
		"FGT90G-CUST4-N2(Primary) $ "
	got := cleanDiagOutput(raw)
	if want := "Vdom: root\nPort(port1) is HW Admin up, SW Admin up, line protocol is up\nfull-duplex, 1000 Mb/s"; got != want {
		t.Errorf("cleanDiagOutput mismatch:\n got: %q\nwant: %q", got, want)
	}
}

func TestDiagCmdFailed(t *testing.T) {
	if !diagCmdFailed("command parse error before 'foo'") {
		t.Error("parse error not detected")
	}
	if !diagCmdFailed("Unknown action 0") {
		t.Error("unknown action not detected")
	}
	if diagCmdFailed("Port(port1) is HW Admin up") {
		t.Error("real data wrongly flagged as failure")
	}
}
