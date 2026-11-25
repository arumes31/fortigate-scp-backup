package web

import "testing"

// TestParseCfgMultiLineQuotedValue: a multi-line automation script embeds
// `edit`/`next`/`end` lines that must not open phantom blocks, close the
// enclosing ones early, or hide settings that follow the script.
func TestParseCfgMultiLineQuotedValue(t *testing.T) {
	cfg := `config system automation-action
edit "shut"
set script "config system interface
edit port1
set status down
next
end"
set timeout 5
next
end
config system interface
edit "port2"
set ip 10.0.0.1 255.255.255.0
next
end`
	doc := parseCfg(cfg)
	for _, b := range doc.blocks {
		if b.Name == "port1" {
			t.Fatalf("phantom block from script content: %+v", b)
		}
	}
	shut, ok := doc.block("config system automation-action > edit shut")
	if !ok || shut.End != 8 {
		t.Fatalf("edit shut = %+v (ok=%t), want End 8", shut, ok)
	}
	if v, idx, ok := doc.settingDirect(shut, "timeout"); !ok || v != "5" || idx != 7 {
		t.Fatalf("timeout after script: v=%q idx=%d ok=%t", v, idx, ok)
	}
	if b, ok := doc.block("config system automation-action"); !ok || b.End != 9 {
		t.Fatalf("automation-action = %+v (ok=%t), want End 9", b, ok)
	}
	ifaces := doc.blocksUnder("config system interface")
	if len(ifaces) != 1 || ifaces[0].Name != "port2" {
		t.Fatalf("expected only port2 under system interface, got %+v", ifaces)
	}
}
