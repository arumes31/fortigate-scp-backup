package reportmodel

import (
	"fmt"
	"strings"
)

func MacroDefinitions() []Option {
	return []Option{
		{"firewall", "Firewall display name", "Firewall-Anzeigename"},
		{"firewall_id", "Firewall ID", "Firewall-ID"},
		{"backup_id", "Backup ID", "Sicherungs-ID"},
		{"backup_at", "Backup time", "Sicherungszeitpunkt"},
		{"generated_at", "Generation time", "Erstellungszeitpunkt"},
		{"publication_count", "Selected publication count", "Anzahl ausgewählter Veröffentlichungen"},
		{"finding_count", "Selected finding count", "Anzahl ausgewählter Feststellungen"},
		{"vdom_count", "Selected VDOM count", "Anzahl ausgewählter VDOMs"},
		{"organization", "Organization", "Organisation"},
		{"customer", "Customer", "Kunde"},
		{"report_title", "Report title", "Berichtstitel"},
	}
}

// ValidateMacros accepts a small literal replacement vocabulary. It does not
// evaluate expressions or HTML, and rejects malformed token delimiters.
func ValidateMacros(value string) error {
	allowed := valueSet(optionIDs(MacroDefinitions()))
	for len(value) > 0 {
		start := strings.Index(value, "{{")
		closeAt := strings.Index(value, "}}")
		if start < 0 {
			if closeAt >= 0 {
				return fmt.Errorf("unmatched report placeholder delimiter")
			}
			return nil
		}
		if closeAt < start+2 {
			return fmt.Errorf("unclosed report placeholder")
		}
		if !allowed[value[start+2:closeAt]] {
			return fmt.Errorf("unknown report placeholder")
		}
		value = value[closeAt+2:]
	}
	return nil
}
