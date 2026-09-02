package fgtconftail

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

type ticketFirewall struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

type ticketPayload struct {
	Status       string         `json:"status"`
	Source       string         `json:"source"`
	Message      string         `json:"message"`
	ChainID      string         `json:"chain_id"`
	Summary      string         `json:"summary"`
	Description  string         `json:"description"`
	Firewall     ticketFirewall `json:"firewall"`
	Admin        string         `json:"admin"`
	StartedAt    time.Time      `json:"started_at"`
	LastChangeAt time.Time      `json:"last_change_at"`
	ChangeCount  int            `json:"change_count"`
	Late         bool           `json:"late,omitempty"`
	Unattributed bool           `json:"unattributed,omitempty"`
}

func buildTicketPayload(
	chain chainRecord,
	events []Event,
	maxDescriptionBytes int,
) (ticketPayload, error) {
	if len(events) == 0 {
		return ticketPayload{}, errors.New("cannot create a ticket for an empty chain")
	}
	changeCount := max(chain.EventCount, len(events))
	shortID := chain.ID
	if len(shortID) > 8 {
		shortID = shortID[:8]
	}
	administrator := ticketAdministrator(chain)
	summary := fmt.Sprintf(
		"[CT-%s] %s / %s / %s",
		shortID,
		chain.FirewallName,
		administrator,
		chain.FirstEventAt.UTC().Format("2006-01-02 15:04Z"),
	)
	summary = truncateString(summary, 255)
	description := buildTicketDescription(chain, events, maxDescriptionBytes)
	return ticketPayload{
		Status:       "OPEN",
		Source:       "FortiSafe ConfTail",
		Message:      description,
		ChainID:      chain.ID,
		Summary:      summary,
		Description:  description,
		Firewall:     ticketFirewall{ID: chain.FirewallID, Name: chain.FirewallName},
		Admin:        administrator,
		StartedAt:    chain.FirstEventAt.UTC(),
		LastChangeAt: chain.LastEventAt.UTC(),
		ChangeCount:  changeCount,
		Late:         chain.Late,
		Unattributed: chain.Unattributed,
	}, nil
}

func buildTicketDescription(chain chainRecord, events []Event, maxBytes int) string {
	var builder strings.Builder
	builder.WriteString("FortiGate configuration change session\n\n")
	if chain.Unattributed {
		builder.WriteString("WARNING: No unique administrator could be attributed to these changes.\n\n")
	}
	if chain.Late {
		builder.WriteString("NOTICE: This session contains configuration events that arrived after an earlier session was sealed.\n\n")
	}
	administrator := ticketAdministrator(chain)
	changeCount := max(chain.EventCount, len(events))
	fmt.Fprintf(
		&builder,
		"Firewall: %s (FortiSafe ID %d)\n"+
			"Administrator: %s\n"+
			"Window: %s to %s\n"+
			"Changes: %d\n"+
			"Session ID: %s\n\n"+
			"Changes (oldest first):\n",
		chain.FirewallName,
		chain.FirewallID,
		administrator,
		chain.FirstEventAt.UTC().Format(time.RFC3339),
		chain.LastEventAt.UTC().Format(time.RFC3339),
		changeCount,
		chain.ID,
	)
	totalEvents := changeCount
	included := 0
	for _, event := range events {
		line := timelineLine(event)
		omittedAfterLine := totalEvents - included - 1
		reserve := 0
		if omittedAfterLine > 0 {
			reserve = len(ticketOmissionLine(omittedAfterLine, chain.ID))
		}
		if builder.Len()+len(line)+reserve > maxBytes {
			break
		}
		builder.WriteString(line)
		included++
	}
	omitted := totalEvents - included
	if omitted <= 0 {
		return truncateUTF8Bytes(builder.String(), maxBytes)
	}
	footer := ticketOmissionLine(omitted, chain.ID)
	if len(footer) >= maxBytes {
		return truncateUTF8Bytes(footer, maxBytes)
	}
	prefix := truncateUTF8Bytes(builder.String(), maxBytes-len(footer))
	return prefix + footer
}

func ticketAdministrator(chain chainRecord) string {
	administrator := strings.TrimSpace(chain.User)
	if chain.Unattributed || administrator == "" || administrator == "-" || administrator == unattributedUser {
		return "Unknown (not uniquely attributed)"
	}
	return administrator
}

func ticketOmissionLine(omitted int, chainID string) string {
	return fmt.Sprintf(
		"… %d additional redacted change(s) omitted; see FortiSafe chain %s for the complete timeline.\n",
		max(omitted, 0),
		chainID,
	)
}

func truncateUTF8Bytes(value string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	value = strings.ToValidUTF8(value, "�")
	if len(value) <= maxBytes {
		return value
	}
	marker := truncatedMarker
	if maxBytes < len(marker) {
		end := maxBytes
		for end > 0 && !utf8.ValidString(value[:end]) {
			end--
		}
		return value[:end]
	}
	end := maxBytes - len(marker)
	for end > 0 && !utf8.ValidString(value[:end]) {
		end--
	}
	return value[:end] + marker
}

func timelineLine(event Event) string {
	var builder strings.Builder
	changeParts := []string{event.EventAt.UTC().Format(time.RFC3339)}
	changeParts = appendTicketValue(changeParts, "", event.Action)
	changeParts = appendTicketValue(changeParts, "", event.Path)
	changeParts = appendTicketValue(changeParts, "Object", event.Object)
	builder.WriteString("- " + strings.Join(changeParts, " | ") + "\n")

	deviceParts := []string{}
	deviceParts = appendTicketValue(deviceParts, "Device", event.DeviceName)
	deviceParts = appendTicketValue(deviceParts, "Serial", event.DeviceID)
	deviceParts = appendTicketValue(deviceParts, "Source", event.Source)
	writeTicketDetailLine(&builder, deviceParts)

	contextParts := []string{}
	contextParts = appendTicketValue(contextParts, "VDOM", event.VDOM)
	contextParts = appendTicketValue(contextParts, "Attribution", event.UserAttribution)
	contextParts = appendTicketValue(contextParts, "Transaction", event.TransactionID)
	contextParts = appendTicketValue(contextParts, "UI", event.UI)
	if len(contextParts) > 0 {
		contextParts[0] = "Context: " + contextParts[0]
		writeTicketDetailLine(&builder, contextParts)
	}

	if diff, ok := parseConfigAttributeDiff(event.ConfigAttribute); ok {
		writeTicketValueLine(&builder, "Attribute", diff.Name)
		writeTicketValueLine(&builder, "Before", diff.Before)
		writeTicketValueLine(&builder, "After", diff.After)
	} else {
		writeTicketValueLine(&builder, "Attribute", event.ConfigAttribute)
	}
	logParts := []string{}
	logParts = appendTicketValue(logParts, "", event.LogID)
	logParts = appendTicketValue(logParts, "", event.LogDescription)
	if len(logParts) > 0 {
		logParts[0] = "Log: " + logParts[0]
		writeTicketDetailLine(&builder, logParts)
	}
	writeTicketValueLine(&builder, "Message", event.Message)
	writeTicketValueLine(&builder, "Event UUID", event.UUID)
	return builder.String()
}

func appendTicketValue(parts []string, label, value string) []string {
	value = ticketText(value)
	if value == "" {
		return parts
	}
	if label != "" {
		value = label + ": " + value
	}
	return append(parts, value)
}

func writeTicketDetailLine(builder *strings.Builder, parts []string) {
	if len(parts) == 0 {
		return
	}
	builder.WriteString("  " + strings.Join(parts, " | ") + "\n")
}

func writeTicketValueLine(builder *strings.Builder, label, value string) {
	value = ticketText(value)
	if value == "" {
		return
	}
	builder.WriteString("  " + label + ": " + value + "\n")
}

func ticketText(value string) string {
	value = strings.TrimSpace(strings.ReplaceAll(value, "\n", " "))
	if value == "-" {
		return ""
	}
	return value
}
