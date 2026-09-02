package fgtconftail

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	attributionExact        = "exact"
	attributionRecovered    = "recovered"
	attributionUnattributed = "unattributed"
	unattributedUser        = "[unattributed]"
	redactedValue           = "[REDACTED]"
	truncatedMarker         = "… [truncated]"
	maxIdentityRunes        = 512
	maxDetailRunes          = 4096
)

var allowedConfigLogIDs = map[string]struct{}{
	"0100044544": {},
	"0100044545": {},
	"0100044546": {},
	"0100044547": {},
}

type firewallRef struct {
	ID      int
	Name    string
	Aliases []string
}

// Event is the bounded, redacted representation persisted by the extension.
type Event struct {
	GraylogID       string
	SemanticHash    string
	CorrelationHash string
	FirewallID      int
	FirewallName    string
	Source          string
	DeviceName      string
	DeviceID        string
	VDOM            string
	User            string
	UserAttribution string
	UserWasMissing  bool
	UI              string
	Action          string
	TransactionID   string
	Path            string
	Object          string
	ConfigAttribute string
	LogID           string
	LogDescription  string
	Message         string
	UUID            string
	EventAt         time.Time
	IngestedAt      time.Time
	ChainID         string
	Late            bool
}

func normalizeRawEvent(raw RawEvent, firewall firewallRef, ingestedAt time.Time) (Event, error) {
	if firewall.ID <= 0 || strings.TrimSpace(firewall.Name) == "" {
		return Event{}, errors.New("invalid logical firewall")
	}
	logID := truncateString(raw.LogID, maxIdentityRunes)
	if _, ok := allowedConfigLogIDs[logID]; !ok {
		return Event{}, errors.New("unsupported configuration log id")
	}
	if !strings.EqualFold(strings.TrimSpace(raw.Type), "event") ||
		!strings.EqualFold(strings.TrimSpace(raw.Subtype), "system") {
		return Event{}, errors.New("configuration event has an unsupported type or subtype")
	}
	if raw.Timestamp.IsZero() {
		return Event{}, errors.New("configuration event has no timestamp")
	}
	if !unixNanoRepresentable(raw.Timestamp) || !unixNanoRepresentable(ingestedAt) {
		return Event{}, errors.New("configuration event timestamp is outside the supported range")
	}
	source := sanitizeExternalString(raw.Source, maxIdentityRunes)
	if source == "" {
		return Event{}, errors.New("configuration event has no source")
	}

	user := sanitizeExternalString(raw.User, maxIdentityRunes)
	userWasMissing := user == ""
	attribution := attributionExact
	if userWasMissing {
		attribution = ""
	}
	event := Event{
		GraylogID:       sanitizeExternalIdentity(raw.MessageID, maxIdentityRunes),
		FirewallID:      firewall.ID,
		FirewallName:    sanitizeExternalString(firewall.Name, maxIdentityRunes),
		Source:          source,
		DeviceName:      sanitizeExternalString(raw.DeviceName, maxIdentityRunes),
		DeviceID:        sanitizeExternalString(raw.DeviceID, maxIdentityRunes),
		VDOM:            sanitizeExternalString(raw.VDOM, maxIdentityRunes),
		User:            user,
		UserAttribution: attribution,
		UserWasMissing:  userWasMissing,
		UI:              sanitizeExternalString(raw.UI, maxIdentityRunes),
		Action:          sanitizeExternalString(raw.Action, maxIdentityRunes),
		TransactionID:   sanitizeExternalString(raw.ConfigTransactionID, maxIdentityRunes),
		Path:            sanitizeExternalString(raw.ConfigPath, maxDetailRunes),
		Object:          sanitizeExternalString(raw.ConfigObject, maxDetailRunes),
		ConfigAttribute: redactAttribute(truncateString(raw.ConfigAttribute, maxDetailRunes)),
		LogID:           logID,
		LogDescription:  redactFreeText(truncateString(raw.LogDescription, maxDetailRunes)),
		Message:         redactFreeText(truncateString(raw.Message, maxDetailRunes)),
		UUID:            sanitizeExternalString(raw.UUID, maxIdentityRunes),
		EventAt:         raw.Timestamp.UTC(),
		IngestedAt:      ingestedAt.UTC(),
	}
	event.CorrelationHash = attributionCorrelationHash(event)
	event.SemanticHash = semanticHash(event)
	return event, nil
}

func recoverMissingUsers(ctx context.Context, events []Event, window time.Duration) error {
	if window < 0 {
		return errors.New("missing-user correlation window must not be negative")
	}
	type recoveryKey struct {
		firewallID    int
		transactionID string
	}
	type userEvidence struct {
		at   time.Time
		user string
	}
	type recoveryGroup struct {
		exact   []userEvidence
		missing []int
	}
	groups := make(map[recoveryKey]*recoveryGroup)
	groupFor := func(event Event) *recoveryGroup {
		key := recoveryKey{firewallID: event.FirewallID, transactionID: event.TransactionID}
		group := groups[key]
		if group == nil {
			group = &recoveryGroup{}
			groups[key] = group
		}
		return group
	}

	for i := range events {
		if err := ctx.Err(); err != nil {
			return err
		}
		event := &events[i]
		if event.User == "" {
			if event.TransactionID == "" {
				attributeMissingUser(event, "")
				continue
			}
			group := groupFor(*event)
			group.missing = append(group.missing, i)
			continue
		}
		if event.UserAttribution == attributionExact && event.TransactionID != "" {
			group := groupFor(*event)
			group.exact = append(group.exact, userEvidence{at: event.EventAt, user: event.User})
		}
	}

	for _, group := range groups {
		if err := ctx.Err(); err != nil {
			return err
		}
		if len(group.missing) == 0 {
			continue
		}
		sort.Slice(group.exact, func(i, j int) bool {
			return group.exact[i].at.Before(group.exact[j].at)
		})
		sort.Slice(group.missing, func(i, j int) bool {
			left := events[group.missing[i]].EventAt
			right := events[group.missing[j]].EventAt
			if left.Equal(right) {
				return group.missing[i] < group.missing[j]
			}
			return left.Before(right)
		})

		counts := make(map[string]int)
		left, right := 0, 0
		for _, missingIndex := range group.missing {
			if err := ctx.Err(); err != nil {
				return err
			}
			missingAt := events[missingIndex].EventAt
			upper := missingAt.Add(window)
			for right < len(group.exact) && !group.exact[right].at.After(upper) {
				if err := ctx.Err(); err != nil {
					return err
				}
				counts[group.exact[right].user]++
				right++
			}
			lower := missingAt.Add(-window)
			for left < right && group.exact[left].at.Before(lower) {
				if err := ctx.Err(); err != nil {
					return err
				}
				user := group.exact[left].user
				counts[user]--
				if counts[user] == 0 {
					delete(counts, user)
				}
				left++
			}

			recoveredUser := ""
			if len(counts) == 1 {
				for user := range counts {
					recoveredUser = user
				}
			}
			attributeMissingUser(&events[missingIndex], recoveredUser)
		}
	}
	return nil
}

func attributeMissingUser(event *Event, recoveredUser string) {
	if recoveredUser == "" {
		event.User = unattributedUser
		event.UserAttribution = attributionUnattributed
	} else {
		event.User = recoveredUser
		event.UserAttribution = attributionRecovered
	}
	event.SemanticHash = semanticHash(*event)
}

func semanticHash(event Event) string {
	parts := []string{
		strconv.Itoa(event.FirewallID),
		event.EventAt.UTC().Format(time.RFC3339Nano),
		event.LogID,
		event.TransactionID,
		event.User,
		event.VDOM,
		event.Action,
		event.Path,
		event.Object,
		event.ConfigAttribute,
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}

func attributionCorrelationHash(event Event) string {
	parts := []string{
		strconv.Itoa(event.FirewallID),
		event.EventAt.UTC().Format(time.RFC3339Nano),
		event.LogID,
		event.TransactionID,
		event.VDOM,
		event.Action,
		event.Path,
		event.Object,
		event.ConfigAttribute,
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}

func redactAttribute(value string) string {
	for _, separator := range []string{"[", "=", ":"} {
		if index := strings.Index(value, separator); index > 0 {
			label := strings.TrimSpace(value[:index])
			if sensitiveAttributeName(label) {
				return truncateString(label, 128) + "=" + redactedValue
			}
		}
	}
	if !containsSensitiveMaterial(value) {
		return value
	}
	for _, separator := range []string{"[", "=", ":"} {
		if index := strings.Index(value, separator); index > 0 {
			label := strings.TrimSpace(value[:index])
			if containsSensitiveName(label) {
				return truncateString(label, 128) + "=" + redactedValue
			}
		}
	}
	return redactedValue
}

func sensitiveAttributeName(value string) bool {
	var normalized strings.Builder
	for _, r := range strings.ToLower(value) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			normalized.WriteRune(r)
		}
	}
	return normalized.String() == "key" || containsSensitiveName(value)
}

func redactFreeText(value string) string {
	if containsSensitiveMaterial(value) {
		return redactedValue
	}
	return value
}

func sanitizeExternalString(value string, maxRunes int) string {
	value = truncateString(value, maxRunes)
	if containsSensitiveValueMaterial(value) {
		return redactedValue
	}
	return value
}

func sanitizeExternalIdentity(value string, maxRunes int) string {
	value = truncateString(value, maxRunes)
	if containsSensitiveValueMaterial(value) {
		// An empty Graylog identity falls back to the redacted semantic identity.
		// A shared redaction marker would otherwise collapse unrelated messages.
		return ""
	}
	return value
}

func containsSensitiveValueMaterial(value string) bool {
	if strings.Contains(strings.ToUpper(value), "ENC ") || containsBareKeyAssignment(value) {
		return true
	}
	for _, separator := range []string{"[", "=", ":"} {
		if index := strings.Index(value, separator); index > 0 &&
			sensitiveAttributeName(strings.TrimSpace(value[:index])) {
			return true
		}
	}
	return false
}

func containsSensitiveMaterial(value string) bool {
	return containsSensitiveValueMaterial(value) || containsSensitiveName(value)
}

func containsBareKeyAssignment(value string) bool {
	runes := []rune(strings.ToLower(value))
	for i := 0; i+3 <= len(runes); i++ {
		if runes[i] != 'k' || runes[i+1] != 'e' || runes[i+2] != 'y' {
			continue
		}
		if i > 0 && (unicode.IsLetter(runes[i-1]) || unicode.IsDigit(runes[i-1]) || runes[i-1] == '_') {
			continue
		}
		j := i + 3
		if j < len(runes) && (unicode.IsLetter(runes[j]) || unicode.IsDigit(runes[j]) || runes[j] == '_') {
			continue
		}
		for j < len(runes) && unicode.IsSpace(runes[j]) {
			j++
		}
		if j < len(runes) && (runes[j] == '[' || runes[j] == '=' || runes[j] == ':') {
			return true
		}
	}
	return false
}

func containsSensitiveName(value string) bool {
	var normalized strings.Builder
	for _, r := range strings.ToLower(value) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			normalized.WriteRune(r)
		}
	}
	name := normalized.String()
	for _, token := range []string{
		"password", "passwd", "secret", "presharedkey", "psk", "token",
		"apikey", "privatekey", "radiussecret", "ldapsecret", "snmpcommunity",
		"authenticationkey", "authkey", "privacykey", "privkey", "community",
		"passphrase", "authpwd", "privpwd", "radiuskey",
	} {
		if strings.Contains(name, token) {
			return true
		}
	}
	return false
}

func truncateString(value string, maxRunes int) string {
	value = strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, value))
	runes := []rune(value)
	if len(runes) <= maxRunes {
		return value
	}
	marker := []rune(truncatedMarker)
	keep := maxRunes - len(marker)
	if keep < 0 {
		keep = 0
	}
	return string(runes[:keep]) + truncatedMarker
}

func unixNanoRepresentable(value time.Time) bool {
	if value.IsZero() {
		return false
	}
	nanos := value.UTC().UnixNano()
	return time.Unix(0, nanos).UTC().Equal(value.UTC())
}
