package reportmodel

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	_ "image/jpeg" // DecodeConfig validates the allowlisted JPEG logo format.
	"image/png"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Profile is a portable, declarative report definition. It has no executable
// SQL, HTML, scripts, URLs, credentials, or delivery destinations.
type Profile struct {
	Schema        int      `json:"schema"`
	Name          string   `json:"name"`
	Organization  string   `json:"organization"`
	Customer      string   `json:"customer"`
	Subtitle      string   `json:"subtitle"`
	Intro         string   `json:"intro"`
	Footer        string   `json:"footer"`
	Accent        string   `json:"accent"`
	Language      string   `json:"language"`
	Orientation   string   `json:"orientation"`
	TimeRange     string   `json:"time_range"`
	LogoBase64    string   `json:"logo_base64"`
	Traffic       bool     `json:"traffic"`
	Cover         bool     `json:"cover"`
	Contents      bool     `json:"contents"`
	ShowFindings  bool     `json:"show_findings"`
	ShowInventory bool     `json:"show_inventory"`
	ShowTraces    bool     `json:"show_traces"`
	Sections      []string `json:"sections"`
	Charts        []string `json:"charts"`
	Filters       Filters  `json:"filters"`
	Schedule      Schedule `json:"schedule"`
}

// Empty filter sets mean all values. Types use Exposure.Kind; Outcomes and
// Priorities use the fixed identifiers returned by their definition helpers.
type Filters struct {
	VDOMs      []string `json:"vdoms"`
	Types      []string `json:"types"`
	Outcomes   []string `json:"outcomes"`
	Priorities []string `json:"priorities"`
}

// A calendar schedule supplements automatic generation on every new backup.
// on_backup disables additional calendar runs. Weekday uses time.Weekday;
// MonthDay 29..31 is clamped to the final day of shorter months by the scheduler.
type Schedule struct {
	Frequency string `json:"frequency"`
	Timezone  string `json:"timezone"`
	Hour      int    `json:"hour"`
	Minute    int    `json:"minute"`
	Weekday   int    `json:"weekday"`
	MonthDay  int    `json:"month_day"`
}

// Option identifiers are stable and are never derived from display strings.
type Option struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	LabelDE string `json:"label_de"`
}

// DefaultProfile returns independent slices so callers can safely edit it.
func DefaultProfile(lang string) Profile {
	if strings.ToLower(strings.TrimSpace(lang)) != "de" {
		lang = "en"
	} else {
		lang = "de"
	}
	name := "Firewall reports"
	if lang == "de" {
		name = "Firewall-Berichte"
	}
	return Profile{
		Schema: SchemaVersion, Name: name, Accent: "#0f766e", Language: lang, Orientation: "portrait", TimeRange: "last24h", Traffic: true,
		Cover: true, Contents: true, ShowFindings: true, ShowInventory: true, ShowTraces: true,
		Sections: optionIDs(SectionDefinitions()), Charts: optionIDs(ChartDefinitions()),
		Filters:  Filters{VDOMs: []string{}, Types: []string{}, Outcomes: []string{}, Priorities: []string{}},
		Schedule: Schedule{Frequency: "on_backup", Timezone: "UTC", Hour: 3, Weekday: 1, MonthDay: 1},
	}
}

var accentPattern = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

// NormalizeProfile bounds user-controlled input and canonicalizes unordered
// filters. It never restores an explicitly empty section/chart list or a false
// display option. Call DefaultProfile before applying partial edits.
func NormalizeProfile(p Profile) (Profile, error) {
	if p.Schema == 0 {
		p.Schema = SchemaVersion
	}
	if p.Schema != SchemaVersion {
		return Profile{}, fmt.Errorf("unsupported report profile schema")
	}
	p.Language = strings.ToLower(strings.TrimSpace(p.Language))
	if p.Language == "" {
		p.Language = "en"
	}
	if p.Language != "en" && p.Language != "de" {
		return Profile{}, fmt.Errorf("report language must be en or de")
	}
	defaults := DefaultProfile(p.Language)
	for _, field := range []struct {
		name  string
		ptr   *string
		max   int
		multi bool
	}{
		{"name", &p.Name, 120, false}, {"organization", &p.Organization, 160, false},
		{"customer", &p.Customer, 160, false}, {"subtitle", &p.Subtitle, 240, false},
		{"intro", &p.Intro, 4000, true}, {"footer", &p.Footer, 300, false},
	} {
		value, err := profileText(*field.ptr, field.max, field.multi)
		if err != nil {
			return Profile{}, fmt.Errorf("%s: %w", field.name, err)
		}
		*field.ptr = value
	}
	if p.Name == "" {
		p.Name = defaults.Name
	}
	for _, value := range []string{p.Intro, p.Subtitle, p.Footer} {
		if err := ValidateMacros(value); err != nil {
			return Profile{}, err
		}
	}
	p.Accent = strings.ToLower(strings.TrimSpace(p.Accent))
	if p.Accent == "" {
		p.Accent = defaults.Accent
	}
	if !accentPattern.MatchString(p.Accent) {
		return Profile{}, fmt.Errorf("accent must be a six-digit hex color")
	}
	p.Orientation = strings.ToLower(strings.TrimSpace(p.Orientation))
	if p.Orientation == "" {
		p.Orientation = defaults.Orientation
	}
	if p.Orientation != "portrait" && p.Orientation != "landscape" {
		return Profile{}, fmt.Errorf("orientation must be portrait or landscape")
	}
	if p.TimeRange == "" {
		p.TimeRange = "last24h"
	}
	if p.TimeRange != "last24h" && p.TimeRange != "last7d" && p.TimeRange != "last30d" {
		return Profile{}, fmt.Errorf("time range must be last24h, last7d, or last30d")
	}
	var err error
	if p.Sections, err = normalizeOptions(p.Sections, SectionDefinitions(), false); err != nil {
		return Profile{}, fmt.Errorf("sections: %w", err)
	}
	if p.Charts, err = normalizeOptions(p.Charts, ChartDefinitions(), false); err != nil {
		return Profile{}, fmt.Errorf("charts: %w", err)
	}
	if len(p.Filters.VDOMs) > 256 {
		return Profile{}, fmt.Errorf("at most 256 VDOM filters are allowed")
	}
	vdoms := make([]string, 0, len(p.Filters.VDOMs))
	for _, vdom := range p.Filters.VDOMs {
		value, e := profileText(vdom, 256, false)
		if e != nil || value == "" {
			return Profile{}, fmt.Errorf("VDOM filters must contain bounded nonempty names")
		}
		vdoms = append(vdoms, value)
	}
	p.Filters.VDOMs = sortedUnique(vdoms)
	if p.Filters.Types, err = normalizeOptions(p.Filters.Types, TypeDefinitions(), true); err != nil {
		return Profile{}, fmt.Errorf("types: %w", err)
	}
	if p.Filters.Outcomes, err = normalizeOptions(p.Filters.Outcomes, OutcomeDefinitions(), true); err != nil {
		return Profile{}, fmt.Errorf("outcomes: %w", err)
	}
	if p.Filters.Priorities, err = normalizeOptions(p.Filters.Priorities, PriorityDefinitions(), true); err != nil {
		return Profile{}, fmt.Errorf("priorities: %w", err)
	}
	p.Schedule.Frequency = strings.ToLower(strings.TrimSpace(p.Schedule.Frequency))
	if p.Schedule.Frequency == "" {
		p.Schedule.Frequency = "on_backup"
	}
	switch p.Schedule.Frequency {
	case "on_backup", "daily", "weekly", "monthly":
	default:
		return Profile{}, fmt.Errorf("unsupported schedule frequency")
	}
	p.Schedule.Timezone = strings.TrimSpace(p.Schedule.Timezone)
	if p.Schedule.Timezone == "" {
		p.Schedule.Timezone = "UTC"
	}
	if len(p.Schedule.Timezone) > 100 || p.Schedule.Timezone == "Local" || strings.Contains(p.Schedule.Timezone, "..") || strings.HasPrefix(p.Schedule.Timezone, "/") {
		return Profile{}, fmt.Errorf("invalid schedule timezone")
	}
	if _, err = time.LoadLocation(p.Schedule.Timezone); err != nil {
		return Profile{}, fmt.Errorf("unknown schedule timezone")
	}
	if p.Schedule.MonthDay == 0 {
		p.Schedule.MonthDay = 1
	}
	if p.Schedule.Hour < 0 || p.Schedule.Hour > 23 || p.Schedule.Minute < 0 || p.Schedule.Minute > 59 || p.Schedule.Weekday < 0 || p.Schedule.Weekday > 6 || p.Schedule.MonthDay < 1 || p.Schedule.MonthDay > 31 {
		return Profile{}, fmt.Errorf("schedule time or day is out of range")
	}
	if p.LogoBase64, err = normalizeLogo(p.LogoBase64); err != nil {
		return Profile{}, err
	}
	return p, nil
}

// ProfileHash hashes the canonical validated definition. Invalid profiles have
// no hash; storage/rendering callers must surface NormalizeProfile's error.
func ProfileHash(p Profile) string {
	normalized, err := NormalizeProfile(p)
	if err != nil {
		return ""
	}
	data, err := json.Marshal(normalized)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func profileText(value string, max int, multiline bool) (string, error) {
	if len(value) > max*4 || !utf8.ValidString(value) || utf8.RuneCountInString(value) > max {
		return "", fmt.Errorf("text exceeds %d characters or is not valid UTF-8", max)
	}
	value = strings.ReplaceAll(value, "\r\n", "\n")
	for _, r := range value {
		allowedWhitespace := multiline && (r == '\n' || r == '\t')
		if unicode.IsControl(r) && !allowedWhitespace || unicode.In(r, unicode.Cf) {
			return "", fmt.Errorf("text contains an unsupported control character")
		}
	}
	return strings.TrimSpace(value), nil
}

func normalizeLogo(encoded string) (string, error) {
	const maxBytes = 256 << 10
	if encoded == "" {
		return "", nil
	}
	if len(encoded) > base64.StdEncoding.EncodedLen(maxBytes) {
		return "", fmt.Errorf("logo exceeds 256 KiB")
	}
	data, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(data) > maxBytes {
		return "", fmt.Errorf("logo must be base64-encoded PNG or JPEG, at most 256 KiB")
	}
	config, format, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil || (format != "png" && format != "jpeg") || config.Width < 1 || config.Height < 1 || config.Width > 1024 || config.Height > 1024 {
		return "", fmt.Errorf("logo must be PNG or JPEG, at most 1024 by 1024 pixels")
	}
	// Decode the bounded image as well: a plausible header alone is insufficient.
	decoded, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("logo image is incomplete or invalid")
	}
	// Canonical PNG removes EXIF, comments, and trailing data. Lossless encoding
	// also makes repeated normalization/hash calls stable, including JPEG input.
	encodedPNG := &boundedLogoBuffer{max: maxBytes}
	if err = png.Encode(encodedPNG, decoded); err != nil {
		return "", fmt.Errorf("normalized logo exceeds 256 KiB or cannot be encoded")
	}
	return base64.StdEncoding.EncodeToString(encodedPNG.Bytes()), nil
}

type boundedLogoBuffer struct {
	bytes.Buffer
	max int
}

func (b *boundedLogoBuffer) Write(data []byte) (int, error) {
	if len(data) > b.max-b.Len() {
		return 0, fmt.Errorf("logo exceeds byte limit")
	}
	return b.Buffer.Write(data)
}

func normalizeOptions(values []string, options []Option, unordered bool) ([]string, error) {
	if len(values) > 256 {
		return nil, fmt.Errorf("too many selections")
	}
	allowed := map[string]bool{}
	for _, option := range options {
		allowed[option.ID] = true
	}
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if !allowed[value] {
			return nil, fmt.Errorf("unknown selection")
		}
		if !seen[value] {
			result = append(result, value)
			seen[value] = true
		}
	}
	if unordered {
		sort.Strings(result)
	}
	return result, nil
}

func optionIDs(options []Option) []string {
	ids := make([]string, 0, len(options))
	for _, option := range options {
		ids = append(ids, option.ID)
	}
	return ids
}

func sortedUnique(values []string) []string {
	sort.Strings(values)
	result := make([]string, 0, len(values))
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}
