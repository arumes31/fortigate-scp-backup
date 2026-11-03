package reportmodel

import "time"

// Telemetry is a bounded observation from Graylog, kept distinct from saved
// configuration facts. Counts refer to received log records, not unique
// sessions, attacks, users, uptime, or complete traffic accounting.
type Telemetry struct {
	Status         string    `json:"status"`
	Reason         string    `json:"reason"`
	WindowStart    time.Time `json:"window_start"`
	WindowEnd      time.Time `json:"window_end"`
	RetrievedAt    time.Time `json:"retrieved_at"`
	DeviceIdentity string    `json:"device_identity"`
	Sources        []string  `json:"sources"`
	// SourceOrigin and SourceMatch are stable provenance identifiers, not
	// operator-supplied text. Query is the bounded generated source/VDOM/time
	// selector actually sent to Graylog; it contains no URL, credentials, or
	// raw message content. Empty diagnostics are valid for older snapshots.
	SourceOrigin string             `json:"source_origin,omitempty"`
	SourceMatch  string             `json:"source_match,omitempty"`
	VDOMs        []string           `json:"vdoms,omitempty"`
	Query        string             `json:"query,omitempty"`
	Datasets     []TelemetryDataset `json:"datasets"`
}

type TelemetryDataset struct {
	ID            string         `json:"id"`
	Title         string         `json:"title"`
	TitleDE       string         `json:"title_de"`
	Status        string         `json:"status"`
	Reason        string         `json:"reason"`
	Total         int64          `json:"total"`
	Returned      int            `json:"returned"`
	Limit         int            `json:"limit"`
	Truncated     bool           `json:"truncated"`
	MissingFields []string       `json:"missing_fields"`
	Rows          []TelemetryRow `json:"rows"`
}

type TelemetryRow struct {
	Label         string    `json:"label"`
	Secondary     string    `json:"secondary,omitempty"`
	Count         int64     `json:"count"`
	Bytes         *int64    `json:"bytes,omitempty"`
	SentBytes     *int64    `json:"sent_bytes,omitempty"`
	ReceivedBytes *int64    `json:"received_bytes,omitempty"`
	Timestamp     time.Time `json:"timestamp,omitempty"`
}
