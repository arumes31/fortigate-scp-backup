package renderpdf

import (
	"context"
	"errors"

	"github.com/arumes31/fortigate-scp-backup/internal/reportmodel"
)

var errProjectionLimit = errors.New("reports: PDF presentation input limit exceeded; report was not published")

// Check the output-relevant inputs before allocating table rows or joining
// large values. The conservative budget includes structural overhead, empty
// entries and repeated text. A bounded walk also observes cancellation before
// font loading and layout. No configuration-derived value enters the error.
func validateProjection(ctx context.Context, source reportmodel.Source, a reportmodel.Assessment, kind string) error {
	b := projectionBudget{ctx: ctx, remaining: maxText - 8192}
	if kind == "customer" {
		// This projection only loops over findings; all other assessment data is
		// counted with len and never copied. The checksum is length-validated.
		for _, f := range a.Findings {
			if !b.take(f.ID, f.Priority) {
				return b.err
			}
		}
		return ctx.Err()
	}
	if !b.take(source.Firewall, a.Firmware, a.Hostname) || !b.list(a.VDOMs) || !b.list(a.Warnings) {
		return b.err
	}
	for _, e := range a.Exposures {
		if !b.take(e.VDOM, e.Name, e.External, e.Outcome, e.GeoStatus) || !b.list(e.Backends) {
			return b.err
		}
		if kind != "forwarding" {
			continue
		}
		if !b.take(e.Type, e.ExternalInterface, e.Evidence) || !b.list(e.Groups) || !b.list(e.PolicyIDs) || !b.list(e.Notes) {
			return b.err
		}
		for _, p := range e.Trace {
			if !b.take(p.ID, p.Name, p.Action, p.Source, p.SourceInterface, p.DestinationInterface,
				p.Destination, p.Service, p.Schedule, p.Status, p.VIPMatch, p.Profiles, p.Logging, p.Effect, p.Evidence) {
				return b.err
			}
		}
	}
	if kind == "technical" {
		for _, s := range a.Sections {
			if !b.take(s.Title, s.TitleDE) {
				return b.err
			}
			for _, r := range s.Rows {
				if !b.take(r.Label, r.Value, r.Evidence) {
					return b.err
				}
			}
		}
		for _, f := range a.Findings {
			if !b.take(f.ID, f.Priority, f.Title, f.TitleDE, f.Detail, f.DetailDE,
				f.Recommendation, f.RecommendationDE, f.Evidence) {
				return b.err
			}
		}
	}
	return ctx.Err()
}

type projectionBudget struct {
	ctx       context.Context
	remaining int
	err       error
}

func (b *projectionBudget) list(values []string) bool {
	for _, value := range values {
		if !b.take(value) {
			return false
		}
	}
	return true
}

func (b *projectionBudget) take(values ...string) bool {
	if b.err = b.ctx.Err(); b.err != nil {
		return false
	}
	for _, value := range values {
		// Reserve two copies plus a row's labels/slice overhead. Subtract
		// before multiplying to keep hostile lengths from overflowing ints.
		if b.remaining < 128 || len(value) > (b.remaining-128)/2 {
			b.err = errProjectionLimit
			return false
		}
		b.remaining -= 128 + 2*len(value)
	}
	return true
}
