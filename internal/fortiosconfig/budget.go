package fortiosconfig

import (
	"context"
	"errors"
)

// A backup controls both graph size and fan-out. These shared and per-walk
// bounds apply before visiting graph edges, including repeated/memoized ones.
// Exhaustion is an analysis error; no partial positive report is published.
type workBudget struct {
	ctx                context.Context
	remaining          int
	notesRemaining     int
	noteBytesRemaining int
	err                error
}

func newWorkBudget(ctx context.Context) *workBudget {
	return &workBudget{ctx: ctx, remaining: 20000000, notesRemaining: 4096, noteBytesRemaining: 1 << 20}
}

// reserveNote must run before formatting or joining a derived note. A modest
// input can create a quadratic number of deny/permit explanations, so the
// traversal budget alone cannot bound the generated model's memory footprint.
func (b *workBudget) reserveNote(maxBytes int) bool {
	if !b.take() {
		return false
	}
	if maxBytes < 0 || b.notesRemaining <= 0 || maxBytes > b.noteBytesRemaining {
		b.err = errors.New("configuration report exceeds the derived note output limit (4096 notes / 1 MiB)")
		return false
	}
	b.notesRemaining--
	b.noteBytesRemaining -= maxBytes
	return true
}

func (b *workBudget) take() bool {
	if b.err != nil {
		return false
	}
	if err := b.ctx.Err(); err != nil {
		b.err = err
		return false
	}
	b.remaining--
	if b.remaining < 0 {
		b.err = errors.New("configuration exceeds the total selector analysis work limit")
		return false
	}
	return true
}

type resolutionBudget struct {
	shared    *workBudget
	remaining int
}

func (inv *inventory) resolverBudget() *resolutionBudget {
	return &resolutionBudget{shared: inv.work, remaining: 10000}
}
func (b *resolutionBudget) take() bool {
	if !b.shared.take() {
		return false
	}
	b.remaining--
	if b.remaining < 0 {
		b.shared.err = errors.New("configuration selector graph exceeds the 10000-edge resolution limit")
		return false
	}
	return true
}

type matchResult struct{ yes, unknown bool }
