package fgtconftail

import (
	"context"
	"crypto/rand"
	"errors"
	"math/big"
	"time"
)

const (
	transientRetryBase     = time.Minute
	transientRetryMax      = 6 * time.Hour
	persistentRetryDelay   = 6 * time.Hour
	deliveryBatchSize      = 20
	acceptanceWriteTimeout = 5 * time.Second
)

type ticketSender interface {
	send(ctx context.Context, correlationID string, frozenPayload []byte) (string, error)
}

type deliveryStats struct {
	Accepted int
	Failed   int
}

func dispatchDeliveries(
	ctx context.Context,
	s *store,
	sender ticketSender,
	clock func() time.Time,
	jitter func(time.Duration) time.Duration,
) (deliveryStats, error) {
	if s == nil || sender == nil {
		return deliveryStats{}, errors.New("conftail delivery dependencies are required")
	}
	if jitter == nil {
		jitter = randomRetryJitter
	}
	if clock == nil {
		clock = time.Now
	}
	deliveries, err := s.dueDeliveries(ctx, clock().UTC(), deliveryBatchSize)
	if err != nil {
		return deliveryStats{}, err
	}
	stats := deliveryStats{}
	for _, delivery := range deliveries {
		requestID, deliveryErr := sender.send(ctx, delivery.ChainID, delivery.Payload)
		attemptedAt := clock().UTC()
		if deliveryErr == nil {
			// A verified 202 is an irreversible remote handoff. Give the durable
			// acceptance write a short shutdown grace period so ordinary process
			// cancellation does not turn it into an avoidable duplicate retry.
			acceptanceCtx, cancel := context.WithTimeout(
				context.WithoutCancel(ctx),
				acceptanceWriteTimeout,
			)
			err := s.markAccepted(acceptanceCtx, delivery.ChainID, requestID, attemptedAt)
			cancel()
			if err != nil {
				return stats, err
			}
			stats.Accepted++
			continue
		}
		if err := ctx.Err(); err != nil {
			return stats, err
		}
		state, nextAttempt := deliveryDecision(
			attemptedAt,
			delivery.Attempts,
			deliveryErr,
			jitter,
		)
		if err := s.markDeliveryFailure(
			ctx,
			delivery.ChainID,
			state,
			nextAttempt,
			deliveryErr,
			attemptedAt,
		); err != nil {
			return stats, err
		}
		stats.Failed++
	}
	return stats, nil
}

func deliveryDecision(
	now time.Time,
	attempts int,
	deliveryErr error,
	jitter func(time.Duration) time.Duration,
) (string, time.Time) {
	if attempts < 0 {
		attempts = 0
	}
	var hookErr *hookwiseError
	if errors.As(deliveryErr, &hookErr) && !hookErr.IsTransient() {
		return deliveryStateFailed, now.Add(persistentRetryDelay)
	}
	delay := transientRetryBase
	for range min(attempts, 9) {
		delay *= 2
	}
	if delay > transientRetryMax {
		delay = transientRetryMax
	}
	if jitter != nil {
		addition := jitter(delay / 5)
		if addition > 0 {
			delay += addition
		}
	}
	if hookErr != nil && hookErr.RetryAfter > delay {
		delay = hookErr.RetryAfter
	}
	if delay > transientRetryMax {
		delay = transientRetryMax
	}
	return deliveryStateRetry, now.Add(delay)
}

func randomRetryJitter(maximum time.Duration) time.Duration {
	if maximum <= 0 {
		return 0
	}
	value, err := rand.Int(rand.Reader, big.NewInt(int64(maximum)+1))
	if err != nil {
		return 0
	}
	return time.Duration(value.Int64())
}
