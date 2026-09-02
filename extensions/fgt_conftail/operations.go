package fgtconftail

import "time"

const (
	adaptivePollActiveInterval = time.Minute
	adaptivePollRecentInterval = 5 * time.Minute
	adaptivePollIdleInterval   = 15 * time.Minute
	adaptivePollActiveWindow   = 5 * time.Minute
	adaptivePollRecentWindow   = 30 * time.Minute
)

type diagnosticCode string

const (
	codeGraylogPollFailed       diagnosticCode = "CT-GL-001"
	codeGraylogPollCompleted    diagnosticCode = "CT-GL-002"
	codeGraylogPollDeferred     diagnosticCode = "CT-GL-003"
	codeDashboardQueryFailed    diagnosticCode = "CT-DB-002"
	codeHookwiseDeliveryFailed  diagnosticCode = "CT-HW-001"
	codeMaintenanceFailed       diagnosticCode = "CT-MAINT-001"
	codeIndexMaintenanceFailed  diagnosticCode = "CT-IDX-001"
	codeCatalogRefreshFailed    diagnosticCode = "CT-CAT-001"
	codeMaintenanceSkipped      diagnosticCode = "CT-MAINT-002"
	codeAdaptivePollStateFailed diagnosticCode = "CT-DB-003"
	codeMaintenanceCompleted    diagnosticCode = "CT-MAINT-003"
	codeDashboardRenderFailed   diagnosticCode = "CT-UI-001"
	codeSessionQueryFailed      diagnosticCode = "CT-UI-002"
	codeDashboardQueried        diagnosticCode = "CT-UI-003"
	codeSessionQueried          diagnosticCode = "CT-UI-004"
)

func (c diagnosticCode) String() string {
	return string(c)
}

func adaptivePollInterval(state PollState, lastIngestedAt, now time.Time) time.Duration {
	hasCurrentFailure := !state.LastFailureAt.IsZero() &&
		(state.LastSuccessAt.IsZero() || !state.LastFailureAt.Before(state.LastSuccessAt))
	if hasCurrentFailure {
		return adaptivePollActiveInterval
	}
	if lastIngestedAt.IsZero() {
		return adaptivePollIdleInterval
	}
	age := now.Sub(lastIngestedAt)
	if age <= adaptivePollActiveWindow {
		return adaptivePollActiveInterval
	}
	if age <= adaptivePollRecentWindow {
		return adaptivePollRecentInterval
	}
	return adaptivePollIdleInterval
}

func adaptivePollDue(state PollState, lastIngestedAt, now time.Time) bool {
	if state.LastStartedAt.IsZero() {
		return true
	}
	interval := adaptivePollInterval(state, lastIngestedAt, now)
	return !now.Before(state.LastStartedAt.Add(interval))
}
