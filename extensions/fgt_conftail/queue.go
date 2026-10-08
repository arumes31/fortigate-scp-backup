package fgtconftail

import (
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5/middleware"
)

func (e *Extension) clearHookwiseQueue(w http.ResponseWriter, r *http.Request) {
	if e.store == nil {
		http.Error(w, "Configuration change Hookwise queue unavailable", http.StatusServiceUnavailable)
		return
	}

	actor := e.requestActor(r)
	e.deliveryMu.Lock()
	cleared, err := e.store.clearPendingDeliveries(r.Context(), time.Now().UTC())
	e.deliveryMu.Unlock()
	if err != nil {
		if e.logger != nil {
			e.logger.ErrorContext(
				r.Context(),
				"conftail Hookwise queue clear failed",
				"code", codeHookwiseQueueClearFailed,
				"actor", actor,
				"err", sanitizeDeliveryError(err),
				"reqid", middleware.GetReqID(r.Context()),
			)
		}
		http.Error(w, "Unable to clear pending Hookwise queue", http.StatusInternalServerError)
		return
	}

	if e.logger != nil {
		e.logger.InfoContext(
			r.Context(),
			"conftail Hookwise queue cleared",
			"code", codeHookwiseQueueCleared,
			"actor", actor,
			"cleared", cleared,
			"reqid", middleware.GetReqID(r.Context()),
		)
	}
	if e.logActivity != nil {
		e.logActivity(actor, "ConfTail Hookwise Queue Cleared", fmt.Sprintf("cleared=%d", cleared))
	}
	result := "cleared"
	if cleared == 0 {
		result = "empty"
	}
	http.Redirect(
		w,
		r,
		"/fgt-conftail/?queue="+result+"#ct-hookwise-delivery",
		http.StatusSeeOther,
	)
}
