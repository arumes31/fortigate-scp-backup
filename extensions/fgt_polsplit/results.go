package fgt_polsplit

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

const (
	resultTTL            = 15 * time.Minute
	maxStoredResults     = 32
	maxStoredResultBytes = 8 << 20
	maxExportBytes       = 12 << 20
)

type resultPanelMeta struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	Kind        string `json:"kind"`
	Count       int    `json:"count"`
	Recommended bool   `json:"recommended,omitempty"`
}

type resultSummaryResponse struct {
	ResultID        string            `json:"result_id"`
	Firewall        FirewallRef       `json:"firewall"`
	Policy          *OrigPolicy       `json:"policy"`
	BackupTime      string            `json:"backup_time"`
	TotalMessages   int64             `json:"total_messages"`
	TupleCount      int               `json:"tuple_count"`
	SrcCount        int               `json:"src_count"`
	DstCount        int               `json:"dst_count"`
	ServiceCount    int               `json:"svc_count"`
	WarningCount    int               `json:"warning_count"`
	UnresolvedCount int               `json:"unresolved_count"`
	ArtifactCount   int               `json:"artifact_count"`
	Warnings        []string          `json:"warnings"`
	Panels          []resultPanelMeta `json:"panels"`
}

type trafficResultPanel struct {
	Tuples          []TrafficTuple   `json:"tuples"`
	StaleTuples     []TrafficTuple   `json:"stale_tuples"`
	DNSSuggestions  []dnsSuggestion  `json:"dns_suggestions"`
	ISDBSuggestions []isdbSuggestion `json:"isdb_suggestions"`
	UTMBlocked      []utmBlocked     `json:"utm_blocked"`
	UserActivity    []userActivity   `json:"user_activity"`
	AppUsage        []appUsage       `json:"app_usage"`
}

type analysisResult struct {
	Firewall      FirewallRef
	Policy        *OrigPolicy
	BackupTime    string
	TotalMessages int64
	TupleCount    int
	SrcCount      int
	DstCount      int
	ServiceCount  int
	Warnings      []string
	Traffic       trafficResultPanel
	Strategies    []Strategy
}

type storedAnalysisResult struct {
	Owner      string
	CreatedAt  time.Time
	Summary    resultSummaryResponse
	Traffic    trafficResultPanel
	Strategies map[string]Strategy
}

func (e *Extension) resultsNow() time.Time {
	if e.resultNow != nil {
		return e.resultNow()
	}
	return time.Now()
}

func (e *Extension) storeResult(owner string, result analysisResult) (string, resultSummaryResponse, error) {
	encoded, err := json.Marshal(result)
	if err != nil {
		return "", resultSummaryResponse{}, err
	}
	if len(encoded) > maxStoredResultBytes {
		return "", resultSummaryResponse{}, errors.New("analysis result exceeds the storage limit")
	}

	resultID := uuid.NewString()
	panels := []resultPanelMeta{{Key: "traffic", Label: "Observed traffic", Kind: "traffic", Count: result.TupleCount}}
	strategies := make(map[string]Strategy, len(result.Strategies))
	unresolved := map[string]bool{}
	artifacts := 0
	for _, strategy := range result.Strategies {
		strategies[strategy.Key] = strategy
		panels = append(panels, resultPanelMeta{Key: strategy.Key, Label: strategy.Label, Kind: "strategy", Count: len(strategy.Policies), Recommended: strategy.Recommended})
		if strategy.Config != "" {
			artifacts++
		}
		for _, object := range strategy.NewObjects {
			unresolved[object.Kind+"\x00"+object.Name] = true
		}
	}
	summary := resultSummaryResponse{
		ResultID: resultID, Firewall: result.Firewall, Policy: result.Policy, BackupTime: result.BackupTime,
		TotalMessages: result.TotalMessages, TupleCount: result.TupleCount, SrcCount: result.SrcCount,
		DstCount: result.DstCount, ServiceCount: result.ServiceCount, WarningCount: len(result.Warnings),
		UnresolvedCount: len(unresolved), ArtifactCount: artifacts, Warnings: result.Warnings, Panels: panels,
	}
	stored := &storedAnalysisResult{Owner: owner, CreatedAt: e.resultsNow(), Summary: summary, Traffic: result.Traffic, Strategies: strategies}

	e.resultMu.Lock()
	defer e.resultMu.Unlock()
	if e.results == nil {
		e.results = map[string]*storedAnalysisResult{}
	}
	e.purgeResultsLocked(stored.CreatedAt)
	for len(e.results) >= maxStoredResults {
		var oldestID string
		var oldest time.Time
		for id, candidate := range e.results {
			if oldestID == "" || candidate.CreatedAt.Before(oldest) {
				oldestID, oldest = id, candidate.CreatedAt
			}
		}
		delete(e.results, oldestID)
	}
	e.results[resultID] = stored
	return resultID, summary, nil
}

func (e *Extension) purgeResultsLocked(now time.Time) {
	for id, result := range e.results {
		if now.Sub(result.CreatedAt) > resultTTL {
			delete(e.results, id)
		}
	}
}

func (e *Extension) ownedResult(r *http.Request) (*storedAnalysisResult, bool) {
	owner := ""
	if e.currentUser != nil {
		owner = e.currentUser(r)
	}
	e.resultMu.Lock()
	defer e.resultMu.Unlock()
	e.purgeResultsLocked(e.resultsNow())
	result, ok := e.results[chi.URLParam(r, "resultID")]
	if !ok || result.Owner != owner {
		return nil, false
	}
	return result, true
}

func (e *Extension) resultPanel(w http.ResponseWriter, r *http.Request) {
	result, ok := e.ownedResult(r)
	if !ok {
		e.jsonError(w, http.StatusNotFound, "result not found or expired")
		return
	}
	key := chi.URLParam(r, "panelKey")
	w.Header().Set("Cache-Control", "no-store")
	if key == "traffic" {
		e.writeJSON(w, map[string]any{"key": key, "kind": "traffic", "data": result.Traffic})
		return
	}
	strategy, ok := result.Strategies[key]
	if !ok {
		e.jsonError(w, http.StatusNotFound, "result panel not found")
		return
	}
	e.writeJSON(w, map[string]any{"key": key, "kind": "strategy", "data": strategy})
}

func safeResultCSV(value string) string {
	trimmed := strings.TrimLeft(value, " \t\r\n")
	if trimmed != "" && strings.ContainsRune("=+-@", rune(trimmed[0])) {
		return "'" + value
	}
	return value
}

func safeResultFilenameToken(value string) string {
	var token strings.Builder
	for _, char := range value {
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '-' || char == '_' {
			token.WriteRune(char)
		}
	}
	if token.Len() == 0 {
		return "result"
	}
	return token.String()
}

func trafficCSV(traffic trafficResultPanel) ([]byte, error) {
	var output bytes.Buffer
	writer := csv.NewWriter(&output)
	_ = writer.Write([]string{"source", "destination", "protocol", "port", "service", "hits", "last_seen", "flow"})
	for _, tuple := range traffic.Tuples {
		_ = writer.Write([]string{safeResultCSV(tuple.SrcIP), safeResultCSV(tuple.DstIP), safeResultCSV(tuple.Proto), strconv.Itoa(tuple.Port), safeResultCSV(tuple.Service), strconv.FormatInt(tuple.Hits, 10), safeResultCSV(tuple.LastSeen), safeResultCSV(tuple.Flow)})
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func (e *Extension) exportResult(w http.ResponseWriter, r *http.Request) {
	result, ok := e.ownedResult(r)
	if !ok {
		e.jsonError(w, http.StatusNotFound, "result not found or expired")
		return
	}
	kind := chi.URLParam(r, "exportType")
	policyID := 0
	if result.Summary.Policy != nil {
		policyID = result.Summary.Policy.ID
	}
	var content []byte
	var contentType, filename, metadataType string
	var err error
	switch kind {
	case "summary":
		content, err = json.MarshalIndent(result.Summary, "", "  ")
		contentType, filename, metadataType = "application/json", fmt.Sprintf("polsplit-policy-%d-summary.json", policyID), "summary"
	case "traffic":
		content, err = trafficCSV(result.Traffic)
		contentType, filename, metadataType = "text/csv; charset=utf-8", fmt.Sprintf("polsplit-policy-%d-traffic.csv", policyID), "traffic"
	case "config":
		strategyKey := r.URL.Query().Get("strategy")
		strategy, found := result.Strategies[strategyKey]
		if !found {
			e.jsonError(w, http.StatusNotFound, "strategy not found")
			return
		}
		content = []byte(strategy.Config)
		contentType, filename, metadataType = "text/plain; charset=utf-8", fmt.Sprintf("polsplit-policy-%d-%s.conf", policyID, safeResultFilenameToken(strategy.Key)), "config:"+strategy.Key
	default:
		e.jsonError(w, http.StatusNotFound, "export type not found")
		return
	}
	if err != nil {
		e.jsonError(w, http.StatusInternalServerError, "failed to build export")
		return
	}
	if len(content) > maxExportBytes {
		e.jsonError(w, http.StatusRequestEntityTooLarge, "export exceeds the size limit")
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.Header().Set("Content-Length", strconv.Itoa(len(content)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
	e.log(r, "PolSplit Export", fmt.Sprintf("result=%s type=%s bytes=%d", result.Summary.ResultID, metadataType, len(content)))
}
