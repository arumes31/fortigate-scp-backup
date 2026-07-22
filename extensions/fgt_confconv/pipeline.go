package fgt_confconv

import (
	"encoding/json"
	"fmt"
)

// canonicalOrder is the fixed sequence recipes run in, regardless of the
// order they appear in a request. Structural interface changes (FortiLink,
// SD-WAN membership, zoning) happen before the recipe that depends on
// SD-WAN members already existing (routes -> rules).
var canonicalOrder = []string{
	RecipeKeyFortiLink,
	RecipeKeySDWAN,
	RecipeKeyZone,
	RecipeKeySDWANRules,
}

var recipeRegistry = map[string]Recipe{
	RecipeKeyFortiLink:  fortiLinkRecipe{},
	RecipeKeySDWAN:      sdwanRecipe{},
	RecipeKeyZone:       zoneRecipe{},
	RecipeKeySDWANRules: sdwanRulesRecipe{},
}

// PipelineError is any failure the HTTP layer should surface as a 400 (a
// selection or precondition problem) rather than a 500 (an unexpected
// failure). Recipe.Run errors are wrapped in one too, since they are always
// the result of bad operator input against the current config, never an
// internal fault.
type PipelineError struct {
	Recipe string
	Msg    string
}

func (e *PipelineError) Error() string {
	if e.Recipe == "" {
		return e.Msg
	}
	return fmt.Sprintf("%s: %s", e.Recipe, e.Msg)
}

// ConvertResult is one pipeline run's full output.
type ConvertResult struct {
	Sections     []CLIBlock `json:"sections"`
	Warnings     []Warning  `json:"warnings"`
	AppliedOrder []string   `json:"appliedOrder"`
	Combined     string     `json:"combined"`
}

// RecipeSelection is one operator-picked recipe plus its options, as
// submitted in a convert request.
type RecipeSelection struct {
	Key     string          `json:"key"`
	Options json.RawMessage `json:"options"`
}

// claimedInterfaces returns the set of interface names a recipe selection's
// options primarily operate on, used only for the pre-run conflict check --
// it does not need to be exhaustive for every field, just the ones that
// determine an interface's structural role (member port, VLAN target,
// SD-WAN member, zone member).
func claimedInterfaces(key string, raw json.RawMessage) ([]string, error) {
	switch key {
	case RecipeKeyFortiLink:
		var o FortiLinkOptions
		if err := json.Unmarshal(raw, &o); err != nil {
			return nil, err
		}
		claimed := append([]string(nil), o.MemberPorts...)
		for _, m := range o.VLANMoves {
			claimed = append(claimed, m.Interface)
		}
		return claimed, nil
	case RecipeKeySDWAN:
		var o SDWANOptions
		if err := json.Unmarshal(raw, &o); err != nil {
			return nil, err
		}
		return o.Members, nil
	case RecipeKeyZone:
		var o ZoneOptions
		if err := json.Unmarshal(raw, &o); err != nil {
			return nil, err
		}
		return o.Interfaces, nil
	case RecipeKeySDWANRules:
		return nil, nil // operates on existing SD-WAN members, claims nothing new
	default:
		return nil, fmt.Errorf("unknown recipe %q", key)
	}
}

// checkClaimConflicts rejects a request where two different selected recipes
// both claim the same interface (e.g. the same port picked as both a
// FortiLink member and a zone member), before any recipe runs.
func checkClaimConflicts(selections []RecipeSelection) error {
	claims := map[string]string{} // interface -> recipe key that claimed it first
	for _, sel := range selections {
		names, err := claimedInterfaces(sel.Key, sel.Options)
		if err != nil {
			return &PipelineError{Recipe: sel.Key, Msg: "invalid options: " + err.Error()}
		}
		for _, name := range names {
			if owner, ok := claims[name]; ok && owner != sel.Key {
				return &PipelineError{Msg: fmt.Sprintf("interface %q was picked for both %q and %q -- an interface can only take on one new role per run", name, owner, sel.Key)}
			}
			claims[name] = sel.Key
		}
	}
	return nil
}

// RunPipeline runs the selected recipes against cfg in canonicalOrder,
// regardless of the order they appear in selections, threading one cloned
// FGConfig through so later recipes see earlier recipes' mutations.
func RunPipeline(cfg *FGConfig, selections []RecipeSelection) (*ConvertResult, error) {
	bySel := make(map[string]RecipeSelection, len(selections))
	for _, sel := range selections {
		if _, ok := recipeRegistry[sel.Key]; !ok {
			return nil, &PipelineError{Recipe: sel.Key, Msg: "unknown recipe"}
		}
		bySel[sel.Key] = sel
	}

	if err := checkClaimConflicts(selections); err != nil {
		return nil, err
	}

	working := cfg.Clone()
	result := &ConvertResult{}

	for _, key := range canonicalOrder {
		sel, ok := bySel[key]
		if !ok {
			continue
		}
		recipe := recipeRegistry[key]

		if applicable, reason := recipe.Applicable(working); !applicable {
			return nil, &PipelineError{Recipe: key, Msg: reason}
		}

		cli, warnings, err := recipe.Run(working, sel.Options)
		if err != nil {
			return nil, &PipelineError{Recipe: key, Msg: err.Error()}
		}

		result.Sections = append(result.Sections, cli...)
		result.Warnings = append(result.Warnings, warnings...)
		result.AppliedOrder = append(result.AppliedOrder, key)
	}

	result.Combined = RenderScript(result.Sections)
	return result, nil
}
