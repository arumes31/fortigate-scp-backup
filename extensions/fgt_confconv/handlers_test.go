package fgt_confconv

import (
	"encoding/json"
	"testing"
)

func TestConvertRequestDecoding(t *testing.T) {
	body := `{
		"fw_id": 42,
		"recipes": [
			{"key": "wan-to-sdwan", "options": {"members": ["wan1", "wan2"]}},
			{"key": "sdwan-routes-to-rules", "options": {"strategy": "manual"}}
		]
	}`
	var req convertRequest
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if req.FwID != 42 {
		t.Errorf("FwID = %d, want 42", req.FwID)
	}
	if len(req.Recipes) != 2 || req.Recipes[0].Key != RecipeKeySDWAN || req.Recipes[1].Key != RecipeKeySDWANRules {
		t.Fatalf("recipes = %+v", req.Recipes)
	}

	var sdwanOpts SDWANOptions
	if err := json.Unmarshal(req.Recipes[0].Options, &sdwanOpts); err != nil {
		t.Fatalf("decode nested options: %v", err)
	}
	if len(sdwanOpts.Members) != 2 || sdwanOpts.Members[0] != "wan1" {
		t.Errorf("sdwan members = %v", sdwanOpts.Members)
	}
}
