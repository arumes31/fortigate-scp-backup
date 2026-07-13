package fgt_confgen

import (
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/arumes31/fortigate-scp-backup/internal/crypto"
)

//go:embed templates/fgt_confgen_index.html
var templatesFS embed.FS

const indexTemplate = "fgt_confgen_index.html"

func (e *Extension) parseTemplates() error {
	t, err := template.New("").ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		return err
	}
	e.tmpl = t
	return nil
}

type indexContext struct {
	Base                any
	Firewalls           []FirewallRef
	Templates           []string
	PreselectedTemplate string
	SSLSSHProfiles      []string
	WebfilterProfiles   []string
	AVProfiles          []string
	ApplicationLists    []string
	IPSSensors          []string
	Interfaces          []string
	Addresses           []string
	AddressGroups       []string
	InternetServices    []string
	VIPs                []string
	IPPools             []string
	Services            []Service
	ServiceGroups       map[string][]string
	Users               []string
	Groups              []string
}

func (e *Extension) index(w http.ResponseWriter, r *http.Request) {
	username := e.currentUser(r)
	e.logger.Debug("Rendering Policy Generator index page", "user", username)

	// Fetch firewalls from main Postgres database
	var firewalls []FirewallRef
	rows, err := e.pgPool.Query(r.Context(), "SELECT id, fqdn FROM firewalls ORDER BY fqdn")
	if err != nil {
		e.logger.Error("Failed to fetch firewalls from main DB", "err", err)
	} else {
		defer rows.Close()
		for rows.Next() {
			var fw FirewallRef
			if err := rows.Scan(&fw.ID, &fw.FQDN); err == nil {
				firewalls = append(firewalls, fw)
			}
		}
	}

	// Fetch templates list for this user and global templates
	templates, err := e.getTemplateNames(username)
	if err != nil {
		e.logger.Error("Failed to fetch template names", "user", username, "err", err)
	}

	// Load last config if available
	config, _ := e.getLastConfigFromDB(username)

	preselected := r.URL.Query().Get("preselected")

	ctx := indexContext{
		Base:                e.baseData(r, "Policy Generator", "configgen"),
		Firewalls:           firewalls,
		Templates:           templates,
		PreselectedTemplate: preselected,
		SSLSSHProfiles:      config.SSLSSHProfiles,
		WebfilterProfiles:   config.WebfilterProfiles,
		AVProfiles:          config.AVProfiles,
		ApplicationLists:    config.ApplicationLists,
		IPSSensors:          config.IPSSensors,
		Interfaces:          config.Interfaces,
		Addresses:           config.Addresses,
		AddressGroups:       config.AddressGroups,
		InternetServices:    config.InternetServices,
		VIPs:                config.VIPs,
		IPPools:             config.IPPools,
		Services:            config.Services,
		ServiceGroups:       config.ServiceGroups,
		Users:               config.Users,
		Groups:              config.Groups,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := e.tmpl.ExecuteTemplate(w, indexTemplate, ctx); err != nil {
		e.logger.Error("Template render failed", "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

func (e *Extension) listFirewalls(w http.ResponseWriter, r *http.Request) {
	rows, err := e.pgPool.Query(r.Context(), "SELECT id, fqdn FROM firewalls ORDER BY fqdn")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var list []FirewallRef
	for rows.Next() {
		var fw FirewallRef
		if err := rows.Scan(&fw.ID, &fw.FQDN); err == nil {
			list = append(list, fw)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"firewalls": list})
}

func (e *Extension) loadFirewallConfig(w http.ResponseWriter, r *http.Request) {
	fwIDStr := r.URL.Query().Get("fw_id")
	fwID, err := strconv.Atoi(fwIDStr)
	if err != nil {
		http.Error(w, "Invalid fw_id", http.StatusBadRequest)
		return
	}

	username := e.currentUser(r)
	e.logger.Info("Loading firewall config backup", "fw_id", fwID, "user", username)

	// Fetch latest successful backup file from main DB
	var filename string
	err = e.pgPool.QueryRow(r.Context(),
		"SELECT filename FROM backups WHERE fw_id = $1 ORDER BY timestamp DESC LIMIT 1", fwID).Scan(&filename)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "No backups found for this firewall", http.StatusNotFound)
			return
		}
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	diskPath := filepath.Join(e.cfg.BackupDir, filepath.FromSlash(filename))
	encData, err := os.ReadFile(diskPath)
	if err != nil {
		e.logger.Error("Failed to read backup file", "path", diskPath, "err", err)
		http.Error(w, "Failed to read backup file from disk", http.StatusInternalServerError)
		return
	}

	// Decrypt config content
	cipher, err := crypto.New(e.cfg.EncryptionKey)
	if err != nil {
		http.Error(w, "Failed to init cipher", http.StatusInternalServerError)
		return
	}
	plain, err := cipher.Decrypt(encData)
	if err != nil {
		e.logger.Error("Failed to decrypt backup", "path", diskPath, "err", err)
		http.Error(w, "Failed to decrypt backup", http.StatusInternalServerError)
		return
	}

	// Parse configuration
	parsed := ParseConfig(string(plain))

	// Save parsed config to SQLite workspace
	if err := e.saveLastConfigToDB(username, parsed); err != nil {
		e.logger.Error("Failed to save last config to SQLite", "err", err)
	}

	e.log(r, "Load Firewall Config", fmt.Sprintf("Loaded latest config from firewall ID %d", fwID))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(parsed)
}

func (e *Extension) loadTemplatesEndpoint(w http.ResponseWriter, r *http.Request) {
	username := e.currentUser(r)
	templates, err := e.getTemplateNames(username)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"templates": templates})
}

func (e *Extension) getTemplate(w http.ResponseWriter, r *http.Request) {
	templateName := chi.URLParam(r, "templateName")
	username := e.currentUser(r)

	dataJSON, owner, err := e.getTemplateFromDB(username, templateName)
	if err != nil {
		http.Error(w, "Template not found", http.StatusNotFound)
		return
	}

	var data TemplateData
	_ = json.Unmarshal([]byte(dataJSON), &data)

	// Build the context for preselected profiles
	interfaces := make(map[string]bool)
	addresses := make(map[string]bool)
	addressGroups := make(map[string]bool)
	internetServices := make(map[string]bool)
	vips := make(map[string]bool)
	ipPools := make(map[string]bool)
	var services []Service
	svcSet := make(map[string]bool)
	serviceGroups := make(map[string][]string)
	sslSSHProfiles := make(map[string]bool)
	webfilterProfiles := make(map[string]bool)
	avProfiles := make(map[string]bool)
	applicationLists := make(map[string]bool)
	ipsSensors := make(map[string]bool)
	users := make(map[string]bool)
	groups := make(map[string]bool)

	for _, policy := range data.Policies {
		for _, intf := range policy.SrcInterfaces {
			interfaces[intf] = true
		}
		for _, intf := range policy.DstInterfaces {
			interfaces[intf] = true
		}
		for _, addr := range policy.SrcAddresses {
			addresses[addr] = true
		}
		for _, addr := range policy.DstAddresses {
			addresses[addr] = true
		}
		for _, agrp := range policy.SrcAddressGroups {
			addressGroups[agrp] = true
		}
		for _, agrp := range policy.DstAddressGroups {
			addressGroups[agrp] = true
		}
		for _, isdb := range policy.SrcInternetServices {
			internetServices[isdb] = true
		}
		for _, isdb := range policy.DstInternetServices {
			internetServices[isdb] = true
		}
		for _, vip := range policy.SrcVIPs {
			vips[vip] = true
		}
		for _, vip := range policy.DstVIPs {
			vips[vip] = true
		}
		if policy.IPPool != "" {
			ipPools[policy.IPPool] = true
		}
		for _, svc := range policy.Services {
			if svc.Type == "group" {
				serviceGroups[svc.Name] = []string{}
			} else {
				if !svcSet[svc.Name] {
					svcSet[svc.Name] = true
					services = append(services, svc)
				}
			}
		}
		if policy.SSLSSHProfile != "" && strings.ToLower(policy.Action) != "deny" {
			sslSSHProfiles[policy.SSLSSHProfile] = true
		}
		if policy.WebfilterProfile != "" && policy.WebfilterEnabled && strings.ToLower(policy.Action) != "deny" {
			webfilterProfiles[policy.WebfilterProfile] = true
		}
		if policy.AVProfile != "" && policy.AVEnabled && strings.ToLower(policy.Action) != "deny" {
			avProfiles[policy.AVProfile] = true
		}
		if policy.ApplicationList != "" && policy.ApplicationListEnabled && strings.ToLower(policy.Action) != "deny" {
			applicationLists[policy.ApplicationList] = true
		}
		if policy.IPSSensor != "" && policy.IPSSensorEnabled && strings.ToLower(policy.Action) != "deny" {
			ipsSensors[policy.IPSSensor] = true
		}
		for _, u := range policy.Users {
			users[u] = true
		}
		for _, g := range policy.Groups {
			groups[g] = true
		}
	}

	keys := func(m map[string]bool) []string {
		var out []string
		for k := range m {
			if k != "" {
				out = append(out, k)
			}
		}
		return out
	}

	resp := map[string]any{
		"status":    "success",
		"data":      data,
		"is_global": owner == "__global__",
		"config": map[string]any{
			"interfaces":         keys(interfaces),
			"addresses":          keys(addresses),
			"address_groups":     keys(addressGroups),
			"internet_services":  keys(internetServices),
			"vips":               keys(vips),
			"ip_pools":           keys(ipPools),
			"services":           services,
			"service_groups":     serviceGroups,
			"ssl_ssh_profiles":   keys(sslSSHProfiles),
			"webfilter_profiles": keys(webfilterProfiles),
			"av_profiles":        keys(avProfiles),
			"application_lists":  keys(applicationLists),
			"ips_sensors":        keys(ipsSensors),
			"users":              keys(users),
			"groups":             keys(groups),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (e *Extension) saveTemplate(w http.ResponseWriter, r *http.Request) {
	username := e.currentUser(r)
	templateName := r.FormValue("template_name")
	policiesJSON := r.FormValue("policies")
	isGlobal := r.FormValue("is_global") == "true" || r.FormValue("is_global") == "on"

	if templateName == "" {
		http.Error(w, "template_name is required", http.StatusBadRequest)
		return
	}
	if policiesJSON == "" {
		http.Error(w, "policies are required", http.StatusBadRequest)
		return
	}

	var policies []Policy
	if err := json.Unmarshal([]byte(policiesJSON), &policies); err != nil {
		http.Error(w, "Invalid policies JSON", http.StatusBadRequest)
		return
	}

	data := TemplateData{Policies: policies}
	dataJSON, _ := json.Marshal(data)

	owner := username
	if isGlobal {
		owner = "__global__"
	}

	if err := e.saveTemplateToDB(owner, templateName, string(dataJSON)); err != nil {
		http.Error(w, "Failed to save template", http.StatusInternalServerError)
		return
	}

	e.log(r, "Save Template", fmt.Sprintf("Saved template '%s' (global: %v)", templateName, isGlobal))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "message": "Template saved"})
}

func (e *Extension) deleteTemplate(w http.ResponseWriter, r *http.Request) {
	templateName := chi.URLParam(r, "templateName")
	username := e.currentUser(r)
	isGlobal := r.URL.Query().Get("is_global") == "true" || r.FormValue("is_global") == "true"

	owner := username
	if isGlobal {
		owner = "__global__"
	}

	affected, err := e.deleteTemplateFromDB(owner, templateName)
	if err != nil {
		http.Error(w, "Failed to delete template", http.StatusInternalServerError)
		return
	}

	if affected == 0 {
		http.Error(w, "Template not found", http.StatusNotFound)
		return
	}

	// Delete associated short URLs
	templateURL := fmt.Sprintf("/confgen/get_template/%s", templateName)
	e.deleteShortURLsByTemplate(templateURL)

	e.log(r, "Delete Template", fmt.Sprintf("Deleted template '%s' (global: %v)", templateName, isGlobal))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "message": "Template deleted"})
}

func (e *Extension) renameTemplate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		OldName  string `json:"old_name"`
		NewName  string `json:"new_name"`
		IsGlobal bool   `json:"is_global"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	username := e.currentUser(r)
	owner := username
	if body.IsGlobal {
		owner = "__global__"
	}

	// Verify new name doesn't exist
	var exists int
	_ = e.db.QueryRow("SELECT COUNT(*) FROM templates WHERE username = ? AND name = ?", owner, body.NewName).Scan(&exists)
	if exists > 0 {
		http.Error(w, "A template with the new name already exists", http.StatusBadRequest)
		return
	}

	affected, err := e.renameTemplateInDB(owner, body.OldName, body.NewName)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	if affected == 0 {
		http.Error(w, "Template not found", http.StatusNotFound)
		return
	}

	e.log(r, "Rename Template", fmt.Sprintf("Renamed template from '%s' to '%s' (global: %v)", body.OldName, body.NewName, body.IsGlobal))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "message": "Template renamed"})
}

func (e *Extension) cloneTemplate(w http.ResponseWriter, r *http.Request) {
	templateName := chi.URLParam(r, "templateName")
	username := e.currentUser(r)

	dataJSON, _, err := e.getTemplateFromDB(username, templateName)
	if err != nil {
		http.Error(w, "Template not found", http.StatusNotFound)
		return
	}

	var data TemplateData
	_ = json.Unmarshal([]byte(dataJSON), &data)

	// Assign new UUIDs to policies in the clone
	for i := range data.Policies {
		data.Policies[i].PolicyID = uuid.New().String()
	}

	newTemplateName := fmt.Sprintf("%s_clone_%s", templateName, randHex(6))
	newDataJSON, _ := json.Marshal(data)

	if err := e.saveTemplateToDB(username, newTemplateName, string(newDataJSON)); err != nil {
		http.Error(w, "Failed to save cloned template", http.StatusInternalServerError)
		return
	}

	e.log(r, "Clone Template", fmt.Sprintf("Cloned template '%s' as '%s'", templateName, newTemplateName))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "new_template_name": newTemplateName})
}

func (e *Extension) clonePolicy(w http.ResponseWriter, r *http.Request) {
	var body struct {
		PolicyID string `json:"policy_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	username := e.currentUser(r)

	// Search in all templates owned by user (or global)
	rows, err := e.db.Query("SELECT name, username, data FROM templates WHERE username = ? OR username = '__global__'", username)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var name, owner, dataJSON string
		if err := rows.Scan(&name, &owner, &dataJSON); err == nil {
			var data TemplateData
			_ = json.Unmarshal([]byte(dataJSON), &data)
			for _, policy := range data.Policies {
				if policy.PolicyID == body.PolicyID {
					newPolicy := policy
					newPolicy.PolicyID = uuid.New().String()
					if len(policy.PolicyName) > 20 {
						newPolicy.PolicyName = fmt.Sprintf("%s_cl", policy.PolicyName[:20])
					} else {
						newPolicy.PolicyName = fmt.Sprintf("%s_cl", policy.PolicyName)
					}

					data.Policies = append(data.Policies, newPolicy)
					newDataJSON, _ := json.Marshal(data)
					_, _ = e.db.Exec("UPDATE templates SET data = ? WHERE username = ? AND name = ?", string(newDataJSON), owner, name)

					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "new_policy": newPolicy})
					return
				}
			}
		}
	}

	http.Error(w, "Policy not found", http.StatusNotFound)
}

func (e *Extension) importTemplate(w http.ResponseWriter, r *http.Request) {
	username := e.currentUser(r)
	templateName := r.FormValue("template_name")
	templateDataStr := r.FormValue("template_data")

	if templateName == "" || templateDataStr == "" {
		http.Error(w, "Missing fields", http.StatusBadRequest)
		return
	}

	var imported struct {
		Name string       `json:"name"`
		Data TemplateData `json:"data"`
	}
	if err := json.Unmarshal([]byte(templateDataStr), &imported); err != nil {
		var directData TemplateData
		if err2 := json.Unmarshal([]byte(templateDataStr), &directData); err2 == nil {
			imported.Data = directData
		} else {
			http.Error(w, "Invalid template JSON format", http.StatusBadRequest)
			return
		}
	}

	for i := range imported.Data.Policies {
		imported.Data.Policies[i].PolicyID = uuid.New().String()
	}

	dataJSON, _ := json.Marshal(imported.Data)
	if err := e.saveTemplateToDB(username, templateName, string(dataJSON)); err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	e.log(r, "Import Template", fmt.Sprintf("Imported template '%s'", templateName))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "message": "Template imported"})
}

func (e *Extension) exportTemplate(w http.ResponseWriter, r *http.Request) {
	templateName := chi.URLParam(r, "templateName")
	username := e.currentUser(r)

	dataJSON, _, err := e.getTemplateFromDB(username, templateName)
	if err != nil {
		http.Error(w, "Template not found", http.StatusNotFound)
		return
	}

	var data TemplateData
	_ = json.Unmarshal([]byte(dataJSON), &data)

	exportData := map[string]any{
		"name": templateName,
		"data": data,
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.json\"", templateName))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(exportData)
}

func (e *Extension) shortenURL(w http.ResponseWriter, r *http.Request) {
	var body struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "Invalid body", http.StatusBadRequest)
		return
	}

	if !strings.Contains(body.URL, "/get_template/") {
		http.Error(w, "Short URLs only allowed for templates", http.StatusForbidden)
		return
	}

	var shortCode string
	err := e.db.QueryRow("SELECT short_code FROM short_urls WHERE url = ?", body.URL).Scan(&shortCode)
	if err == sql.ErrNoRows {
		shortCode = randHex(6)
		_ = e.shortenURLInDB(body.URL, shortCode)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "short_code": shortCode})
}

func (e *Extension) redirectShortURL(w http.ResponseWriter, r *http.Request) {
	shortCode := chi.URLParam(r, "shortCode")
	originalURL, err := e.getURLFromShortCode(shortCode)
	if err != nil {
		http.Error(w, "Short URL not found", http.StatusNotFound)
		return
	}

	parts := strings.Split(originalURL, "/get_template/")
	if len(parts) < 2 {
		http.Error(w, "Invalid original URL format", http.StatusBadRequest)
		return
	}
	templateName := parts[1]

	http.Redirect(w, r, "/fgt-confgen/?preselected="+templateName, http.StatusMovedPermanently)
}

func (e *Extension) logFrontend(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Message string `json:"message"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err == nil {
		e.logger.Debug("Frontend log", "msg", body.Message)
	}
	w.WriteHeader(http.StatusOK)
}

func (e *Extension) generatePolicy(w http.ResponseWriter, r *http.Request) {
	policiesJSON := r.FormValue("policies")
	if policiesJSON == "" {
		http.Error(w, "policies are required", http.StatusBadRequest)
		return
	}

	var policies []Policy
	if err := json.Unmarshal([]byte(policiesJSON), &policies); err != nil {
		http.Error(w, "Invalid policies JSON", http.StatusBadRequest)
		return
	}

	var outputs []map[string]any
	for _, p := range policies {
		outputs = append(outputs, map[string]any{
			"policy_id":   p.PolicyID,
			"policy_name": p.PolicyName,
			"output1":     GenerateOutput1(p),
			"output2":     GenerateOutput2(p),
			"output3":     GenerateOutput3(p),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"outputs": outputs})
}

func randHex(n int) string {
	const hexChars = "0123456789abcdef"
	b := make([]byte, n)
	for i := range b {
		b[i] = hexChars[rand.Intn(len(hexChars))]
	}
	return string(b)
}
