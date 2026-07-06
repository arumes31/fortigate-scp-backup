package fgtadmvpnconf

import (
	"bytes"
	"database/sql"
	"embed"
	"encoding/csv"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

//go:embed templates/fgt_adm_vpn_conf_index.html templates/fgt_adm_vpn_conf_edit_form.html
var templatesFS embed.FS

const indexTemplate = "fgt_adm_vpn_conf_index.html"
const editFormTemplate = "fgt_adm_vpn_conf_edit_form.html"

func (e *Extension) parseTemplates() error {
	t, err := template.New("").ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		return err
	}
	e.tmpl = t
	return nil
}

// formGet returns the posted value for key, or def when the key is entirely
// absent (mirroring Python request.form.get(key, default)).
func formGet(r *http.Request, key, def string) string {
	if vs, ok := r.PostForm[key]; ok {
		if len(vs) > 0 {
			return vs[0]
		}
		return ""
	}
	return def
}

// formHas reports whether a key is present in the posted form (checkbox test).
func formHas(r *http.Request, key string) bool {
	return len(r.PostForm[key]) > 0
}

func (e *Extension) serverError(w http.ResponseWriter, err error) {
	e.logger.Error("fgt_adm_vpn_conf handler error", "err", err)
	http.Error(w, "An error occurred. Check logs for details.", http.StatusInternalServerError)
}

// ---- index ------------------------------------------------------------------

type configRow struct {
	*VpnConfig
	NextCheckISO string
}

type indexData struct {
	Configs                []configRow
	AvailableIPsCount      int
	AvailableIPsPercentage string
}

func (e *Extension) index(w http.ResponseWriter, r *http.Request) {
	configs, err := e.allConfigs()
	if err != nil {
		e.logger.Error("fgt_adm_vpn_conf index error", "err", err)
		http.Error(w, "An error occurred in the FGT ADM VPN Config page. Check logs for details.", http.StatusInternalServerError)
		return
	}
	available, total, err := e.availableIPs()
	if err != nil {
		e.logger.Error("fgt_adm_vpn_conf index error", "err", err)
		http.Error(w, "An error occurred in the FGT ADM VPN Config page. Check logs for details.", http.StatusInternalServerError)
		return
	}
	count := len(available)
	pct := 0.0
	if total > 0 {
		pct = float64(count) / float64(total) * 100
	}

	rows := make([]configRow, 0, len(configs))
	for _, c := range configs {
		iso := ""
		if c.GraylogEnabled {
			if nc := c.NextGraylogCheck(); nc != nil {
				iso = nc.UTC().Format("2006-01-02T15:04:05Z")
			}
		}
		rows = append(rows, configRow{VpnConfig: c, NextCheckISO: iso})
	}

	data := indexData{
		Configs:                rows,
		AvailableIPsCount:      count,
		AvailableIPsPercentage: fmt.Sprintf("%.2f", pct),
	}

	var buf bytes.Buffer
	if err := e.tmpl.ExecuteTemplate(&buf, indexTemplate, data); err != nil {
		e.serverError(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = buf.WriteTo(w)
}

// ---- add --------------------------------------------------------------------

func (e *Extension) add(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	kundenname := r.PostForm.Get("kundenname")
	standort := r.PostForm.Get("standort")

	remoteip, err := e.nextAvailableIP()
	if err != nil {
		e.serverError(w, err)
		return
	}
	if remoteip == "" {
		_, _ = w.Write([]byte("No available IP in the pool."))
		return
	}
	lastOctet := remoteip[strings.LastIndex(remoteip, ".")+1:]
	remoteip1st := "10.150.11." + lastOctet

	dnsName := "fgt-" + kundenname + "-" + standort
	dnsNameFull := dnsName + ".adm.eworx.at"

	firewallname := formGet(r, "firewallname", "")
	if firewallname == "" {
		firewallname = kundenname + "-" + standort
	}

	cid := strings.TrimSpace(formGet(r, "cid", ""))
	if cid == "" {
		http.Error(w, "Error: CID is required.", http.StatusBadRequest)
		return
	}
	if !isDigits(cid) {
		http.Error(w, "Error: CID must be a number.", http.StatusBadRequest)
		return
	}

	c := &VpnConfig{
		Kundenname:       kundenname,
		Standort:         standort,
		RemoteipFull:     remoteip,
		RemoteipFull1st:  remoteip1st,
		Ike2Username:     "vpn-adm-" + kundenname + "-" + standort,
		WanInterface:     formGet(r, "wan_interface", "wan1"),
		LanInterface:     formGet(r, "lan_interface", "loopback"),
		DnsName:          dnsName,
		Firewallname:     firewallname,
		Cid:              cid,
		IpsecPskRo:       formGet(r, "ipsec_psk_ro", "psauto"),
		IpsecPskHci:      formGet(r, "ipsec_psk_hci", "psauto"),
		Radiusmgt:        formGet(r, "radiusmgt", "YES"),
		DnsNameFull:      dnsNameFull,
		GraylogEnabled:   formHas(r, "graylog_enabled"),
		ClusterHostnames: formGet(r, "cluster_hostnames", ""),
	}
	if err := e.insertConfig(c); err != nil {
		e.serverError(w, err)
		return
	}
	e.log(r, "FGT ADM VPN - Add", fmt.Sprintf("Added config for %s - %s (%s)", kundenname, standort, remoteip))
	http.Redirect(w, r, e.Prefix()+"/", http.StatusSeeOther)
}

// ---- edit -------------------------------------------------------------------

func (e *Extension) editForm(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	c, err := e.getConfig(id)
	if err == sql.ErrNoRows {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		e.serverError(w, err)
		return
	}
	var buf bytes.Buffer
	if err := e.tmpl.ExecuteTemplate(&buf, editFormTemplate, c); err != nil {
		e.serverError(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = buf.WriteTo(w)
}

func (e *Extension) editSubmit(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	c, err := e.getConfig(id)
	if err == sql.ErrNoRows {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		e.serverError(w, err)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	c.Kundenname = r.PostForm.Get("kundenname")
	c.Standort = r.PostForm.Get("standort")
	c.WanInterface = r.PostForm.Get("wan_interface")
	c.LanInterface = r.PostForm.Get("lan_interface")
	c.GraylogEnabled = formHas(r, "graylog_enabled")
	c.ClusterHostnames = formGet(r, "cluster_hostnames", "")

	newRemote := strings.TrimSpace(r.PostForm.Get("remoteip_full"))
	// Reject an empty/invalid IP: otherwise RemoteipFull1st is derived as the
	// broken "10.150.11." and the row drops out of IP-pool accounting.
	if net.ParseIP(newRemote) == nil {
		http.Error(w, "Error: A valid remote IP address is required.", http.StatusBadRequest)
		return
	}
	if newRemote != c.RemoteipFull {
		taken, err := e.remoteIPTaken(newRemote, c.ID)
		if err != nil {
			e.serverError(w, err)
			return
		}
		if taken {
			http.Error(w, fmt.Sprintf("Error: IP address %s is already in use by another entry.", newRemote), http.StatusBadRequest)
			return
		}
	}
	c.RemoteipFull = newRemote
	lastOctet := c.RemoteipFull[strings.LastIndex(c.RemoteipFull, ".")+1:]
	c.RemoteipFull1st = "10.150.11." + lastOctet

	c.IpsecPskRo = r.PostForm.Get("ipsec_psk_ro")
	c.IpsecPskHci = r.PostForm.Get("ipsec_psk_hci")
	c.Radiusmgt = r.PostForm.Get("radiusmgt")

	firewallname := formGet(r, "firewallname", "")
	if firewallname != "" {
		c.Firewallname = firewallname
	} else {
		c.Firewallname = c.Kundenname + "-" + c.Standort
	}

	cid := strings.TrimSpace(formGet(r, "cid", ""))
	if cid == "" {
		http.Error(w, "Error: CID is required.", http.StatusBadRequest)
		return
	}
	if !isDigits(cid) {
		http.Error(w, "Error: CID must be a number.", http.StatusBadRequest)
		return
	}
	c.Cid = cid

	c.DnsName = "fgt-" + c.Kundenname + "-" + c.Standort
	c.DnsNameFull = c.DnsName + ".adm.eworx.at"
	c.Ike2Username = "vpn-adm-" + c.Kundenname + "-" + c.Standort

	if err := e.updateConfigFull(c); err != nil {
		e.serverError(w, err)
		return
	}
	e.log(r, "FGT ADM VPN - Edit", fmt.Sprintf("Edited config for %s - %s (ID: %d)", c.Kundenname, c.Standort, c.ID))
	http.Redirect(w, r, e.Prefix()+"/", http.StatusSeeOther)
}

// ---- delete -----------------------------------------------------------------

func (e *Extension) delete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	c, err := e.getConfig(id)
	if err == sql.ErrNoRows {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		e.serverError(w, err)
		return
	}
	if err := e.deleteConfig(id); err != nil {
		e.serverError(w, err)
		return
	}
	e.log(r, "FGT ADM VPN - Delete", fmt.Sprintf("Deleted config for %s - %s (ID: %d)", c.Kundenname, c.Standort, id))
	http.Redirect(w, r, e.Prefix()+"/", http.StatusSeeOther)
}

// ---- generate ---------------------------------------------------------------

func (e *Extension) generateSingle(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		_, _ = w.Write([]byte("Entry not found."))
		return
	}
	c, err := e.getConfig(id)
	if err == sql.ErrNoRows {
		_, _ = w.Write([]byte("Entry not found."))
		return
	}
	if err != nil {
		e.serverError(w, err)
		return
	}
	buf, err := e.buildConfigZip(c)
	if err != nil {
		e.serverError(w, err)
		return
	}
	e.log(r, "FGT ADM VPN - Download", fmt.Sprintf("Generated and downloaded config for %s - %s (ID: %d)", c.Kundenname, c.Standort, id))
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="fgt_adm_config_%s-%s.zip"`, c.Kundenname, c.Standort))
	_, _ = w.Write(buf.Bytes())
}

// ---- export CSV -------------------------------------------------------------

func (e *Extension) exportCSV(w http.ResponseWriter, r *http.Request) {
	configs, err := e.allConfigs()
	if err != nil {
		e.serverError(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=vpn_configs_backup.csv")

	cw := csv.NewWriter(w)
	cw.UseCRLF = true
	_ = cw.Write([]string{
		"Kundenname", "Standort", "REMOTEIP-FULL", "REMOTEIP-FULL-1st",
		"ike2_username", "WAN-Interface", "LAN-Interface", "DNS-Name",
		"IPSEC-PSK-RO", "IPSEC-PSK-HCI", "RADIUSMGT", "DNS-Name-Full",
		"Firewallname", "CID", "graylog_enabled", "cluster_hostnames",
	})
	for _, c := range configs {
		gl := "NO"
		if c.GraylogEnabled {
			gl = "YES"
		}
		_ = cw.Write([]string{
			c.Kundenname, c.Standort, c.RemoteipFull, c.RemoteipFull1st,
			c.Ike2Username, c.WanInterface, c.LanInterface, c.DnsName,
			c.IpsecPskRo, c.IpsecPskHci, c.Radiusmgt, c.DnsNameFull,
			c.Firewallname, c.Cid, gl, c.ClusterHostnames,
		})
	}
	cw.Flush()
	e.log(r, "FGT ADM VPN - Export", "Exported all configs to CSV")
}

// ---- export bookmarks -------------------------------------------------------

func (e *Extension) exportBookmarks(w http.ResponseWriter, r *http.Request) {
	configs, err := e.allConfigs()
	if err != nil {
		e.serverError(w, err)
		return
	}
	ts := time.Now().Unix()

	var b strings.Builder
	b.WriteString("<!DOCTYPE NETSCAPE-Bookmark-file-1>\n")
	b.WriteString("<!-- This is an automatically generated file.\n")
	b.WriteString("     It will be read and overwritten.\n")
	b.WriteString("     DO NOT EDIT! -->\n")
	b.WriteString(`<META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=UTF-8">` + "\n")
	b.WriteString("<TITLE>Bookmarks</TITLE>\n")
	b.WriteString("<H1>Bookmarks</H1>\n")
	b.WriteString("<DL><p>\n")
	b.WriteString(fmt.Sprintf("    <DT><H3 ADD_DATE=\"%d\" LAST_MODIFIED=\"%d\">FGT ADM VPN</H3>\n", ts, ts))
	b.WriteString("    <DL><p>\n")
	for _, c := range configs {
		url := fmt.Sprintf("https://%s:9443", c.DnsNameFull)
		name := fmt.Sprintf("FGT ADM - %s - %s", c.Kundenname, c.Standort)
		b.WriteString(fmt.Sprintf("        <DT><A HREF=\"%s\" ADD_DATE=\"%d\">%s</A>\n", url, ts, name))
	}
	b.WriteString("    </DL><p>\n")
	b.WriteString("</DL><p>\n")

	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Content-Disposition", "attachment; filename=fgt_adm_bookmarks.html")
	_, _ = io.WriteString(w, b.String())
	e.log(r, "FGT ADM VPN - Export Bookmarks", "Exported all DNS names to browser bookmarks")
}

// ---- public Graylog DSV -----------------------------------------------------

func (e *Extension) graylogDSV(w http.ResponseWriter, r *http.Request) {
	configs, err := e.enabledConfigs()
	if err != nil {
		e.serverError(w, err)
		return
	}
	lines := []string{"Firewallname;Remote_IP;Status"}
	for _, c := range configs {
		if c.RemoteipFull == "" {
			continue
		}
		if c.ClusterHostnames != "" {
			for _, h := range splitHostnames(c.ClusterHostnames) {
				lines = append(lines, fmt.Sprintf("%s;%s;active", h, c.RemoteipFull))
			}
		} else if c.Firewallname != "" {
			lines = append(lines, fmt.Sprintf("%s;%s;active", c.Firewallname, c.RemoteipFull))
		}
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = io.WriteString(w, strings.Join(lines, "\n"))
}

// ---- CSV import -------------------------------------------------------------

func (e *Extension) importCSV(w http.ResponseWriter, r *http.Request) {
	file, _, err := r.FormFile("file")
	if err != nil {
		_, _ = w.Write([]byte("No file uploaded."))
		return
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		e.serverError(w, err)
		return
	}
	// utf-8-sig: strip a leading UTF-8 BOM if present.
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})

	cr := csv.NewReader(bytes.NewReader(data))
	cr.FieldsPerRecord = -1
	records, err := cr.ReadAll()
	if err != nil {
		_, _ = w.Write([]byte(fmt.Sprintf("Failed to parse CSV: %v", err)))
		return
	}
	if len(records) == 0 {
		_, _ = w.Write([]byte("No file uploaded."))
		return
	}

	header := records[0]
	colMap := map[string]int{}
	headerLower := map[string]bool{}
	for i, h := range header {
		key := strings.ToLower(strings.TrimSpace(h))
		colMap[key] = i
		headerLower[key] = true
	}

	expectedCols := []string{
		"kundenname", "standort", "remoteip-full", "remoteip-full-1st",
		"ipsec-psk-ro", "ipsec-psk-hci", "radiusmgt", "wan-interface", "lan-interface", "firewallname",
	}
	var missing []string
	for _, col := range expectedCols {
		if !headerLower[col] {
			missing = append(missing, col)
		}
	}
	if len(missing) > 0 {
		_, _ = w.Write([]byte("Missing required CSV columns: " + strings.Join(missing, ", ")))
		return
	}

	cell := func(row []string, name string) string {
		if idx, ok := colMap[name]; ok && idx < len(row) {
			return strings.TrimSpace(row[idx])
		}
		return ""
	}

	var errorsList []string
	for i, row := range records[1:] {
		rowNo := i + 2 // header is row 1, first data row is row 2
		if len(row) == 0 || cell(row, "kundenname") == "xxxx" {
			continue
		}

		kundenname := cell(row, "kundenname")
		standort := cell(row, "standort")

		firewallname := cell(row, "firewallname")
		if firewallname == "" {
			firewallname = kundenname + "-" + standort
		}

		dnsName := "fgt-" + kundenname + "-" + standort
		dnsNameFull := dnsName + ".adm.eworx.at"
		ike2 := "vpn-adm-" + kundenname + "-" + standort

		remoteip := cell(row, "remoteip-full")
		if remoteip == "" {
			remoteip, err = e.nextAvailableIP()
			if err != nil {
				errorsList = append(errorsList, fmt.Sprintf("Row %d: An unexpected error occurred: %v", rowNo, err))
				continue
			}
			if remoteip == "" {
				errorsList = append(errorsList, fmt.Sprintf("Row %d: No available IP in the pool during import.", rowNo))
				continue
			}
		}

		remoteip1st := cell(row, "remoteip-full-1st")
		if remoteip1st == "" {
			lastOctet := remoteip[strings.LastIndex(remoteip, ".")+1:]
			remoteip1st = "10.150.11." + lastOctet
		}

		ipsecRo := valueOr(cell(row, "ipsec-psk-ro"), "psauto")
		ipsecHci := valueOr(cell(row, "ipsec-psk-hci"), "psauto")
		radiusmgt := valueOr(cell(row, "radiusmgt"), "YES")
		wan := valueOr(cell(row, "wan-interface"), "wan1")
		lan := valueOr(cell(row, "lan-interface"), "loopback")

		graylogEnabled := true
		if _, ok := colMap["graylog_enabled"]; ok {
			graylogEnabled = strings.ToUpper(cell(row, "graylog_enabled")) == "YES"
		}
		clusterHostnames := ""
		if _, ok := colMap["cluster_hostnames"]; ok {
			clusterHostnames = cell(row, "cluster_hostnames")
		}

		cid := cell(row, "cid")
		if cid == "" {
			errorsList = append(errorsList, fmt.Sprintf("Row %d: CID is required.", rowNo))
			continue
		}
		if !isDigits(cid) {
			errorsList = append(errorsList, fmt.Sprintf("Row %d: CID must be a number.", rowNo))
			continue
		}

		fwID, fwFound, err := e.findIDByFirewallname(firewallname)
		if err != nil {
			errorsList = append(errorsList, fmt.Sprintf("Row %d: An unexpected error occurred: %v", rowNo, err))
			continue
		}
		ripID, ripFound, err := e.findIDByRemoteip(remoteip)
		if err != nil {
			errorsList = append(errorsList, fmt.Sprintf("Row %d: An unexpected error occurred: %v", rowNo, err))
			continue
		}

		c := &VpnConfig{
			Kundenname:       kundenname,
			Standort:         standort,
			RemoteipFull:     remoteip,
			RemoteipFull1st:  remoteip1st,
			Ike2Username:     ike2,
			WanInterface:     wan,
			LanInterface:     lan,
			DnsName:          dnsName,
			Firewallname:     firewallname,
			Cid:              cid,
			IpsecPskRo:       ipsecRo,
			IpsecPskHci:      ipsecHci,
			Radiusmgt:        radiusmgt,
			DnsNameFull:      dnsNameFull,
			GraylogEnabled:   graylogEnabled,
			ClusterHostnames: clusterHostnames,
		}

		if fwFound {
			if ripFound && ripID != fwID {
				errorsList = append(errorsList, fmt.Sprintf("Row %d: Skipping row for firewallname '%s': remoteip_full '%s' is already in use by another entry (ID: %d).", rowNo, firewallname, remoteip, ripID))
				continue
			}
			if err := e.updateConfigImport(fwID, c); err != nil {
				errorsList = append(errorsList, fmt.Sprintf("Row %d: An unexpected error occurred: %v", rowNo, err))
				continue
			}
		} else {
			if ripFound {
				errorsList = append(errorsList, fmt.Sprintf("Row %d: Skipping insert for firewallname '%s': remoteip_full '%s' is already in use by an existing entry (ID: %d).", rowNo, firewallname, remoteip, ripID))
				continue
			}
			if err := e.insertConfig(c); err != nil {
				errorsList = append(errorsList, fmt.Sprintf("Row %d: An unexpected error occurred: %v", rowNo, err))
				continue
			}
		}
	}

	if len(errorsList) > 0 {
		e.log(r, "FGT ADM VPN - Import Failed", fmt.Sprintf("Import finished with errors: %d errors", len(errorsList)))
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// The messages embed user-supplied CSV values (firewallname, remoteip);
		// escape each before writing into the HTML response so a crafted cell
		// cannot inject markup/script. "<br>" is our own trusted separator.
		escaped := make([]string, len(errorsList))
		for i, msg := range errorsList {
			escaped[i] = template.HTMLEscapeString(msg)
		}
		_, _ = io.WriteString(w, strings.Join(escaped, "<br>"))
		return
	}
	e.log(r, "FGT ADM VPN - Import Success", "Imported configs from CSV")
	http.Redirect(w, r, e.Prefix()+"/", http.StatusSeeOther)
}

// valueOr returns v if non-empty, else def (mirrors the "value if value else
// default" idiom used throughout import_csv).
func valueOr(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
