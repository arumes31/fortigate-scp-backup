package fgtadmvpnconf

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"fmt"
	"io"
	"mime"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

const (
	maxBulkEntries   = 100
	maxBulkFormBytes = 64 << 10
)

var configCSVHeader = []string{
	"Kundenname", "Standort", "REMOTEIP-FULL", "REMOTEIP-FULL-1st",
	"ike2_username", "WAN-Interface", "LAN-Interface", "DNS-Name",
	"IPSEC-PSK-RO", "IPSEC-PSK-HCI", "RADIUSMGT", "DNS-Name-Full",
	"Firewallname", "CID", "graylog_enabled", "cluster_hostnames",
}

type bulkSelectionError string

func (e bulkSelectionError) Error() string { return string(e) }

func (e *Extension) bulkGenerate(w http.ResponseWriter, r *http.Request) {
	ids, configs, ok := e.validatedBulkSelection(w, r)
	if !ok {
		return
	}

	var archive bytes.Buffer
	zipWriter := zip.NewWriter(&archive)
	var report bytes.Buffer
	reportWriter := csv.NewWriter(&report)
	_ = reportWriter.Write([]string{"id", "firewall", "status", "filename", "message"})
	failedIDs := make([]string, 0)
	succeeded := 0
	for _, config := range configs {
		filename := bulkConfigFilename(config)
		bundle, err := e.configZipForBulk(config)
		if err != nil {
			failedIDs = append(failedIDs, strconv.FormatInt(config.ID, 10))
			_ = reportWriter.Write([]string{strconv.FormatInt(config.ID, 10), safeCSVDisplay(config.Firewallname), "failed", "", "generation failed"})
			e.logger.Error("ADM VPN bulk entry generation failed", "id", config.ID, "err", err)
			continue
		}
		if err := addBytesFile(zipWriter, filename, bundle.Bytes()); err != nil {
			_ = zipWriter.Close()
			e.serverError(w, err)
			return
		}
		succeeded++
		_ = reportWriter.Write([]string{strconv.FormatInt(config.ID, 10), safeCSVDisplay(config.Firewallname), "generated", filename, ""})
	}
	reportWriter.Flush()
	if err := reportWriter.Error(); err != nil {
		_ = zipWriter.Close()
		e.serverError(w, err)
		return
	}
	if err := addBytesFile(zipWriter, "_results.csv", report.Bytes()); err != nil {
		_ = zipWriter.Close()
		e.serverError(w, err)
		return
	}
	if err := zipWriter.Close(); err != nil {
		e.serverError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="fgt_adm_configs_%d_selected.zip"`, len(ids)))
	w.Header().Set("X-FortiSafe-Bulk-Succeeded", strconv.Itoa(succeeded))
	w.Header().Set("X-FortiSafe-Bulk-Failed", strconv.Itoa(len(failedIDs)))
	w.Header().Set("X-FortiSafe-Bulk-Failed-IDs", strings.Join(failedIDs, ","))
	e.log(r, "FGT ADM VPN - Bulk Generate", fmt.Sprintf(
		"Generated bulk config archive; count: %d; IDs: %s; succeeded: %d; failed: %d",
		len(ids), joinBulkIDs(ids), succeeded, len(failedIDs),
	))
	_, _ = w.Write(archive.Bytes())
}

func (e *Extension) bulkExport(w http.ResponseWriter, r *http.Request) {
	ids, configs, ok := e.validatedBulkSelection(w, r)
	if !ok {
		return
	}
	var payload bytes.Buffer
	if err := writeConfigsCSV(&payload, configs); err != nil {
		e.serverError(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="vpn_configs_%d_selected.csv"`, len(ids)))
	w.Header().Set("X-FortiSafe-Bulk-Succeeded", strconv.Itoa(len(ids)))
	w.Header().Set("X-FortiSafe-Bulk-Failed", "0")
	e.log(r, "FGT ADM VPN - Bulk Export", fmt.Sprintf("Exported selected configs; count: %d; IDs: %s", len(ids), joinBulkIDs(ids)))
	_, _ = w.Write(payload.Bytes())
}

func (e *Extension) validatedBulkSelection(w http.ResponseWriter, r *http.Request) ([]int64, []*VpnConfig, bool) {
	ids, err := parseBulkIDs(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return nil, nil, false
	}
	configs, err := e.configsByIDs(ids)
	if err != nil {
		e.serverError(w, err)
		return nil, nil, false
	}
	if len(configs) != len(ids) {
		http.Error(w, "Selection contains unavailable entries.", http.StatusBadRequest)
		return nil, nil, false
	}
	return ids, configs, true
}

func parseBulkIDs(w http.ResponseWriter, r *http.Request) ([]int64, error) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBulkFormBytes)
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		return nil, bulkSelectionError("Invalid selection.")
	}
	switch mediaType {
	case "multipart/form-data":
		err = r.ParseMultipartForm(maxBulkFormBytes)
	case "application/x-www-form-urlencoded":
		err = r.ParseForm()
	default:
		return nil, bulkSelectionError("Invalid selection.")
	}
	if err != nil {
		return nil, bulkSelectionError("Invalid selection.")
	}
	if r.MultipartForm != nil {
		defer func() { _ = r.MultipartForm.RemoveAll() }()
		if len(r.MultipartForm.File) != 0 {
			return nil, bulkSelectionError("Invalid selection.")
		}
	}
	values := r.PostForm["id"]
	if len(values) == 0 {
		return nil, bulkSelectionError("Select at least one entry.")
	}
	if len(values) > maxBulkEntries {
		return nil, bulkSelectionError(fmt.Sprintf("A maximum of %d entries can be processed at once.", maxBulkEntries))
	}
	ids := make([]int64, 0, len(values))
	seen := make(map[int64]struct{}, len(values))
	for _, value := range values {
		id, err := strconv.ParseInt(value, 10, 64)
		if err != nil || id <= 0 {
			return nil, bulkSelectionError("Invalid selection.")
		}
		if _, duplicate := seen[id]; duplicate {
			return nil, bulkSelectionError("Invalid selection.")
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids, nil
}

func (e *Extension) configZipForBulk(config *VpnConfig) (*bytes.Buffer, error) {
	if e.buildConfigZipFn != nil {
		return e.buildConfigZipFn(config)
	}
	return e.buildConfigZip(config)
}

func bulkConfigFilename(config *VpnConfig) string {
	return fmt.Sprintf("%03d-%s.zip", config.ID, safeFilenamePart(config.Firewallname))
}

func safeFilenamePart(value string) string {
	var output strings.Builder
	lastDash := false
	for _, char := range strings.ToLower(value) {
		allowed := char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '.' || char == '_'
		if allowed {
			output.WriteRune(char)
			lastDash = false
		} else if !lastDash {
			output.WriteByte('-')
			lastDash = true
		}
		if output.Len() >= 72 {
			break
		}
	}
	name := strings.Trim(output.String(), ".-_")
	if name == "" {
		return "entry"
	}
	return name
}

// safeCSVDisplay neutralizes spreadsheet formula prefixes in the human-facing
// result report. The configuration backup CSV intentionally remains lossless.
func safeCSVDisplay(value string) string {
	trimmed := strings.TrimLeft(value, " \t\r\n")
	if trimmed != "" && strings.ContainsRune("=+-@", rune(trimmed[0])) {
		return "'" + value
	}
	return value
}

func addBytesFile(writer *zip.Writer, name string, content []byte) error {
	entry, err := writer.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
	if err != nil {
		return err
	}
	_, err = entry.Write(content)
	return err
}

func joinBulkIDs(ids []int64) string {
	values := make([]string, len(ids))
	for index, id := range ids {
		values[index] = strconv.FormatInt(id, 10)
	}
	return strings.Join(values, ",")
}

func writeConfigsCSV(writer io.Writer, configs []*VpnConfig) error {
	csvWriter := csv.NewWriter(writer)
	csvWriter.UseCRLF = true
	if err := csvWriter.Write(configCSVHeader); err != nil {
		return err
	}
	for _, config := range configs {
		graylogEnabled := "NO"
		if config.GraylogEnabled {
			graylogEnabled = "YES"
		}
		if err := csvWriter.Write([]string{
			config.Kundenname, config.Standort, config.RemoteipFull, config.RemoteipFull1st,
			config.Ike2Username, config.WanInterface, config.LanInterface, config.DnsName,
			config.IpsecPskRo, config.IpsecPskHci, config.Radiusmgt, config.DnsNameFull,
			config.Firewallname, config.Cid, graylogEnabled, config.ClusterHostnames,
		}); err != nil {
			return err
		}
	}
	csvWriter.Flush()
	return csvWriter.Error()
}
