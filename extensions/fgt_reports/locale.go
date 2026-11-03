package fgt_reports

func reportText(lang, key string) string {
	texts := map[string][2]string{
		"title":            {"Reports", "Berichte"},
		"intro":            {"Three PDF reports are generated automatically after each successful configuration backup. Only the latest successful set is retained per firewall.", "Nach jeder erfolgreichen Konfigurationssicherung werden automatisch drei PDF-Berichte erstellt. Pro Firewall bleibt nur der letzte erfolgreich erstellte Berichtssatz erhalten."},
		"forwarding":       {"Port Forwarding & Exposure", "Portweiterleitungen & Freigaben"},
		"technical":        {"Technical Configuration", "Technische Konfiguration"},
		"customer":         {"Customer Review & Roadmap", "Kundenübersicht & Maßnahmenplan"},
		"forwarding_help":  {"VIPs, virtual servers, related policies and geographic restrictions.", "VIPs, virtuelle Server, zugehörige Regeln und geografische Einschränkungen."},
		"technical_help":   {"Configuration inventory, evidence and engineering recommendations.", "Konfigurationsübersicht, Nachweise und technische Empfehlungen."},
		"customer_help":    {"A reduced customer-facing view with priorities and next steps.", "Eine reduzierte Kundenansicht mit Prioritäten und nächsten Schritten."},
		"scope":            {"Saved configuration assessment. Live reachability, backend health and subscriptions are not verified.", "Bewertung der gespeicherten Konfiguration. Erreichbarkeit, Backend-Zustand und Abonnements werden nicht verifiziert."},
		"search":           {"Search firewalls", "Firewalls suchen"},
		"search_exposures": {"Search VIPs, addresses, ports or policy IDs", "VIPs, Adressen, Ports oder Regel-IDs suchen"},
		"firewall":         {"Firewall", "Firewall"},
		"newest":           {"Newest backup", "Neueste Sicherung"},
		"report_backup":    {"Report source backup", "Quellsicherung des Berichts"},
		"generated":        {"Generated", "Erstellt"},
		"state":            {"Status", "Status"},
		"downloads":        {"Reports", "Berichte"},
		"queued":           {"Queued", "In Warteschlange"},
		"running":          {"Generating", "Wird erstellt"},
		"ready":            {"Ready", "Bereit"},
		"failed":           {"Generation failed", "Erstellung fehlgeschlagen"},
		"limited":          {"Analysis limitations", "Eingeschränkte Analyse"},
		"stale":            {"An older successful set is available while the latest backup is processed. Check its source timestamp.", "Ein älterer erfolgreicher Berichtssatz ist verfügbar, während die neueste Sicherung verarbeitet wird. Beachten Sie den Zeitstempel der Quelle."},
		"error_source":     {"The source could not be verified or is unavailable. Automatic retries are bounded; retry after checking the backup.", "Die Quelle konnte nicht verifiziert werden oder ist nicht verfügbar. Automatische Wiederholungen sind begrenzt; prüfen Sie die Sicherung und versuchen Sie es erneut."},
		"error_analysis":   {"The backup could not be analyzed completely. Check for truncation or an unsupported backup format.", "Die Sicherung konnte nicht vollständig analysiert werden. Prüfen Sie auf unvollständige Daten oder ein nicht unterstütztes Sicherungsformat."},
		"error_rendering":  {"The PDF set could not be generated within its resource limits. The previous set remains available.", "Der PDF-Satz konnte innerhalb der Ressourcenlimits nicht erstellt werden. Der vorherige Satz bleibt verfügbar."},
		"error_storage":    {"The new report set could not be saved. The previous set remains available.", "Der neue Berichtssatz konnte nicht gespeichert werden. Der vorherige Satz bleibt verfügbar."},
		"preview":          {"Inspect findings", "Ergebnisse ansehen"},
		"regenerate":       {"Regenerate latest", "Neueste Berichte erstellen"},
		"pending":          {"Reports will appear here automatically.", "Berichte werden hier automatisch angezeigt."},
		"empty":            {"No successful backups are available yet. Reports will be created after the first successful backup.", "Noch keine erfolgreichen Sicherungen vorhanden. Berichte werden nach der ersten erfolgreichen Sicherung erstellt."},
		"refresh":          {"Refresh status", "Status aktualisieren"},
		"back":             {"All firewalls", "Alle Firewalls"},
		"coverage":         {"Analysis coverage", "Analyseumfang"},
		"complete":         {"Supported configuration paths analyzed. Runtime conditions remain unverified.", "Unterstützte Konfigurationspfade wurden analysiert. Laufzeitbedingungen bleiben ungeprüft."},
		"definitions":      {"VIP / virtual-server definitions", "VIP- / Virtual-Server-Definitionen"},
		"firmware":         {"Firmware in backup", "Firmware laut Sicherung"},
		"evidence":         {"Evidence", "Nachweis"},
		"source":           {"Source", "Quelle"},
		"destination":      {"Destination", "Ziel"},
		"service":          {"Service", "Dienst"},
		"schedule":         {"Schedule", "Zeitplan"},
		"action":           {"Action", "Aktion"},
		"policy":           {"Policy", "Regel"},
		"effect":           {"Assessment", "Bewertung"},
		"geo":              {"Geographic restrictions", "Geografische Einschränkungen"},
		"backends":         {"Configured backends", "Konfigurierte Backends"},
		"groups":           {"VIP groups", "VIP-Gruppen"},
		"profiles":         {"Security profiles", "Sicherheitsprofile"},
		"logging":          {"Logging", "Protokollierung"},
		"no_exposures":     {"No VIP or virtual-server definitions found in the captured scope. This is not a statement about all Internet-facing services.", "Keine VIP- oder Virtual-Server-Definitionen im erfassten Umfang gefunden. Dies ist keine Aussage über alle aus dem Internet erreichbaren Dienste."},
		"findings":         {"Review findings", "Prüfergebnisse"},
		"inventory":        {"Technical inventory", "Technisches Inventar"},
		"language":         {"PDF language", "PDF-Sprache"},
	}
	value, ok := texts[key]
	if !ok {
		return key
	}
	if lang == "de" {
		return value[1]
	}
	return value[0]
}
