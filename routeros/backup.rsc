# SB-GATEWAY manual encrypted backup/export helper.
:global "SB_PANEL_PASSWORD"
:if ([:len $"SB_PANEL_PASSWORD"] < 12) do={ :error "SB-GATEWAY: enter the current panel administrator password in a private session" }
/export file="sb-gateway-manual-export"
/system/backup/save name="sb-gateway-manual-backup" password=$"SB_PANEL_PASSWORD" encryption=aes-sha256
:set "SB_PANEL_PASSWORD" ""
:log info "SB-GATEWAY: wrote sb-gateway-manual-export.rsc and encrypted sb-gateway-manual-backup.backup"
