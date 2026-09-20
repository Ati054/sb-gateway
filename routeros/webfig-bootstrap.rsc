# SB-GATEWAY one-time WebFig bootstrap for the Web UI control plane.
# The dedicated account is source-restricted to the actual SB_CONTAINER_IP. It
# does not expose RouterOS REST to WAN/VLESS and does not alter the update channel.

:global "SB_ROUTEROS_API_USER"
:global "SB_ROUTEROS_API_PASSWORD"
:global "SB_ROUTEROS_REST_PORT"
:global "SB_ROUTEROS_HTTPS_CERTIFICATE"
:global "SB_CONTAINER_IP"
:global "SB_MANAGEMENT_SOURCES"

:local sbContainerHostRoute ($"SB_CONTAINER_IP" . "/32")
:local sbExistingRestAccount [/user/find where name=$"SB_ROUTEROS_API_USER"]
:if ([:len $sbExistingRestAccount] > 1) do={ :error "SB-GATEWAY: requested API username is ambiguous" }
:if (([:len $sbExistingRestAccount] = 0) && ([:len $"SB_ROUTEROS_API_PASSWORD"] < 16)) do={ :error "SB-GATEWAY: set a private 16+ character API password for initial account creation; do not save it in Git" }
:if (($"SB_ROUTEROS_REST_PORT" < 1) || ($"SB_ROUTEROS_REST_PORT" > 65535)) do={ :error "SB-GATEWAY: select and confirm the existing www-ssl TCP port in WebFig" }
:if ([:len $"SB_MANAGEMENT_SOURCES"] = 0) do={ :error "SB-GATEWAY: set at least one exact management CIDR before bootstrap" }
:if ([:len $"SB_ROUTEROS_HTTPS_CERTIFICATE"] = 0) do={ :error "SB-GATEWAY: select the existing www-ssl certificate name before bootstrap" }

:local sbHttpsService [/ip/service/find where name="www-ssl"]
:if ([:len $sbHttpsService] != 1) do={ :error "SB-GATEWAY: RouterOS www-ssl service is unavailable or ambiguous" }
:if ([/ip/service/get $sbHttpsService disabled] = true) do={ :error "SB-GATEWAY: enable www-ssl and select its certificate once in WebFig before importing this script" }
:local sbHttpsAddresses [/ip/service/get $sbHttpsService available-from]
:if ([:len $sbHttpsAddresses] = 0) do={ :error "SB-GATEWAY: restrict www-ssl addresses to the actual management CIDR and container /32 in WebFig before bootstrap" }
:if ([:len $sbHttpsAddresses] != ([:len $"SB_MANAGEMENT_SOURCES"] + 1)) do={ :error "SB-GATEWAY: www-ssl Available From must contain exactly the management CIDRs and container /32" }
:local sbHttpsAddressText (";" . [:tostr $sbHttpsAddresses] . ";")
:if (([:typeof [:find $sbHttpsAddressText ";0.0.0.0/0;"]] != "nil") || ([:typeof [:find $sbHttpsAddressText ";::/0;"]] != "nil")) do={ :error "SB-GATEWAY: www-ssl must never be available from a default route" }
:if ([:typeof [:find $sbHttpsAddressText (";" . $sbContainerHostRoute . ";")]] = "nil") do={ :error "SB-GATEWAY: www-ssl Available From is missing the container /32" }
:foreach sbManagementSource in=$"SB_MANAGEMENT_SOURCES" do={
  :local sbManagementNeedle (";" . [:tostr $sbManagementSource] . ";")
  :if ([:typeof [:find $sbHttpsAddressText $sbManagementNeedle]] = "nil") do={ :error ("SB-GATEWAY: www-ssl Available From is missing management entry: " . [:tostr $sbManagementSource]) }
}
:if ([/ip/service/get $sbHttpsService port] != $"SB_ROUTEROS_REST_PORT") do={ :error "SB-GATEWAY: SB_ROUTEROS_REST_PORT must match the existing www-ssl port; service was not changed" }
:local sbHttpsCertificate [/ip/service/get $sbHttpsService certificate]
:if (([:len $sbHttpsCertificate] = 0) || ($sbHttpsCertificate = "none")) do={ :error "SB-GATEWAY: www-ssl must have a certificate before bootstrap" }
:if ($sbHttpsCertificate != $"SB_ROUTEROS_HTTPS_CERTIFICATE") do={ :error "SB-GATEWAY: www-ssl certificate mismatch; service was not changed" }

:if ([:len $sbExistingRestAccount] = 1) do={
  :if ([/user/get $sbExistingRestAccount comment] != "SB-GATEWAY control-plane REST user") do={ :error "SB-GATEWAY: requested API username already belongs to another account" }
  :if ([/user/get $sbExistingRestAccount group] != "sb-gateway-api") do={ :error "SB-GATEWAY: existing REST account has an unexpected group; password was not changed" }
  :if ([:tostr [/user/get $sbExistingRestAccount address]] != $sbContainerHostRoute) do={ :error "SB-GATEWAY: existing REST account is not restricted to the configured container /32; password was not changed" }
  :if ([/user/get $sbExistingRestAccount disabled] = true) do={ :error "SB-GATEWAY: existing REST account is disabled; password was not changed" }
  :set "SB_ROUTEROS_API_PASSWORD" ""
  :log info "SB-GATEWAY: existing dedicated REST account verified; password was not changed"
} else={
  /export file="sb-gateway-before-webfig-bootstrap"
  /system/backup/save name="sb-gateway-before-webfig-bootstrap" password=$"SB_ROUTEROS_API_PASSWORD" encryption=aes-sha256

  :if ([:len [/user/group/find where name="sb-gateway-api"]] = 0) do={
    :onerror sbRestGroupError in={
      /user/group/add name="sb-gateway-api" policy=ssh,ftp,read,write,policy,test,sensitive,api,rest-api comment="SB-GATEWAY REST group"
    } do={ :error "SB-GATEWAY: required REST policy capability is unavailable; no user was created" }
  }
  :local sbRestGroup [/user/group/find where name="sb-gateway-api"]
  :if ([:len $sbRestGroup] != 1) do={ :error "SB-GATEWAY: REST group is missing or ambiguous" }
  :if ([/user/group/get $sbRestGroup comment] != "SB-GATEWAY REST group") do={ :error "SB-GATEWAY: requested REST group already belongs to another configuration" }
  # The encrypted pre-Apply binary backup contains sensitive fields and both the
  # export and backup are files. RouterOS therefore requires `sensitive` and
  # `ftp`; the REST account remains source-restricted to the container /32 and
  # this script does not enable the FTP service.
  /user/group/set $sbRestGroup policy=ssh,ftp,read,write,policy,test,sensitive,api,rest-api

  /user/add name=$"SB_ROUTEROS_API_USER" group="sb-gateway-api" address=$sbContainerHostRoute password=$"SB_ROUTEROS_API_PASSWORD" comment="SB-GATEWAY control-plane REST user"
  :set "SB_ROUTEROS_API_PASSWORD" ""
  :log warning "SB-GATEWAY: REST account is restricted to the configured container host route; provision username/password through the Web UI"
}
