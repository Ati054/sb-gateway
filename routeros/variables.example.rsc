# SB-GATEWAY variables for RouterOS 7. Import a private copy, not this example.
# Last tested baseline: RouterOS 7.21.5 long-term on ARM64. The scripts accept
# any RouterOS 7 channel and gate changes on concrete capabilities.

# Default bootstrap path: upload the verified Docker archive through WebFig
# Files.  Set SB_IMAGE_SOURCE="registry" only when an OCI registry is
# deliberately used; the RouterOS version/channel is unrelated to this choice.
:global "SB_IMAGE_SOURCE" "file"
:global "SB_IMAGE_FILE" "usb1/sb-gateway/sb-gateway-1.6.22-linux-arm64.tar"
:global "SB_IMAGE" ""
:global "SB_BRIDGE" "bridge-sb"
:global "SB_VETH" "veth-sb"
:global "SB_ROUTER_ADDRESS" "172.31.255.1/30"
:global "SB_ROUTER_IP" "172.31.255.1"
:global "SB_CONTAINER_ADDRESS" "172.31.255.2/30"
:global "SB_CONTAINER_IP" "172.31.255.2"
:global "SB_CONTAINER_NETWORK" "172.31.255.0/30"
:global "SB_TUN_ADDRESS" "172.31.254.1/30"
:global "SB_ROUTING_TABLE" "to-sb-gateway"
# Set true only in the private copy after every address above has been replaced
# or deliberately confirmed against the current RouterOS configuration.
:global "SB_ADDRESSES_CONFIRMED" false

# These paths must resolve to an external USB SSD, never internal flash/NAND.
:global "SB_STORAGE_ROOT" "usb1/sb-gateway"
:global "SB_ROOT_DIR" "usb1/sb-gateway/root-1.6.22"
:global "SB_CONFIG_DIR" "usb1/sb-gateway/config"
:global "SB_DATA_DIR" "usb1/sb-gateway/data"
:global "SB_LOGS_DIR" "usb1/sb-gateway/logs"
:global "SB_STATE_DIR" "usb1/sb-gateway/state"
# 1 GiB RouterOS profile: keep enough headroom for RAM-backed caches without
# starving RouterOS or a temporary update candidate.
:global "SB_CONTAINER_MEMORY_HIGH" "224M"
:global "SB_CONTAINER_MEMORY_MAX" "256M"

# Exact client and network CIDRs; examples are documentation addresses.
:global "SB_MANAGED_CLIENTS" {"192.168.88.25/32";"10.20.0.2/32"}
:global "SB_INTERNAL_NETWORKS" {"192.168.88.0/24";"10.20.0.0/24"}
:global "SB_BYPASS_ENDPOINTS" [:toarray ""]
:global "SB_CONTAINER_ALLOWED_INTERNAL" [:toarray ""]
:global "SB_MANAGEMENT_SOURCES" {"192.168.88.0/24"}
# Actual RouterOS interface names selected in the Web UI.  Source CIDRs are
# never trusted across unrelated VPN/WAN interfaces merely because they match.
:global "SB_MANAGEMENT_INGRESS_INTERFACES" {"bridge"}

# block_managed requires all assigned managed-client IPv6 addresses/prefixes.
# Leave IPv6 disabled on those clients until this list is complete.
:global "SB_IPV6_MODE" "block_managed"
:global "SB_MANAGED_CLIENTS_V6" [:toarray ""]
:global "SB_INTERNAL_NETWORKS_V6" [:toarray ""]

# Public ingress names are rendered inside the container.
:global "SB_WS_HOST" "ws.example.invalid"
:global "SB_GRPC_HOST" "grpc.example.invalid"
:global "SB_STATUS_HOST" "status.example.invalid"
:global "SB_HU_HOST" "hu.example.invalid"
:global "SB_HTTPUPGRADE_ENABLED" "0"

# RouterOS polls the container-only health listener. It never enables routing
# from a public liveness response.
:global "SB_HEALTH_URL" "http://172.31.255.2:9080/traffic-ready"
:global "SB_HEALTH_INTERVAL" "5s"
:global "SB_HEALTH_FAILURE_THRESHOLD" 3
:global "SB_HEALTH_RECOVERY_THRESHOLD" 3
:global "SB_HEALTH_COOLDOWN_TICKS" 12

# Web-UI control plane REST bootstrap. Set the password interactively in a
# private script or WebFig terminal; never commit it.
:global "SB_ROUTEROS_API_USER" "sb-gateway-api"
:global "SB_ROUTEROS_API_PASSWORD" ""
# Dedicated high www-ssl port used only for RouterOS REST/WebFig management.
# Keep 17443 free for the user-facing SB Gateway panel. Confirm that 59443 is
# unused before installation, or deliberately select another high TCP port.
:global "SB_ROUTEROS_REST_PORT" 59443
# Exact existing www-ssl certificate name selected in WebFig. Bootstrap rejects
# an empty value or a service without a certificate.
:global "SB_ROUTEROS_HTTPS_CERTIFICATE" ""
