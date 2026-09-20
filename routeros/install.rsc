# SB-GATEWAY idempotent install for RouterOS 7 ARM64.
# Import variables, preflight, and fasttrack-patch first. The new diversion gate
# is created disabled and is enabled only by watchdog hysteresis.

:global "SB_IMAGE"
:global "SB_IMAGE_SOURCE"
:global "SB_IMAGE_FILE"
:global "SB_BRIDGE"
:global "SB_VETH"
:global "SB_ROUTER_ADDRESS"
:global "SB_ROUTER_IP"
:global "SB_CONTAINER_ADDRESS"
:global "SB_CONTAINER_IP"
:global "SB_CONTAINER_NETWORK"
:global "SB_TUN_ADDRESS"
:global "SB_ROUTING_TABLE"
:global "SB_ROOT_DIR"
:global "SB_CONFIG_DIR"
:global "SB_DATA_DIR"
:global "SB_LOGS_DIR"
:global "SB_STATE_DIR"
:global "SB_CONTAINER_MEMORY_HIGH"
:global "SB_CONTAINER_MEMORY_MAX"
:global "SB_MANAGED_CLIENTS"
:global "SB_INTERNAL_NETWORKS"
:global "SB_BYPASS_ENDPOINTS"
:global "SB_CONTAINER_ALLOWED_INTERNAL"
:global "SB_MANAGEMENT_SOURCES"
:global "SB_MANAGEMENT_INGRESS_INTERFACES"
:global "SB_IPV6_MODE"
:global "SB_MANAGED_CLIENTS_V6"
:global "SB_INTERNAL_NETWORKS_V6"
:global "SB_WS_HOST"
:global "SB_GRPC_HOST"
:global "SB_STATUS_HOST"
:global "SB_HU_HOST"
:global "SB_HTTPUPGRADE_ENABLED"
:global "SB_ROUTEROS_REST_PORT"

:local containerMemoryHigh $"SB_CONTAINER_MEMORY_HIGH"
:local containerMemoryMax $"SB_CONTAINER_MEMORY_MAX"
:if ([:len $containerMemoryHigh] = 0) do={ :set containerMemoryHigh "224M" }
:if ([:len $containerMemoryMax] = 0) do={ :set containerMemoryMax "256M" }

# Re-imports also start fail-open.  Only the exact project gate/connections are
# touched while trusted ingress and policy rules are reconciled.
/ip/firewall/mangle/disable [find where comment="SB-GATEWAY diversion-gate"]
/ip/firewall/connection/remove [find where connection-mark="sb-managed"]

:if ([:len [/interface/bridge/find where name=$"SB_BRIDGE"]] = 0) do={
  /interface/bridge/add name=$"SB_BRIDGE" protocol-mode=none comment="SB-GATEWAY container bridge"
}
:if ([:len [/interface/veth/find where name=$"SB_VETH"]] = 0) do={
  /interface/veth/add name=$"SB_VETH" address=$"SB_CONTAINER_ADDRESS" gateway=$"SB_ROUTER_IP" comment="SB-GATEWAY container veth"
}
:if ([:len [/interface/bridge/port/find where bridge=$"SB_BRIDGE" and interface=$"SB_VETH"]] = 0) do={
  /interface/bridge/port/add bridge=$"SB_BRIDGE" interface=$"SB_VETH" comment="SB-GATEWAY veth bridge port"
}
:if ([:len [/ip/address/find where interface=$"SB_BRIDGE" and address=$"SB_ROUTER_ADDRESS"]] = 0) do={
  /ip/address/add address=$"SB_ROUTER_ADDRESS" interface=$"SB_BRIDGE" comment="SB-GATEWAY router address"
}

:if ([:len [/interface/list/find where name="SB_MANAGEMENT_INGRESS"]] = 0) do={
  /interface/list/add name="SB_MANAGEMENT_INGRESS" comment="SB-GATEWAY management ingress list"
}
:local ingressList [/interface/list/find where name="SB_MANAGEMENT_INGRESS" and comment="SB-GATEWAY management ingress list"]
:if ([:len $ingressList] != 1) do={ :error "SB-GATEWAY: management ingress interface-list is missing or ambiguous" }
:foreach member in=[/interface/list/member/find where list="SB_MANAGEMENT_INGRESS"] do={
  :if ([/interface/list/member/get $member comment] != "SB-GATEWAY management ingress") do={ :error "SB-GATEWAY: refusing to alter an unowned management ingress member" }
}
:foreach member in=[/interface/list/member/find where list="SB_MANAGEMENT_INGRESS" and comment="SB-GATEWAY management ingress"] do={
  /interface/list/member/remove $member
}
:foreach interfaceName in=$"SB_MANAGEMENT_INGRESS_INTERFACES" do={
  :if ([:len [/interface/find where name=$interfaceName]] != 1) do={ :error ("SB-GATEWAY: trusted ingress interface is missing or ambiguous: " . $interfaceName) }
  /interface/list/member/add list="SB_MANAGEMENT_INGRESS" interface=$interfaceName comment="SB-GATEWAY management ingress"
}

:if ([:len [/interface/list/find where name="SB_WIREGUARD_INGRESS"]] = 0) do={
  /interface/list/add name="SB_WIREGUARD_INGRESS" comment="SB-GATEWAY WireGuard panel ingress list"
}
:local wireguardIngressList [/interface/list/find where name="SB_WIREGUARD_INGRESS" and comment="SB-GATEWAY WireGuard panel ingress list"]
:if ([:len $wireguardIngressList] != 1) do={ :error "SB-GATEWAY: WireGuard panel ingress interface-list is missing or ambiguous" }
:foreach member in=[/interface/list/member/find where list="SB_WIREGUARD_INGRESS"] do={
  :if ([/interface/list/member/get $member comment] != "SB-GATEWAY WireGuard panel ingress") do={ :error "SB-GATEWAY: refusing to alter an unowned WireGuard panel ingress member" }
}
:foreach member in=[/interface/list/member/find where list="SB_WIREGUARD_INGRESS" and comment="SB-GATEWAY WireGuard panel ingress"] do={
  /interface/list/member/remove $member
}
:foreach wgInterface in=[/interface/wireguard/find where disabled=no] do={
  :local wgName [/interface/wireguard/get $wgInterface name]
  /interface/list/member/add list="SB_WIREGUARD_INGRESS" interface=$wgName comment="SB-GATEWAY WireGuard panel ingress"
}

:foreach sbManagedCidr in=$"SB_MANAGED_CLIENTS" do={
  :local sbManagedText [:tostr $sbManagedCidr]
  :local sbManagedLookup $sbManagedText
  :local sbManagedHostSuffix [:find $sbManagedText "/32"]
  :if (($sbManagedHostSuffix != nil) && ([:pick $sbManagedText $sbManagedHostSuffix [:len $sbManagedText]] = "/32")) do={ :set sbManagedLookup [:pick $sbManagedText 0 $sbManagedHostSuffix] }
  :if ([:len [/ip/firewall/address-list/find where list="SB_MANAGED_CLIENTS" and address=$sbManagedLookup]] = 0) do={
    /ip/firewall/address-list/add list="SB_MANAGED_CLIENTS" address=$sbManagedText comment="SB-GATEWAY managed client"
  }
}
:foreach sbInternalCidr in=$"SB_INTERNAL_NETWORKS" do={
  :local sbInternalText [:tostr $sbInternalCidr]
  :local sbInternalLookup $sbInternalText
  :local sbInternalHostSuffix [:find $sbInternalText "/32"]
  :if (($sbInternalHostSuffix != nil) && ([:pick $sbInternalText $sbInternalHostSuffix [:len $sbInternalText]] = "/32")) do={ :set sbInternalLookup [:pick $sbInternalText 0 $sbInternalHostSuffix] }
  :if ([:len [/ip/firewall/address-list/find where list="SB_INTERNAL_NETWORKS" and address=$sbInternalLookup]] = 0) do={
    /ip/firewall/address-list/add list="SB_INTERNAL_NETWORKS" address=$sbInternalText comment="SB-GATEWAY internal network"
  }
}
:foreach sbBypassCidr in=$"SB_BYPASS_ENDPOINTS" do={
  :local sbBypassText [:tostr $sbBypassCidr]
  :local sbBypassLookup $sbBypassText
  :local sbBypassHostSuffix [:find $sbBypassText "/32"]
  :if (($sbBypassHostSuffix != nil) && ([:pick $sbBypassText $sbBypassHostSuffix [:len $sbBypassText]] = "/32")) do={ :set sbBypassLookup [:pick $sbBypassText 0 $sbBypassHostSuffix] }
  :if ([:len [/ip/firewall/address-list/find where list="SB_BYPASS_ENDPOINTS" and address=$sbBypassLookup]] = 0) do={
    /ip/firewall/address-list/add list="SB_BYPASS_ENDPOINTS" address=$sbBypassText comment="SB-GATEWAY loop bypass"
  }
}
:foreach sbAllowedCidr in=$"SB_CONTAINER_ALLOWED_INTERNAL" do={
  :local sbAllowedText [:tostr $sbAllowedCidr]
  :local sbAllowedLookup $sbAllowedText
  :local sbAllowedHostSuffix [:find $sbAllowedText "/32"]
  :if (($sbAllowedHostSuffix != nil) && ([:pick $sbAllowedText $sbAllowedHostSuffix [:len $sbAllowedText]] = "/32")) do={ :set sbAllowedLookup [:pick $sbAllowedText 0 $sbAllowedHostSuffix] }
  :if ([:len [/ip/firewall/address-list/find where list="SB_CONTAINER_ALLOWED_INTERNAL" and address=$sbAllowedLookup]] = 0) do={
    /ip/firewall/address-list/add list="SB_CONTAINER_ALLOWED_INTERNAL" address=$sbAllowedText comment="SB-GATEWAY explicit container LAN access"
  }
}
:foreach sbManagementCidr in=$"SB_MANAGEMENT_SOURCES" do={
  :local sbManagementText [:tostr $sbManagementCidr]
  :local sbManagementLookup $sbManagementText
  :local sbManagementHostSuffix [:find $sbManagementText "/32"]
  :if (($sbManagementHostSuffix != nil) && ([:pick $sbManagementText $sbManagementHostSuffix [:len $sbManagementText]] = "/32")) do={ :set sbManagementLookup [:pick $sbManagementText 0 $sbManagementHostSuffix] }
  :if ([:len [/ip/firewall/address-list/find where list="SB_MANAGEMENT_SOURCES" and address=$sbManagementLookup]] = 0) do={
    /ip/firewall/address-list/add list="SB_MANAGEMENT_SOURCES" address=$sbManagementText comment="SB-GATEWAY management source"
  }
}
:if ([:len [/ip/firewall/address-list/find where list="SB_INTERNAL_NETWORKS" and address=$"SB_CONTAINER_NETWORK"]] = 0) do={
  /ip/firewall/address-list/add list="SB_INTERNAL_NETWORKS" address=$"SB_CONTAINER_NETWORK" comment="SB-GATEWAY container network bypass"
}

:if ([:len [/routing/table/find where name=$"SB_ROUTING_TABLE"]] = 0) do={
  /routing/table/add name=$"SB_ROUTING_TABLE" fib comment="SB-GATEWAY routing table"
}
:if ([:len [/ip/route/find where dst-address="0.0.0.0/0" and routing-table=$"SB_ROUTING_TABLE" and comment="SB-GATEWAY container default"]] = 0) do={
  /ip/route/add dst-address="0.0.0.0/0" gateway=($"SB_CONTAINER_IP" . "@main") routing-table=$"SB_ROUTING_TABLE" distance=1 check-gateway=ping comment="SB-GATEWAY container default"
}

:if ([:len [/container/mounts/find where list="sb-gateway-config"]] = 0) do={ /container/mounts/add list="sb-gateway-config" src=$"SB_CONFIG_DIR" dst="/config" comment="SB-GATEWAY config mount" }
:if ([:len [/container/mounts/find where list="sb-gateway-data"]] = 0) do={ /container/mounts/add list="sb-gateway-data" src=$"SB_DATA_DIR" dst="/data" comment="SB-GATEWAY data mount" }
:if ([:len [/container/mounts/find where list="sb-gateway-logs"]] = 0) do={ /container/mounts/add list="sb-gateway-logs" src=$"SB_LOGS_DIR" dst="/logs" comment="SB-GATEWAY logs mount" }
:if ([:len [/container/mounts/find where list="sb-gateway-state"]] = 0) do={ /container/mounts/add list="sb-gateway-state" src=$"SB_STATE_DIR" dst="/state" comment="SB-GATEWAY state mount" }

:if ([:len [/container/envs/find where list="sb-gateway-env" and key="SB_ROUTEROS_GATEWAY"]] = 0) do={ /container/envs/add list="sb-gateway-env" key="SB_ROUTEROS_GATEWAY" value=$"SB_ROUTER_IP" comment="SB-GATEWAY runtime env" }
:if ([:len [/container/envs/find where list="sb-gateway-env" and key="SB_CONTAINER_ADDRESS"]] = 0) do={ /container/envs/add list="sb-gateway-env" key="SB_CONTAINER_ADDRESS" value=$"SB_CONTAINER_ADDRESS" comment="SB-GATEWAY runtime env" }
:if ([:len [/container/envs/find where list="sb-gateway-env" and key="SB_CONTAINER_IP"]] = 0) do={ /container/envs/add list="sb-gateway-env" key="SB_CONTAINER_IP" value=$"SB_CONTAINER_IP" comment="SB-GATEWAY runtime env" }
:if ([:len [/container/envs/find where list="sb-gateway-env" and key="SB_TUN_ADDRESS"]] = 0) do={ /container/envs/add list="sb-gateway-env" key="SB_TUN_ADDRESS" value=$"SB_TUN_ADDRESS" comment="SB-GATEWAY runtime env" }
:if ([:len [/container/envs/find where list="sb-gateway-env" and key="SB_WS_HOST"]] = 0) do={ /container/envs/add list="sb-gateway-env" key="SB_WS_HOST" value=$"SB_WS_HOST" comment="SB-GATEWAY runtime env" }
:if ([:len [/container/envs/find where list="sb-gateway-env" and key="SB_GRPC_HOST"]] = 0) do={ /container/envs/add list="sb-gateway-env" key="SB_GRPC_HOST" value=$"SB_GRPC_HOST" comment="SB-GATEWAY runtime env" }
:if ([:len [/container/envs/find where list="sb-gateway-env" and key="SB_STATUS_HOST"]] = 0) do={ /container/envs/add list="sb-gateway-env" key="SB_STATUS_HOST" value=$"SB_STATUS_HOST" comment="SB-GATEWAY runtime env" }
:if ([:len [/container/envs/find where list="sb-gateway-env" and key="SB_HU_HOST"]] = 0) do={ /container/envs/add list="sb-gateway-env" key="SB_HU_HOST" value=$"SB_HU_HOST" comment="SB-GATEWAY runtime env" }
:if ([:len [/container/envs/find where list="sb-gateway-env" and key="SB_HTTPUPGRADE_ENABLED"]] = 0) do={ /container/envs/add list="sb-gateway-env" key="SB_HTTPUPGRADE_ENABLED" value=$"SB_HTTPUPGRADE_ENABLED" comment="SB-GATEWAY runtime env" }

:local containerId [/container/find where comment="SB-GATEWAY container"]
:local containerCreated false
:if ([:len $containerId] = 0) do={
  :onerror sbContainerError in={
    :if ($"SB_IMAGE_SOURCE" = "file") do={
      /container/add file=$"SB_IMAGE_FILE" interface=$"SB_VETH" root-dir=$"SB_ROOT_DIR" mountlists="sb-gateway-config,sb-gateway-data,sb-gateway-logs,sb-gateway-state" envlist="sb-gateway-env" dns=$"SB_ROUTER_IP" memory-high=$containerMemoryHigh memory-max=$containerMemoryMax start-on-boot=yes logging=yes comment="SB-GATEWAY container"
    } else={
      /container/add remote-image=$"SB_IMAGE" interface=$"SB_VETH" root-dir=$"SB_ROOT_DIR" mountlists="sb-gateway-config,sb-gateway-data,sb-gateway-logs,sb-gateway-state" envlist="sb-gateway-env" dns=$"SB_ROUTER_IP" memory-high=$containerMemoryHigh memory-max=$containerMemoryMax start-on-boot=yes logging=yes comment="SB-GATEWAY container"
    }
  } do={
    :log error ("SB-GATEWAY: container add/capability check failed; diversion remains disabled: " . $sbContainerError)
    :error ("SB-GATEWAY: container creation failed: " . $sbContainerError)
  }
  :set containerId [/container/find where comment="SB-GATEWAY container"]
  :if ([:len $containerId] != 1) do={ :error "SB-GATEWAY: newly added container is missing or ambiguous" }
  :set containerCreated true
} else={
  :if ([:len $containerId] != 1) do={ :error "SB-GATEWAY: project container is ambiguous" }
}

# Apply lifecycle limits to both a freshly added container and an existing
# project-owned container. A fresh install must never retain RouterOS defaults
# restart-policy=no/restart-interval=0s.
/container/set $containerId memory-high=$containerMemoryHigh memory-max=$containerMemoryMax start-on-boot=yes logging=yes
:do { /container/set $containerId restart-policy=always restart-interval=10s } on-error={ /container/set $containerId auto-restart-interval=10s }

:local imageReady false
:local imageWaitAttempt 0
:local containerStopped false
:local legacyContainerStatus "unknown"
:if ($containerCreated = false) do={ :set imageReady true }
:while (($imageReady = false) && ($imageWaitAttempt < 360)) do={
  :local stoppedKnown false
  :local runningKnown false
  :local containerRunning false
  :local imageOsProbe ""
  :local imageArchProbe ""
  :do {
    :set containerStopped [/container/get $containerId stopped]
    :set stoppedKnown true
  } on-error={
    :do { :set containerRunning [/container/get $containerId running]; :set runningKnown true } on-error={
      :do { :set legacyContainerStatus [/container/get $containerId status] } on-error={ :set legacyContainerStatus "unknown" }
    }
  }
  :do { :set imageOsProbe [/container/get $containerId os]; :set imageArchProbe [/container/get $containerId arch] } on-error={}
  :if ((($stoppedKnown = true) || (($runningKnown = true) && ($containerRunning = true))) && ([:len $imageOsProbe] > 0) && ([:len $imageArchProbe] > 0)) do={
    :set imageReady true
  } else={
    :if (($stoppedKnown = false) && (($legacyContainerStatus = "stopped") || ($legacyContainerStatus = "running"))) do={ :set imageReady true }
    :if (($stoppedKnown = false) && ($legacyContainerStatus = "error")) do={
      :log error "SB-GATEWAY: container image download/extraction failed; diversion remains disabled and existing Internet is unchanged"
      :error "SB-GATEWAY: container image preparation failed"
    }
    :if ($imageReady = false) do={
      :set imageWaitAttempt ($imageWaitAttempt + 1)
      :delay 5s
    }
  }
}
:if ($imageReady = false) do={
  :log error "SB-GATEWAY: container image was not ready after 30 minutes; diversion remains disabled and existing Internet is unchanged"
  :error "SB-GATEWAY: timed out waiting for container image extraction"
}
:local imageOs ""
:local imageArch ""
:do {
  :set imageOs [/container/get $containerId os]
  :set imageArch [/container/get $containerId arch]
} on-error={
  :log error "SB-GATEWAY: unable to inspect extracted container platform; diversion remains disabled and existing Internet is unchanged"
  :error "SB-GATEWAY: container platform inspection failed"
}
:if (($imageOs != "linux") || ($imageArch != "arm64")) do={
  :log error ("SB-GATEWAY: refusing container platform " . $imageOs . "/" . $imageArch . "; expected linux/arm64; diversion remains disabled")
  :error "SB-GATEWAY: wrong container platform"
}

:if ([:len [/ip/firewall/mangle/find where comment="SB-GATEWAY diversion-gate"]] = 0) do={
  /ip/firewall/mangle/add chain=prerouting action=jump jump-target="sb-gateway-divert" src-address-list="SB_MANAGED_CLIENTS" dst-address-list="!SB_INTERNAL_NETWORKS" dst-address-type=!local disabled=yes comment="SB-GATEWAY diversion-gate"
}
:local diversionGate [/ip/firewall/mangle/find where comment="SB-GATEWAY diversion-gate"]
:if ([:len $diversionGate] != 1) do={ :error "SB-GATEWAY: diversion gate is missing or ambiguous" }
/ip/firewall/mangle/unset $diversionGate in-interface-list
/ip/firewall/mangle/set $diversionGate chain=prerouting action=jump jump-target="sb-gateway-divert" src-address-list="SB_MANAGED_CLIENTS" dst-address-list="!SB_INTERNAL_NETWORKS" dst-address-type=!local disabled=yes
:if ([:len [/ip/firewall/mangle/find where comment="SB-GATEWAY endpoint bypass"]] = 0) do={
  /ip/firewall/mangle/add chain="sb-gateway-divert" action=return dst-address-list="SB_BYPASS_ENDPOINTS" comment="SB-GATEWAY endpoint bypass"
}
:if ([:len [/ip/firewall/mangle/find where comment="SB-GATEWAY mark connection"]] = 0) do={
  /ip/firewall/mangle/add chain="sb-gateway-divert" action=mark-connection connection-state=new connection-mark=no-mark new-connection-mark="sb-managed" passthrough=yes comment="SB-GATEWAY mark connection"
}
:if ([:len [/ip/firewall/mangle/find where comment="SB-GATEWAY mark routing"]] = 0) do={
  /ip/firewall/mangle/add chain="sb-gateway-divert" action=mark-routing connection-mark="sb-managed" new-routing-mark=$"SB_ROUTING_TABLE" passthrough=no comment="SB-GATEWAY mark routing"
}
:local endpointBypass [/ip/firewall/mangle/find where comment="SB-GATEWAY endpoint bypass"]
:local markConnection [/ip/firewall/mangle/find where comment="SB-GATEWAY mark connection"]
:local markRouting [/ip/firewall/mangle/find where comment="SB-GATEWAY mark routing"]
:if (([:len $endpointBypass] != 1) || ([:len $markConnection] != 1) || ([:len $markRouting] != 1)) do={ :error "SB-GATEWAY: diversion rules are missing or ambiguous" }
/ip/firewall/mangle/set $endpointBypass chain="sb-gateway-divert" action=return dst-address-list="SB_BYPASS_ENDPOINTS" disabled=no
/ip/firewall/mangle/set $markConnection chain="sb-gateway-divert" action=mark-connection connection-state=new connection-mark=no-mark new-connection-mark="sb-managed" passthrough=yes disabled=no
/ip/firewall/mangle/set $markRouting chain="sb-gateway-divert" action=mark-routing connection-mark="sb-managed" new-routing-mark=$"SB_ROUTING_TABLE" passthrough=no disabled=no
:local firstMangleRules [/ip/firewall/mangle/find]
:if (([:len $firstMangleRules] > 0) && ([:pick $firstMangleRules 0 1] != $diversionGate)) do={ /ip/firewall/mangle/move $diversionGate destination=[:pick $firstMangleRules 0 1] }
/ip/firewall/mangle/move $markConnection destination=$markRouting
/ip/firewall/mangle/move $endpointBypass destination=$markConnection

:if ([:len [/ip/firewall/nat/find where comment="SB-GATEWAY container WAN masquerade"]] = 0) do={
  /ip/firewall/nat/add chain=srcnat action=masquerade src-address=$"SB_CONTAINER_NETWORK" out-interface-list=WAN comment="SB-GATEWAY container WAN masquerade"
}
:if ([:len [/ip/firewall/nat/find where comment="SB-GATEWAY container LAN masquerade"]] = 0) do={
  /ip/firewall/nat/add chain=srcnat action=masquerade src-address=$"SB_CONTAINER_NETWORK" dst-address-list="SB_CONTAINER_ALLOWED_INTERNAL" comment="SB-GATEWAY container LAN masquerade"
}
:if ([:len [/ip/firewall/nat/find where comment="SB-GATEWAY WireGuard panel dstnat"]] = 0) do={
  /ip/firewall/nat/add chain=dstnat action=dst-nat in-interface-list="SB_WIREGUARD_INGRESS" dst-address-type=local protocol=tcp dst-port=9443 to-addresses=$"SB_CONTAINER_IP" to-ports=9443 comment="SB-GATEWAY WireGuard panel dstnat"
}
:local containerMasquerade [/ip/firewall/nat/find where comment="SB-GATEWAY container WAN masquerade"]
:local containerLanMasquerade [/ip/firewall/nat/find where comment="SB-GATEWAY container LAN masquerade"]
:local wireguardPanelDstnat [/ip/firewall/nat/find where comment="SB-GATEWAY WireGuard panel dstnat"]
:if (([:len $containerMasquerade] != 1) || ([:len $containerLanMasquerade] != 1) || ([:len $wireguardPanelDstnat] != 1)) do={ :error "SB-GATEWAY: NAT rules are missing or ambiguous" }
/ip/firewall/nat/set $containerMasquerade chain=srcnat action=masquerade src-address=$"SB_CONTAINER_NETWORK" out-interface-list=WAN disabled=no
/ip/firewall/nat/set $containerLanMasquerade chain=srcnat action=masquerade src-address=$"SB_CONTAINER_NETWORK" dst-address-list="SB_CONTAINER_ALLOWED_INTERNAL" disabled=no
/ip/firewall/nat/set $wireguardPanelDstnat chain=dstnat action=dst-nat in-interface-list="SB_WIREGUARD_INGRESS" dst-address-type=local protocol=tcp dst-port=9443 to-addresses=$"SB_CONTAINER_IP" to-ports=9443 disabled=no
:local firstNatRules [/ip/firewall/nat/find]
:if (([:len $firstNatRules] > 0) && ([:pick $firstNatRules 0 1] != $wireguardPanelDstnat)) do={ /ip/firewall/nat/move $wireguardPanelDstnat destination=[:pick $firstNatRules 0 1] }

# A single scoped jump is placed before existing user rules. Its custom chain
# returns unmatched packets, preserving the user's firewall and VPN policy.
:if ([:len [/ip/firewall/filter/find where comment="SB-GATEWAY forward policy jump"]] = 0) do={
  :local firstForward [/ip/firewall/filter/find where chain=forward]
  :if ([:len $firstForward] > 0) do={
    /ip/firewall/filter/add chain=forward action=jump jump-target="sb-gateway-forward" place-before=[:pick $firstForward 0 1] comment="SB-GATEWAY forward policy jump"
  } else={
    /ip/firewall/filter/add chain=forward action=jump jump-target="sb-gateway-forward" comment="SB-GATEWAY forward policy jump"
  }
}
:if ([:len [/ip/firewall/filter/find where comment="SB-GATEWAY WireGuard panel allow"]] = 0) do={ /ip/firewall/filter/add chain="sb-gateway-forward" action=accept in-interface-list="SB_WIREGUARD_INGRESS" dst-address=$"SB_CONTAINER_IP" protocol=tcp dst-port=9443 comment="SB-GATEWAY WireGuard panel allow" }
:if ([:len [/ip/firewall/filter/find where comment="SB-GATEWAY management allow"]] = 0) do={ /ip/firewall/filter/add chain="sb-gateway-forward" action=accept in-interface-list="SB_MANAGEMENT_INGRESS" src-address-list="SB_MANAGEMENT_SOURCES" dst-address=$"SB_CONTAINER_IP" protocol=tcp dst-port=9443 comment="SB-GATEWAY management allow" }
:if ([:len [/ip/firewall/filter/find where comment="SB-GATEWAY management deny"]] = 0) do={ /ip/firewall/filter/add chain="sb-gateway-forward" action=drop dst-address=$"SB_CONTAINER_IP" protocol=tcp dst-port=9443 comment="SB-GATEWAY management deny" }
:if ([:len [/ip/firewall/filter/find where comment="SB-GATEWAY managed to container"]] = 0) do={ /ip/firewall/filter/add chain="sb-gateway-forward" action=accept src-address-list="SB_MANAGED_CLIENTS" out-interface=$"SB_BRIDGE" comment="SB-GATEWAY managed to container" }
:if ([:len [/ip/firewall/filter/find where comment="SB-GATEWAY container return to managed"]] = 0) do={ /ip/firewall/filter/add chain="sb-gateway-forward" action=accept in-interface=$"SB_BRIDGE" dst-address-list="SB_MANAGED_CLIENTS" connection-state=established,related comment="SB-GATEWAY container return to managed" }
:if ([:len [/ip/firewall/filter/find where comment="SB-GATEWAY container return to management"]] = 0) do={ /ip/firewall/filter/add chain="sb-gateway-forward" action=accept in-interface=$"SB_BRIDGE" dst-address-list="SB_MANAGEMENT_SOURCES" connection-state=established,related comment="SB-GATEWAY container return to management" }
:if ([:len [/ip/firewall/filter/find where comment="SB-GATEWAY WireGuard panel return"]] = 0) do={ /ip/firewall/filter/add chain="sb-gateway-forward" action=accept in-interface=$"SB_BRIDGE" out-interface-list="SB_WIREGUARD_INGRESS" src-address=$"SB_CONTAINER_IP" protocol=tcp src-port=9443 connection-state=established,related connection-nat-state=dstnat comment="SB-GATEWAY WireGuard panel return" }
:if ([:len [/ip/firewall/filter/find where comment="SB-GATEWAY container explicit LAN allow"]] = 0) do={ /ip/firewall/filter/add chain="sb-gateway-forward" action=accept in-interface=$"SB_BRIDGE" dst-address-list="SB_CONTAINER_ALLOWED_INTERNAL" comment="SB-GATEWAY container explicit LAN allow" }
:if ([:len [/ip/firewall/filter/find where comment="SB-GATEWAY container LAN deny"]] = 0) do={ /ip/firewall/filter/add chain="sb-gateway-forward" action=drop in-interface=$"SB_BRIDGE" dst-address-list="SB_INTERNAL_NETWORKS" comment="SB-GATEWAY container LAN deny" }
:if ([:len [/ip/firewall/filter/find where comment="SB-GATEWAY container WAN allow"]] = 0) do={ /ip/firewall/filter/add chain="sb-gateway-forward" action=accept in-interface=$"SB_BRIDGE" out-interface-list=WAN comment="SB-GATEWAY container WAN allow" }
:if ([:len [/ip/firewall/filter/find where comment="SB-GATEWAY fail-closed public drop"]] = 0) do={ /ip/firewall/filter/add chain="sb-gateway-forward" action=drop src-address-list="SB_FAIL_CLOSED_CLIENTS" dst-address-list="!SB_INTERNAL_NETWORKS" comment="SB-GATEWAY fail-closed public drop" }
:if ([:len [/ip/firewall/filter/find where comment="SB-GATEWAY forward policy return"]] = 0) do={ /ip/firewall/filter/add chain="sb-gateway-forward" action=return comment="SB-GATEWAY forward policy return" }
:local forwardJump [/ip/firewall/filter/find where comment="SB-GATEWAY forward policy jump"]
:local wireguardPanelAllow [/ip/firewall/filter/find where comment="SB-GATEWAY WireGuard panel allow"]
:local managementAllow [/ip/firewall/filter/find where comment="SB-GATEWAY management allow"]
:local managementDeny [/ip/firewall/filter/find where comment="SB-GATEWAY management deny"]
:local managedToContainer [/ip/firewall/filter/find where comment="SB-GATEWAY managed to container"]
:local containerReturn [/ip/firewall/filter/find where comment="SB-GATEWAY container return to managed"]
:local containerManagementReturn [/ip/firewall/filter/find where comment="SB-GATEWAY container return to management"]
:local wireguardPanelReturn [/ip/firewall/filter/find where comment="SB-GATEWAY WireGuard panel return"]
:local explicitLanAllow [/ip/firewall/filter/find where comment="SB-GATEWAY container explicit LAN allow"]
:local containerLanDeny [/ip/firewall/filter/find where comment="SB-GATEWAY container LAN deny"]
:local containerWanAllow [/ip/firewall/filter/find where comment="SB-GATEWAY container WAN allow"]
:local failClosedDrop [/ip/firewall/filter/find where comment="SB-GATEWAY fail-closed public drop"]
:local forwardReturn [/ip/firewall/filter/find where comment="SB-GATEWAY forward policy return"]
:if (([:len $forwardJump] != 1) || ([:len $wireguardPanelAllow] != 1) || ([:len $managementAllow] != 1) || ([:len $managementDeny] != 1) || ([:len $managedToContainer] != 1) || ([:len $containerReturn] != 1) || ([:len $containerManagementReturn] != 1) || ([:len $wireguardPanelReturn] != 1) || ([:len $explicitLanAllow] != 1) || ([:len $containerLanDeny] != 1) || ([:len $containerWanAllow] != 1) || ([:len $failClosedDrop] != 1) || ([:len $forwardReturn] != 1)) do={ :error "SB-GATEWAY: forward filter rules are missing or ambiguous" }
/ip/firewall/filter/set $forwardJump chain=forward action=jump jump-target="sb-gateway-forward" disabled=no
/ip/firewall/filter/set $wireguardPanelAllow chain="sb-gateway-forward" action=accept in-interface-list="SB_WIREGUARD_INGRESS" dst-address=$"SB_CONTAINER_IP" protocol=tcp dst-port=9443 disabled=no
/ip/firewall/filter/set $managementAllow chain="sb-gateway-forward" action=accept in-interface-list="SB_MANAGEMENT_INGRESS" src-address-list="SB_MANAGEMENT_SOURCES" dst-address=$"SB_CONTAINER_IP" protocol=tcp dst-port=9443 disabled=no
/ip/firewall/filter/set $managementDeny chain="sb-gateway-forward" action=drop dst-address=$"SB_CONTAINER_IP" protocol=tcp dst-port=9443 disabled=no
/ip/firewall/filter/unset $managedToContainer in-interface-list
/ip/firewall/filter/set $managedToContainer chain="sb-gateway-forward" action=accept src-address-list="SB_MANAGED_CLIENTS" out-interface=$"SB_BRIDGE" disabled=no
/ip/firewall/filter/set $containerReturn chain="sb-gateway-forward" action=accept in-interface=$"SB_BRIDGE" dst-address-list="SB_MANAGED_CLIENTS" connection-state=established,related disabled=no
/ip/firewall/filter/set $containerManagementReturn chain="sb-gateway-forward" action=accept in-interface=$"SB_BRIDGE" dst-address-list="SB_MANAGEMENT_SOURCES" connection-state=established,related disabled=no
/ip/firewall/filter/set $wireguardPanelReturn chain="sb-gateway-forward" action=accept in-interface=$"SB_BRIDGE" out-interface-list="SB_WIREGUARD_INGRESS" src-address=$"SB_CONTAINER_IP" protocol=tcp src-port=9443 connection-state=established,related connection-nat-state=dstnat disabled=no
/ip/firewall/filter/set $explicitLanAllow chain="sb-gateway-forward" action=accept in-interface=$"SB_BRIDGE" dst-address-list="SB_CONTAINER_ALLOWED_INTERNAL" disabled=no
/ip/firewall/filter/set $containerLanDeny chain="sb-gateway-forward" action=drop in-interface=$"SB_BRIDGE" dst-address-list="SB_INTERNAL_NETWORKS" disabled=no
/ip/firewall/filter/set $containerWanAllow chain="sb-gateway-forward" action=accept in-interface=$"SB_BRIDGE" out-interface-list=WAN disabled=no
/ip/firewall/filter/set $failClosedDrop chain="sb-gateway-forward" action=drop src-address-list="SB_FAIL_CLOSED_CLIENTS" dst-address-list="!SB_INTERNAL_NETWORKS" disabled=no
/ip/firewall/filter/set $forwardReturn chain="sb-gateway-forward" action=return disabled=no
:local firstFilterRules [/ip/firewall/filter/find]
:if (([:len $firstFilterRules] > 0) && ([:pick $firstFilterRules 0 1] != $forwardJump)) do={ /ip/firewall/filter/move $forwardJump destination=[:pick $firstFilterRules 0 1] }
/ip/firewall/filter/move $containerWanAllow destination=$forwardReturn
/ip/firewall/filter/move $failClosedDrop destination=$forwardReturn
/ip/firewall/filter/move $containerLanDeny destination=$containerWanAllow
/ip/firewall/filter/move $explicitLanAllow destination=$containerLanDeny
/ip/firewall/filter/move $containerManagementReturn destination=$explicitLanAllow
/ip/firewall/filter/move $wireguardPanelReturn destination=$explicitLanAllow
/ip/firewall/filter/move $containerReturn destination=$containerManagementReturn
/ip/firewall/filter/move $managedToContainer destination=$containerReturn
/ip/firewall/filter/move $managementDeny destination=$managedToContainer
/ip/firewall/filter/move $managementAllow destination=$managementDeny
/ip/firewall/filter/move $wireguardPanelAllow destination=$managementAllow

:if ([:len [/ip/firewall/filter/find where comment="SB-GATEWAY input policy jump"]] = 0) do={
  :local firstInput [/ip/firewall/filter/find where chain=input]
  :if ([:len $firstInput] > 0) do={
    /ip/firewall/filter/add chain=input action=jump jump-target="sb-gateway-input" place-before=[:pick $firstInput 0 1] comment="SB-GATEWAY input policy jump"
  } else={
    /ip/firewall/filter/add chain=input action=jump jump-target="sb-gateway-input" comment="SB-GATEWAY input policy jump"
  }
}
:local sshService [/ip/service/find where name="ssh" and dynamic=no]
:local winboxService [/ip/service/find where name="winbox" and dynamic=no]
:if (([:len $sshService] != 1) || ([:len $winboxService] != 1)) do={ :error "SB-GATEWAY: RouterOS SSH or Winbox service is missing or ambiguous; services were not changed" }
:local remoteManagementPorts (([/ip/service/get $sshService port]) . "," . $"SB_ROUTEROS_REST_PORT" . "," . ([/ip/service/get $winboxService port]))
:foreach obsoleteComment in={"SB-GATEWAY RouterOS www-ssl management allow";"SB-GATEWAY RouterOS www-ssl deny"} do={ :local obsoleteRules [/ip/firewall/filter/find where comment=$obsoleteComment]; :if ([:len $obsoleteRules] > 1) do={ :error ("SB-GATEWAY obsolete management rule is ambiguous: " . $obsoleteComment) }; :if ([:len $obsoleteRules] = 1) do={ /ip/firewall/filter/remove $obsoleteRules } }
:if ([:len [/ip/firewall/filter/find where comment="SB-GATEWAY RouterOS REST allow"]] = 0) do={ /ip/firewall/filter/add chain="sb-gateway-input" action=accept in-interface=$"SB_BRIDGE" src-address=$"SB_CONTAINER_IP" dst-address=$"SB_ROUTER_IP" protocol=tcp dst-port=$"SB_ROUTEROS_REST_PORT" comment="SB-GATEWAY RouterOS REST allow" }
:if ([:len [/ip/firewall/filter/find where comment="SB-GATEWAY RouterOS remote full management allow"]] = 0) do={ /ip/firewall/filter/add chain="sb-gateway-input" action=accept in-interface=$"SB_BRIDGE" src-address=$"SB_CONTAINER_IP" protocol=tcp dst-port=$remoteManagementPorts comment="SB-GATEWAY RouterOS remote full management allow" }
:if ([:len [/ip/firewall/filter/find where comment="SB-GATEWAY RouterOS DNS UDP allow"]] = 0) do={ /ip/firewall/filter/add chain="sb-gateway-input" action=accept in-interface=$"SB_BRIDGE" src-address=$"SB_CONTAINER_IP" dst-address=$"SB_ROUTER_IP" protocol=udp dst-port=53 comment="SB-GATEWAY RouterOS DNS UDP allow" }
:if ([:len [/ip/firewall/filter/find where comment="SB-GATEWAY RouterOS DNS TCP allow"]] = 0) do={ /ip/firewall/filter/add chain="sb-gateway-input" action=accept in-interface=$"SB_BRIDGE" src-address=$"SB_CONTAINER_IP" dst-address=$"SB_ROUTER_IP" protocol=tcp dst-port=53 comment="SB-GATEWAY RouterOS DNS TCP allow" }
:if ([:len [/ip/firewall/filter/find where comment="SB-GATEWAY RouterOS ICMP allow"]] = 0) do={ /ip/firewall/filter/add chain="sb-gateway-input" action=accept in-interface=$"SB_BRIDGE" src-address=$"SB_CONTAINER_IP" dst-address=$"SB_ROUTER_IP" protocol=icmp comment="SB-GATEWAY RouterOS ICMP allow" }
:if ([:len [/ip/firewall/filter/find where comment="SB-GATEWAY container established input"]] = 0) do={ /ip/firewall/filter/add chain="sb-gateway-input" action=accept in-interface=$"SB_BRIDGE" src-address=$"SB_CONTAINER_IP" connection-state=established,related comment="SB-GATEWAY container established input" }
:if ([:len [/ip/firewall/filter/find where comment="SB-GATEWAY RouterOS management deny"]] = 0) do={ /ip/firewall/filter/add chain="sb-gateway-input" action=drop src-address=$"SB_CONTAINER_IP" comment="SB-GATEWAY RouterOS management deny" }
:if ([:len [/ip/firewall/filter/find where comment="SB-GATEWAY input policy return"]] = 0) do={ /ip/firewall/filter/add chain="sb-gateway-input" action=return comment="SB-GATEWAY input policy return" }
:local inputJump [/ip/firewall/filter/find where comment="SB-GATEWAY input policy jump"]
:local restAllow [/ip/firewall/filter/find where comment="SB-GATEWAY RouterOS REST allow"]
:local remoteFullManagementAllow [/ip/firewall/filter/find where comment="SB-GATEWAY RouterOS remote full management allow"]
:local dnsUdpAllow [/ip/firewall/filter/find where comment="SB-GATEWAY RouterOS DNS UDP allow"]
:local dnsTcpAllow [/ip/firewall/filter/find where comment="SB-GATEWAY RouterOS DNS TCP allow"]
:local icmpAllow [/ip/firewall/filter/find where comment="SB-GATEWAY RouterOS ICMP allow"]
:local containerEstablishedInput [/ip/firewall/filter/find where comment="SB-GATEWAY container established input"]
:local routerManagementDeny [/ip/firewall/filter/find where comment="SB-GATEWAY RouterOS management deny"]
:local inputReturn [/ip/firewall/filter/find where comment="SB-GATEWAY input policy return"]
:if (([:len $inputJump] != 1) || ([:len $restAllow] != 1) || ([:len $remoteFullManagementAllow] != 1) || ([:len $dnsUdpAllow] != 1) || ([:len $dnsTcpAllow] != 1) || ([:len $icmpAllow] != 1) || ([:len $containerEstablishedInput] != 1) || ([:len $routerManagementDeny] != 1) || ([:len $inputReturn] != 1)) do={ :error "SB-GATEWAY: RouterOS input rules are missing or ambiguous" }
/ip/firewall/filter/set $inputJump chain=input action=jump jump-target="sb-gateway-input" disabled=no
/ip/firewall/filter/set $restAllow chain="sb-gateway-input" action=accept in-interface=$"SB_BRIDGE" src-address=$"SB_CONTAINER_IP" dst-address=$"SB_ROUTER_IP" protocol=tcp dst-port=$"SB_ROUTEROS_REST_PORT" disabled=no
/ip/firewall/filter/set $remoteFullManagementAllow chain="sb-gateway-input" action=accept in-interface=$"SB_BRIDGE" src-address=$"SB_CONTAINER_IP" protocol=tcp dst-port=$remoteManagementPorts disabled=no
/ip/firewall/filter/set $dnsUdpAllow chain="sb-gateway-input" action=accept in-interface=$"SB_BRIDGE" src-address=$"SB_CONTAINER_IP" dst-address=$"SB_ROUTER_IP" protocol=udp dst-port=53 disabled=no
/ip/firewall/filter/set $dnsTcpAllow chain="sb-gateway-input" action=accept in-interface=$"SB_BRIDGE" src-address=$"SB_CONTAINER_IP" dst-address=$"SB_ROUTER_IP" protocol=tcp dst-port=53 disabled=no
/ip/firewall/filter/set $icmpAllow chain="sb-gateway-input" action=accept in-interface=$"SB_BRIDGE" src-address=$"SB_CONTAINER_IP" dst-address=$"SB_ROUTER_IP" protocol=icmp disabled=no
/ip/firewall/filter/set $containerEstablishedInput chain="sb-gateway-input" action=accept in-interface=$"SB_BRIDGE" src-address=$"SB_CONTAINER_IP" connection-state=established,related disabled=no
/ip/firewall/filter/set $routerManagementDeny chain="sb-gateway-input" action=drop src-address=$"SB_CONTAINER_IP" disabled=no
/ip/firewall/filter/set $inputReturn chain="sb-gateway-input" action=return disabled=no
:set firstFilterRules [/ip/firewall/filter/find]
:if (([:len $firstFilterRules] > 0) && ([:pick $firstFilterRules 0 1] != $inputJump)) do={ /ip/firewall/filter/move $inputJump destination=[:pick $firstFilterRules 0 1] }
/ip/firewall/filter/move $routerManagementDeny destination=$inputReturn
/ip/firewall/filter/move $containerEstablishedInput destination=$routerManagementDeny
/ip/firewall/filter/move $icmpAllow destination=$containerEstablishedInput
/ip/firewall/filter/move $dnsTcpAllow destination=$icmpAllow
/ip/firewall/filter/move $dnsUdpAllow destination=$dnsTcpAllow
/ip/firewall/filter/move $remoteFullManagementAllow destination=$dnsUdpAllow
/ip/firewall/filter/move $restAllow destination=$remoteFullManagementAllow

:if ($"SB_IPV6_MODE" = "block_managed") do={
  :foreach sbManagedCidrV6 in=$"SB_MANAGED_CLIENTS_V6" do={
    :local sbManagedTextV6 [:tostr $sbManagedCidrV6]
    :local sbManagedLookupV6 $sbManagedTextV6
    :local sbManagedHostSuffixV6 [:find $sbManagedTextV6 "/128"]
    :if (($sbManagedHostSuffixV6 != nil) && ([:pick $sbManagedTextV6 $sbManagedHostSuffixV6 [:len $sbManagedTextV6]] = "/128")) do={ :set sbManagedLookupV6 [:pick $sbManagedTextV6 0 $sbManagedHostSuffixV6] }
    :if ([:len [/ipv6/firewall/address-list/find where list="SB_MANAGED_CLIENTS_V6" and address=$sbManagedLookupV6]] = 0) do={ /ipv6/firewall/address-list/add list="SB_MANAGED_CLIENTS_V6" address=$sbManagedTextV6 comment="SB-GATEWAY managed IPv6 client" }
  }
  :foreach sbInternalCidrV6 in=$"SB_INTERNAL_NETWORKS_V6" do={
    :local sbInternalTextV6 [:tostr $sbInternalCidrV6]
    :local sbInternalLookupV6 $sbInternalTextV6
    :local sbInternalHostSuffixV6 [:find $sbInternalTextV6 "/128"]
    :if (($sbInternalHostSuffixV6 != nil) && ([:pick $sbInternalTextV6 $sbInternalHostSuffixV6 [:len $sbInternalTextV6]] = "/128")) do={ :set sbInternalLookupV6 [:pick $sbInternalTextV6 0 $sbInternalHostSuffixV6] }
    :if ([:len [/ipv6/firewall/address-list/find where list="SB_INTERNAL_NETWORKS_V6" and address=$sbInternalLookupV6]] = 0) do={ /ipv6/firewall/address-list/add list="SB_INTERNAL_NETWORKS_V6" address=$sbInternalTextV6 comment="SB-GATEWAY internal IPv6 network" }
  }
  :if ([:len [/ipv6/firewall/filter/find where comment="SB-GATEWAY managed IPv6 WAN block"]] = 0) do={ /ipv6/firewall/filter/add chain=forward action=drop src-address-list="SB_MANAGED_CLIENTS_V6" dst-address-list="!SB_INTERNAL_NETWORKS_V6" out-interface-list=WAN comment="SB-GATEWAY managed IPv6 WAN block" }
  :local managedIpv6Block [/ipv6/firewall/filter/find where comment="SB-GATEWAY managed IPv6 WAN block"]
  :if ([:len $managedIpv6Block] != 1) do={ :error "SB-GATEWAY: managed IPv6 WAN block is missing or ambiguous" }
  /ipv6/firewall/filter/set $managedIpv6Block chain=forward action=drop src-address-list="SB_MANAGED_CLIENTS_V6" dst-address-list="!SB_INTERNAL_NETWORKS_V6" out-interface-list=WAN disabled=no
  :local firstIpv6FilterRules [/ipv6/firewall/filter/find]
  :if (([:len $firstIpv6FilterRules] > 0) && ([:pick $firstIpv6FilterRules 0 1] != $managedIpv6Block)) do={ /ipv6/firewall/filter/move $managedIpv6Block destination=[:pick $firstIpv6FilterRules 0 1] }
}

:local shouldStart true
:do {
  :local containerRunningNow [/container/get $containerId running]
  :if ($containerRunningNow = true) do={ :set shouldStart false }
} on-error={
  :do {
    :set shouldStart [/container/get $containerId stopped]
  } on-error={
    :do {
      :set legacyContainerStatus [/container/get $containerId status]
      :set shouldStart ($legacyContainerStatus != "running")
    } on-error={ :set shouldStart true }
  }
}
:if ($shouldStart = true) do={ /container/start $containerId }
/ip/firewall/mangle/disable [find where comment="SB-GATEWAY diversion-gate"]
/ip/firewall/connection/remove [find where connection-mark="sb-managed"]
:log warning "SB-GATEWAY: install complete in fail-open state; install the watchdog, then finish the first-launch wizard"
