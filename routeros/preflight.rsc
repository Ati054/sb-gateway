# SB-GATEWAY read-mostly capability preflight. It does not change update channel,
# stop an existing container, or alter existing routes/firewall.

:global "SB_IMAGE"
:global "SB_IMAGE_SOURCE"
:global "SB_IMAGE_FILE"
:global "SB_BRIDGE"
:global "SB_VETH"
:global "SB_ROUTING_TABLE"
:global "SB_STORAGE_ROOT"
:global "SB_MANAGED_CLIENTS"
:global "SB_MANAGEMENT_INGRESS_INTERFACES"
:global "SB_ROUTEROS_REST_PORT"
:global "SB_IPV6_MODE"
:global "SB_MANAGED_CLIENTS_V6"
:global "SB_ADDRESSES_CONFIRMED"

:local version [/system/resource/get version]
:local architecture [/system/resource/get architecture-name]
:if ([:pick $version 0 2] != "7.") do={ :error ("SB-GATEWAY requires RouterOS major 7; detected " . $version) }
:if ($architecture != "arm64") do={ :error ("SB-GATEWAY requires ARM64; detected " . $architecture) }

:local channel "unknown"
:do { :set channel [/system/package/update/get channel] } on-error={ :log warning "SB-GATEWAY: unable to read update channel; no channel change will be made" }
:log info ("SB-GATEWAY: RouterOS " . $version . ", channel=" . $channel . ", architecture=" . $architecture)
:if (($channel != "stable") && ($channel != "long-term")) do={
  :log warning ("SB-GATEWAY: channel " . $channel . " is accepted but is lower-trust metadata; it will not be changed automatically")
}

:if ([:len [/system/package/find where name="container"]] = 0) do={ :error "SB-GATEWAY: container package is not installed" }
:local containerMode ""
:do { :set containerMode [/system/device-mode/get container] } on-error={ :error "SB-GATEWAY: RouterOS does not expose device-mode container capability" }
:if (($containerMode != true) && ($containerMode != "yes")) do={ :error "SB-GATEWAY: container device-mode is disabled; enable it physically before applying" }

:if (([:len $"SB_STORAGE_ROOT"] = 0) || ([:find $"SB_STORAGE_ROOT" "flash"] = 0)) do={ :error "SB-GATEWAY: storage root must be an external disk, not internal flash" }
:if (($"SB_IMAGE_SOURCE" != "file") && ($"SB_IMAGE_SOURCE" != "registry")) do={ :error "SB-GATEWAY: SB_IMAGE_SOURCE must be file or registry" }
:local projectContainers [/container/find where comment="SB-GATEWAY container"]
:if ([:len $projectContainers] > 1) do={ :error "SB-GATEWAY: project container is ambiguous" }
:if ([:len $projectContainers] = 0) do={
  :if ($"SB_IMAGE_SOURCE" = "file") do={
    :if ([:len $"SB_IMAGE_FILE"] = 0) do={ :error "SB-GATEWAY: set SB_IMAGE_FILE to the verified ARM64 Docker archive uploaded through WebFig Files" }
    :if ([:find $"SB_IMAGE_FILE" ($"SB_STORAGE_ROOT" . "/")] != 0) do={ :error "SB-GATEWAY: local image archive must be stored below SB_STORAGE_ROOT on the external disk" }
    :local localImage [/file/find where name=$"SB_IMAGE_FILE"]
    :if ([:len $localImage] != 1) do={ :error ("SB-GATEWAY: local image archive is missing or ambiguous: " . $"SB_IMAGE_FILE") }
    :if ([/file/get $localImage size] < 1048576) do={ :error "SB-GATEWAY: local image archive is unexpectedly small; verify its SHA256 on the administrator PC and upload it again" }
  }
  :if ($"SB_IMAGE_SOURCE" = "registry") do={
    :if (([:len $"SB_IMAGE"] = 0) || ([:typeof [:find $"SB_IMAGE" "example.invalid"]] != "nil")) do={ :error "SB-GATEWAY: set a real immutable ARM64 registry image reference" }
    :if ([:typeof [:find $"SB_IMAGE" "@sha256:"]] = "nil") do={ :error "SB-GATEWAY: registry image must be pinned by @sha256 digest" }
  }
} else={
  :log info "SB-GATEWAY: project container already exists; image archive/reference is informational for this idempotent preflight"
}
:if ($"SB_ADDRESSES_CONFIRMED" != true) do={ :error "SB-GATEWAY: replace/confirm every example network value and set SB_ADDRESSES_CONFIRMED=true in the private variables file" }
:if ([:len $"SB_MANAGED_CLIENTS"] = 0) do={ :log warning "SB-GATEWAY: SB_MANAGED_CLIENTS is empty; local diversion will remain a no-op" }
:if ([:len $"SB_MANAGEMENT_INGRESS_INTERFACES"] = 0) do={ :error "SB-GATEWAY: select at least one actual trusted ingress interface in the Web UI" }
:if (($"SB_ROUTEROS_REST_PORT" < 1) || ($"SB_ROUTEROS_REST_PORT" > 65535)) do={ :error "SB-GATEWAY: select and confirm the existing www-ssl TCP port; zero/default placeholders are rejected" }
:foreach interfaceName in=$"SB_MANAGEMENT_INGRESS_INTERFACES" do={
  :if ([:len [/interface/find where name=$interfaceName]] != 1) do={ :error ("SB-GATEWAY: trusted ingress interface is missing or ambiguous: " . $interfaceName) }
}

:local sbWanList [/interface/list/find where name="WAN"]
:if ([:len $sbWanList] != 1) do={ :error "SB-GATEWAY: exactly one existing WAN interface-list is required" }
:if ([:len [/interface/list/member/find where list="WAN"]] = 0) do={ :error "SB-GATEWAY: WAN interface-list must contain at least one interface" }

:local existingIngressList [/interface/list/find where name="SB_MANAGEMENT_INGRESS"]
:if ([:len $existingIngressList] > 0) do={
  :if (([:len $existingIngressList] != 1) || ([/interface/list/get $existingIngressList comment] != "SB-GATEWAY management ingress list")) do={ :error "SB-GATEWAY: interface-list name collision: SB_MANAGEMENT_INGRESS" }
  :foreach member in=[/interface/list/member/find where list="SB_MANAGEMENT_INGRESS"] do={
    :if ([/interface/list/member/get $member comment] != "SB-GATEWAY management ingress") do={ :error "SB-GATEWAY: unowned member found in project management ingress list" }
  }
}

:if (($"SB_IPV6_MODE" = "block_managed") && ([:len $"SB_MANAGED_CLIENTS"] > 0) && ([:len $"SB_MANAGED_CLIENTS_V6"] = 0)) do={
  :local ipv6Disabled true
  :do { :set ipv6Disabled [/ipv6/settings/get disable-ipv6] } on-error={ :set ipv6Disabled true }
  :if ($ipv6Disabled = false) do={ :error "SB-GATEWAY: IPv6 is active; populate SB_MANAGED_CLIENTS_V6 or implement parity before applying" }
}

:local existingBridge [/interface/bridge/find where name=$"SB_BRIDGE"]
:if ([:len $existingBridge] > 0) do={
  :if ([/interface/bridge/get $existingBridge comment] != "SB-GATEWAY container bridge") do={ :error ("SB-GATEWAY: bridge name collision: " . $"SB_BRIDGE") }
}
:local existingVeth [/interface/veth/find where name=$"SB_VETH"]
:if ([:len $existingVeth] > 0) do={
  :if ([/interface/veth/get $existingVeth comment] != "SB-GATEWAY container veth") do={ :error ("SB-GATEWAY: veth name collision: " . $"SB_VETH") }
}
:local existingTable [/routing/table/find where name=$"SB_ROUTING_TABLE"]
:if ([:len $existingTable] > 0) do={
  :if ([/routing/table/get $existingTable comment] != "SB-GATEWAY routing table") do={ :error ("SB-GATEWAY: routing table name collision: " . $"SB_ROUTING_TABLE") }
}

:local fasttrack [/ip/firewall/filter/find where action="fasttrack-connection" and disabled=no]
:if ([:len $fasttrack] > 1) do={ :error "SB-GATEWAY: multiple enabled FastTrack rules are ambiguous; no patch was applied" }
:if ([:len $fasttrack] = 1) do={
  :local mark [/ip/firewall/filter/get $fasttrack connection-mark]
  :if (($mark != "") && ($mark != "no-mark")) do={ :error ("SB-GATEWAY: FastTrack already has an incompatible connection-mark matcher: " . $mark) }
}
:if ([:len $fasttrack] = 0) do={ :log warning "SB-GATEWAY: no enabled FastTrack rule found; no FastTrack patch is needed" }

:log info "SB-GATEWAY: capability preflight passed; restart-policy/restart-interval (or legacy auto-restart-interval) is verified atomically when the container is added"
