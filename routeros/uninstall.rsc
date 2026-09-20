# SB-GATEWAY complete uninstall. Set the exact dedicated external-storage
# directory used by this installation before importing this file. The script
# refuses internal flash and a bare disk root.

:global "SB_STORAGE_ROOT"
:local storageRoot [:tostr $"SB_STORAGE_ROOT"]
:if (([:len $storageRoot] < 5) || ([:typeof [:find $storageRoot "/"]] = "nil") || ([:typeof [:find $storageRoot ".."]] != "nil") || ([:find $storageRoot "flash"] = 0) || ([:find $storageRoot "Flash"] = 0) || ([:find $storageRoot "FLASH"] = 0) || ($storageRoot = "disk1") || ($storageRoot = "usb1") || ($storageRoot = "usb2") || ($storageRoot = "sata1") || ($storageRoot = "nvme1")) do={
  :error "SB-GATEWAY: SB_STORAGE_ROOT must be a dedicated external-storage directory"
}
:if ([:len [/file/find where name=$storageRoot]] != 1) do={
  :error "SB-GATEWAY: exact project storage directory is missing or ambiguous"
}

:local gate [/ip/firewall/mangle/find where comment="SB-GATEWAY diversion-gate"]
:if ([:len $gate] = 1) do={ /ip/firewall/mangle/disable $gate }
/ip/firewall/connection/remove [find where connection-mark="sb-managed"]

:foreach state in=[/system/script/find where comment~"^SB-GATEWAY WG egress peer state "] do={
  :local stateData [/system/script/get $state source]
  :local separator [:find $stateData "|"]
  :if (($separator = nil) || ($separator < 2)) do={ :error "SB-GATEWAY: WireGuard peer restore state is invalid" }
  :local peerKey [:pick $stateData 1 $separator]
  :local originalAllowed [:pick $stateData ($separator + 1) [:len $stateData]]
  :local peer [/interface/wireguard/peers/find where public-key=$peerKey]
  :if ([:len $peer] != 1) do={ :error "SB-GATEWAY: WireGuard peer restore target is missing or ambiguous" }
  /interface/wireguard/peers/set $peer allowed-address=$originalAllowed
}

/system/scheduler/remove [find where comment~"^SB-GATEWAY "]
/system/script/remove [find where comment~"^SB-GATEWAY "]
/ip/firewall/mangle/remove [find where comment~"^SB-GATEWAY "]
/ip/firewall/filter/remove [find where comment~"^SB-GATEWAY "]
/ip/firewall/nat/remove [find where comment~"^SB-GATEWAY "]
/ip/firewall/address-list/remove [find where list="SB_PUBLIC_ABUSE"]
/ip/firewall/address-list/remove [find where comment~"^SB-GATEWAY "]
:do { /ipv6/firewall/filter/remove [find where comment~"^SB-GATEWAY "] } on-error={}
:do { /ipv6/firewall/address-list/remove [find where comment~"^SB-GATEWAY "] } on-error={}
/ip/route/remove [find where comment~"^SB-GATEWAY "]
:do { /interface/list/member/remove [find where comment~"^SB-GATEWAY "] } on-error={}

:local containerId [/container/find where comment="SB-GATEWAY container"]
:if ([:len $containerId] = 1) do={
  :do { /container/stop $containerId } on-error={}
  :local stopped false
  :local stopAttempt 0
  :while (($stopped = false) && ($stopAttempt < 60)) do={
    :do { :if ([/container/get $containerId running] = false) do={ :set stopped true } } on-error={}
    :do { :if ([/container/get $containerId stopped] = true) do={ :set stopped true } } on-error={}
    :do { :if ([/container/get $containerId status] = "stopped") do={ :set stopped true } } on-error={}
    :if ($stopped = false) do={ :set stopAttempt ($stopAttempt + 1); :delay 2s }
  }
  :if ($stopped = false) do={ :error "SB-GATEWAY: container did not stop; storage was preserved" }
  /container/remove $containerId
}
/container/envs/remove [find where comment~"^SB-GATEWAY "]
/container/mounts/remove [find where comment~"^SB-GATEWAY "]
/ip/address/remove [find where comment~"^SB-GATEWAY "]
/interface/bridge/port/remove [find where comment~"^SB-GATEWAY "]
/interface/veth/remove [find where comment~"^SB-GATEWAY "]
/interface/bridge/remove [find where comment~"^SB-GATEWAY "]
/interface/list/remove [find where comment~"^SB-GATEWAY "]
/routing/table/remove [find where comment="SB-GATEWAY routing table"]
/user/remove [find where comment="SB-GATEWAY control-plane REST user"]
/user/group/remove [find where comment="SB-GATEWAY REST group"]
/file/remove [find where name~"^sb-gateway-(before-|pre-)"]

:local storageEntry [/file/find where name=$storageRoot]
:if ([:len $storageEntry] = 1) do={ /file/remove $storageEntry }
:log warning "SB-GATEWAY: full uninstall complete; foreign RouterOS objects were preserved"
