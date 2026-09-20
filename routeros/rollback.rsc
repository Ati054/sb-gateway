# SB-GATEWAY scoped rollback. It never wipes a table and never removes objects
# without the SB-GATEWAY comment/name. Existing VPNs, routes and firewall stay.

:local gate [/ip/firewall/mangle/find where comment="SB-GATEWAY diversion-gate"]
:if ([:len $gate] = 1) do={ /ip/firewall/mangle/disable $gate }
/ip/firewall/connection/remove [find where connection-mark="sb-managed"]

:if ([:len [/system/script/find where name="SB-GATEWAY-fasttrack-state"]] = 1) do={
  :local fasttrack [/ip/firewall/filter/find where action="fasttrack-connection" and disabled=no]
  :if ([:len $fasttrack] = 1) do={
    :if ([/ip/firewall/filter/get $fasttrack connection-mark] = "no-mark") do={
      /ip/firewall/filter/set $fasttrack connection-mark=""
      :log warning "SB-GATEWAY: restored the sole FastTrack connection-mark matcher to empty"
    }
  } else={
    :log error "SB-GATEWAY: FastTrack became ambiguous; matcher was not restored automatically"
  }
}

/system/scheduler/remove [find where comment~"^SB-GATEWAY "]
/system/script/remove [find where comment~"^SB-GATEWAY "]
/ip/firewall/mangle/remove [find where comment~"^SB-GATEWAY "]
/ip/firewall/filter/remove [find where comment~"^SB-GATEWAY "]
/ip/firewall/nat/remove [find where comment~"^SB-GATEWAY "]
/ip/firewall/address-list/remove [find where list="SB_PUBLIC_ABUSE"]
/ip/firewall/address-list/remove [find where comment~"^SB-GATEWAY "]
:do { /interface/list/member/remove [find where comment~"^SB-GATEWAY "] } on-error={}
:do { /interface/list/remove [find where comment="SB-GATEWAY management ingress list"] } on-error={}
:do { /ipv6/firewall/filter/remove [find where comment~"^SB-GATEWAY "] } on-error={}
:do { /ipv6/firewall/address-list/remove [find where comment~"^SB-GATEWAY "] } on-error={}
/ip/route/remove [find where comment~"^SB-GATEWAY "]

:local containerId [/container/find where comment="SB-GATEWAY container"]
:if ([:len $containerId] = 1) do={
  :do { /container/stop $containerId } on-error={}
  /container/remove $containerId
}
/container/envs/remove [find where comment~"^SB-GATEWAY "]
/container/mounts/remove [find where comment~"^SB-GATEWAY "]

/ip/address/remove [find where comment~"^SB-GATEWAY "]
/interface/bridge/port/remove [find where comment~"^SB-GATEWAY "]
/interface/veth/remove [find where comment~"^SB-GATEWAY "]
/interface/bridge/remove [find where comment~"^SB-GATEWAY "]
/routing/table/remove [find where comment="SB-GATEWAY routing table"]

/user/remove [find where comment="SB-GATEWAY control-plane REST user"]
/user/group/remove [find where comment="SB-GATEWAY REST group"]
:log warning "SB-GATEWAY: scoped rollback complete; backups/exports and USB data were preserved"
