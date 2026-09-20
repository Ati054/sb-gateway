# SB-GATEWAY Cloudflare IPv4+IPv6 updater.
# Both official feeds are validated into staging lists before either live list
# changes. New entries are added before stale entries are removed, so origin
# filtering never has a fail-open gap and a bad download preserves both LKGs.

:if ([:len [/system/script/find where name="SB-GATEWAY-cloudflare-update"]] > 0) do={ /system/script/remove [find where name="SB-GATEWAY-cloudflare-update"] }
/system/script/add name="SB-GATEWAY-cloudflare-update" policy=read,write,test,ftp source={
  :local v4stage "SB_CLOUDFLARE_V4_NEXT"
  :local v6stage "SB_CLOUDFLARE_V6_NEXT"
  :local v4live "SB_CLOUDFLARE_V4"
  :local v6live "SB_CLOUDFLARE_V6"
  :local v4response
  :local v6response
  :local downloadsOk true

  :onerror sbCloudflareV4Error in={
    :set v4response [/tool/fetch url="https://www.cloudflare.com/ips-v4" output=user as-value idle-timeout=60s]
  } do={ :set downloadsOk false; :log error ("SB-GATEWAY: Cloudflare IPv4 fetch failed: " . $sbCloudflareV4Error) }
  :onerror sbCloudflareV6Error in={
    :set v6response [/tool/fetch url="https://www.cloudflare.com/ips-v6" output=user as-value idle-timeout=60s]
  } do={ :set downloadsOk false; :log error ("SB-GATEWAY: Cloudflare IPv6 fetch failed: " . $sbCloudflareV6Error) }
  :if (($downloadsOk = false) || (($v4response->"status") != "finished") || (($v6response->"status") != "finished")) do={
    :log error "SB-GATEWAY: Cloudflare feed fetch failed; keeping both current allow-lists"
  } else={

  /ip/firewall/address-list/remove [find where list=$v4stage and comment="SB-GATEWAY cloudflare staging v4"]
  /ipv6/firewall/address-list/remove [find where list=$v6stage and comment="SB-GATEWAY cloudflare staging v6"]
  :local v4data ($v4response->"data")
  :local v6data ($v6response->"data")
  :local v4accepted 0
  :local v6accepted 0

  :while ([:len $v4data] > 0) do={
    :local newline [:find $v4data "\n"]
    :local line ""
    :if ($newline = nil) do={ :set line $v4data; :set v4data "" } else={
      :set line [:pick $v4data 0 $newline]
      :set v4data [:pick $v4data ($newline + 1) [:len $v4data]]
    }
    :if (([:len $line] > 0) && ([:pick $line ([:len $line] - 1) [:len $line]] = "\r")) do={ :set line [:pick $line 0 ([:len $line] - 1)] }
    :if (([:len $line] > 0) && ([:typeof [:find $line "/"]] != "nil") && ([:typeof [:find $line " "]] = "nil") && ([:typeof [:find $line ":"]] = "nil")) do={
      :do {
        /ip/firewall/address-list/add list=$v4stage address=$line comment="SB-GATEWAY cloudflare staging v4"
        :set v4accepted ($v4accepted + 1)
      } on-error={ :log error "SB-GATEWAY: invalid IPv4 CIDR in Cloudflare feed" }
    }
  }

  :while ([:len $v6data] > 0) do={
    :local newline [:find $v6data "\n"]
    :local line ""
    :if ($newline = nil) do={ :set line $v6data; :set v6data "" } else={
      :set line [:pick $v6data 0 $newline]
      :set v6data [:pick $v6data ($newline + 1) [:len $v6data]]
    }
    :if (([:len $line] > 0) && ([:pick $line ([:len $line] - 1) [:len $line]] = "\r")) do={ :set line [:pick $line 0 ([:len $line] - 1)] }
    :if (([:len $line] > 0) && ([:typeof [:find $line "/"]] != "nil") && ([:typeof [:find $line " "]] = "nil") && ([:typeof [:find $line ":"]] != "nil")) do={
      :do {
        /ipv6/firewall/address-list/add list=$v6stage address=$line comment="SB-GATEWAY cloudflare staging v6"
        :set v6accepted ($v6accepted + 1)
      } on-error={ :log error "SB-GATEWAY: invalid IPv6 CIDR in Cloudflare feed" }
    }
  }

  :if (($v4accepted < 10) || ($v6accepted < 5)) do={
    /ip/firewall/address-list/remove [find where list=$v4stage and comment="SB-GATEWAY cloudflare staging v4"]
    /ipv6/firewall/address-list/remove [find where list=$v6stage and comment="SB-GATEWAY cloudflare staging v6"]
    :log error ("SB-GATEWAY: Cloudflare feed validation failed (v4=" . $v4accepted . ", v6=" . $v6accepted . "); keeping both current allow-lists")
  } else={

  :foreach staged in=[/ip/firewall/address-list/find where list=$v4stage and comment="SB-GATEWAY cloudflare staging v4"] do={
    :local cidr [/ip/firewall/address-list/get $staged address]
    :if ([:len [/ip/firewall/address-list/find where list=$v4live and address=$cidr and comment="SB-GATEWAY cloudflare active v4"]] = 0) do={
      /ip/firewall/address-list/add list=$v4live address=$cidr comment="SB-GATEWAY cloudflare active v4"
    }
  }
  :foreach staged in=[/ipv6/firewall/address-list/find where list=$v6stage and comment="SB-GATEWAY cloudflare staging v6"] do={
    :local cidr [/ipv6/firewall/address-list/get $staged address]
    :if ([:len [/ipv6/firewall/address-list/find where list=$v6live and address=$cidr and comment="SB-GATEWAY cloudflare active v6"]] = 0) do={
      /ipv6/firewall/address-list/add list=$v6live address=$cidr comment="SB-GATEWAY cloudflare active v6"
    }
  }

  :foreach current in=[/ip/firewall/address-list/find where list=$v4live and comment="SB-GATEWAY cloudflare active v4"] do={
    :local cidr [/ip/firewall/address-list/get $current address]
    :if ([:len [/ip/firewall/address-list/find where list=$v4stage and address=$cidr and comment="SB-GATEWAY cloudflare staging v4"]] = 0) do={ /ip/firewall/address-list/remove $current }
  }
  :foreach current in=[/ipv6/firewall/address-list/find where list=$v6live and comment="SB-GATEWAY cloudflare active v6"] do={
    :local cidr [/ipv6/firewall/address-list/get $current address]
    :if ([:len [/ipv6/firewall/address-list/find where list=$v6stage and address=$cidr and comment="SB-GATEWAY cloudflare staging v6"]] = 0) do={ /ipv6/firewall/address-list/remove $current }
  }

  /ip/firewall/address-list/remove [find where list=$v4stage and comment="SB-GATEWAY cloudflare staging v4"]
  /ipv6/firewall/address-list/remove [find where list=$v6stage and comment="SB-GATEWAY cloudflare staging v6"]
  :log info ("SB-GATEWAY: Cloudflare allow-lists updated (v4=" . $v4accepted . ", v6=" . $v6accepted . ")")
  }
  }
} comment="SB-GATEWAY Cloudflare updater"

:if ([:len [/system/scheduler/find where name="SB-GATEWAY-cloudflare-update"]] = 0) do={
  /system/scheduler/add name="SB-GATEWAY-cloudflare-update" interval=1d start-time=03:17:00 on-event="/system/script/run SB-GATEWAY-cloudflare-update" policy=read,write,test,ftp comment="SB-GATEWAY Cloudflare scheduler"
}
/system/scheduler/set [find where name="SB-GATEWAY-cloudflare-update"] policy=read,write,test,ftp
/system/script/run "SB-GATEWAY-cloudflare-update"
