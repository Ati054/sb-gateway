# SB-GATEWAY narrowly scoped FastTrack compatibility patch.
# It aborts on ambiguity and never deletes an existing firewall rule.

:local fasttrack [/ip/firewall/filter/find where action="fasttrack-connection" and disabled=no]
:if ([:len $fasttrack] > 1) do={ :error "SB-GATEWAY: multiple enabled FastTrack rules; patch aborted" }
:if ([:len $fasttrack] = 0) do={
  :log warning "SB-GATEWAY: no enabled FastTrack rule; nothing to patch"
} else={
  :local current [/ip/firewall/filter/get $fasttrack connection-mark]
  :if (($current != "") && ($current != "no-mark")) do={ :error ("SB-GATEWAY: incompatible existing FastTrack connection-mark=" . $current) }

  :if ($current = "") do={
    /ip/firewall/filter/set $fasttrack connection-mark=no-mark
    :if ([:len [/system/script/find where name="SB-GATEWAY-fasttrack-state"]] = 0) do={
      /system/script/add name="SB-GATEWAY-fasttrack-state" policy=read,write source=":put \"SB-GATEWAY changed the sole enabled FastTrack matcher from empty to no-mark\"" comment="SB-GATEWAY rollback state"
    }
    :log warning "SB-GATEWAY: sole FastTrack rule patched to connection-mark=no-mark"
  } else={
    :log info "SB-GATEWAY: FastTrack already matches only unmarked connections"
  }
}
