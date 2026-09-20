# SB-GATEWAY local Internet continuity watchdog.
# Remote VLESS ingress is intentionally not given a direct-WAN fallback.

:global "SB_HEALTH_URL"
:global "SB_HEALTH_INTERVAL"
:global "SB_HEALTH_FAILURE_THRESHOLD"
:global "SB_HEALTH_RECOVERY_THRESHOLD"
:global "SB_HEALTH_COOLDOWN_TICKS"

# Imports and re-imports are fail-open from their first mutation. Disable only
# the exact project gate and clear only project-marked connections.
/system/scheduler/disable [find where name="SB-GATEWAY-health-watchdog"]
/ip/firewall/mangle/disable [find where comment="SB-GATEWAY diversion-gate"]
/ip/firewall/connection/remove [find where connection-mark="sb-managed"]

:if (([:typeof $"SB_HEALTH_URL"] != "str") || (($"SB_HEALTH_URL" ~ "^http://[0-9.]+:9080/traffic-ready\$") = false)) do={
  :error "SB-GATEWAY: SB_HEALTH_URL must be a container-only IPv4 http://address:9080/traffic-ready URL; diversion remains fail-open"
}
:if (([:typeof $"SB_HEALTH_FAILURE_THRESHOLD"] != "num") || ($"SB_HEALTH_FAILURE_THRESHOLD" < 1) || ($"SB_HEALTH_FAILURE_THRESHOLD" > 60)) do={
  :error "SB-GATEWAY: failure threshold must be an integer from 1 to 60; diversion remains fail-open"
}
:if (([:typeof $"SB_HEALTH_RECOVERY_THRESHOLD"] != "num") || ($"SB_HEALTH_RECOVERY_THRESHOLD" < 1) || ($"SB_HEALTH_RECOVERY_THRESHOLD" > 60)) do={
  :error "SB-GATEWAY: recovery threshold must be an integer from 1 to 60; diversion remains fail-open"
}
:if (([:typeof $"SB_HEALTH_COOLDOWN_TICKS"] != "num") || ($"SB_HEALTH_COOLDOWN_TICKS" < 0) || ($"SB_HEALTH_COOLDOWN_TICKS" > 720)) do={
  :error "SB-GATEWAY: cooldown ticks must be an integer from 0 to 720; diversion remains fail-open"
}
:if ([:len $"SB_HEALTH_INTERVAL"] = 0) do={
  :error "SB-GATEWAY: health interval is empty; diversion remains fail-open"
}

# RouterOS globals are runtime state, not persisted configuration. Snapshot the
# validated settings as literal assignments in a persisted loader script.
:local configSource (":global \"SB_HEALTH_URL\" \"" . $"SB_HEALTH_URL" . "\";\r\n" . ":global \"SB_HEALTH_FAILURE_THRESHOLD\" " . [:tostr $"SB_HEALTH_FAILURE_THRESHOLD"] . ";\r\n" . ":global \"SB_HEALTH_RECOVERY_THRESHOLD\" " . [:tostr $"SB_HEALTH_RECOVERY_THRESHOLD"] . ";\r\n" . ":global \"SB_HEALTH_COOLDOWN_TICKS\" " . [:tostr $"SB_HEALTH_COOLDOWN_TICKS"] . ";\r\n")
:if ([:len [/system/script/find where name="SB-GATEWAY-watchdog-config"]] > 0) do={ /system/script/remove [find where name="SB-GATEWAY-watchdog-config"] }
/system/script/add name="SB-GATEWAY-watchdog-config" policy=read,write,test source=$configSource comment="SB-GATEWAY watchdog persisted config"

:if ([:len [/system/script/find where name="SB-GATEWAY-startup-fail-open"]] > 0) do={ /system/script/remove [find where name="SB-GATEWAY-startup-fail-open"] }
/system/script/add name="SB-GATEWAY-startup-fail-open" policy=read,write,test source={
  :global sbHealthFailures 0
  :global sbHealthSuccesses 0
  :global sbRecoveryTicks 0
  :global sbFailOpen true
  :global sbStartupSafety true
  :global sbWatchdogStage "startup"
  :global sbLastHealthStatus "not-checked"
  /ip/firewall/mangle/disable [find where comment="SB-GATEWAY diversion-gate"]
  /ip/firewall/connection/remove [find where connection-mark="sb-managed"]
  :log warning "SB-GATEWAY: startup safety forced managed clients to main/WAN; health hysteresis must pass before diversion"
} comment="SB-GATEWAY startup fail-open"

:if ([:len [/system/script/find where name="SB-GATEWAY-health-watchdog"]] > 0) do={ /system/script/remove [find where name="SB-GATEWAY-health-watchdog"] }
# RouterOS scheduler jobs use their own user environment. `policy` together
# with `test` is required to see and update the admin-owned global hysteresis
# state. This fixed project script receives neither `password` nor `sensitive`.
/system/script/add name="SB-GATEWAY-health-watchdog" policy=ftp,read,write,policy,test source={
  :local configLoaded true
  :do { /system/script/run SB-GATEWAY-watchdog-config } on-error={ :set configLoaded false }
  :global "SB_HEALTH_URL"
  :global "SB_HEALTH_FAILURE_THRESHOLD"
  :global "SB_HEALTH_RECOVERY_THRESHOLD"
  :global "SB_HEALTH_COOLDOWN_TICKS"
  :global sbHealthFailures
  :global sbHealthSuccesses
  :global sbRecoveryTicks
  :global sbFailOpen
  :global sbStartupSafety
  :global sbWatchdogStage
  :global sbLastHealthStatus
  :set sbWatchdogStage "started"

  :local exactGates [/ip/firewall/mangle/find where comment="SB-GATEWAY diversion-gate"]
  :if ($configLoaded = false) do={
    /ip/firewall/mangle/disable $exactGates
    /ip/firewall/connection/remove [find where connection-mark="sb-managed"]
    :set sbFailOpen true
    :set sbWatchdogStage "config-error"
    :set sbLastHealthStatus "not-checked"
    :log error "SB-GATEWAY: persisted watchdog config unavailable; diversion forced fail-open"
  } else={

  :set sbWatchdogStage "config-loaded"

  :local stateMissing false
  :if ([:typeof $sbHealthFailures] != "num") do={ :set sbHealthFailures 0 }
  :if ([:typeof $sbHealthSuccesses] != "num") do={ :set sbHealthSuccesses 0 }
  :if ([:typeof $sbRecoveryTicks] != "num") do={ :set sbRecoveryTicks 0 }
  :if ([:typeof $sbFailOpen] != "bool") do={ :set sbFailOpen true; :set stateMissing true }
  :if ([:typeof $sbStartupSafety] != "bool") do={ :set sbStartupSafety false }

  :if ([:len $exactGates] != 1) do={
    /ip/firewall/mangle/disable $exactGates
    /ip/firewall/connection/remove [find where connection-mark="sb-managed"]
    :set sbFailOpen true
    :set sbWatchdogStage "gate-error"
    :set sbLastHealthStatus "not-checked"
    :log error "SB-GATEWAY: diversion gate missing or ambiguous; all exact project gates forced fail-open"
  } else={
  :local gate $exactGates
  :if ($stateMissing = true) do={
    /ip/firewall/mangle/disable $gate
    /ip/firewall/connection/remove [find where connection-mark="sb-managed"]
  }

  :local healthy false
  :set sbWatchdogStage "fetching"
  :set sbLastHealthStatus "checking"
  :onerror sbFetchError in={
    :local response [/tool/fetch url=$"SB_HEALTH_URL" output=user as-value idle-timeout=4s]
    :set sbLastHealthStatus [:tostr ($response->"status")]
    :if (($response->"status") = "finished") do={ :set healthy true }
  } do={
    :set sbLastHealthStatus ("error:" . [:tostr $sbFetchError])
    :set healthy false
  }

  :if ($healthy = true) do={
    :local gateDisabled [/ip/firewall/mangle/get $gate disabled]
    :set sbHealthFailures 0
    :set sbHealthSuccesses ($sbHealthSuccesses + 1)
    :if ($sbFailOpen = true) do={ :set sbRecoveryTicks ($sbRecoveryTicks + 1) }
    # Apply can disable the gate in another RouterOS user environment. A fresh
    # readiness response reconciles that drift even if our globals say healthy.
    # /traffic-ready already proves a current-process selector readback. On a
    # boot/update start, admit it on the first successful poll. Later recovery
    # from a live outage keeps the configured hysteresis.
    :if (($gateDisabled = true) && (($sbStartupSafety = true) || ($sbFailOpen = false) || (($sbHealthSuccesses >= $"SB_HEALTH_RECOVERY_THRESHOLD") && ($sbRecoveryTicks >= $"SB_HEALTH_COOLDOWN_TICKS")))) do={
      /ip/firewall/mangle/enable $gate
      :set sbFailOpen false
      :set sbStartupSafety false
      :set sbRecoveryTicks 0
      :log info "SB-GATEWAY: container stably ready; managed-client diversion enabled"
    }
    :if ($gateDisabled = false) do={ :set sbFailOpen false; :set sbRecoveryTicks 0 }
    :set sbWatchdogStage "healthy"
  } else={
    :set sbHealthSuccesses 0
    :set sbRecoveryTicks 0
    :set sbHealthFailures ($sbHealthFailures + 1)
    :if ($sbHealthFailures >= $"SB_HEALTH_FAILURE_THRESHOLD") do={
      /ip/firewall/mangle/disable $gate
      /ip/firewall/connection/remove [find where connection-mark="sb-managed"]
      :if ($sbFailOpen = false) do={ :log warning "SB-GATEWAY: container unhealthy; only SB_MANAGED_CLIENTS failed open to normal WAN" }
      :set sbFailOpen true
    }
    :set sbWatchdogStage "unhealthy"
  }
  }
  }
} comment="SB-GATEWAY health watchdog"

# interval=0s is deliberate: RouterOS executes this scheduler once, about three
# seconds after every boot. The repeating scheduler does not run at startup.
/system/scheduler/remove [find where name="SB-GATEWAY-startup-fail-open"]
/system/scheduler/add name="SB-GATEWAY-startup-fail-open" interval=0s start-time=startup on-event="/system/script/run SB-GATEWAY-startup-fail-open" policy=read,write,test comment="SB-GATEWAY startup fail-open scheduler"
/system/script/run SB-GATEWAY-startup-fail-open

/system/scheduler/remove [find where name="SB-GATEWAY-health-watchdog"]
/system/scheduler/add name="SB-GATEWAY-health-watchdog" interval=$"SB_HEALTH_INTERVAL" start-time=startup on-event="/system/script/run SB-GATEWAY-health-watchdog" policy=ftp,read,write,policy,test comment="SB-GATEWAY health scheduler"

:log info "SB-GATEWAY: watchdog installed; boot and current state are fail-open until recovery hysteresis passes"
