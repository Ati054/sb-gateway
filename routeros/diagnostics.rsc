# SB-GATEWAY read-only diagnostics. No UUID, subscription URL or password output.
:put "=== SB-GATEWAY resource ==="
/system/resource/print
:put "=== container ==="
/container/print detail where comment="SB-GATEWAY container"
:put "=== health scheduler ==="
/system/scheduler/print detail where comment~"^SB-GATEWAY"
:put "=== diversion gate ==="
/ip/firewall/mangle/print stats detail where comment="SB-GATEWAY diversion-gate"
:put "=== scoped routes ==="
/ip/route/print detail where comment~"^SB-GATEWAY"
:put "=== managed connections ==="
:put ([:len [/ip/firewall/connection/find where connection-mark="sb-managed"]])
:put "=== scoped filter/nat counters ==="
/ip/firewall/filter/print stats where comment~"^SB-GATEWAY"
/ip/firewall/nat/print stats where comment~"^SB-GATEWAY"
:put "=== logs (last matching entries) ==="
/log/print where message~"SB-GATEWAY"

