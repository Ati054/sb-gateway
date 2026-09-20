# SB-GATEWAY read-only inventory helper for adapting scripts to a real router.
# Default export hides sensitive values. Never add the show-sensitive flag.

:put "SB-GATEWAY: writing a redacted full export to sb-gateway-inventory.rsc"
/export file="sb-gateway-inventory"
:put "=== RESOURCE ==="
/system/resource/print
:put "=== PACKAGES / CHANNEL (channel is metadata only) ==="
/system/package/print detail
/system/package/update/print
:put "=== DISKS ==="
/disk/print detail
:put "=== INTERFACES ==="
/interface/print detail
:put "=== IP ROUTES / ROUTING TABLES ==="
/ip/route/print detail
/routing/table/print detail
:put "=== FILTER / MANGLE / NAT ==="
/ip/firewall/filter/print detail
/ip/firewall/mangle/print detail
/ip/firewall/nat/print detail
:put "=== ADDRESS LISTS ==="
/ip/firewall/address-list/print detail
:put "=== CONTAINERS / MOUNTS / ENVS ==="
/container/print detail
/container/mounts/print detail
/container/envs/print without-paging
:put "SB-GATEWAY: download sb-gateway-inventory.rsc plus this terminal output; review before sharing"
