# Managed DNS runtime ownership and recovery

Managed LAN DNS has one owner of port 1053. Current generated bundles assign that
listener to PolicyDNS in Go. A coherent legacy bundle can still assign it to
Xray; PolicyDNS without managed ingress binds only its forwarding lanes. Generic
TUN DNS and resolver upstreams retain their existing paths. Listener literals
must not contain an IPv6 zone; IPv4-mapped literals are normalized only after
that scope check.

For managed IPv4 LAN and WireGuard clients, RouterOS sends eligible TCP/UDP
port 53 queries directly to that Go listener, including queries addressed to
external DNS servers. The original client address selects the same ordered DNS
policy lanes. Internal destinations and subscription endpoints retain their
existing diversion bypasses; WAN ingress, the container's own queries and
unmanaged sources are excluded. Authenticated VLESS users retain Xray's user
identity path, and VPN resolver upstreams still use their assigned transport.
DoH, DoT and IPv6 traffic are not broadened by this IPv4 port-53 rule.

Apply explicitly clears the old NAT rule's local-destination restriction.
An image upgrade with the previous committed traffic script offers a runtime
Apply even when the saved configuration is unchanged. After fail-open recovery,
the watchdog expires only untranslated, unmarked TCP/UDP DNS connections from
managed sources whose destination is local or eligible for public diversion.
It preserves internal/endpoint bypasses, existing destination NAT, unrelated
connection marks and the container's own connections. Gate admission precedes
this cleanup so a reused UDP socket can acquire the restored DNS route.

Startup normally regenerates legacy artifacts from the committed configuration
and its committed node snapshot. If optional migration fails, a coherent legacy
bundle can continue serving. An inconsistent listener pair cannot start workers.

A power loss during Apply can leave runtime files from different generations.
For a pending operation, startup repairs only an inconsistent local bundle using
the active commit point and its node snapshot. A pending first Apply uses its
separately persisted safe recovery generation. It does not apply the draft,
fetch subscriptions, change RouterOS, clear the transaction journal, replace LKG,
or publish a new active configuration. The normal recovery worker subsequently
reconciles the complete operation and records the resulting runtime revision.
Missing or invalid authoritative recovery inputs prevent that local repair.

Activation and rollback release the previous owner of port 1053 before starting its
replacement. Moving to Go restarts Xray before PolicyDNS; restoring the legacy
Xray listener restarts PolicyDNS first. A subscription transition that changes
this listener also requires a core restart. Rollback restores complete managed
artifacts; its inspection callback never edits backups or prepares candidates.
Activation and rollback validate the target pair before publishing any file.
An invalid backup pair leaves the working runtime and its processes unchanged.
Go-to-Go changes use the same safe ordering because the published target cannot
prove the running owner's generation; this changes order, not the restart set.
