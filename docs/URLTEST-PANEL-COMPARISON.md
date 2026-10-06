# URLTest Panels And Selection

Reviewed 2026-10-06 against the official branches linked below.
This is a source comparison, not a HomeProxy/PassWall2/Mihomo runtime benchmark.
SB Gateway source changes are not an installed RC2 image acceptance claim.

## Panels Are Not Independent Selectors

- HomeProxy generates native sing-box URLTest groups. Its simple form exposes
  interval (180 seconds) and tolerance (50 ms); custom groups also expose URL,
  idle timeout and connection interruption. The generator extends idle timeout
  for unusually long simple-group intervals.
  [Form](https://github.com/immortalwrt/homeproxy/blob/master/htdocs/luci-static/resources/view/homeproxy/client.js),
  [Generator](https://github.com/immortalwrt/homeproxy/blob/master/root/etc/homeproxy/scripts/generate_client.uc).
- Official PassWall2 also generates native sing-box URLTest groups: URL,
  interval (3 minutes), tolerance (50 ms), idle timeout (30 minutes), and
  connection interruption (off). Its UI chooses Google generate_204, whereas
  the generator falls back to Gstatic when the URL key is absent.
  No separate retries or numeric parallelism appear in this URLTest form.
  [Form](https://github.com/Openwrt-Passwall/openwrt-passwall2/blob/main/luci-app-passwall2/luasrc/model/cbi/passwall2/client/type/1_sing-box.lua#L121),
  [Generator](https://github.com/Openwrt-Passwall/openwrt-passwall2/blob/main/luci-app-passwall2/luasrc/passwall2/util_sing-box.lua#L1322).
- PassWall2 SOCKS auto-switch is a different mechanism: interval 30 seconds,
  curl connect timeout 3 seconds, retry count 1, ordered backups and optional
  return to the primary. It tests backups sequentially, not by minimum latency.
  The connect timeout is not the whole switching deadline.
  [Form](https://github.com/Openwrt-Passwall/openwrt-passwall2/blob/main/luci-app-passwall2/luasrc/model/cbi/passwall2/client/socks_config.lua#L138),
  [Worker](https://github.com/Openwrt-Passwall/openwrt-passwall2/blob/main/luci-app-passwall2/root/usr/share/passwall2/socks_auto_switch.sh).
- `C:\passwall2` is the local SB Gateway for OpenWrt derivative, not the
  independent upstream PassWall2. Its `NOTICE.md` identifies its origin;
  `monitor.js` still has our old seven monitor controls. Do not use those
  controls as independent evidence for their necessity.

## Core Selection

The reviewed sing-box testing source ranks the latest successful stored delay
with tolerance, removes failed probe history, and has no accumulated node
penalty or 600-second hold. Its initial no-history path can use the first
supported outbound; selection while collecting history also applies tolerance.
The round limits concurrency to ten, skips fresh history and suppresses overlap.
Scheduled update follows round completion, not the first usable result.
[Group source](https://github.com/SagerNet/sing-box/blob/testing/protocol/group/urltest.go),
[Controls](https://sing-box.sagernet.org/configuration/outbound/urltest/).

Mihomo URLTest similarly finds the lowest latest delay among alive nodes and
retains the current one within tolerance, unless unavailable or manually
overridden. Provider health checks have a concurrency limit of ten and wait
for completion; this is not proof of a global ten-worker limit for every API.
Mihomo is a core used by Clash-family clients, not a panel.
[Selector](https://github.com/MetaCubeX/mihomo/blob/Meta/adapter/outboundgroup/urltest.go),
[Provider checks](https://github.com/MetaCubeX/mihomo/blob/Meta/adapter/provider/healthcheck.go).

## SB Gateway Decision And Differences

Keep three global controls: active availability cadence (3 seconds), shared
quality cadence (60 seconds), and resource budget (10 simultaneous nodes,
range 1-64). Keep the per-list millisecond tolerance only for URLTest.
The quality cadence is not the fast availability cadence, and three seconds
is not a promised complete failover time. Old separate reserve/full-scan,
retry, absolute ceiling and cooldown controls are not needed in the panel.
These defaults are our choices, not upstream defaults or universal CPU claims.

Our two independent winning comparisons and three recovery confirmations remain
deliberate differences. They are not present as matching controls in the
reviewed sing-box group. They need continued stability testing, not a claim
that SB Gateway now behaves identically to sing-box.

Our emergency path selects the first freshly usable reserve without waiting
for the remaining workers, then cancels/joins them safely. Cold URLTest selects
the lowest successful primary delay in its first bounded batch; it does not
wait for every subscription node. Quality and fallback-only availability remain
separate, and existing client connections are preserved.

The 100-node CHR fixture with only the last candidate usable still takes about
31 seconds after confirmed outage. The strict 30-second gate remains open.
Bounded discovery, fairness across failed policies and fallback-only candidates
must all survive any scheduler improvement; copying an upstream wait-all round
or testing only one primary origin would not close these requirements.
See [Verification](URLTEST-CLEANUP-VERIFICATION.md).
