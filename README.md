# SB Gateway for MikroTik RouterOS 7

SB Gateway 1.6.17 is a bilingual Web-managed traffic-policy gateway packaged as
one Linux ARM64 RouterOS container. The current server runtime is Xray-core 26.9.9
only; sing-box is not shipped and there is no core switch in the UI.

The server uses Xray 26.9.9; exported Reverse VLESS bridge profiles remain pinned
to 26.7.28 and advertise that requirement in their response header. Both use the
current `streamSettings.method` transport field. Compatibility is accepted only
after an end-to-end reverse data-plane test, not by connection status alone.

Xray 26.9.9 is pinned by its exact upstream commit. Upstream currently marks
this tag as a prerelease, so image promotion still requires the complete
ARM64 configuration and data-plane acceptance gate.

Supported server-side connections are:

- VLESS over WebSocket, gRPC, HTTPUpgrade, or XHTTP through ordinary TLS/CDN;
- direct VLESS + REALITY + Vision;
- direct VLESS + gRPC + REALITY;
- direct VLESS + XHTTP + REALITY;
- Hysteria 2 over QUIC/UDP.

The gateway routes selected services or a complete public-Internet flow for
specific LAN, Wi-Fi, WireGuard, SSTP, or OpenVPN clients through provider
VLESS/Hysteria nodes, Reverse VLESS, or selected RouterOS WireGuard tunnels. It does not take
ownership of existing LANs, VPNs, routes, Wi-Fi, or unrelated firewall rules.
All project-created RouterOS objects are scoped by the `SB-GATEWAY` owner
marker. The only mutation of a pre-existing object is the explicitly selected
WireGuard peer's `allowed-address`; its original value is recorded and restored.

An incoming WireGuard client is identified by its RouterOS peer, not by the
shared WireGuard interface. The saved peer `.id` is stable across public-key or
address edits on the same RouterOS object. The client source CIDRs are derived
from that peer's current concrete IPv4 entries before Check, Plan, and Apply.
Host `/32` and site-to-site prefixes are accepted; `0.0.0.0/0` is never treated
as a client source.
Deleting and recreating the peer produces a new identity and requires explicit
reselection; the gateway never transfers a policy by guessing from an address.

The reference hardware is MikroTik hAP ax3, but compatibility is capability
based: a target needs ARM64 RouterOS 7, the matching `container` package,
kernel TPROXY/nftables support, external writable storage, and the
routing/firewall primitives verified by preflight. Compatibility does not
depend on one fixed RouterOS release channel.

## First installation

Download `sb-gateway-1.6.17-routeros-bundle.zip` from the GitHub release and
verify its SHA-256 checksum. The bundle contains the ARM64 container archive,
its checksum and manifest, and the RouterOS scripts required for installation.

Use a USB SSD for the container root and application data. Create a private
copy of `routeros/variables.example.rsc` named `variables.rsc`, enter the
RouterOS addresses and temporary bootstrap credentials, then upload the
container archive and the `routeros` directory to one folder on the SSD.
Import `bootstrap.rsc` once from WebFig Terminal. The script checks the target,
creates project-owned RouterOS objects, installs the container, and leaves
managed traffic on the normal WAN until the selected routes pass readiness
checks. Finish network and route configuration in the Web UI.

The complete procedure, verification commands, and recovery steps are in the
[English installation guide](docs/INSTALL.md). The
[Russian installation guide](docs/INSTALL-RU.md) follows the same release
contract.

## Main operating model

- The Web UI at `https://<container-address>:9443` is the normal control
  surface. WebFig and the static `sb-gateway` binary are recovery paths.
- **Operations → Xray Core logs** shows the bounded tail of the core error and
  process logs with three-second refresh and copy support. Xray log level is a
  normal checked draft setting; per-connection access logging stays disabled,
  and an applied `debug` level automatically returns to `warning` after 15
  minutes.
- Critical RouterOS topology/firewall changes use preview, validation, a fresh
  backup, a RouterOS-local rollback scheduler, readiness checks, and rollback.
  Stable releases use SSH Safe Mode as an additional owner; RouterOS 7.24 uses
  the scheduler guard directly because its SSH console can terminate after
  acknowledging Safe Mode.
- Container-only or atomically replaceable data changes do not enter the full
  protected RouterOS path. CDN CIDR lists and other LKG-backed network data are
  replaced without dropping established connections.
- A `display_name`-only draft uses `state_only` after a fresh render proves
  every runtime artifact and the RouterOS candidate byte-identical. It commits
  local metadata without RouterOS discovery, backup, runtime publication,
  restart, or health probes; any failed proof falls back to the normal path.
- Apply inventories independent RouterOS REST tables through a bounded worker
  pool and reuses that verified snapshot for post-apply capability checks; the
  post-check refreshes only live container state. Post-Apply recovery archive
  creation/mirroring and stale-backup pruning run as persisted maintenance;
  rapid commits are coalesced to the latest active generation.
- Full protected RouterOS Apply stages both content-addressed apply and rollback
  imports in one legacy SCP session. Symmetric deltas up to 16 KiB per script
  are installed directly through REST, avoiding SCP/import while retaining the
  same backup, scheduler guard, health checks, and rollback contract.
- RouterOS changes use complete renderer-owned section deltas when they are
  materially smaller than the full candidate; backup, the
  independent rollback scheduler, health checks, and automatic full fallback
  remain mandatory.
- A rule-only Xray change is proven against the live config and published with
  Xray RoutingService. A changed DNS artifact restarts only the in-process DNS
  component; there is no background config polling and Xray stays running.
  Structural Xray changes use the native controller restart contract. The exact Xray
  config validated before such a restart receives a one-shot SHA-256 marker, so
  only the duplicate binary test is skipped. Cold/manual starts still validate
  the live config.
- The `watchdog` role of the same static Go binary uses direct API/process
  evidence every 5 seconds and batches
  listener, TPROXY route and nftables evidence into a 30-second deep probe. It does
  not poll `supervisorctl`: a blocked XML-RPC client must never consume a
  router core and starve DNS. Listener inventory is read from `/proc`, and the
  process parses generated JSON directly.
- The direct DNS provider selected in the panel also owns RouterOS DNS:
  provider bootstrap IPs and the selected DoH URL are rendered as an isolated
  RouterOS DNS delta. Changing it does not clear established connections.
- Policy DNS is the `dns` role of the single static `sb-gateway` Go binary. It
  keeps bounded in-memory cache/workers, coalesces duplicate lookups, reuses
  UDP/DoH/DoT connections, ages cached TTLs, and serves bounded stale data only
  after an upstream failure. Apply restarts this component only when its
  generated artifact really changed; an idle router performs no DNS reload polling.
- The `agent` role samples Xray/nft client counters outside the request-serving API,
  persists the complete dashboard snapshot atomically, and drops from a
  30-second foreground cadence to five minutes when the overview is closed.
  The same process owns selector health/hysteresis. It consumes renderer-
  normalized candidate groups, preserves the selected route across restarts,
  and changes an Xray selector only after the configured confirmations.
  Counter polling never changes routing state.
- Trusted catalog cards retain recursive upstream dependencies and narrow
  reviewed release fallbacks. Binance ships as a built-in card and keeps its
  website, official API domains, and AWS WAF token host on the card's selected
  egress instead of routing shared AWS/CloudFront infrastructure globally.
  The Russian telecom card similarly pins `sibset.ru`, `sibseti.ru`,
  `lk.sibseti.ru`, and `211.ru` while its broader catalog continues to refresh
  daily.
- QUIC compatibility for service cards is an explicit, off-by-default switch.
  When enabled it rejects only matched UDP/443 before the same selected
  direct/VPN/Reverse route, allowing normal HTTPS/TCP retry without changing
  the card's egress or unrelated QUIC.
- Runtime artifacts equal to the live files skip validation, publication,
  restart, and process readiness. Large comparisons, atomic copies, and hashes
  are streamed to avoid transient whole-file RAM duplication.
- Local managed clients choose WAN fail-open or LAN-only fail-closed for a
  container outage. Remote VLESS/Hysteria users always fail closed and never
  receive ordinary WAN as an implicit fallback.
- In `VLESS + WAN`, selected service cards use WAN and the remaining traffic
  uses the selected VPN policy. In `WAN + VLESS`, the same cards use the VPN
  policy and the remaining traffic uses WAN. The VPN side can contain provider
  VLESS/Hysteria nodes, Reverse VLESS, and RouterOS WireGuard exits. With no
  service cards, only the base route applies. WAN and VPN use isolated DNS
  lanes, so an upstream DNS connection follows the same selector as data.
- A selected RouterOS WireGuard interface is prepared automatically with an
  isolated `sb-wg-*` table and a synthetic SB Gateway source identity. The
  main MikroTik default route is not replaced, and the peer's original
  `allowed-address` value is retained for restoration.

## CDN, direct ingress, and subscriptions

Each CDN transport has one protocol template and one or more independent CDN
deployments. Every deployment can use its own distribution hostname, client
SNI, origin hostname/port, TLS profile, origin protection, and publication
flag. Direct REALITY transports are not CDN transports and use their own
SNI/handshake target and X25519 material.

TLS profiles support uploaded PEM pairs, automatic ACME issuance, and a local
ECDSA `MyRootCA` with a ten-year leaf for one concrete SNI. The local mode is
intended for TLS-pinned clients and rotates only on an explicit action or SNI
change.

The client subscription uses one opaque random path without `sub`,
`subscription`, or `links`. The UI exposes three publication scenarios:

1. through CDN, using either a new subscription hostname or an already
   configured CDN deployment;
2. direct HTTPS on the MikroTik WAN;
3. both CDN and direct HTTPS, with a selectable primary address.

Several CDN hostnames and the subscription can share public TCP/443 through
TLS SNI and HTTP path routing. A direct HTTPS subscription consumes its chosen
WAN TCP port and therefore cannot share the same address/port with a direct
REALITY listener. The validator reports such conflicts before Apply.

The same opaque subscription URL negotiates a URI/base64 fallback, a complete
Xray or sing-box JSON profile, or a Mihomo YAML profile. Complete profiles can carry the
selected service exceptions, split encrypted DNS, client-side node fallback,
conservative ad blocking, and local-network preservation. LAN authorization is
still enforced by the remote user's **LAN access** profile on SB Gateway; a
client profile cannot grant itself access.

No standalone public decoy website or TCP/80 listener is created. Unknown SNI
is rejected. Unknown paths on configured TLS/CDN hostnames receive a neutral
JSON 404. Direct REALITY can either retain an external handshake target or use
the same managed API cover on a selected local certificate; Hysteria 2 uses the
managed JSON cover by default for unauthorized HTTP/3 probes.

## Client activity and backups

The overview shows compact local and remote client rows with current uplink,
downlink, monthly traffic, last activity, and an `A` marker for an active
client. Remote counters come from the local Xray StatsService. Local counters
come from an isolated counter-only nftables table; it never accepts, drops,
marks, NATs, redirects, or inspects packet payloads.

Application recovery archives use the encrypted `.sbgw` format. The current
panel password is used as the encryption secret; there is no separate backup
password. At most three current archives are retained on the external storage;
up to three RouterOS Files mirrors are maintained asynchronously on a
best-effort basis and never block an update. Archives can be created,
downloaded, uploaded, and restored from the Web UI. Restore asks for the
password because the archive
must be decrypted; image update and full uninstall require only the logged-in
session and one explicit checkbox.

## Image installation and update

The maintainer build command creates a versioned single-platform Docker image
archive plus checksum/manifest evidence:

```powershell
.\scripts\build-routeros-bundle.ps1
```

The one-time WebFig bootstrap uses the verified bundle. A later Web UI update
requires only one RouterOS-compatible `linux/arm64` `.tar`: the panel streams
and verifies SHA-256, image metadata, lifecycle protocol, and the declared
configuration-schema range itself. A candidate is accepted for a direct
skipped-release update only when its minimum schema includes the schema used by
the installed release. No second image and no
`.sha256` upload are required. RouterOS keeps the previous stopped container
during probation and restores it automatically if the candidate fails. After
success, the previous container, temporary root, uploaded archive, worker, and
temporary veth are removed so exactly one SB Gateway container remains.

## Development checks

```sh
make validate
go build ./cmd/...
npm ci --ignore-scripts
npm run lint
npm run build
npm run build:static
```

Build checks do not replace validation on the target MikroTik and the
administrator's external nodes.

## Documentation

`README.md`, `README-RU.md`, `PRODUCT.md`, `DESIGN.md`, and the current files
under `docs/` define the maintained product contract. The supported public
release baseline and public history start with 1.6.17.

- [Полное русское руководство](README-RU.md)
- [Installation](docs/INSTALL.md)
- [Установка](docs/INSTALL-RU.md)
- [Product contract](PRODUCT.md)
- [Visual design system](DESIGN.md)
- [Web UI](docs/WEB-UI.md)
- [Клиенты, маршруты и подписки](docs/CLIENTS.md)
- [Расширенная эксплуатация и восстановление](docs/OPERATIONS.md)
- [RouterOS](docs/ROUTEROS.md)
- [Архитектура](docs/ARCHITECTURE.md)
- [CDN и Cloudflare](docs/CLOUDFLARE.md)
- [Безопасность](docs/SECURITY.md)
- [Диагностика](docs/TROUBLESHOOTING.md)
- [История изменений](CHANGELOG.md)

## License

Copyright (C) 2026 [Ati054](https://github.com/Ati054)
<ati054@tutamail.com>.

SB Gateway is free software licensed under the GNU Affero General Public
License, version 3 or any later version. See [LICENSE](LICENSE). SPDX metadata
for the repository is maintained in [.reuse/dep5](.reuse/dep5).
