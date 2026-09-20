# Install SB Gateway 1.6.18

This guide covers the first installation on an ARM64 MikroTik running
RouterOS 7. Use the matching Russian guide if needed:
[INSTALL-RU.md](INSTALL-RU.md).

## Requirements

- ARM64 MikroTik with RouterOS 7 and the matching `container` package.
- USB SSD with enough space for the image, container root, data, logs, and
  recovery archives. Do not place the container on internal flash.
- Wired access from an administrator computer on a trusted management LAN.
- A RouterOS certificate for the `www-ssl` service and one unused management
  TCP port.
- The release files listed below.

Record the current RouterOS version and channel before changing the router.
The `container` package version must match RouterOS.

## Release files

Download these assets from GitHub Release `v1.6.18`:

- `sb-gateway-1.6.18-routeros-bundle.zip`
- `sb-gateway-1.6.18-routeros-bundle.zip.sha256`

The bundle contains:

- `sb-gateway-1.6.18-linux-arm64.tar`
- `sb-gateway-1.6.18-linux-arm64.tar.sha256`
- `sb-gateway-1.6.18-linux-arm64.manifest.json`
- the `routeros/` installation scripts
- this installation guide in English and Russian

Verify the bundle before extracting it.

PowerShell:

```powershell
(Get-FileHash .\sb-gateway-1.6.18-routeros-bundle.zip -Algorithm SHA256).Hash
Get-Content .\sb-gateway-1.6.18-routeros-bundle.zip.sha256
```

Linux or macOS:

```sh
sha256sum -c sb-gateway-1.6.18-routeros-bundle.zip.sha256
```

After extraction, verify the container archive too:

```sh
sha256sum -c sb-gateway-1.6.18-linux-arm64.tar.sha256
```

The expected container SHA-256 is:

```text
56fda6f5c16d3bb86233ad7091c4ddbe1222dc1592efd7318443b19202ea420f
```

## Prepare RouterOS

1. Connect the administrator computer by Ethernet to the trusted management
   LAN. Keep local physical access to the router during installation.
2. Create and download a RouterOS binary backup and a text export without
   sensitive values.
3. Confirm the RouterOS architecture and package versions:

   ```routeros
   /system/resource/print
   /system/package/print
   ```

4. Enable container mode. RouterOS may require a physical confirmation and a
   reboot:

   ```routeros
   /system/device-mode/update container=yes
   ```

5. Connect and format the USB SSD according to the RouterOS storage guide.
   Create `usb1/sb-gateway` or another dedicated project directory.
6. Configure `www-ssl` with a valid certificate and an unused management port.
   Limit **Available From** to the management network and the container address.
   Do not expose RouterOS management services to the Internet.

## Configure `variables.rsc`

Copy `routeros/variables.example.rsc` to `variables.rsc`. Keep this file
private. Set at least the following values:

- `SB_IMAGE_FILE`
- `SB_STORAGE_ROOT` and `SB_ROOT_DIR`
- router, container, and TPROXY addresses
- managed clients and internal networks
- management source networks and ingress interfaces
- RouterOS REST port and certificate name
- temporary RouterOS API password

Review every example network. Set `SB_ADDRESSES_CONFIRMED=true` only after the
addresses match the router. The default image and root paths for this release
are:

```routeros
:global "SB_IMAGE_FILE" "usb1/sb-gateway/sb-gateway-1.6.18-linux-arm64.tar"
:global "SB_ROOT_DIR" "usb1/sb-gateway/root-1.6.18"
```

## Upload and install

Upload these files to the same RouterOS directory:

```text
usb1/sb-gateway/
  bootstrap.rsc
  cloudflare-update.rsc
  fasttrack-patch.rsc
  install.rsc
  preflight.rsc
  variables.rsc
  watchdog.rsc
  webfig-bootstrap.rsc
  sb-gateway-1.6.18-linux-arm64.tar
```

Copy the contents of the bundle's `routeros/` directory, not the directory
itself. Keep `variables.rsc` beside `bootstrap.rsc`.

Run one command in WebFig Terminal:

```routeros
/import file-name=usb1/sb-gateway/bootstrap.rsc
```

The bootstrap script checks every required file before making changes. It then
runs preflight, creates the dedicated REST account, checks FastTrack, installs
the container, and creates the health watchdog. After the image is extracted
successfully, it removes the local `.tar`, private `variables.rsc`, and one-shot
installer `.rsc` files; `cloudflare-update.rsc` remains as a separate optional
tool. Managed clients continue to use the normal WAN until their selected routes
pass readiness checks.

Follow installation messages if needed:

```routeros
/log/print without-paging where message~"SB-GATEWAY"
```

## Finish setup in the Web UI

Wait for the container to reach `running` or `healthy`:

```routeros
/container/print detail where comment="SB-GATEWAY container"
```

Open the panel from the management LAN. The default address is:

```text
https://172.31.255.2:9443
```

The first-launch wizard asks you to:

1. create the panel administrator account;
2. upload a current RouterOS export without sensitive values;
3. confirm the RouterOS, container, TPROXY, and DNS addresses;
4. select trusted LAN and VPN interfaces;
5. store RouterOS REST credentials in the encrypted secret store;
6. configure routes, nodes, certificates, and client policies;
7. run Check and review the generated plan before Apply.

Successful bootstrap removes the private `variables.rsc` automatically. If the
installation stops early, remove it manually after diagnosis. Keep an encrypted
offline copy if you need it for recovery.

## Verify the installation

Check the container, watchdog, and diversion gate:

```routeros
/container/print detail where comment="SB-GATEWAY container"
/system/scheduler/print detail where name="SB-GATEWAY-health-watchdog"
/ip/firewall/mangle/print detail where comment="SB-GATEWAY diversion-gate"
```

The diversion gate can remain disabled until you enable a client policy and the
selected route passes health checks. RouterOS keeps ordinary WAN routing
available during startup and image update. A client configured for LAN-only
outage handling keeps that stricter policy.

## Update and recovery

Use **Operations → Container image update** for later releases. Upload the new
`linux/arm64` `.tar`; do not upload the release ZIP or the `.sha256` file into
the update form. The panel verifies the archive and retains the previous
container until the new image passes probation.

See [OPERATIONS.md](OPERATIONS.md) for backup, recovery, rollback, and removal.
Use [TROUBLESHOOTING.md](TROUBLESHOOTING.md) if preflight or readiness fails.
