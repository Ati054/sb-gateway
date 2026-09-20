import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

const text = (path) => readFile(new URL(`../${path}`, import.meta.url), "utf8");
const packageVersion = JSON.parse(await text("package.json")).version;
const escapedPackageVersion = packageVersion.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

test("mandatory Claude and Antigravity candidate packs stay narrow and complete", async () => {
  const catalog = JSON.parse(await text("internal/rulesets/service-packs.json"));
  const packs = Object.fromEntries(catalog.map((pack) => [pack.id, pack]));

  assert.deepEqual(packs.claude.fallback_domains, [
    "claude.ai",
    "anthropic.com",
    "claudeusercontent.com",
  ]);
  assert.deepEqual(packs.antigravity.fallback_domains, [
    "antigravity.google",
    "aiplatform.googleapis.com",
    "generativelanguage.googleapis.com",
    "servicedirectory.googleapis.com",
  ]);
  for (const id of ["claude", "antigravity"]) {
    assert.equal(packs[id].broad, false);
    assert.equal(packs[id].always_direct, false);
    assert.equal(packs[id].update_mode, "bundled-official");
  }
  assert.ok(!packs.antigravity.fallback_domains.includes("google.com"));
  assert.ok(!packs.antigravity.fallback_domains.includes("googleapis.com"));
});

test("ARM64 image builds pinned Xray and static UI", async () => {
  const dockerfile = await text("Dockerfile");
  assert.match(dockerfile, /ARG XRAY_VERSION=26\.9\.9/);
  assert.match(dockerfile, /52a412d9e2f5c2a5142b1b4e2ab3771dacb8b120/);
  assert.match(dockerfile, /XRAY_GO_IMAGE=golang:1\.27\.1-alpine@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125/);
  assert.match(dockerfile, /FROM --platform=\$BUILDPLATFORM \$\{XRAY_GO_IMAGE\} AS xray-build/);
  assert.match(dockerfile, /server can use the current validated core/);
  assert.match(dockerfile, /xray run -test -config \/tmp\/xray-build-validation\.json/);
  assert.doesNotMatch(dockerfile, /xray\.smoke\.json/);
  assert.match(dockerfile, /npm run build:static/);
  assert.doesNotMatch(dockerfile, /COPY tests |\.test\.mjs|_test\.go/);
  assert.match(dockerfile, /npm run lint/);
  assert.match(dockerfile, /COPY rulesets \.\/rulesets/);
  assert.match(dockerfile, /SB_RULESET_DIR=\/opt\/sb-gateway\/rulesets-seed/);
  assert.match(
    dockerfile,
    /HEALTHCHECK --interval=10s --timeout=10s --start-period=60s --retries=3/,
  );
  assert.doesNotMatch(dockerfile, /sing-box/i);
  const entrypoint = await text("entrypoint.sh");
  const appliance = await text("internal/appliance/run.go");
  assert.doesNotMatch(entrypoint, /ruleset_worker --prepare/);
  assert.match(entrypoint, /exec \/usr\/local\/bin\/sb-gateway appliance/);
  assert.match(appliance, /Name: "monitor"/);
  assert.doesNotMatch(dockerfile, /PYTHON_IMAGE|pip install|supervisord|uvicorn/);
});

test("Policy DNS ships as a native Go component", async () => {
  const [dockerfile, appliance, makefile, imageTool] = await Promise.all([
    text("Dockerfile"),
    text("internal/appliance/run.go"),
    text("Makefile"),
    text("cmd/routeros-image/main.go"),
  ]);
  assert.match(dockerfile, /AS sb-gateway-build/);
  assert.match(imageTool, /runGoReleaseChecks\(root, runtime\.GOOS\)/);
  assert.match(imageTool, /if goos != "windows"/);
  assert.match(imageTool, /commandOutput\(root, "go", append\(\[\]string\{"list"\}, targets\.\.\.\)\.\.\.\)/);
  assert.match(imageTool, /for attempt := 1; attempt <= 2; attempt\+\+/);
  assert.match(imageTool, /return \[\]string\{"\.\/cmd\/\.\.\.", "\.\/internal\/\.\.\.", "\.\/tests\/tools"\}/);
  assert.match(
    dockerfile,
    /COPY --from=sb-gateway-build \/out\/sb-gateway \/usr\/local\/bin\/sb-gateway/,
  );
  assert.match(appliance, /Name: "dns"/);
  assert.match(appliance, /policydns\.Serve/);
  assert.doesNotMatch(dockerfile, /run-policy-dns\.sh/);
  assert.match(makefile, /go-test:/);
});

test("RouterOS container uses kernel TPROXY and mount lists", async () => {
  const install = await text("routeros/install.rsc");
  const preflight = await text("scripts/preflight.sh");
  assert.match(install, /mountlists="sb-gateway-config,/);
  assert.doesNotMatch(install, /devices="\/dev\/net\/tun"/);
  assert.doesNotMatch(preflight, /\/dev\/net\/tun/);
  assert.match(install, /\/container\/mounts\/add list="sb-gateway-config"/);
  assert.doesNotMatch(install, /\/container\/mounts\/add name=/);
  assert.match(
    install,
    /\}\s*\n\s*# Apply lifecycle limits to both[\s\S]*\/container\/set \$containerId restart-policy=always restart-interval=10s[\s\S]*:local imageReady false/,
  );
  const managementAllow = install.indexOf(
    'comment="SB-GATEWAY management allow"',
  );
  const managementDeny = install.indexOf(
    'comment="SB-GATEWAY management deny"',
  );
  const managedAccept = install.indexOf(
    'comment="SB-GATEWAY managed to container"',
  );
  const containerReturn = install.indexOf(
    'comment="SB-GATEWAY container return to managed"',
  );
  const containerLanDeny = install.indexOf(
    'comment="SB-GATEWAY container LAN deny"',
    'comment="SB-GATEWAY container LAN masquerade"',
  );
  assert.ok(
    managementAllow >= 0 &&
      managementDeny > managementAllow &&
      managedAccept > managementDeny &&
      containerReturn >= 0 &&
      containerLanDeny > containerReturn,
  );
  assert.match(install, /in-interface-list="SB_MANAGEMENT_INGRESS"/);
  assert.match(
    install,
    /name="SB_MANAGEMENT_INGRESS" comment="SB-GATEWAY management ingress list"/,
  );
  assert.match(
    install,
    /\/ip\/firewall\/filter\/move \$managementAllow destination=\$managementDeny/,
  );
  assert.match(
    install,
    /\/ip\/firewall\/filter\/move \$containerManagementReturn destination=\$explicitLanAllow/,
  );
  assert.match(
    install,
    /\/ip\/firewall\/filter\/move \$containerReturn destination=\$containerManagementReturn/,
  );
  assert.match(
    install,
    /in-interface=\$"SB_BRIDGE" src-address=\$"SB_CONTAINER_IP" dst-address=\$"SB_ROUTER_IP" protocol=tcp dst-port=\$"SB_ROUTEROS_REST_PORT"/,
  );
  assert.match(install, /:local remoteManagementPorts .*\/ip\/service\/get/);
  assert.match(install, /comment="SB-GATEWAY RouterOS remote full management allow"/);
  assert.match(install, /obsoleteComment in=\{"SB-GATEWAY RouterOS www-ssl management allow";"SB-GATEWAY RouterOS www-ssl deny"\}/);
  assert.doesNotMatch(install, /\/ip\/service\/(?:set|enable|disable)/);
  assert.match(
    install,
    /set \$routerManagementDeny chain="sb-gateway-input" action=drop src-address=\$"SB_CONTAINER_IP"/,
  );
  assert.match(
    install,
    /dst-address-list="SB_MANAGED_CLIENTS" connection-state=established,related/,
  );
  assert.doesNotMatch(install, /established,related,untracked/);
});

test("Xray transit uses kernel TPROXY and a dedicated policy table", async () => {
  const [routing, runner] = await Promise.all([
    text("scripts/configure-transparent-routing.sh"),
    text("scripts/run-xray.sh"),
  ]);
  assert.match(routing, /meta l4proto tcp tproxy to :\$tproxy_port/);
  assert.match(routing, /meta l4proto udp tproxy to :\$tproxy_port/);
  assert.match(routing, /ip route replace local default dev lo table "\$route_table"/);
  assert.match(routing, /fwmark "\$tproxy_mark" table "\$route_table"/);
  assert.match(routing, /write_ipv4_setting ip_forward 1/);
  assert.doesNotMatch(routing, /default dev "\$tun_dev"|gvisor|sb-tun0/);
  assert.match(runner, /configure-transparent-routing\.sh apply/);
  assert.match(runner, /startup_deadline=\$\(\(startup_started \+ startup_timeout_seconds\)\)/);
  assert.match(runner, /tcp-ready --address "\$xray_api_server" --timeout 200ms/);
});

test("RouterOS bootstrap accepts a local ARM64 archive and waits for extraction", async () => {
  const [variables, preflight, install, bundle, wrapper] = await Promise.all([
    text("routeros/variables.example.rsc"),
    text("routeros/preflight.rsc"),
    text("routeros/install.rsc"),
    text("internal/imagebundle/archive.go"),
    text("scripts/build-routeros-bundle.ps1"),
  ]);
  assert.match(variables, /:global "SB_IMAGE_SOURCE" "file"/);
  assert.match(
    variables,
    new RegExp(`sb-gateway-${escapedPackageVersion}-linux-arm64\\.tar`),
  );
  assert.match(preflight, /\/file\/find where name=\$"SB_IMAGE_FILE"/);
  assert.match(
    preflight,
    /\(\$containerMode != true\) && \(\$containerMode != "yes"\)/,
  );
  assert.match(variables, /:global "SB_BYPASS_ENDPOINTS" \[:toarray ""\]/);
  assert.doesNotMatch(variables, /:global "SB_[A-Z0-9_]+"\s+\{\}/);
  assert.match(install, /\/container\/add file=\$"SB_IMAGE_FILE"/);
  assert.match(install, /\/container\/add remote-image=\$"SB_IMAGE"/);
  assert.match(install, /\/container\/get \$containerId stopped/);
  assert.match(install, /\$containerCreated = false/);
  assert.match(install, /\$legacyContainerStatus = "stopped"/);
  assert.match(install, /:set shouldStart \[\/container\/get \$containerId stopped\]/);
  assert.match(install, /\$imageArch != "arm64"/);
  assert.match(
    install,
    /timed out waiting for container image extraction/,
  );
  assert.match(bundle, /manifest\.json/);
  assert.match(bundle, /sha256\.New/);
  assert.match(bundle, /RouterOS-compatible/);
  assert.match(wrapper, /\.\/cmd\/routeros-image/);
  assert.doesNotMatch(wrapper, /python/i);
});

test("setup mode cannot falsely advertise data-plane readiness", async () => {
  const [entrypoint, runner, appliance, watchdog] = await Promise.all([
    text("entrypoint.sh"),
    text("scripts/run-xray.sh"),
    text("internal/appliance/run.go"),
    text("internal/watchdog/watchdog.go"),
  ]);
  assert.match(entrypoint, /session-signing-key/);
  assert.match(entrypoint, /bootstrap\.pem/);
  assert.match(entrypoint, /-checkip "\$bootstrap_ip"/);
  assert.doesNotMatch(entrypoint, /SB_CONTAINER_IP:-172\./);
  assert.match(runner, /while \[ ! -s "\$config" \]; do/);
  assert.match(runner, /xray run -test -config "\$config"/);
  assert.match(
    runner,
    /ip rule add priority 1000 from "\$container_ip\/32" table 1001/,
  );
  assert.doesNotMatch(runner, /SB_CONTAINER_IP:-172\./);
  assert.match(appliance, /XrayRunner/);
  assert.match(watchdog, /awaiting_configuration/);
  assert.match(watchdog, /processRunning\("xray"\)/);
  assert.match(watchdog, /local default dev lo/);
  assert.match(watchdog, /tproxy_policy_rule/);
  assert.match(watchdog, /procListeningPorts\("tcp"\)/);
  assert.match(watchdog, /procListeningPorts\("udp"\)/);
  assert.doesNotMatch(watchdog, /ss -H -ln/);
  assert.match(watchdog, /"run", "-test", "-config"/);
  assert.doesNotMatch(watchdog, /sing-box/i);
  assert.match(watchdog, /\/config\/generated\/watchdog\.env/);
  assert.match(watchdog, /pruneRestarts/);
  assert.match(watchdog, /r\.restarts >= current\.restartBudget/);
  assert.match(watchdog, /restart_budget_exhausted/);
  assert.match(watchdog, /staying alive for diagnostics/);
  assert.match(watchdog, /publishLease/);
  assert.match(watchdog, /defer r\.clearLease\(\)/);
  assert.match(appliance, /Name: "monitor"/);
});

test("RouterOS boot starts fail-open and reloads persisted watchdog settings", async () => {
  const watchdog = await text("routeros/watchdog.rsc");
  assert.match(watchdog, /SB-GATEWAY-watchdog-config/);
  assert.match(watchdog, /9080\/traffic-ready/);
  assert.match(watchdog, /SB-GATEWAY-startup-fail-open/);
  assert.match(watchdog, /sbStartupSafety true/);
  assert.match(watchdog, /\$sbStartupSafety = true/);
  assert.match(watchdog, /interval=0s start-time=startup/);
  assert.match(
    watchdog,
    /\/system\/script\/run SB-GATEWAY-watchdog-config/,
  );
  const startup = watchdog.indexOf(
    '/system/script/add name="SB-GATEWAY-startup-fail-open"',
  );
  const periodic = watchdog.indexOf(
    '/system/script/add name="SB-GATEWAY-health-watchdog"',
  );
  assert.ok(startup >= 0 && periodic > startup);
});

test("boot restores a validated last-known-good Nginx config", async () => {
  const entrypoint = await text("entrypoint.sh");
  assert.doesNotMatch(entrypoint, /xray-normalize-transports/);
  assert.match(
    entrypoint,
    /SB_NGINX_LKG_CONFIG:-\$\{SB_RUNTIME_CANDIDATE_DIR\}\/runtime-lkg\/nginx\.conf/,
  );
  assert.doesNotMatch(entrypoint, /\/data\/last-known-good\/nginx\.conf/);
  assert.match(entrypoint, /\[ -s "\$lkg" \] && \[ -s "\$selected_config" \]/);
  assert.match(
    entrypoint,
    /grep -Eq '\^# sb-gateway-nginx-schema: \(2\|3\)\$' "\$lkg" \|\| return 1/,
  );
  assert.match(entrypoint, /nginx -t -c "\$candidate" -p \//);
  assert.match(entrypoint, /mv "\$candidate" "\$runtime_config"/);
  assert.match(entrypoint, /if ! restore_lkg_nginx; then/);
});

test("Nginx separates public and management surfaces without logging paths", async () => {
  const nginx = await text("templates/nginx.conf.j2");
  const managementOffset = nginx.indexOf("listen 9443 ssl");
  assert.ok(managementOffset > 0);
  assert.doesNotMatch(nginx, /auth_basic/);
  assert.match(nginx, /^# sb-gateway-nginx-schema: 3/m);
  assert.match(nginx, /server_names_hash_bucket_size 64/);
  assert.match(nginx, /client_body_buffer_size 256k/);
  assert.match(
    nginx,
    /client_body_temp_path \/run\/sb-gateway\/nginx-client-body 1 2/,
  );
  const staticAssetsOffset = nginx.indexOf(
    "location ^~ /_next/static/",
    managementOffset,
  );
  const bootstrapOffset = nginx.indexOf(
    "location = /api/v1/auth/bootstrap",
    managementOffset,
  );
  assert.ok(
    staticAssetsOffset > managementOffset && staticAssetsOffset < bootstrapOffset,
  );
  const staticAssetsBlock = nginx.slice(staticAssetsOffset, bootstrapOffset);
  assert.match(staticAssetsBlock, /try_files \$uri =404/);
  assert.match(
    staticAssetsBlock,
    /Cache-Control "public, max-age=31536000, immutable"/,
  );
  assert.doesNotMatch(staticAssetsBlock, /no-store/);
  const uploadOffset = nginx.indexOf(
    "location = /api/v1/lifecycle/image-upload",
    managementOffset,
  );
  const uploadGenericApiOffset = nginx.indexOf("location /api/", uploadOffset);
  assert.ok(uploadOffset > managementOffset);
  assert.match(nginx.slice(uploadOffset, uploadGenericApiOffset), /client_max_body_size 2048m/);
  assert.match(nginx.slice(uploadOffset, uploadGenericApiOffset), /proxy_request_buffering off/);
  const imageUpdateOffset = nginx.indexOf(
    "location = /api/v1/lifecycle/image-update",
    uploadOffset,
  );
  assert.ok(imageUpdateOffset > uploadOffset && imageUpdateOffset < uploadGenericApiOffset);
  assert.match(nginx.slice(imageUpdateOffset, uploadGenericApiOffset), /proxy_read_timeout 900s/);
  assert.match(nginx.slice(imageUpdateOffset, uploadGenericApiOffset), /proxy_send_timeout 900s/);
  assert.doesNotMatch(nginx.slice(0, managementOffset), /location \/api\//);
  assert.match(nginx.slice(0, managementOffset), /access_log off/);
  assert.match(nginx.slice(0, managementOffset), /\$\{DEFAULT_PUBLIC_SERVER\}/);
  assert.doesNotMatch(nginx, /-f \/run\/sb-gateway\/router-ready/);
  assert.equal(
    (
      nginx.match(
        /proxy_pass http:\/\/127\.0\.0\.1:8080\/api\/health\/router-ready/g,
      ) ?? []
    ).length,
    1,
  );
  assert.match(
    nginx,
    /proxy_pass http:\/\/127\.0\.0\.1:8080\/api\/health\/traffic-ready/,
  );
  assert.match(nginx, /\$\{STATUS_SERVER\}/);
  const genericApiOffset = nginx.indexOf("location /api/", bootstrapOffset);
  const longOperationsOffset = nginx.indexOf(
    "location ~ ^/api/v1/drafts/(apply|rollback)$",
    bootstrapOffset,
  );
  const recoveryRestoreOffset = nginx.indexOf(
    "location = /api/v1/recovery/restore",
    bootstrapOffset,
  );
  assert.ok(bootstrapOffset > managementOffset);
  assert.ok(longOperationsOffset > bootstrapOffset);
  assert.ok(longOperationsOffset < genericApiOffset);
  assert.ok(recoveryRestoreOffset > bootstrapOffset);
  assert.ok(recoveryRestoreOffset < genericApiOffset);
  assert.ok(genericApiOffset > bootstrapOffset);
  assert.match(
    nginx.slice(bootstrapOffset, genericApiOffset),
    /Authorization "Bearer \$\{MANAGEMENT_TOKEN\}"/,
  );
  assert.match(
    nginx.slice(longOperationsOffset, genericApiOffset),
    /Authorization \$http_authorization/,
  );
  assert.match(
    nginx.slice(longOperationsOffset, genericApiOffset),
    /proxy_read_timeout 900s/,
  );
  assert.match(
    nginx.slice(longOperationsOffset, genericApiOffset),
    /proxy_send_timeout 900s/,
  );
  assert.match(
    nginx.slice(recoveryRestoreOffset, genericApiOffset),
    /proxy_read_timeout 300s/,
  );
  assert.match(
    nginx.slice(recoveryRestoreOffset, genericApiOffset),
    /proxy_send_timeout 300s/,
  );
  assert.doesNotMatch(
    nginx.slice(genericApiOffset),
    /Bearer \$\{MANAGEMENT_TOKEN\}/,
  );
});

test("boot prepares the bounded Nginx request-body spill directory", async () => {
  const entrypoint = await text("entrypoint.sh");
  assert.match(entrypoint, /mkdir -p[\s\S]*\/run\/sb-gateway\/nginx-client-body/);
  assert.match(entrypoint, /chmod 0700 \/run\/sb-gateway\/nginx-client-body/);
  assert.match(
    entrypoint,
    /chown www-data:www-data \/logs\/nginx \/run\/sb-gateway\/nginx-client-body/,
  );
});

test("fresh boot replaces every uppercase Nginx template token", async () => {
  const [template, renderer] = await Promise.all([
    text("templates/nginx.conf.j2"),
    text("scripts/render-runtime.sh"),
  ]);
  const tokens = [...new Set(template.match(/\$\{[A-Z][A-Z0-9_]*\}/g) ?? [])];
  assert.ok(tokens.length > 0);
  for (const token of tokens) {
    assert.match(renderer, new RegExp(token.replace(/[${}]/g, "\\$&")));
  }
  assert.match(renderer, /REALITY_COVER_SERVER=""/);
});

test("Cloudflare updater validates and stages IPv4 and IPv6", async () => {
  const [updater, install, renderer] = await Promise.all([
    text("routeros/cloudflare-update.rsc"),
    text("routeros/install.rsc"),
    text("internal/runtimeconfig/routeros_render.go"),
  ]);
  assert.match(updater, /https:\/\/www\.cloudflare\.com\/ips-v4/);
  assert.match(updater, /https:\/\/www\.cloudflare\.com\/ips-v6/);
  assert.match(updater, /SB_CLOUDFLARE_V4_NEXT/);
  assert.match(updater, /SB_CLOUDFLARE_V6_NEXT/);
  assert.match(updater, /keeping both current allow-lists/);
  assert.match(updater, /interval=1d start-time=03:17:00/);
  assert.doesNotMatch(updater, /\/ip\/firewall\/connection\/remove/);
  assert.doesNotMatch(updater, /\/routing\//);
  // Public ingress is generated by native Apply, not hard-coded at install.
  assert.match(renderer, /src-address-list="SB_CLOUDFLARE_V4"/);
  assert.doesNotMatch(install, /SB_CLOUDFLARE_IPV4/);
});

test("RouterOS scripts compare missing find results by type", async () => {
  const scripts = await Promise.all([
    text("routeros/uninstall.rsc"),
    text("routeros/preflight.rsc"),
    text("routeros/cloudflare-update.rsc"),
  ]);
  for (const script of scripts) {
    assert.doesNotMatch(script, /\[:find[^\r\n]*\]\s*(?:!=|=)\s*nil/);
  }
  assert.match(scripts[0], /\[:typeof \[:find \$storageRoot "\.\."\]\] != "nil"/);
});

test("destructive RouterOS cleanup uses the complete ownership prefix", async () => {
  const scripts = await Promise.all([
    text("routeros/uninstall.rsc"),
    text("routeros/rollback.rsc"),
  ]);
  for (const script of scripts) {
    assert.doesNotMatch(script, /comment~"\^SB-GATEWAY"/);
    assert.match(script, /comment~"\^SB-GATEWAY "/);
  }
});

test("fresh install positions filter jumps by RouterOS item id", async () => {
  const install = await text("routeros/install.rsc");
  assert.doesNotMatch(install, /place-before=0/);
  assert.match(install, /place-before=\[:pick \$firstForward 0 1\]/);
  assert.match(install, /place-before=\[:pick \$firstInput 0 1\]/);
});

test("single-entry RouterOS bootstrap validates the full bundle before mutation", async () => {
  const [bootstrap, webfig] = await Promise.all([
    text("routeros/bootstrap.rsc"),
    text("routeros/webfig-bootstrap.rsc"),
  ]);
  for (const artifact of ["preflight.rsc", "webfig-bootstrap.rsc", "fasttrack-patch.rsc", "install.rsc", "watchdog.rsc"]) {
    assert.match(bootstrap, new RegExp(artifact.replace(".", "\\.")));
  }
  assert.ok(
    bootstrap.indexOf(':foreach requiredFile') < bootstrap.indexOf('/import file-name=$variablesPath'),
    "the complete release bundle must be checked before variables or mutating scripts run",
  );
  assert.ok(
    bootstrap.indexOf('/preflight.rsc') < bootstrap.indexOf('/webfig-bootstrap.rsc'),
    "preflight must run before the first mutating bootstrap step",
  );
  assert.doesNotMatch(bootstrap, /cloudflare-update\.rsc/);
  assert.ok(
    bootstrap.indexOf('/watchdog.rsc') < bootstrap.indexOf(':foreach transientFile'),
    "one-shot release files must be removed only after every install stage succeeds",
  );
  for (const artifact of ["bootstrap.rsc", "install.rsc", "preflight.rsc", "variables.rsc", "watchdog.rsc", "webfig-bootstrap.rsc"]) {
    assert.match(bootstrap, new RegExp(`transientFile[\\s\\S]*${artifact.replace(".", "\\.")}`));
  }
  assert.match(bootstrap, /\/file\/remove \$imageFile/);
  assert.match(webfig, /existing dedicated REST account verified; password was not changed/);
  assert.match(webfig, /existing REST account is not restricted to the configured container \/32/);
  assert.match(webfig, /\} else=\{/);
  assert.doesNotMatch(webfig, /^\s*:return(?:\s|$)/m);
  assert.doesNotMatch(webfig, /\/user\/set[^\n]*password=/);
});

test("release separates the user panel port from RouterOS REST", async () => {
  const [defaults, variables] = await Promise.all([
    text("internal/controlplane/default-config.json"),
    text("routeros/variables.example.rsc"),
  ]);
  assert.match(defaults, /"routeros_panel_port": 17443/);
  assert.match(variables, /"SB_ROUTEROS_REST_PORT" 59443/);
  assert.doesNotMatch(variables, /"SB_ROUTEROS_REST_PORT" 17443/);
  assert.match(
    variables,
    new RegExp(`sb-gateway-${escapedPackageVersion}-linux-arm64\\.tar`),
  );
  assert.match(
    variables,
    new RegExp(`"SB_ROOT_DIR" "usb1/sb-gateway/root-${escapedPackageVersion}"`),
  );
  assert.doesNotMatch(variables, /1\.5\.10/);
});
