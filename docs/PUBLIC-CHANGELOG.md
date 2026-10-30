# Changelog

## 1.6.89

- Исправлена проверка готовности при плавном обновлении Nginx.
- Обновлено серверное ядро Xray до 26.10.29.
- URLTest: Исправлены ошибки, улучшена стабильность.

## 1.6.88

- Исправлены прерывания соединений при плавном обновлении Nginx.
- Обновлено серверное ядро Xray до 26.10.29.
- URLTest: Исправлены ошибки, улучшена стабильность.

## 1.6.87

- Обновлено серверное ядро Xray до 26.10.29.
- URLTest: Исправлены ошибки, улучшена стабильность.

## 1.6.86

- URLTest: Исправлены ошибки, улучшена стабильность.

## 1.6.85

- Сокращено ожидание применения настроек, когда фоновая проверка неизменённых маршрутных листов ещё не завершена.
- URLTest: Исправлены ошибки, улучшена стабильность.

## 1.6.84

- Исправлен лишний откат Apply при обновлении процессов Nginx.

- Улучшена обработка прерванных служебных команд RouterOS при Apply.

- Подтверждение Apply ожидает готовности трафика после изменения служб.
- Исправлено определение результата после потери соединения с панелью.
- Плановая пауза больше не запускает лишний полный обход узлов.

- Устранено зависание полей памяти и исчезновение локальных адресов панели после Apply.
- Исправлено преждевременное завершение Apply при одновременном изменении параметров ядра и маршрутных листов.

- Крупные частичные изменения RouterOS больше не требуют повторной установки всех правил.
- Ускорено применение интервалов мониторинга без ожидания фонового обхода узлов.
- Сокращено ожидание Apply при изменении режима маршрутного листа.
- Изменения Nginx применяются плавно, без разрыва HTTP-ответа Apply.
- Исправлено подтверждение одновременных изменений маршрутизации и служебных настроек.
- URLTest: Исправлены ошибки, улучшена стабильность.
- Ускорено применение настроек при недоступности источника CDN-адресов и при повторном использовании неизменённой конфигурации.
- Устранены лишнее ожидание после планового перезапуска ядра и задержка завершения Apply при обновлении статистики.
- Применение изменённых правил завершается после подтверждённого восстановления маршрутизации.
- Исправлена очистка отслеживаемых соединений при применении настроек и обновлении.
- План точнее определяет необходимость изменений RouterOS.
- Сокращены повторяющиеся служебные предупреждения REALITY.

## 1.6.79

- URLTest: Исправлены ошибки, улучшена стабильность.
- Reduce duplicate DNS policy state and pending request memory. Coalesce compatible requests before upstream admission and isolate active work and waiting queues between resolver profiles.
- Use 32 global DNS upstream work slots by default; keep saved overrides, resolver routing and existing container memory defaults.

## 1.6.79-rc.5

- Keep active quality observations close to later survey batches, so the remaining inventory can acquire valid Delta comparisons without increasing shared cycle limits.
- Bound ordinary batches by actual probe lanes and request deadlines, avoiding a long sequential queue on a single lane. Keep saved settings, ten-second pair qualification and emergency recovery behavior.
- Verify 24-member surveys across restarts, mixed-interval policies sharing one slot, and the first complete confirmation after an incomplete nomination.
- Retain the DNS admission and memory improvements from rc.4 with unchanged core and container memory defaults.

## 1.6.79-rc.4

- Keep actual UDP DNS request lengths instead of retaining a maximum-sized buffer for each pending request.
- Share compatible DNS lookups before upstream admission, with separate bounded duplicate waiters and retained request bytes.
- Use 32 global DNS work slots and isolate a single resolver profile to half of active work and unique pending capacity when several profiles exist. Preserve routing, access decisions and original deadlines.
- Retain the URLTest and shared DNS policy improvements from rc.3.

## 1.6.79-rc.3

- Share identical effective DNS policies across clients while preserving resolver selection, rule order and access restrictions.
- Reduce duplicate host-only DNS routing entries and reconcile committed wiring automatically at startup.
- Retain the URLTest scheduling and Delta display improvements from rc.2 with unchanged memory defaults and probe intervals.

## 1.6.79-rc.2

- Finish a started URLTest pair within its existing slot budget without waiting for the regular quality timer. Preserve failure-recovery priority and cool overdue pairs on the normal schedule.
- Keep the last qualified Delta percentage visible between checks, with original measurement times in its tooltip and invalidation when its active baseline or endpoint changes. Route selection still requires fresh independent confirmations.
- Provide opt-in isolated HTTPS acceptance with actual per-minute request counters and controlled timing and outage scenarios.

## 1.6.79-rc.1

- Compare close-time quality observations before planned URLTest switches. Complete nominated pairs within existing probe budgets, including one-slot scheduling.
- Keep the configured latency margin, two independent confirmations, availability failover and existing memory limits unchanged.

## 1.6.78

- Reuse policy DNS answers and pending lookups across clients only after each client's access rules select the same resolver route. Preserve DNS options, transaction IDs, detour isolation and existing resource limits; start each DNS runtime with empty caches.

## 1.6.77

- Keep outgoing DoH request bodies independent of recycled DNS input buffers after early HTTP errors or cancellation, including retries.

## 1.6.76

- Update the pinned server core to Xray v26.10.21 and Go 1.27.3 with maintained gateway patches and updated TLS trust roots.
- Smooth planned URLTest selection with up to three recent full-HTTPS samples, while preserving the configured millisecond margin and separate failure handling.
- Require fresh measurements on both sides between the two planned-switch confirmations; an eligible pending nominee survives temporary rank changes.
- Align current Delta with the short latency window and identify the effective margin and sample times in switch comparisons.
- Preserve existing container memory limits and the independent exported Reverse bridge compatibility pin.

## 1.6.75

- Keep the current permitted VLESS after confirmed HTTPS timeouts when no freshly successful reserve exists, without a WAN fallback or a healthy status.
- Require a fresh online-session observation before retaining Reverse; removed or disabled nodes and explicit network/TLS failures still fail closed without a working reserve.

## 1.6.74

- Publish confirmed route selections before background quality surveys after a cold start.
- Finish image updates only after route readiness and RouterOS traffic admission are confirmed.
- Update the pinned server core to upstream Xray v26.10.17 with maintained gateway patches.
- Preserve existing memory limits and the independent exported Reverse bridge compatibility pin.

## 1.6.73

- Restore traffic after container restarts without the live-outage recovery pause.
- Complete URLTest confirmations when fast reserves trade places in the latency ranking.
- Report recurring Xray transport deprecation notices once per process.

## 1.6.72

- Reduce CPU and temporary memory use in traffic-readiness checks with bounded socket and netlink diagnostics.
- Keep deep diagnostics off the live heartbeat path and invalidate cached evidence on runtime changes.
- Return valid DNS failure responses for EDNS requests and reuse TLS sessions for encrypted DNS reconnections.
- Use 288/320 MiB for new installations without changing existing memory limits.

## 1.6.72-rc.5

- Reuse TLS sessions for encrypted DNS reconnections.

## 1.6.72-rc.4

- Reduce CPU and temporary memory use in traffic-readiness checks.
- Return valid DNS failure responses for EDNS requests.
- Use 288/320 MiB for new installations without changing existing memory limits.

## 1.6.72-rc.3

- Prevent false loss of traffic readiness while UDP connections are being created and closed.

## 1.6.72-rc.2

- Reduce periodic readiness-check overhead without weakening firewall validation.

## 1.6.72-rc.1

- Keep traffic readiness responsive during slow local system checks.
- Limit cached readiness to the current runtime and a bounded lifetime.

## 1.6.71

- Keep a failed route from disabling unrelated routes.
- Prevent command warnings from invalidating machine-readable readiness checks.

## 1.6.70

- Prevent unnecessary traffic interruptions after a transient local readiness check.

## 1.6.69

- Handle short DNS request bursts without immediately rejecting uncached queries.
- Prevent overlapping RouterOS health recovery jobs.
- Avoid repeated connection resets during fail-open operation.
- Preserve translated DNS connections during recovery.

## 1.6.68

- Reduced memory retained by completed DNS requests.
- Apply the DNS forwarding improvement automatically after image updates without changing saved settings.

## 1.6.67

- Keep cached DNS answers available while upstream queries are busy.
- Reduced DNS memory use while preserving existing domain-rule matching.
- Fixed native memory-limit changes and completion status.
- Return borrowed certificate-task memory when other container memory needs headroom.
- Clear old Xray startup readiness before starting services.

## 1.6.66

- Reduced DNS memory and garbage-collector scanning by reusing Xray's compact domain matcher.
- Preserved matching order and compatibility with existing domain rules.
- Fixed memory-limit changes and completion status across RouterOS state and path representations.

## 1.6.63

- Reduced background CPU work in telemetry, subscription reconciliation and node statistics.
- Reused idle certificate-task memory in the controller without raising container limits.
- Preserved traffic readiness during Apply when runtime artifacts remain unchanged.

## 1.6.62

- Raised Nginx connection capacity and upgraded saved limits automatically at startup.
- Added periodic size-based rotation for Xray and Nginx diagnostic logs without restarting traffic services.
- Added startup warnings for unverified streaming limits in custom saved Nginx configurations.

## 1.6.61

- Kept DNS domain rules compatible with image rollback while sharing their in-memory membership.
- Updated Xray and REALITY to pinned upstream revisions through 2026-10-14.
- Fixed gRPC channel reconnection after a completed or canceled first request and improved Hysteria cancellation and cleanup.

## 1.6.60

- Shared large domain sets across routing and DNS rules and streamed catalog updates.
- Fixed large and idle gRPC/XHTTP uploads through Nginx.
- Derived process memory budgets from container limits, reserving space for temporary tasks.

## 1.6.59

- Fixed saving Settings with the default zero recovery cooldown.
- Split panel sections while preserving drafts and one Apply across navigation.
- Added browser regression checks and simplified installation guidance.
- Retained the public release history in source archives.

## 1.6.58

- Added a WAN ping switch; related ICMP errors and required multicast/broadcast remain allowed.
- Improved Reverse status, name editing, startup recovery and connection stability.
- Improved HTTPS availability checks, URLTest reserve selection and inactive-profile certificate issuance.
- Run Apply once after upgrading to reconcile settings and RouterOS rules.

## 1.6.49

- Reduced memory use and background CPU work.
- Container startup waits for the storage it actually uses; existing installations migrate automatically.
- Preserved selected routes across Apply and improved DNS recovery and smart-home service cards.
- Added independent container memory limits and safer offline recovery.
- URLTest uses HTTPS latency instead of download-speed probes.

## 1.6.35

- Added confirmed speed-degradation failover and paired comparisons before planned URLTest switches.
- Improved reserve selection and bounded background probe work.

## 1.6.34

- Improved failover, subscription updates, node-quality display and route editors.
- Reduced false rollbacks with large GeoIP rules and preserved selected routes during rule updates.
- Kept unrelated RouterOS logging rules and existing connections intact.

## 1.6.33

- Updated the server to Xray-core 26.9.30 and fixed concurrent selector, XHTTP and certificate updates.
- Added dynamic node groups, custom routing rules, country GeoIP routes and regional service cards.
- Improved Apply recovery and rejected conflicting draft mutations without late writes.

## 1.6.27

- Reduced false switches and delays when finding a working reserve.
- Improved retry of failed speed measurements and reduced memory accumulation during subscription updates.

## 1.6.26

- Added confirmed URLTest switches based on speed gain while retaining latency limits and anti-flap protection.
- Corrected the panel's HTTPS median threshold label.

## 1.6.25

- A single failed HTTPS test site no longer marks a VLESS node unavailable.
- Preserved RouterOS logging exclusions and fixed final-line handling in optional CDN feed updates.

## 1.6.24

- Added immediate confirmation probes after connection failures and a dedicated route-switch log.
- Improved bounded reserve searches and discarded stale health evidence after node changes.

## 1.6.22

- Continued searching untested reserves during complete outages.
- Safely cleaned obsolete subscription snapshots and retired handlers after confirmed selection.

## 1.6.21

- Added global route-monitor settings and aligned the quality table with priority order.
- Preserved existing configuration, secrets and node statistics across updates.

## 1.6.20

- Added recovery for an interrupted first Apply and serialized manual rollback with other management operations.

## 1.6.19

- Improved recovery after interrupted Apply and container updates without starting duplicate operations.
- Rejected invalid subscription responses while retaining the last working configuration.

## 1.6.18

- Fixed protected Apply finalization and distinguished confirmed rollback from an unknown operation result.
- Kept priority-route quality rows in their configured order.

## 1.6.17

- First public release: browser-managed routing, subscriptions, local and remote clients, certificates and container updates.
- Added protected Apply with backup and rollback for supported ARM64 RouterOS containers.
