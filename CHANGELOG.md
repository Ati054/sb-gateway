# Changelog

## 1.6.17

## Русский

### Описание

SB Gateway — локальный шлюз и панель управления для MikroTik RouterOS 7. Он
работает в одном ARM64-контейнере, направляет выбранный трафик локальных и
удалённых клиентов через управляемые выходы и сохраняет существующую сетевую
конфигурацию MikroTik.

Версия 1.6.17 — первая публичная версия и начало поддерживаемой публичной
истории проекта.

### Основные возможности

- Маршрутные листы для отдельного устройства, всей LAN/Wi-Fi и удалённых
  клиентов с собственным порядком основных и резервных выходов.
- VLESS, REALITY, WebSocket, gRPC, HTTPUpgrade, XHTTP и Hysteria 2; выбранные
  WireGuard-интерфейсы MikroTik и Reverse VLESS могут использоваться как
  управляемые выходы.
- Kernel TPROXY, раздельная DNS-политика и сервисные правила без глобальной
  замены default route MikroTik.
- Подписки, стабильная идентификация узлов, фоновые проверки резервов, быстрый
  переход на известный исправный выход и защита от лишних переключений при
  общей деградации WAN или DNS.
- Безопасное применение конфигурации с preflight-проверками, резервной копией,
  RouterOS Safe Mode и автоматическим откатом.
- Веб-интерфейс для настройки, мониторинга, журналов, резервных копий,
  сертификатов и обновления контейнера с проверкой SHA-256 и видимым состоянием
  выполнения.

### Установка

Для чистой установки используйте
`sb-gateway-1.6.17-routeros-bundle.zip` и инструкцию
[INSTALL-RU.md](../INSTALL-RU.md).

Для замены образа загрузите `sb-gateway-1.6.17-linux-arm64.tar` в разделе
**Эксплуатация → Обновление контейнера**. Панель проверит архитектуру, версию и
SHA-256 до остановки действующего контейнера, сохранит предыдущий образ для
отката и вернёт управляемый трафик после подтверждения готовности.

### Требования и совместимость

- Первая поддерживаемая публичная версия: `1.6.17`.
- Платформа: `linux/arm64`.
- RouterOS 7 с совпадающей версией пакета `container`.
- Xray-core `26.9.9`.

### Проверка релиза

Перед публикацией сборка проходит unit/UI-тесты, проверку публичной границы,
ARM64-сборку, RouterOS dry-run всех установочных скриптов и полный цикл
обновления, отката, запуска и маршрутизации на изолированном виртуальном
MikroTik CHR. Контрольные суммы публикуются вместе с артефактами.

## English

### Overview

SB Gateway is a local gateway and management panel for MikroTik RouterOS 7. It
runs in a single ARM64 container, routes selected traffic from local and remote
clients through managed egress paths, and preserves the existing MikroTik
network configuration.

Version 1.6.17 is the first public release and the start of the supported public
project history.

### Key capabilities

- Route lists for an individual device, the entire LAN/Wi-Fi, and remote
  clients, each with an ordered set of primary and reserve egress paths.
- VLESS, REALITY, WebSocket, gRPC, HTTPUpgrade, XHTTP, and Hysteria 2; selected
  MikroTik WireGuard interfaces and Reverse VLESS can be used as managed egress
  paths.
- Kernel TPROXY, policy-specific DNS, and service rules without replacing the
  MikroTik default route globally.
- Subscriptions, stable node identity, background reserve health checks, fast
  selection of a known healthy egress, and anti-flap protection during shared
  WAN or DNS degradation.
- Safe configuration apply with preflight checks, backup, RouterOS Safe Mode,
  and automatic rollback.
- A web interface for configuration, monitoring, logs, backups, certificates,
  and container updates with SHA-256 validation and visible operation status.

### Installation

For a clean installation, use
`sb-gateway-1.6.17-routeros-bundle.zip` and follow
[INSTALL.md](../INSTALL.md).

To replace the image, upload `sb-gateway-1.6.17-linux-arm64.tar` from
**Operations → Container update**. The panel validates architecture, version,
and SHA-256 before stopping the active container, retains the previous image
for rollback, and restores managed traffic after readiness is confirmed.

### Requirements and compatibility

- First supported public version: `1.6.17`.
- Platform: `linux/arm64`.
- RouterOS 7 with the matching `container` package.
- Xray-core `26.9.9`.

### Release verification

Before publication, the build passes unit and UI tests, public-boundary checks,
an ARM64 build, RouterOS dry-runs of every installation script, and a complete
update, rollback, startup, and routing cycle on an isolated virtual MikroTik
CHR. Checksums are published with the artifacts.
