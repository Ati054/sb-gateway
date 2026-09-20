# Changelog

## 1.6.18

## Русский

### Описание

Версия 1.6.18 исправляет завершение защищённого Apply и приводит таблицу
качества узлов к порядку маршрутного листа.

### Изменения

- Control plane снимает RouterOS rollback-scheduler до публикации `active.json`
  и runtime LKG. Ошибка снятия guard блокирует Finalize, запускает сохранённый
  rollback и оставляет scheduler повторной страховкой.
- API и панель различают подтверждённый откат, ожидаемое восстановление и
  неподтверждённое состояние. Панель не предлагает повторный Apply, пока итог
  операции требует проверки.
- `active.json` служит единственной точкой фиксации. Ошибка записи производных
  LKG/metadata запускает последующее восстановление документов без отката
  работающего Xray.
- Таблица **Качество узлов** показывает приоритетный маршрут в настроенном
  порядке. Режим URLTest сохраняет сортировку по измеренному качеству.
- Публичные исходники содержат очищенные Go- и browser-регрессии. Release CI
  запускает их вместе со сборкой и проверкой публичной границы.

### Установка и обновление

Для чистой установки используйте `sb-gateway-1.6.18-routeros-bundle.zip` и
[инструкцию](../INSTALL-RU.md).

Для обновления работающей установки загрузите
`sb-gateway-1.6.18-linux-arm64.tar` в разделе
**Эксплуатация → Обновление контейнера**. Панель проверит архитектуру, версию и
SHA-256 до остановки текущего контейнера.

### Проверка релиза

Перед публикацией команда проекта выполняет Go- и browser-тесты, ESLint,
production-сборку интерфейса, проверку публичного дерева, ARM64-сборку,
RouterOS dry-run и цикл обновления на изолированном MikroTik CHR.

## English

### Overview

Version 1.6.18 fixes the protected Apply finalization path and aligns the node
quality table with route-list priority.

### Changes

- The control plane disarms the RouterOS rollback scheduler before publishing
  `active.json` and the runtime LKG. A disarm failure blocks Finalize, runs the
  saved rollback, and keeps the scheduler as a second recovery attempt.
- The API and Web UI distinguish a completed rollback, pending recovery, and
  an unconfirmed final state. The UI withholds retry guidance until the
  operation state has been checked.
- `active.json` is the sole application commit point. A derivative LKG or
  metadata write failure schedules document repair without reverting the live
  Xray configuration.
- The **Node quality** table follows configured order for priority routes.
  URLTest routes retain quality-based ranking.
- Public source archives include sanitized Go and browser regressions. Release
  CI runs them with build and public-boundary checks.

### Installation and update

For a clean installation, use `sb-gateway-1.6.18-routeros-bundle.zip` and the
[installation guide](../INSTALL.md).

To update an existing installation, upload
`sb-gateway-1.6.18-linux-arm64.tar` under
**Operations → Container update**. The panel checks architecture, version, and
SHA-256 before it stops the current container.

### Release verification

Before publication, the project runs Go and browser tests, ESLint, the
production UI build, public-tree verification, the ARM64 build, RouterOS
dry-run checks, and an update cycle on an isolated MikroTik CHR.
