# Установка SB Gateway 1.6.22

Инструкция описывает первую установку на MikroTik ARM64 с RouterOS 7. Английская
версия находится в [INSTALL.md](INSTALL.md).

## Требования

- MikroTik ARM64 с RouterOS 7 и пакетом `container` той же версии.
- USB SSD для образа, root-dir, данных, журналов и архивов восстановления.
  Внутреннюю flash-память для контейнера не используйте.
- Проводное подключение компьютера администратора к доверенной management LAN.
- Сертификат RouterOS для `www-ssl` и один свободный management TCP-порт.
- Файлы релиза из следующего раздела.

До изменения роутера запишите версию и канал RouterOS. Версия пакета
`container` должна совпадать с версией RouterOS.

## Файлы релиза

Скачайте из GitHub Release `v1.6.22`:

- `sb-gateway-1.6.22-routeros-bundle.zip`
- `sb-gateway-1.6.22-routeros-bundle.zip.sha256`

В комплект входят:

- `sb-gateway-1.6.22-linux-arm64.tar`
- `sb-gateway-1.6.22-linux-arm64.tar.sha256`
- `sb-gateway-1.6.22-linux-arm64.manifest.json`
- установочные скрипты в каталоге `routeros/`
- инструкции на русском и английском языках

До распаковки проверьте контрольную сумму комплекта.

PowerShell:

```powershell
(Get-FileHash .\sb-gateway-1.6.22-routeros-bundle.zip -Algorithm SHA256).Hash
Get-Content .\sb-gateway-1.6.22-routeros-bundle.zip.sha256
```

Linux или macOS:

```sh
sha256sum -c sb-gateway-1.6.22-routeros-bundle.zip.sha256
```

После распаковки проверьте контейнер:

```sh
sha256sum -c sb-gateway-1.6.22-linux-arm64.tar.sha256
```

Ожидаемый SHA-256 контейнера:

```text
56fda6f5c16d3bb86233ad7091c4ddbe1222dc1592efd7318443b19202ea420f
```

## Подготовка RouterOS

1. Подключите компьютер администратора кабелем к доверенной management LAN.
   Во время установки сохраните физический доступ к роутеру.
2. Создайте и скачайте binary backup RouterOS и текстовый export без
   чувствительных значений.
3. Проверьте архитектуру и версии пакетов:

   ```routeros
   /system/resource/print
   /system/package/print
   ```

4. Включите container mode. RouterOS может запросить физическое подтверждение и
   перезагрузку:

   ```routeros
   /system/device-mode/update container=yes
   ```

5. Подключите и отформатируйте USB SSD по инструкции RouterOS. Создайте каталог
   `usb1/sb-gateway` или другой отдельный каталог проекта.
6. Настройте `www-ssl`: выберите сертификат и свободный management-порт. В поле
   **Available From** оставьте management-сеть и адрес контейнера. Не открывайте
   службы управления RouterOS в Интернет.

## Настройка `variables.rsc`

Скопируйте `routeros/variables.example.rsc` в `variables.rsc`. Не публикуйте
этот файл. Укажите как минимум:

- `SB_IMAGE_FILE`
- `SB_STORAGE_ROOT` и `SB_ROOT_DIR`
- адреса RouterOS, контейнера и TPROXY
- управляемые устройства и внутренние сети
- management-сети и входные интерфейсы
- порт REST RouterOS и имя сертификата
- временный пароль учётной записи RouterOS API

Проверьте каждую примерную сеть. Установите `SB_ADDRESSES_CONFIRMED=true` только
после сверки адресов с конфигурацией роутера. Стандартные пути этого релиза:

```routeros
:global "SB_IMAGE_FILE" "usb1/sb-gateway/sb-gateway-1.6.22-linux-arm64.tar"
:global "SB_ROOT_DIR" "usb1/sb-gateway/root-1.6.22"
```

## Загрузка и установка

Загрузите в один каталог RouterOS следующие файлы:

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
  sb-gateway-1.6.22-linux-arm64.tar
```

Копируйте содержимое каталога `routeros/`, а не сам каталог. Файлы
`variables.rsc` и `bootstrap.rsc` должны находиться рядом.

Выполните одну команду в WebFig Terminal:

```routeros
/import file-name=usb1/sb-gateway/bootstrap.rsc
```

Bootstrap проверит комплектность файлов, выполнит preflight, создаст отдельную
учётную запись REST, проверит FastTrack, установит контейнер и watchdog. После
успешного извлечения образа он удалит локальный `.tar`, приватный
`variables.rsc` и одноразовые установочные `.rsc`; `cloudflare-update.rsc`
останется как отдельный необязательный инструмент. До подтверждения готовности
выбранных маршрутов управляемые устройства используют обычный WAN.

Для просмотра сообщений установки выполните:

```routeros
/log/print without-paging where message~"SB-GATEWAY"
```

## Завершение настройки в Web UI

Дождитесь состояния контейнера `running` или `healthy`:

```routeros
/container/print detail where comment="SB-GATEWAY container"
```

Откройте панель из management LAN. Стандартный адрес:

```text
https://172.31.255.2:9443
```

Мастер первого запуска предложит:

1. создать учётную запись администратора панели;
2. загрузить актуальный export RouterOS без чувствительных значений;
3. подтвердить адреса RouterOS, контейнера, TPROXY и DNS;
4. выбрать доверенные LAN- и VPN-интерфейсы;
5. сохранить REST credentials RouterOS в зашифрованном secret store;
6. настроить маршруты, узлы, сертификаты и политики устройств;
7. выполнить Check и проверить план перед Apply.

При успешном bootstrap приватный `variables.rsc` удаляется автоматически. Если
установка прервалась, удалите его вручную после диагностики. Зашифрованную
автономную копию можно оставить для восстановления.

## Проверка установки

Проверьте контейнер, watchdog и diversion gate:

```routeros
/container/print detail where comment="SB-GATEWAY container"
/system/scheduler/print detail where name="SB-GATEWAY-health-watchdog"
/ip/firewall/mangle/print detail where comment="SB-GATEWAY diversion-gate"
```

Diversion gate может оставаться выключенным, пока не включена политика
устройства и выбранный маршрут не прошёл health-check. Во время запуска и
обновления RouterOS сохраняет обычный WAN. Для устройства с режимом LAN-only
действует выбранная строгая политика отказа.

## Обновление и восстановление

Следующие версии устанавливаются через **Операции → Обновление контейнера**.
В форму загружается новый `.tar` для `linux/arm64`; ZIP комплекта и файл
`.sha256` туда загружать не нужно. Панель проверяет архив и сохраняет прежний
контейнер до завершения probation нового образа.

Резервное копирование, rollback, восстановление и удаление описаны в
[OPERATIONS.md](OPERATIONS.md). Ошибки preflight и readiness разобраны в
[TROUBLESHOOTING.md](TROUBLESHOOTING.md).
