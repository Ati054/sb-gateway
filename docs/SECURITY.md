# Безопасность

Документ соответствует модели безопасности SB Gateway 1.6.17.

## Модель угроз

Учитываются: сканирование origin, компрометация UUID, утечка subscription URL,
подмена обновления, SSRF через подписку/health URL, обход политики по IPv6/DNS,
доступ remote user к RouterOS management, supply-chain образа и потеря
управления при crash-loop.

## Секреты

ACME хранит DNS API доступ и ключ аккаунта в SecretStore, без возврата в UI,
argv или журнал. Это файлы 0600, **не шифрование на диске**. Используйте
минимальные права зоны; CDN Free не означает ограниченный DNS API токен.
Первый выпуск требует явного действия и принятия условий CA, имена сертификата
публичны в CT. [Подробности и границы проверки ACME](acme-certificates.md).

Дополнительный ACME-DNS-адаптер требует явно выбранного доверенного HTTPS-сервиса:
его оператор может подтверждать сертификаты делегированных имён. JSON регистрации
хранится в SecretStore; статус возвращает только CNAME, не `username`/`password`.
Смена адреса требует повторной загрузки ключей. API использует фиксированный
`POST /update`, без произвольных заголовков/скриптов, proxy из окружения и redirect.
Все DNS-адреса назначения проверяются до числового dial: локальные, частные,
служебные и смешанные небезопасные ответы отклоняются; обычная проверка TLS
не отключается. CNAME проверяется до обращения к CA и перед TXT update.
Вызов проверки из панели требует сессию/CSRF, не сохраняет доступ и не запускает
выпуск. У ACME-DNS нет удаления TXT; последние challenge-значения остаются,
а CNAME нужен для продления. Пароли в эти DNS-записи не попадают. Этот адаптер
проверен автоматическими тестами; реальный выпуск через выбранный сервис и CA
нужно подтвердить с собственным доменом и ограниченной учётной записью DNS.

Worker передаёт backend только allowlisted код стадии, а не текст DNS API/CA:
провайдеры иногда отражают учётные данные в ошибке. Stderr worker не читается,
а status API получает короткое сообщение о DNS API, propagation, CA или локальной
установке; нераспознанная причина остаётся общей ошибкой worker.

Секреты существуют только в runtime `/config/secrets` на внешнем SSD:

```text
management-api-token
management.htpasswd
ws-path
grpc-service
httpupgrade-path
users/*.uuid
subscriptions/*.url
```

TLS-пары транспортов хранятся по именованным профилям в
`/config/secrets/tls-profiles/<id>/`; приватные ключи не принадлежат WebSocket
или другой карточке транспорта. Файлы имеют mode 0600, каталоги 0700. Git,
diagnostics, logs, status API и UI diff не содержат значений. Панель показывает
только метаданные сертификата и поддерживает replace/rotate парой.

`secrets/` и `client-exports/` должны быть исключены из Git, кроме `.gitkeep`.
Перед публикацией запускается secret scan.

Импортированная клиентская подписка считается владельцем параметров своих
узлов. Certificate pin из `pcs`, `pinnedPeerCertSha256` или `pinSHA256`
нормализуется и применяется только к соответствующему Xray outbound. Legacy
`insecure=1`/`allowInsecure=1` без pin отклоняется; при наличии pin старый флаг
не попадает в runtime, а сертификат проверяется по SHA-256. Панель не
распространяет параметры на подписку целиком, другие источники или ручные
резервные подключения.

## Management plane

- Nginx management HTTPS `:9443` доступен только при совпадении management
  CIDR и явно выбранного доверенного RouterOS ingress-интерфейса.
- Management source сейчас задаётся только IPv4 CIDR; `0.0.0.0/0` запрещён
  и в Web UI, и validator, и bootstrap.
- Control API `127.0.0.1:8080` и Xray gRPC API `127.0.0.1:10085` доступны
  только внутри контейнера.
- Порт 9443 не публикуется через WAN/Cloudflare/VLESS.
- TLS, одноразовый bearer только для bootstrap, администраторская сессия,
  короткий idle timeout и secure+SameSite cookies.
- Обычный вход остаётся нативной HTTPS-формой с `username` и
  `current-password`. Включённая по умолчанию галочка «Запомнить данные»
  разрешает стандартные подсказки автозаполнения; при снятой галочке форма
  отправляется с отключённым autocomplete. Сохранением и сроком хранения
  управляет системный менеджер паролей браузера. Панель не копирует пароль в
  `localStorage`, cookie или собственную базу автозаполнения; HTTP для обхода
  политики браузера не включается.
- State-changing запросы требуют CSRF/origin protection и повторной
  аутентификации для secret rotation/restore. Update и full uninstall используют
  действующую защищённую сессию, CSRF/origin checks, preview и одну явную
  галочку; повторный ввод пароля не добавляет криптографической защиты.
- Только фиксированные project-owned health script и scheduler получают
  RouterOS `policy` вместе с `test`: это требуется для общего hysteresis-state
  между scheduler/admin environments. В их policy отсутствуют `password` и
  `sensitive`, а source не принимает пользовательские команды.
- RouterOS WebFig/API/SSH/WinBox закрыты для контейнера и remote users.
- До разрешений trusted-role удалённым VLESS отклоняются loopback
  `127.0.0.0/8`/`::1`, точные container/TUN IP и все адреса RouterOS,
  импортированные из свежего обычного export без флага `show-sensitive`.
  При Apply этот набор
  объединяется с текущим live REST discovery и сохраняется в generation.
- RouterOS REST/DNS/ICMP allow от контейнера дополнительно ограничены
  выделенным container bridge как ingress и фактическим gateway как
  destination; остальные пакеты контейнера в input отклоняются.
- SB Gateway не изменяет `/ip service`, включая `winbox`, `ssh` и `www-ssl`,
  и не вводит глобальный deny для их портов. Установщик только читает
  фактические порты SSH и Winbox для собственного разрешения от container IP.
  Их **Available From** и доступ из пользовательских LAN/VPN остаются под
  управлением владельца RouterOS.
- Project-owned input-chain принимает только необходимые обращения контейнера
  к RouterOS, отклоняет остальные пакеты именно от container IP и завершает
  обработку `return`, чтобы все прочие источники продолжили проходить через
  существующий пользовательский firewall.
- Management allow/deny для 9443 всегда располагаются до широкого правила
  managed-client → container.
- Не добавляйте вручную matcher-поля к правилам с точными комментариями
  `SB-GATEWAY`. Apply восстанавливает основные поля и порядок и останавливается
  при дубликатах, но RouterOS может сохранить неизвестный дополнительный
  matcher. После ручного drift используйте recovery-процедуру с backup и
  повторным импортом `install.rsc`.

## Data plane

- Каждый выбранный Cloudflare HTTPS-порт (`443`, `2053`, `2083`, `2087`,
  `2096` или `8443`) принимает только Cloudflare ranges. Другие CDN используют
  свой проверенный feed либо секретный origin-header. RouterOS публикует только
  фактически используемые origin-порты.
- Nginx проверяет SNI и path/service; неизвестное закрывается нейтрально.
- Direct REALITY slots выключены в безопасном seed и включаются только явным
  Apply с выбранными SNI/target/port.
- Remote public route не содержит direct fallback.
- Внутренние DNS-зоны доступны локальному TUN и remote-профилю доступа
  `trusted-full`;
  limited/internet-only identity получает DNS reject до своей public-DNS policy.
- WAN и VPN DNS разделены на source/auth-aware lanes. DoH/DoT upstream
  VPN-линии направляется тем же VLESS, Reverse VLESS или WireGuard selector,
  что и данные; fallback на WAN для remote user не создаётся.
- Полные клиентские Xray/sing-box/Mihomo-профили не используют системный DNS. Имена
  самих VPN-узлов разрешаются прямым шифрованным DoH по IP до установления
  туннеля, чтобы не создать bootstrap-цикл. Xray/Mihomo направляют доменные
  исключения и основной трафик к resolver своего направления; sing-box
  выбирает resolver по основному направлению и не копирует сервисный каталог
  в DNS. Plaintext DNS fallback не добавляется.
- Клиентская индивидуальная маршрутизация может уменьшить трафик через шлюз,
  но не является авторизацией LAN. Профиль включает только CIDR, разрешённые
  настройкой **Доступ к LAN**; Xray на шлюзе остаётся авторитетным enforcement и
  отклоняет внутренние назначения для `internet-only` и всё вне allow-list для
  `trusted-limited`.
- Выбранный WireGuard egress получает отдельную `sb-wg-*` table и source `/32`
  из `198.18.0.0/15`. Default route `main` не меняется. Исходный
  `allowed-address` peer хранится только в project-owned recovery state и
  восстанавливается при снятии выбора; интерфейс и ключи не становятся
  собственностью SB Gateway.
- Входящий WireGuard-клиент авторизуется сохранённым RouterOS peer `.id`, а не
  именем интерфейса или устаревшим source CIDR. Его точные IPv4 `/32`
  пересчитываются по live inventory перед Check, Plan и Apply. Изменения
  public key и адресов у того же peer не создают новую identity; удалённый и
  созданный заново peer не наследует доступ и вызывает
  `wireguard_peer_missing` до явного повторного выбора.
- Широкие `allowed-address` используются как маршруты, но не как source
  identity клиента. Неоднозначная legacy-привязка закрывается fail-closed.
- Local fail-open реализован в RouterOS и не расширяет права контейнера.
- Internal destinations перечисляются явно.
- IPv6 managed clients блокируется до parity.

### Публичные порты и сканирование

- Самостоятельный публичный сайт-заглушка и отдельные слушатели HTTP/80 или
  HTTPS/443 не создаются. Контейнер публикует только реально включённые
  транспорты и, при выборе отдельного режима, CDN-endpoint подписки.
- Неизвестный SNI отклоняется default server без выдачи чужого сертификата.
  На известном CDN-домене неизвестный путь получает нейтральный HTTP-ответ без
  сведений о шлюзе; отдельный домен, сертификат или каталог сайта для этого не
  нужны.
- CDN WS, HTTPUpgrade, gRPC и XHTTP принимаются только на известной паре
  SNI+path/service и используют обычный TLS от выбранного CDN-профиля. Любой
  другой HTTP-путь на известном домене получает нейтральный JSON 404 с
  `Cache-Control: no-store`; ответ не содержит имени панели, Xray или версии.
- Direct VLESS REALITY не относится к CDN: внешний порт маскируется выбранным
  SNI/target и REALITY-ключом. В режиме **API JSON** неподтверждённый REALITY
  ClientHello передаётся только на локальный TLS listener `127.0.0.1:16448` с
  сертификатом выбранного профиля; неизвестный SNI отклоняется TLS handshake.
  Панель предлагает этот режим, а backend принимает его только если каждый SNI
  покрыт метаданными выбранного собственного сертификата. Внешний API-порт при
  этом не создаётся. Hysteria 2 остаётся QUIC/UDP; его
  стандартная API-маскировка обслуживается loopback helper, а необязательный
  website fallback обслуживает только обычный
  HTTP/3 через отдельный loopback helper с фиксированным публичным HTTPS
  target. Это не TCP/443-сайт и не полная имитация исходного сайта; Salamander
  не пропускает к нему обычных HTTP/3-клиентов.
- Direct `VLESS + gRPC + TLS Pin` публикуется отдельным TCP listener и принимает
  только сертификат выбранного TLS-профиля. Клиентские экспорты закрепляют один
  SHA-256 pin текущего leaf-сертификата; `allowInsecure` и пара старый+новый pin
  не используются. SNI обязан быть конкретным DNS SAN этого сертификата.
  TLS-профиль может создать частный ECDSA P-256 `MyRootCA` и подписанный им leaf:
  владение доменом не проверяется, сертификат не отправляется в публичный CA и CT.
  Root CA, его ключ и leaf-ключ остаются в SecretStore с режимом `0600`; клиенту
  передаётся только pin leaf. Это не делает произвольный SNI гарантированно
  разрешённым сетью и не скрывает сам ClientHello SNI.
- RouterOS connection guard касается только новых WAN-соединений к фактически
  опубликованным project-owned TCP/UDP-портам. Established/related,
  management/LAN и подтверждённые source ranges CDN не ограничиваются. После
  превышения настраиваемого per-source rate/burst адрес временно помещается в
  `SB_PUBLIC_ABUSE`; это защита от массового сканирования, а не замена
  криптографической аутентификации транспорта.
- Website fallback имеет отдельный общий payload budget (по умолчанию
  1 Мбит/с, настраивается в пределах 0,1–100 Мбит/с) для чтения upstream и
  ответа клиенту, а также лимиты запросов, соединений, body и deadline. Он
  применяется только после попадания HTTP-запроса в helper: не является
  защитой от QUIC handshake/TLS flood и не ограничивает авторизованный VPN.
- `X-Forwarded-*` может включить только локальный Hysteria masquerade proxy;
  website fallback не принимает и не передаёт эти заголовки. Серверные настройки
  QUIC (`Brutal` loss compensation, GSO и Stateless Reset) не экспортируются
  в клиентские подписки и не меняют RouterOS firewall guard.
- API cover разрешает `OPTIONS` без тела, для остальных неизвестных запросов
  отвечает JSON 404 с непредсказуемым `request_id`; `HEAD` не получает body.
  Это защита от обычного активного probing, а не сокрытие SNI от пассивного DPI.
- Ссылка подписки содержит один случайный сегмент 256+ bit без слов `sub`,
  `subscription` или `links`. Ротация сразу отзывает предыдущий токен; ответы
  запрещают cache/indexing.
- Cloudflare origin ограничивается автоматически обновляемыми официальными
  CIDR. Обновление проходит через временные списки и атомарную замену без
  Safe Mode и полного Apply; established/related соединения не сбрасываются,
  а ошибка оставляет последний рабочий набор. Для CDN без официального
  машинного списка используется секретный origin-заголовок; ручные CIDR
  остаются расширенным резервным вариантом.
- Nginx virtual hosts могут делить один origin-порт только при одинаковой
  RouterOS source-границе. Валидатор и renderer отклоняют сочетание
  Cloudflare-only/manual-CIDR с открытым или иначе ограниченным listener на том
  же порту: RouterOS не видит TLS hostname, поэтому широкое NAT-правило иначе
  ослабило бы защиту соседнего host.

## Обновления

- версии образов/бинарников фиксируются;
- локальный RouterOS bootstrap принимает только одиночный Docker image archive
  из `docker save`/`podman save`: упаковщик проверяет внутренние manifest,
  `linux/arm64`, tag и application-version label, затем атомарно публикует tar,
  manifest и SHA256;
- SHA256 локального tar проверяется на администраторском компьютере до WebFig
  upload; RouterOS после распаковки независимо требует `os=linux` и
  `arch=arm64`, но документация не приписывает Files отсутствующую общую
  SHA256-функцию;
- registry image допускается только по `@sha256` digest;
- subscription/rule-set downloads имеют HTTPS, timeout и size limit;
- automatic service-pack updater принимает только встроенные IDs и
  `raw.githubusercontent.com`, запрещает redirects, ограничивает include graph
  и никогда не удаляет локальный LKG при ошибке;
- parser отбрасывает неизвестное/некорректное;
- candidate проходит `xray run -test -config /config/generated/xray.json` и `nginx -t`;
- Web UI image update принимает один Docker `.tar`, без proxy buffering пишет
  его прямо на внешний SSD и лишь после `fsync` проверяет SHA-256 и ограниченные
  metadata; перед запуском хеш проверяется повторно, второй tar и sidecar
  `.sha256` не требуются;
- файл заменяется атомарно, LKG сохраняется;
- отсутствие изменений не перезапускает процесс.

URL подписки может указывать только на разрешённые HTTPS destinations; private,
loopback, link-local, container и metadata ranges блокируются после DNS
resolution, включая redirect.

## Логи и backups

UUID, URL/token, auth headers, path/service names и keys редактируются. Логи
ротационные, ограничены 10 MiB × 5 и находятся на SSD. Public status не
публикуется. Секретный URL без семантического префикса может обслуживаться
через CDN, прямой HTTPS или оба адреса. В CDN-сценарии используется новый
hostname либо существующее CDN deployment без дополнительного WAN listener.

Binary backup RouterOS и client exports сами являются секретами. Application
archive `.sbgw` шифруется AES-256-GCM с ключом, производным от текущего пароля
панели; отдельного backup password нет. До трёх управляемых архивов обязательно
хранятся на SSD; до трёх зеркал в RouterOS Files создаются асинхронно по
принципу best effort. Пароль и активные sessions в архив не входят. Support
bundle не включает `/config/secrets`, client-exports, private keys или raw
RouterOS export.

Клиентская телеметрия не анализирует payload и назначения. Remote traffic
считается Xray StatsService, local — отдельной nftables-таблицей только с
named byte counters и `policy accept`. В ней нет drop/mark/NAT/redirect;
ошибка collector не меняет firewall или routing.

Обычный export скрывает значения паролей/private keys, но не является
анонимным: он всё ещё может содержать serial/software ID, имена, SSID, public
keys, endpoints и полную топологию. Загруженный `.rsc` используется только для
локального анализа и не включается в repository/support bundle.

## Перенос TLS-профиля

Экспорт `.sbtls` — отдельное явное исключение из запрета выдачи секретов:
браузер получает только зашифрованный архив, не открытые ключи/DNS-пароли.
Оба POST endpoint требуют сессию администратора и CSRF; аудит содержит только
действие и ID. Пароль архива не сохраняется, ответ помечен `no-store`.
AES-256-GCM защищает целостность/содержимое; scrypt с фиксированными параметрами
и ограничение размера/конкурентности ограничивают расход ресурсов.

Импорт не извлекает пути из архива: он принимает только типизированные поля,
создаёт новые локальные ссылки и никогда не перезаписывает действующую пару.
Импортированный профиль и автопродление выключены; RouterOS/Apply не запускаются.
Файл включает DNS-доступ управляемой ACME-пары: берегите его как резервную копию
секретов и не публикуйте. Источник доверия — безопасная передача файла и пароля,
а не подпись исходного роутера. Подробности: [ACME](acme-certificates.md).

## Зависимости сборки панели

Релизный lockfile использует:
Next.js / eslint-config-next 16.3.4, React / React DOM / RSC 19.2.8,
Vite 8.2.2, Vinext 1.0.0-beta.9, RSC plugin 0.5.34,
Cloudflare Vite plugin 1.54.8 и Wrangler 4.131.1; совместимые транзитивные
зависимости также обновлены. В частности, обе используемые ветви `sharp`
закреплены на 0.35.4 с исправлением
[GHSA-rgj7-g3m4-5g8c](https://github.com/advisories/GHSA-rgj7-g3m4-5g8c).
`npm audit` показывает 0 известных уязвимостей на дату проверки. Это не аудит
всех Go/Alpine/Xray-компонентов и не гарантия отсутствия ещё неизвестных
уязвимостей.

### Встроенные копии image-size

Нулевой npm-аудит не покрывает код, встроенный внутрь чужих пакетов.
Vinext переносит `image-size@2.0.2` внутрь своего дистрибутива, а Next.js
также содержит скомпилированную копию. Отдельного исправленного npm-релиза
`image-size` на дату проверки нет. Ошибки ICNS и JXL/HEIF способны зависать
на некорректной длине блока:
[ICNS](https://github.com/advisories/GHSA-w3rx-r6r6-pgpr),
[JXL/HEIF](https://github.com/advisories/GHSA-5p2g-fcmc-qvqq).
[Перенос внутрь Vinext](https://github.com/cloudflare/vinext/pull/2913)
сам по себе не исправляет эти ошибки.

`build/harden-image-size.mjs` применяет узкое локальное исправление обеих
копий: проверяет границы ICNS-записей и гарантирует продвижение по блокам
JXL/HEIF. Нулевая длина ISO-блока трактуется как «до конца файла»; длины
меньше заголовка и выход за буфер отклоняются. Исходные и исправленные
SHA-256, версия и единственность замен проверяются; неизвестный дистрибутив
останавливает сборку и требует пересмотра патча, а не молчаливого пропуска.
Повторный запуск ничего не меняет.

Защита выполняется через `postinstall` и повторно перед `npm run dev`,
`npm run build`, `npm run build:static`, `npm start`. Поэтому Docker-сценарий
`npm ci --ignore-scripts` также защищён перед сборкой. После установки с
отключёнными lifecycle scripts нельзя запускать бинарники Next/Vinext напрямую:
используйте npm-команды проекта либо сначала `node build/harden-image-size.mjs`.
При обновлении фреймворков нужно проверить встроенный код, пересмотреть hashes
и удалить локальное исправление только после доказанного upstream-исправления.

Перед релизом выполнить:

```sh
npm ci --ignore-scripts
npm run audit:dependencies
npm run lint
npm test
npm run build:static
```

`audit:dependencies` не допускает даже low findings и дополнительно запускает
регрессии встроенных парсеров: повреждённые ICNS/JXL/HEIF обрабатываются в
дочернем процессе с таймаутом; проверяются также штатные размеры PNG, GIF,
JPEG, SVG, HEIF и ICNS. Статическая панель MikroTik не включает Node.js,
Next/Vinext server или эти парсеры; данное исправление защищает инструменты
разработки/сборки и сохраняет отдельный вариант сборки Sites.

Релизная проверка запускает `npm run audit:dependencies`, lint, TypeScript,
production build и static build на закреплённом Node 22. Исходные проверки
нормализуют CRLF/LF, поэтому Windows и Linux проверяют один контракт.

## Реагирование

При подозрении на компрометацию:

1. ограничить ingress/management в WebFig;
2. сделать forensic backup без публикации;
3. Rotate affected UUID/path/service/API tokens;
4. отозвать/заменить Origin Certificate;
5. обновить Cloudflare lists и проверить audit log;
6. применить candidate и отозвать старые client profiles;
7. проверить remote home-WAN leak и RouterOS management access.
