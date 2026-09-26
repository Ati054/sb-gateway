# RouterOS 7

Документ соответствует SB Gateway 1.6.21 и capability-based поддержке ARM64
RouterOS 7. Preflight проверяет требуемые возможности вместо точного номера
версии RouterOS.

## Версия и пакеты

Поддерживается ARM64 **RouterOS 7**, в которой capability-preflight обнаружил
все требуемые возможности. Имя канала — long-term, stable, testing,
development, пользовательское или будущее — не является gate.

Web UI определяет текущие version/channel и показывает риск-уровень. Канал
информационный: проект не меняет его и не обновляет RouterOS автоматически.
Compatibility-gate нового Apply блокируется только отсутствием конкретной
capability, а не названием канала. Помимо него
остаются независимые safety/readiness-проверки адресов, export, сертификатов и
секретов.

Проверяются containers/device-mode, ARM64 package compatibility,
kernel TPROXY/nftables, `start-on-boot`, `restart-policy`/`restart-interval` (с fallback
на старый `auto-restart-interval`), veth/routing,
firewall/mangle и scheduler primitives. Пакет `container` обязан иметь ту же
версию, что основной RouterOS. Проект не отключает сохранённую generation из-за
смены version/channel metadata. Обновление RouterOS перезагружает устройство;
на старте точный project gate сначала выключается, контейнер поднимается через
`start-on-boot`/auto-restart, а diversion возвращается после hysteresis.

Перед пользовательским обновлением создаются binary backup, обычный
несекретный export и rollback. После обновления отдельно проверяются LAN, Wi‑Fi и все
существующие VPN. Доступные версии можно сверить на
[официальной странице MikroTik](https://mikrotik.com/download/routeros).

## Что проект имеет право добавить

Все добавленные объекты содержат комментарий/префикс `SB-GATEWAY`:

- `bridge-sb`, `veth-sb`;
- фактический адрес RouterOS на выделенном container bridge;
- таблица `to-sb-gateway`;
- address-lists `SB_MANAGED_CLIENTS`, `SB_INTERNAL_NETWORKS`,
  `SB_CLOUDFLARE_V4`, `SB_CLOUDFLARE_V6`, `SB_WG_EGRESS_SOURCES`;
- точечные mangle/filter/NAT rules;
- для выбранных WG-выходов: interface-list `SB_WG_EGRESS`, таблицы
  `sb-wg-*`, source rules, return routes и state для возврата peer;
- контейнер, mounts, watchdog scripts/scheduler.

Обычная локальная установка запускается одним `bootstrap.rsc`; перечисленные
объекты и проверки остаются раздельными внутри него, но не требуют от владельца
ручного импорта каждого этапа. Скрипт останавливается на первой ошибке, а
preflight выполняется до создания project-owned объектов.

При сверке address-list удаляются только записи с точным owner-комментарием
SB Gateway. Уже существующая пользовательская запись с теми же `list + address`
считается действующим членством: система не создаёт дубликат, не меняет её
комментарий и не получает право удалить её позже. Это правило одинаково для
IPv4 и IPv6.

Скрипты не очищают таблицы, не удаляют чужие правила и не становятся
владельцами существующих WireGuard/SSTP/OpenVPN/LAN/Wi‑Fi. Единственное
исключение — явно выбранный WireGuard peer: его `allowed-address` может быть
временно расширен после сохранения исходного значения. При снятии выбора и
uninstall значение возвращается. Остальное удаление работает только по точному
идентификатору владения.

Live-инвентаризация LAN/Wi‑Fi не превращает динамические DHCP Active Hosts в
управляемые устройства. В селектор попадают только lease, переведённые в
`Make Static`; для подписи сначала используется `comment`, затем `host-name`,
сообщённый DHCP-клиентом, и только затем MAC/IP.

Отдельный общий режим LAN/Wi-Fi не перечисляет DHCP Active Hosts. Control plane
читает IPv4-сети адресов интерфейсов из списка RouterOS `LAN` и сохраняет эти
CIDR как один broad source. Так адреса, полученные динамически внутри сети,
сразу входят в `SB_MANAGED_CLIENTS`. В Xray routing, DNS и симуляции точечные
клиенты всегда сортируются перед этой общей записью; порядок создания карточек
на приоритет не влияет. Интерфейсы WAN, WireGuard/PPP и маршруты до удалённых
сетей сами по себе в общий LAN source не попадают.

## Контейнерная сеть

| Назначение | Пример из ТЗ (обязательно заменить/подтвердить) |
|---|---|
| RouterOS bridge/veth gateway | `172.31.255.1/30` |
| Container eth0 | `172.31.255.2/30` |
| Зарезервированная legacy client-TUN сеть | `172.31.254.0/30` |
| Management HTTPS | `172.31.255.2:9443` |
| Lifecycle/process health | `172.31.255.2:9080/healthz` |
| Допуск managed traffic | `172.31.255.2:9080/traffic-ready` |

До установки preflight проверяет отсутствие пересечений. Серверный dataplane
использует kernel TPROXY и отдельную policy table внутри контейнера; userspace
TUN/gVisor и `/dev/net/tun` ему не требуются. Поле legacy client-TUN сети пока
сохраняется в schema только для совместимости и проверки пересечений, но не
участвует в серверном пути пакета. `/config`, `/data`, `/logs`,
`/state` и root-dir размещаются на внешнем SSD. Это соответствует
[рекомендации MikroTik для контейнеров](https://help.mikrotik.com/docs/spaces/ROS/pages/84901929/Container).

Для устройства с 1 ГБ RAM installer по умолчанию задаёт контейнеру
`memory-high=224M` и `memory-max=256M`. Первый порог допускает bounded RAM-кэши,
но начинает reclaim до исчерпания памяти RouterOS; второй ограничивает аварию
процесса и оставляет запас для самого роутера и временного update candidate.
Лимиты можно переопределить через `SB_CONTAINER_MEMORY_HIGH` и
`SB_CONTAINER_MEMORY_MAX` в приватном variables-файле. Они не резервируют RAM
заранее: контейнер использует только фактически необходимую память.
Это начальные пороги для реальной нагрузки, не подтверждённая максимальная
ёмкость по клиентам. После наблюдения за CPU, memory pressure, DNS и обновлением
образа их можно уточнить. Основной control plane сохраняет Go
`GOMEMLIMIT=128MiB` и `GOGC=150`, а процесс Xray запускается с отдельным мягким
`GOMEMLIMIT=192MiB`. Xray level `0` использует 128-КиБ connection buffer вместо
минимального ARM64 default 4 КиБ: это снижает copy/wakeup pressure на
продолжительном прозрачном трафике, но не резервирует 128 КиБ для каждого соединения
заранее. Web-обновление поднимает значения контейнера до этих минимумов и не
уменьшает более высокие пользовательские лимиты.

Провайдерские outbounds хранятся в подписанном runtime-contract и загружаются
в Xray через HandlerService только для активного маршрута и текущей health-пробы.
Сотни невыбранных узлов не входят в стартовый `xray.json`; статическими остаются
direct/block, DNS, RouterOS WireGuard и Reverse VLESS. Это уменьшает RSS и время
старта без сокращения доступного каталога или резервов.

Основной bootstrap использует загруженный через WebFig Files versioned
Docker-архив и `/container/add file=...`; registry остаётся опциональным
режимом с digest-pinned `remote-image`. Installer ждёт окончания асинхронной
распаковки и до запуска требует read-only `os=linux` и `arch=arm64`.
SHA256 архива сверяется на компьютере до загрузки, потому что общий hash файла
в RouterOS Files документирован не был.

В registry-режиме OCI resolver контейнера — фактический RouterOS gateway, чтобы
pull/start не зависели от ещё не запущенного Xray. DNS управляемого трафика
перехватывается внутри Xray/TUN; отдельного
DNS-listener на примерном container IP нет.

## Policy routing

Таблица `to-sb-gateway` содержит default через фактический container IP. Порядок mangle:

1. return для `SB_INTERNAL_NETWORKS`;
2. return для адреса RouterOS;
3. return для container/TUN networks;
4. return для нормализованных outbound endpoints;
5. mark-connection `sb-managed` только new от `SB_MANAGED_CLIENTS`;
6. mark-routing `to-sb-gateway`;
7. исключение пакетов, пришедших с `veth-sb`.

Обычные маршруты `main` и существующие VPN routes не заменяются. До `veth-sb`
нет src-nat. Разрешён обычный masquerade контейнера при выходе в WAN.

### WireGuard peer как источник управляемого клиента

Для входящего клиента inventory читает `/interface/wireguard/peers`, а не
создаёт одну запись на WireGuard interface. Основная подпись — имя peer;
interface показывается только как контекст. В одну строку объединяются все
конкретные IPv4-префиксы из `allowed-address` этого peer: `/32` для обычного
клиента и сети для site-to-site. Default route `0.0.0.0/0` исключается.

Сохранённая запись содержит RouterOS peer `.id` в `source_peer_refs`.
`source_cidrs` обновляется из live RouterOS перед Check, Plan и Apply. Изменение
public key или адресов у того же объекта не меняет его идентичность. Если peer
удалён и создан заново, его новый `.id` не наследует прежнюю политику:
preflight возвращает `wireguard_peer_missing` и блокирует Apply.

Маршрутные сети и full-tunnel scopes в `allowed-address` не становятся source
identity. Это разделяет «какие назначения доступны через peer» и «какой адрес
принадлежит клиенту».

### Выбранный WireGuard как egress

Live inventory предлагает только включённые WireGuard-интерфейсы. Кандидат
считается однозначным, если у него один включённый peer либо ровно один
включённый peer уже содержит `0.0.0.0/0`. Если у интерфейса несколько peers и
full-tunnel peer определить нельзя, Apply блокируется.

Вручную добавлять `0.0.0.0/0` в WebFig не требуется. Для каждого выбранного
выхода Apply:

1. сохраняет исходный `allowed-address` peer в project-owned state;
2. при необходимости добавляет `0.0.0.0/0` этому peer;
3. создаёт собственную таблицу `sb-wg-*` с default через WG interface;
4. создаёт `lookup-only-in-table` только для выделенного source `/32` Xray из
   `198.18.0.0/15`;
5. создаёт обратный route к контейнеру и scoped masquerade/filter.

Default route `main` не создаётся и не меняется. Поэтому RouterOS services,
сам роутер и неуправляемые клиенты не начинают ходить через выбранный WG.
Снятие выбора удаляет только эти объекты и восстанавливает сохранённый
`allowed-address`. Весь набор относится к RouterOS topology change и проходит
Safe Mode/rollback.

## FastTrack

`sb-managed` должен быть исключён из FastTrack, остальные соединения сохраняют
аппаратный/обычный FastTrack. `fasttrack-patch.rsc`:

- обнаруживает существующие fasttrack rules;
- экспортирует конфигурацию;
- формирует точечный patch;
- прекращает работу при нескольких неоднозначных вариантах.

Не применяйте patch без сравнения counters и параметров исходного правила.

## Входящий CDN и прямые порты

Для Cloudflare только source из `SB_CLOUDFLARE_V4/V6` может попасть:

```text
WAN tcp/443 → dst-nat → <фактический-container-ip>:443
```

Списки обновляются из официальных `ips-v4`/`ips-v6` во временные address-lists,
проверяются на непустой корректный CIDR-набор и заменяются атомарно. Ошибка
сохраняет старый список.

Другие CDN-развёртывания получают собственные origin-порты. Если существует
проверенный официальный feed, он обновляется по тому же staging/LKG принципу;
иначе Nginx требует секретный `X-SB-Origin`, а ручной CIDR остаётся optional
fallback. Несколько public CDN hostname могут делить TCP/443 через SNI/path.
Внутренние Xray `11001`–`11004` на WAN не публикуются.

Клиентская подписка при выборе готового CDN-развёртывания создаёт только
отдельный path и не добавляет dst-nat/filter или новый WAN-порт. Отдельный CDN endpoint использует
общий Nginx TLS ingress. Direct HTTPS подписка создаёт точные правила для
выбранного WAN TCP-порта и конфликтует с direct REALITY на том же IP:port.

Прямые правила создаются как выключенные project-owned объекты и включаются
только после успешного Apply соответствующего транспорта:

- REALITY: настраиваемый TCP-порт (по умолчанию 2443);
- Hysteria 2: настраиваемый UDP-порт (по умолчанию 443).

REALITY TCP/443 при одновременно включённом Cloudflare TCP/443 допускается
только с отдельным публичным IPv4 назначения. На одном IP validator блокирует
конфликт. TCP/443 и UDP/443 могут работать одновременно.

Публичные CDN/TLS/QUIC/REALITY-входы дополняются только точными dst-nat/filter
правилами фактически включённых транспортов и цепочкой
`sb-gateway-public-guard`. Отдельные правила сайта-заглушки и публичные
HTTP/80/HTTPS/443 слушатели не создаются. Guard видит только новые
WAN-соединения после project-owned dst-nat, пропускает официальные CDN source
ranges, применяет per-source `dst-limit`, временно помещает превышение в
`SB_PUBLIC_ABUSE` и не участвует в LAN/management/established трафике.

## Обновление и удаление контейнера

Смена образа и полное удаление запускаются одноразовыми RouterOS scheduler
после того, как панель проверила live container, точный внешний storage root и
доступность автономного recovery worker. Операция не держится на HTTPS-сессии панели:
worker переживает остановку самого контейнера. Перед изменением выключается
только `SB-GATEWAY diversion-gate`, поэтому обычный WAN остаётся доступен.

При update новый контейнер получает отдельный `root-<version>`, а прежняя запись
контейнера остаётся остановленной и готовой к немедленному запуску. Новый контейнер
проходит RouterOS-only `/healthz`; при ошибке кандидат удаляется, а прежний
контейнер запускается без второго архива и повторной распаковки. Отдельный
`/traffic-ready` требует свежий selector-readback текущего процесса для каждой
включённой локальной политики. До него diversion выключен: обычный WAN
доступен, а `container_outage=lan_only` продолжает блокироваться своим точным
RouterOS-правилом. Registry разрешён
только по digest; локальный `.tar` загружается и проверяется панелью. Full uninstall
удаляет точные `SB-GATEWAY`-объекты и ровно один проверенный каталог проекта,
не трогая чужие маршруты, VPN или остальные файлы диска.

На RouterOS 7.24 кандидат сначала распаковывается остановленным на изолированном
`veth-sb-hold`, пока старая запись продолжает владеть рабочим veth и обслуживать
VLESS. После распаковки старый контейнер останавливается, кандидат получает
рабочий veth, а старая запись переносится на `veth-sb-hold`. При продвижении или
откате временный veth удаляется автоматически.

Web UI передаёт worker один проверенный `.tar`; отдельный rollback archive не
нужен. Три lifecycle probation checks используют только `/healthz`. Первый
свежий `/traffic-ready` текущего запуска включает diversion независимо от
номера probation-проверки; если VLESS временно недоступен, исправный образ
может завершить probation, оставляя клиентов на настроенном outage-пути. После
probation прежняя container record/root,
временный veth, upload, worker и служебный export удаляются. Нормальное итоговое
состояние — ровно один контейнер с комментарием `SB-GATEWAY container`.

Application recovery archives `.sbgw` ротационно и обязательно хранятся на
external SSD. До трёх зеркал в RouterOS Files создаются асинхронно по принципу
best effort и не входят в критический путь update/restore. Удаление/ротация
совпадают по строгому имени `SB-GATEWAY-state-*`; остальные файлы RouterOS не
затрагиваются.

## Доступ к панели

Панель `:9443` открывается только при одновременном совпадении двух независимых
условий: source входит в `system.management.allowed_source_cidrs`, а пакет пришёл
через интерфейс из `system.management.allowed_ingress_interfaces`. Обычно это
management LAN (например, `192.168.88.0/24`) и его bridge. Для WireGuard/OpenVPN добавляйте
только выбранные стабильные адреса устройств как `/32` и фактический VPN
интерфейс; для динамического OpenVPN нужен стабильный server binding/interface.

`0.0.0.0/0`, внутренний container bridge и интерфейс, обнаруженный как WAN,
отклоняются до Apply. После разрешающего правила устанавливается явный deny для
остальных источников к container `:9443`; публичного dst-nat для панели нет.
Разрешение IP без доверенного ingress или ingress без разрешённого IP доступа не
дают. Изменение этого списка не должно затрагивать обычный forward/WAN клиентов.

Для пользовательского router-local порта панели (по умолчанию `17443`) есть
отдельный owned-путь WireGuard: текущие включённые WireGuard-интерфейсы
пересобираются в `SB_WIREGUARD_INGRESS` при каждом RouterOS Apply и направляют
тот же LAN-адрес MikroTik на container `:9443`. Это не публикует порт через WAN;
клиентский `AllowedIPs` всё равно должен включать выбранный LAN-IP или подсеть.
Для обратного пакета существует отдельное узкое established/related правило:
только из container bridge, только из container `:9443`, только по соединению с
`dstnat` и только обратно в `SB_WIREGUARD_INGRESS`. Без него WireGuard-подсеть,
которая одновременно входит в `SB_INTERNAL_NETWORKS`, попадала под container LAN
deny: входящий SYN разрешался, но TLS-ответ отбрасывался и браузер видел timeout.

Этот список управляет только HTTPS-панелью контейнера `:9443`. SB Gateway не
меняет `available-from`, состояние или порт RouterOS-сервисов WinBox, SSH,
WebFig/API и не закрывает их глобальным input-правилом. После обработки
project-owned трафика из container bridge цепочка выполняет `return`; доступ к
самому RouterOS из остальных LAN/VPN полностью определяется уже существующими
пользовательскими `/ip service` и `/ip firewall filter`.

## Firewall контейнера

Разрешено:

- established/related;
- DNS/NTP и WAN;
- для `trusted-limited` ровно перечисленные внутренние сети; при наличии
  `trusted-full` — RFC1918-сети, к которым RouterOS имеет маршрут;
- исходящие VLESS/REALITY/Hysteria 2 endpoints;
- management 9443 только из management CIDR на явно доверенном ingress;
- health 9080 только с фактического RouterOS gateway.

Запрещено:

- неизвестные внутренние сети;
- WebFig/API/SSH/WinBox RouterOS от контейнера по умолчанию;
- внутренние control/Xray API 8080/10085 с veth или WAN;
- 9443 с WAN;
- служебные Xray backends извне контейнера;
- публичный Cloudflare TCP/443 не из Cloudflare; прямые REALITY/Hysteria 2
  разрешаются только точными project-owned dst-nat/filter правилами.

Ответы от LAN и сетей за site-to-site VPN не обязаны знать container CIDR.
Узкий `srcnat` применяется только к source-сети контейнера и destination-list
`SB_CONTAINER_ALLOWED_INTERNAL`. Поэтому основной LAN, VPN-маршруты и обычный
трафик MikroTik не маскарадуются; для разрешённого удалённого клиента RouterOS
выбирает source-адрес фактического выходного интерфейса и обеспечивает обратный
путь одинаково для VLESS, gRPC, XHTTP и Hysteria 2.

Отдельная таблица `sb_gateway_client_telemetry` содержит только nftables named
byte counters для включённых local source CIDR, hook forward с `policy accept`
и return после совпадения. Она не принимает/отклоняет трафик, не ставит mark,
не выполняет NAT/redirect и не меняет RouterOS policy routing.

## Watchdog и fail-open

После запуска контейнер проверяет правила `/system/logging` и исключает
`fetch,info` из тех правил, которые иначе записали бы успешные опросы
watchdog. Существующие отрицания тем (например, `info,!wireguard`) сохраняются;
правила с дополнительной обязательной темой, `fetch,warning` и `fetch,error`
не меняются. При недоступном RouterOS REST проверка повторяется, а частота
и работа watchdog остаются прежними. Для диагностики проверьте
`/system/logging/print detail`: каждое включённое правило, способное писать
`fetch,info`, должно содержать `!fetch` или `!info`. Уже записанные строки
журнала не удаляются.

Контейнер настроен с `start-on-boot=yes`, `restart-policy=always` и
`restart-interval=10s`; на старых RouterOS используется совместимый
`auto-restart-interval=10s`.
Внутренний watchdog завершает PID 1, если Nginx/Xray зависли или readiness
не может быть восстановлен, позволяя RouterOS выполнить штатный restart.

RouterOS health state machine:

- probe каждые 5 s;
- 3 ошибки → `BYPASS`;
- первый свежий `/traffic-ready` после boot/update → `HEALTHY` без
  искусственных дополнительных циклов;
- после последующего живого отказа 3 успеха без дополнительного cooldown по
  умолчанию → `HEALTHY`; отдельный
  cooldown остаётся настраиваемым, если оператор сознательно предпочитает более
  медленный возврат;
- restart budget: не более 6 принудительных рестартов в час.

При загрузке и повторном импорте `SB-GATEWAY-startup-fail-open` немедленно
выключает точный diversion gate и очищает только соединения с mark
`sb-managed`. Пороги и restart budget меняются в Web UI. RouterOS опрашивает
не постоянный marker, а `/traffic-ready`: короткоживущую process lease плюс
свежий selector-readback текущего запуска. Остановка/зависание process-watchdog
автоматически превращает health в 503. Контейнер получает
новый `watchdog.env` атомарно, RouterOS — новый источник принадлежащего проекту
watchdog config-script и interval scheduler. После исчерпания restart budget
PID 1 больше не завершается: контейнер и логи остаются для диагностики через
WebFig; Web UI доступен только если management API исправен. Gate остаётся в
BYPASS.

Внутренний watchdog не отсиживает весь startup grace, если `run-xray.sh` уже
опубликовал привязанный к текущему PID маркер после восстановления selectors и
TPROXY. Он немедленно выполняет полный API/process/listener/route/DNS deep-check
и публикует первую lease после одного успеха. Настроенный recovery threshold
применяется только к восстановлению после последующего живого отказа.

В BYPASS выключается только route-mark rule `SB-GATEWAY` для новых локальных
соединений. Клиенты с `container_outage=direct` идут по main/WAN. Источники с
`container_outage=lan_only` остаются в `SB_FAIL_CLOSED_CLIENTS`: внутренние
назначения доступны. Только исключения, назначенные на WAN в режиме
`VLESS + WAN`, могут быть разрешены персональными RouterOS DNS/address-list
правилами на TCP 80/443 и UDP 443; исключения режима `WAN + VLESS`, назначенные
на VLESS, при отказе контейнера не выпускаются напрямую. Остальной публичный
forward блокируется до восстановления контейнера.

Базовое правило `SB-GATEWAY fail-closed public drop` создаётся установщиком в
собственной цепочке `sb-gateway-forward` непосредственно перед её `return`.
Оно всегда включено, но действует только на адреса из
`SB_FAIL_CLOSED_CLIENTS`. Поэтому пустой список на новой или client-only
установке никого не блокирует. Generated candidate восстанавливает
отсутствующее правило перед сверкой аварийных исключений; наличие нескольких
правил с тем же project-owned comment по-прежнему блокирует Apply как
неоднозначное состояние.
DNS такого клиента принудительно перехватывается RouterOS только в BYPASS;
IPv6 публичный обход закрыт. Удалённый пользователь не может использовать этот
путь при полном отказе контейнера, потому что его ingress находится внутри него.

Каталожные списки обновляются внутри контейнера ежедневно и используют LKG.
RouterOS получает аварийный снимок встроенных ключевых доменов при подтверждённом
Apply. Динамический L3 address-list не различает сайты, разделяющие один CDN IP,
поэтому широкие пакеты (особенно вся RU/РФ) включаются только явно.

Не используйте `/system watchdog watch-address` на внешний IP как механизм
контейнера: эта функция перезагружает весь роутер при потере пинга и может
сделать WAN менее доступным. Системный software watchdog RouterOS остаётся
включённым, а контейнер контролирует отдельный script/scheduler. Описание
различий есть в [документации MikroTik Watchdog](https://help.mikrotik.com/docs/spaces/ROS/pages/8978694/Watchdog).

## IPv6

По умолчанию `block_managed`: IPv6 блокируется только для источников
`SB_MANAGED_CLIENTS`, пока не реализован parity. Это предотвращает обход
сервисной политики и не отключает IPv6 другим клиентам.

`parity` разрешается только когда настроены IPv6 veth/TUN, internal lists,
mangle/routes, firewall, DNS и тесты утечек.

## MTU/MSS

Начальное TUN MTU — 1400. MSS clamp применяется только к пути SB Gateway и
только после обнаружения PMTU-проблемы. Глобальный clamp запрещён. Проверяйте
WS, gRPC, WG, SSTP, OpenVPN и двойной VLESS отдельно.

## Проверка после применения

В WebFig:

- все исходные VPN/interface/routes/firewall на месте;
- counters SB rules меняются только для управляемого source;
- внутреннее назначение не увеличивает counter `to-sb-gateway`;
- veth получает исходный client IP;
- контейнер running и auto-restart=10s;
- management 9443 недоступен с WAN;
- health 9080 недоступен не-RouterOS источнику.

Скачайте `diagnostics.rsc` report и приложите к протоколу приёмки без
чувствительного export.
