# Архитектура SB Gateway

Документ соответствует SB Gateway 1.6.20, серверному Xray-core 26.9.9 и runtime renderer
schema 38.

## Границы системы

Проект добавляет изолированный контейнер `sb-gateway` и строго именованные
объекты RouterOS с комментарием `SB-GATEWAY`. Он не становится владельцем
существующих интерфейсов, VPN, маршрутов, Wi‑Fi или firewall. Для явно
выбранного WireGuard egress допускается одно обратимое изменение существующего
peer: расширение `allowed-address` после сохранения исходного значения. Скрипт
останавливается, если безопасное место вставки FastTrack/mangle неоднозначно.

В контейнере одновременно работают:

- Nginx: public TLS на независимо выбранных CDN HTTPS-портах, management TLS
  `:9443`, RouterOS-only health `:9080`;
- management API на `127.0.0.1:8080`;
- единственное proxy-ядро Xray-core; канонический renderer
  сохраняет одинаковый порядок клиентских, LAN и сервисных политик;
- контроллер подписок, узлов, health/hysteresis и атомарного обновления;
- Go process watchdog; при зависании обязательного процесса он завершает PID 1,
  после чего RouterOS перезапускает контейнер.

## Процессы и владение состоянием

PID 1 — статический `sb-gateway appliance`: API, policy DNS и monitor работают
как компоненты одного Go runtime и разделяют малые пулы памяти; Xray и Nginx
остаются отдельными
сторонними process groups под нативным controller. RouterOS следит за контейнером
целиком.

| Компонент | Что читает | Чем владеет и что записывает |
|---|---|---|
| controller / API | draft, active/LKG, secrets, runtime inventory | единственный writer configuration pointers, `/config/generated` и `/data/last-known-good` |
| `sb-gateway dns` | `/config/generated/policy-dns.json` | только RAM: bounded TTL cache, coalescing одинаковых запросов и connection pools; файлов не изменяет |
| `sb-gateway monitor` | renderer-normalized health pool, Xray/nft counters, interest marker, readiness API, `/proc`, active rulesets | один Go runtime выполняет telemetry/selector health, watchdog и суточное ruleset maintenance; writers остаются разделены по своим project-owned файлам |
| Xray | `/config/generated/xray.json` | только своё runtime-состояние соединений и API |

Нативный supervisor пишет различимые события планового restart и неожиданного
завершения дочерней программы с кодом ошибки и backoff. Поэтому обрыв Xray при
Apply/обновлении подписки не смешивается в диагностике с crash или OOM всего
контейнера.

Controller остаётся единственным владельцем persistent configuration. Go monitor
имеет отдельный namespace auxiliary state и не изменяет draft, active/LKG,
generation или generated runtime. Его
падение не останавливает уже запущенные Xray и Go DNS: data plane продолжает
работать с последними опубликованными файлами, а нативный controller перезапускает
только упавший компонент. После старта controller сверяет active generation и live
runtime, а не создаёт состояние заново. Отдельного telemetry-бинарника нет:
сбор выполняет monitor того же артефакта. API только читает
атомарный snapshot и обновляет tmpfs interest-marker; при закрытом обзоре monitor
снижает частоту Xray/nft polling с 30 до 300 секунд.

Native renderer публикует `xray.json` и `urltest-pool.json` одной candidate-
generation из одного снимка черновика и provider inventory. Health contract
содержит точный порядок кандидатов, priority groups, подписи и страны. Go agent не
повторяет семантику выбора стран/городов и не придумывает маршрут — он работает
только с этим validated contract. Membership policy/service selectors в
`xray.json` стабилен и содержит fail-closed leaf первым и все доступные runtime
leaf далее; право выбора среди них задаёт только текущий health contract.
Поэтому изменение eligibility, порядка или service access публикует новый
`urltest-pool.json`, но не перезапускает Xray. Живой agent замечает атомарную
публикацию не позднее чем через 500 мс и перечитывает contract без рестарта
общего monitor/watchdog. `selector-health.json` хранит подтверждения,
cooldown, bounded 24h/7d/30d history и последний выбранный outbound. При старте
Xray startup helper восстанавливает подтверждённый доступный выход в `best` и
`priority` до включения transparent routing. Для `priority` дополнительно
проверяется сохранённый порядок кандидатов: несвязанный Apply сохраняет выход,
явная перестановка приоритетов применяется. Если сохранённый active удалён,
startup helper выбирает подтверждённый резерв по shortlist/новому порядку; при
отсутствии пригодной истории он заменяет холодный `block` первым кандидатом
текущего contract. Service selectors используют тот же
выход с проверкой текущего service access; дополнительные кэши не создаются.
При старте или смене PID Xray agent сначала читает фактический override selector. После
`xray api bo` он обязательно читает selector обратно; persisted и UI-active
обновляются только при точном совпадении запрошенного и фактического member.
Переключение затрагивает новые соединения; предыдущий динамический handler
сохраняется для уже установленных сессий. Ошибка probe, Xray API или state write
не разрешает выбирать другой маршрут.

Agent кеширует уже применённый member каждого Xray selector и запускает
`xray api bo` только при реальном изменении. Runtime cache сбрасывается при смене
PID Xray; смена только health pool сохраняет сведения о живых динамических
outbound и будит controller для сверки нового contract. Поэтому восстановление
после рестарта остаётся явным, а
три HTTPS-цели одной health-проверки и неизменившиеся service selectors не
создают повторяющийся CLI burst.

Роль `sb-gateway api` является единственным production control plane. Она
реализует сессии, CSRF, crash-safe state и ленивый кэш разобранных
JSON-документов не более 4 файлов. Кэш ничего не
предзагружает и не хранит варианты «про запас»: документ попадает туда только
после фактического запроса. Кэш
проверяет `mtime` и размер, поэтому видит записи внешних runtime-компонентов,
но не выполняет повторный JSON parse на каждом UI-запросе. Это намеренный
обмен небольшого объёма RAM на снижение CPU для MikroTik с 1 ГБ памяти.
Control plane использует одну реализацию схемы и один набор runtime-контрактов.

Между штатными quality-циклами health-loop проверяет только доступность активного
пути с паузой 3 секунды. Один успешный HTTPS-ответ завершает проверку. Для быстрого
цикла timeout одной цели ограничен 2 секундами и сразу завершает текущую попытку;
ошибки HTTP/короткого ответа могут перейти к следующей контрольной цели.
Быстрый цикл не дренирует scan queue, не пересчитывает quality/history, не
увеличивает recovery confirmations и не выполняет speed download. В RAM хранятся
только два срока на policy, сбрасываемые при смене core/contract. Успешный быстрый
цикл не вызывает JSON serialization/fsync; изменения отказа сохраняются.
Буфер короткого HTTPS-ответа ограничен 1 КиБ вместо буфера скачивания 64 КиБ.
После availability failure активного узла health-loop классифицирует причину.
`connection refused`, `no route` и фатальная TLS-ошибка подтверждают отказ сразу;
обычный timeout требует двух последовательных запросов в одном fast-lane цикле,
остальные ошибки — настроенного порога. Перед сменой узла общий sentinel проверяет прямой WAN и DNS:
при общей аварии лист остаётся на текущем узле и не перебирает резервы.
Непосредственно перед аварийным Select underlay проверяется повторно: если WAN
или DNS упал между fast-lane пробой и обработкой подтверждённого отказа, счётчик
узла сбрасывается и смена selector не выполняется.
Если общий WAN/DNS уже восстановился, накопленный во время общей аварии счётчик
также сбрасывается, а активный узел проверяется заново. Свежий underlay recovery
не может превратить устаревший отказ в немедленное переключение на резерв:
первая сетевая ошибка после восстановления считается новой подтверждающей
пробой, и только следующая независимая быстрая ошибка разрешает смену узла.
Фатальная TLS-ошибка остаётся немедленной, поскольку относится к endpoint, а не
к восстановлению общего канала.
Подтверждённый локальный отказ сначала использует свежий уже подтверждённый
резерв из health-карты без новой сетевой проверки. Если его нет, до трёх
изолированных availability-линий проверяют аварийную порцию параллельно. Первый
подходящий результат немедленно переключает selector, остальные результаты
завершаются в фоне и обновляют карту. После аварийного перехода рабочий резерв
удерживается configured cooldown, чтобы нестабильный исходный путь не создавал
ping-pong. В этом окне накопленные quality-ошибки не обходят anti-flap; новый
подтверждённый отказ доступности всё равно переключает немедленно. Первичный
выход нового листа из `block` cooldown не получает, поэтому
может штатно дооптимизироваться. Плановые переключения сохраняют
cooldown/recovery hysteresis и прежнюю частоту quality/backup/full-scan проверок.
Когда selector находится в `block`, health-loop временно сокращает паузу до
15 секунд и проверяет до 3 кандидатов за цикл (не выше configured batch).
Выбор по старейшему `last_probe_at` охватывает весь pool, а не только shortlist,
и не требует отдельного persisted cache/очереди. Первая свежая HTTPS-доступность
восстанавливает selector, не ожидая завершения остальных параллельных probes;
speed download в аварийном цикле не запускается. Обычный режим сохраняет прежние
интервалы и hysteresis.
Это пауза между циклами, не end-to-end SLA: длительность ограниченных probes
и размер выбранного набора также влияют на время обнаружения восстановления.
Политика без сохранённого/подтверждённого runtime state сортируется перед
штатными листами. Аварийная порция использует короткий `ProbeAvailability`,
поэтому создание нового листа не блокируется полной quality-проверкой каждой
контрольной цели; детальная оценка выполняется на следующем обычном цикле.

Go API обслуживает health/readiness, status,
client-telemetry, current-draft, overview, bootstrap-state, lifecycle и
collection state contracts. `bootstrap-state` строит draft и overview из одной
копии конфигурации, а list/get коллекций используют тот же ограниченный cache.
Последние audit events извлекаются из ограниченного 512-КиБ хвоста JSONL, а не
чтением всего журнала. Live RouterOS overlay использует bounded REST adapter и
не запускает внешний процесс на каждый запрос.

После проверенного login/bootstrap Go API создаёт recovery master key и wrapper:
scrypt `16384/8/1`, AES-256-GCM и URL-safe Base64. Здоровая пара ключей на
повторном входе не перезаписывается, неполная или несогласованная пара
отклоняется, а пароль нативного RouterOS backup хранится только в SecretStore.
Поддерживается только актуальный формат control plane; старые схемы и
recovery-архивы v1 не поддерживаются.

Go recovery format v2 отделяет password-wrapped key от зашифрованного payload:
два фиксированных 512-байтных key-slot находятся в начале файла, а payload
аутентифицируется независимо от них. Смена пароля читает только ограниченный
prefix, записывает неактивный slot следующего поколения и делает `fsync`; сам
образ не читается, не хешируется и не шифруется повторно. После смены hash и
session signing key все прежние сессии становятся недействительны. При ошибке
записи hash выполняется best-effort возврат wrapper к старому паролю.
Go API уже выполняет `POST /api/v1/drafts/check` нативно. Поддерживается только
полная конфигурация актуальной schema v1 без default merge и миграций. JSON
разбирается один раз на входе, а один
семантический проход проверяет размеры коллекций, ID, CIDR, порты, secret refs и
ссылки между политиками, сетями, TLS, транспортами и Reverse VLESS. Read-only UI
переиспользует результат только одной текущей revision; при смене revision кэш
заменяется, а исторические варианты не удерживаются. `PUT/PATCH drafts/current`
проверяют и атомарно сохраняют полную schema v1 под одним writer lock, а reset
возвращает draft к проверенной active generation. Apply публикуется после
переноса renderer/apply pipeline.

`POST /api/v1/route/simulate` также выполняется внутри Go API и использует
тот же schema v1 без изменения Draft. Симулятор сохраняет границы отказа:
локальный клиент следует своему `container_outage`, удалённый клиент никогда
не получает fallback в домашний WAN, а недоступный VLESS не превращает
full-tunnel или выбранное исключение в утечку. Внутренние CIDR, оба режима
`VLESS + WAN`/`WAN + VLESS`, точечные домены, встроенные и локальные service
packs проверяются тем же порядком правил, который показывается в overview.
Встроенный каталог разбирается один раз при старте API; конфигурации и результаты
симуляций не накапливаются в памяти.

`POST /api/v1/network/tls-probe` использует встроенный Go resolver. Он
дедуплицирует и сортирует адреса, отклоняет наборы больше 16 адресов и
до сетевого соединения сверяет REALITY target с известными адресами MikroTik.
Каждый TLS handshake имеет семисекундный deadline, использует системные CA,
проверяет заданный SNI и предлагает только `h2`/`http/1.1`. Ответ перечисляет
результат каждого адреса, версии TLS, ALPN, cipher, SAN и срок сертификата; если
ни один адрес не прошёл проверку, endpoint возвращает 422, а не ложный успех.
Проверка read-only и не сохраняет DNS либо TLS результаты в RAM/state.

`POST /api/v1/diagnostics` агрегирует проверки непосредственно в Go, не
запускает subprocess и не создаёт внешний трафик. Один снимок Draft проходит
семантическую validation; active/LKG сравниваются как crash-safe pointers;
при настроенных учётных данных выполняется один authenticated RouterOS REST
health; при активной generation нативный controller делает bounded probe
Nginx, DNS, Xray и monitor. Ненастроенные проверки явно возвращаются как
`performed=false`, поэтому интерфейс не выдаёт отсутствие проверки за PASS.
Снимки диагностики не кэшируются и не записываются в state.

Go API нативно возвращает метаданные `GET /remote-users/{id}/exports`: только
включённые и не исключённые транспорты, ожидаемые имена файлов и факт наличия
UUID/Hysteria2 secret. Сами значения секретов endpoint не читает и не
возвращает. `POST /service-packs/resolve` сопоставляет домен со встроенным
каталогом без сети; только неизвестный пользовательский pack по явному запросу
загружается штатным bounded ruleset worker и атомарно заменяет один JSON.
Каталог, dependency index и итоговые счётчики правил вычисляются один раз при
старте API; повторные UI-запросы не пересобирают их.

`POST /api/v1/routeros/credentials` валидирует HTTPS origin с явным портом,
SSH port, имя, длину пароля и необязательный PEM CA нативными Go parsers до
записи. Draft получает только стабильные SecretStore refs. Сами значения
пишутся атомарно с undo: если сохранение проверенной schema v1 не удалось,
предыдущие credentials восстанавливаются без хранения дополнительных версий.
Пароль RouterOS backup по-прежнему создаётся только после подтверждённого входа
в панель и не передаётся этим endpoint.

`GET /api/v1/routeros/discover` использует один authenticated Go REST client.
Обязательный `/system/resource` читается первым, затем фиксированный allowlist
из 13 inventory endpoints выполняется максимум четырьмя workers и четырьмя
keep-alive соединениями под общим 30-секундным deadline. Ошибка необязательной
таблицы отмечает только её completeness, а не подменяет данные. Ответ строит
версию/channel/architecture, container/IPv6 факты, внутренние маршруты и
выбираемые статические LAN, WireGuard peer и PPP источники. WAN interface-list
и DHCP-client используются для исключения внешних connected/route CIDR.
Динамические DHCP, публичные dynamic routes, default WireGuard route,
выключенные и `SB-GATEWAY`-owned объекты не выдаются
за пользовательские устройства. Live WireGuard egress eligibility пока явно
возвращается неполной, пока отдельный detector не перенесён в Go.

`POST /api/v1/routeros/import` разбирает загруженный обычный RouterOS `/export`
целиком внутри Go. Размер JSON вместе с экспортом ограничен
2 МиБ. До изменения Draft parser отклоняет `show-sensitive=yes` и непустые
`password`, `private-key`, `preshared-key`, `secret` и `token`; допустимы только
штатно скрытые значения. Один проход собирает interface/network inventory,
адреса самого роутера, version/channel, LAN management suggestions, существующую
`SB-GATEWAY` topology и предупреждения о небезопасном SOCKS, SSTP/WAN firewall
или WireGuard default route. Найденные CIDR не применяются автоматически:
покрытые уже настроенной сетью помечаются `accepted`, прежние явные решения
`accepted/ignored` сохраняются, остальные остаются `pending`, а deployment-ready
сбрасывается. Два служебных `/30` предлагаются из фиксированных private pools
только после проверки пересечений; это подсказка для UI с обязательной live
проверкой, а не доверенный RouterOS факт. Экспорт хешируется один раз SHA-256,
сам текст и секретные варианты в state либо памяти-кэше не сохраняются.

Публичный `GET /{subscription-token}` также обслуживается Go API. По умолчанию
он отдаёт Base64-набор VLESS/Hysteria 2 links; по `format` либо User-Agent/Accept
строит единый Xray JSON, sing-box JSON или Mihomo YAML. Источником служит только активная
immutable generation, поэтому несохранённый Draft не меняет рабочий профиль.
Токены длиной 43–128 символов читаются по стабильным SecretStore refs и
сравниваются через `hmac.Equal`; неверный, отозванный, отключённый пользователь,
неполный transport и неизвестный формат одинаково дают пустой 404. Ответы имеют
`no-store`, `noindex` и не попадают в серверный cache. VLESS WebSocket, gRPC,
HTTPUpgrade, XHTTP, Reality/Vision, gRPC+Reality и XHTTP+Reality расширяются по
всем включённым CDN deployments. Отдельный direct gRPC+TLS Pin не расширяется
через CDN: экспорт получает один SHA-256 pin leaf-сертификата выбранного
TLS-профиля. Hysteria 2 сохраняет TLS pin и salamander obfs.
Опциональный UDP hopping хранится на транспорте как диапазон, интервалы и список
исключённых портов. Клиентский Xray 26.9.9 получает внешнюю маску `udphop` перед
`salamander`; серверный inbound её не получает. RouterOS раскладывает оставшиеся
сегменты диапазона в управляемые UDP dstnat-правила на один внутренний listener.
До мутации проверяются чужие dstnat и WireGuard listen-port; конфликт останавливает
Apply и требует исключить занятый порт. Проверка повторяется по живому состоянию
RouterOS на каждом Apply и сравнивает диапазоны без перебора каждого порта.
Xray и Mihomo документы включают TUN, перехват DNS и безопасный full-tunnel к
активному узлу; при включённом client auto-fallback несколько узлов образуют
health-tested fallback. Серверная policy остаётся авторитетной для маршрутизации
remote user, поэтому профиль не переносит доверительные решения в публичный URL.

Администраторский `POST /api/v1/remote-users/{id}/exports/download` использует
тот же Go profile builder, но только после session+CSRF и повторной проверки
пароля панели. ZIP формируется целиком в памяти с жёстким пределом 8 МиБ и
режимом `store`: текстовые профили не тратят CPU роутера на почти бесполезный
уровень Deflate 9. Архив содержит combined Xray/Mihomo, отдельные Xray и share
links для каждого transport/deployment, общий список ссылок и короткий README;
entries имеют mode `0600`. Архив не записывается на диск и не кэшируется, а audit
получает только user ID и имена файлов, но не их секретное содержимое.

Go repository уже содержит crash-safe commit поколения. Immutable generation
сначала проверяется по SHA-256, затем `active.json` атомарно становится
единственной точкой commit; `last-known-good.json` и `apply-metadata.json`
записываются после неё и при старте восстанавливаются только из проверенного
active pointer, без сканирования и догадок. Pointer хранит previous/runtime
revision, backup reference, actor и UTC timestamp.

Первые вынесенные в Go роли — policy DNS и process watchdog. DNS находится на горячем
пути каждого сайта и приложения. Она сохраняет существующий JSON-контракт и
порядок first-match правил, ограничивает число одновременных upstream-запросов,
кэширует ответы по TTL, объединяет одинаковые запросы и переиспользует HTTP/2
DoH и DoT/TCP соединения. Изменение `policy-dns.json` не опрашивается фоновым
таймером: атомарный Apply определяет изменившийся артефакт и точечно
перезапускает только DNS-компонент, не затрагивая Xray.
Watchdog сохраняет прежние hysteresis, apply-guard и restart budget, но читает
process/listener inventory непосредственно из `/proc` и парсит generated JSON
внутри процесса. Внешние `ip`/`nft` остаются
только в 30-секундном deep probe, а `xray -test` — только после изменения
опубликованного config. На неизменившемся файле watchdog сравнивает только
`mtime` и размер; SHA-256 и JSON читаются заново лишь после смены метаданных.

Компилятор policy DNS runtime также перенесён в Go. Он сохраняет канонический
`policy-dns.json`, порядок identity lanes, first-match доменных правил и
loopback tunnel wiring для Xray. Service ruleset читается и разбирается один раз
только в рамках текущей компиляции, ограничен 16 МиБ и после завершения не
остаётся в постоянном cache. Подключение этого компилятора к production Apply
выполняется вместе с переносом общего source-model/Xray renderer; до этого
production topology по-прежнему не переключается на частичный Go controller.
Нормализованный DNS source-model строится напрямую из текущей schema v1 без
миграций, сетевых запросов и default merge. Неизменяемый встроенный
каталог сервисов разбирается один раз на процесс; это единственная общая копия,
а не cache ревизий. Остальные правила и серверы создаются заново только при
явной подготовке кандидата.

Go candidate workspace принимает только полный набор известных runtime-
артефактов, ограничивает один файл 32 МиБ и весь candidate 64 МиБ. На диске
остаётся ровно одна воспроизводимая revision; старые candidate не кешируются.
`Plan → Apply` загружает её по manifest и SHA-256 одним последовательным
чтением с общим 128-КиБ буфером, не выполняя повторный render и не загружая
файлы целиком в RAM. Activation сравнивает и публикует только изменившиеся
файлы, держит одну rollback-копию до успешного LKG commit и затем удаляет её.
Каталоги и отдельные файлы публикуются через `fsync` и rename; partial candidate,
path traversal, symlinked cleanup и подмена артефакта после Plan отклоняются.

Вспомогательные runtime-артефакты `watchdog.env` и `client-telemetry.nft`
рендерятся Go-кодом из той же schema v1. nft-программа нормализует и объединяет
только IPv4 CIDR включённых локальных клиентов, содержит лишь named counters и
`return` и не может менять verdict/mark/NAT. Правила обоих направлений идут от
наиболее специфичного префикса к общему: отдельный `/32` учитывается своей
карточкой и не попадает в расположенный раньше в документе all-LAN `/24`.
Renderer и telemetry collector
используют одну функцию имён счётчиков, поэтому рассинхронизация хешей между
двумя реализациями исключена. Список исключений transparent proxy также
строится в Go: только включённые internal/management CIDR и маскированная IPv4
подсеть контейнера, с дедупликацией без изменения порядка.

Входы Xray и их stream settings рендерятся непосредственно из проверенной
schema v1 в Go. Поддерживаются только используемые runtime-контракты `tun`,
`mixed`, VLESS и Hysteria 2, а также TCP, WebSocket, gRPC, HTTPUpgrade, XHTTP,
TLS и REALITY. Reverse user связывается с reverse tag при одном проходе списка
пользователей. Неизвестный транспорт и вручную заданный outbound TLS с
`allowInsecure` блокируют candidate вместо скрытого fallback или неявного
преобразования. Узлы импортированной клиентской подписки сохраняют
собственные `pcs`/`pinnedPeerCertSha256`, `vcn`, ALPN и ClientHello fingerprint.
Renderer передаёт pin как `pinnedPeerCertSha256`, поддерживаемый Xray 26.9.9.
Legacy `insecure=1`/`allowInsecure=1` допустим только при наличии pin: старый
флаг отбрасывается, а проверка закреплённого сертификата остаётся обязательной.
Остальные подписки и ручные резервы не ослабляются.
Статус автоматической активации привязан к канонической ревизии нормализованных
узлов, а не только к fingerprint исходного ответа провайдера. Поэтому повторный
refresh с тем же содержимым всё равно заменяет runtime-снимок, если новая версия
парсера уточнила transport или индивидуальные TLS-параметры узла.
Серверный runtime всегда задаёт transport актуальным для Xray 26.9.9 полем
`method`. Клиентские и Reverse bridge экспорты используют совместимый ключ
`network`, который понимают как закреплённое ядро 26.7.28, так и текущие ядра;
обновление серверного ядра поэтому не требует повторной генерации уже
установленного reverse JSON. Header экспорта сообщает проверенную bridge-версию,
а совместимость нового серверного ядра со старым bridge всё равно подтверждается
отдельным data-plane прогоном.
Исходная inbound-модель также собирается в Go: секреты UUID, путей, REALITY,
VLESS Encryption и Hysteria читаются только для включённых сущностей текущего
render, reverse user добавляется только в явно выбранные `transport_ids`, а
пути сертификатов Hysteria и direct gRPC+TLS Pin передаются Xray без повторного
чтения их содержимого. gRPC-вход использует ALPN `h2`; leaf читается отдельно
только при формировании клиентского pin.
Устаревший одиночный `transport_id` намеренно не восстанавливается.
Исходящие direct, block, VLESS, Hysteria 2 и policy selectors преобразуются тем
же Go-пакетом. Вложенные selectors разворачиваются в реальные leaf-теги с
сохранением приоритета и отклонением циклов; reverse-тег никогда не подменяется
Freedom handler. `direct-wan` привязан к адресу container veth и получает
минимальный allow-list только из аутентифицированных direct-правил к private
CIDR, сохраняя блокировку остальных private/reserved назначений.
Ordered Xray routing rules тоже компилируются в Go. `sniff` и `hijack-dns`
остаются в специализированных стадиях, selectors получают `balancerTag`, а
обычные выходы — `outboundTag`. Локальный ruleset читается один раз на текущий
render с лимитом 16 МиБ, разворачивается без catch-all деградации и не остаётся
в cache после подготовки candidate. В конец всегда добавляется явный block для
TCP/UDP.

Исходная route-модель теперь также строится из schema v1 в Go. Сохраняется
порядок служебных запретов, разрешений ролей, защиты RouterOS/LAN, сервисных и
доменных исключений, IPv6-политики и финальных маршрутов. Неизвестная политика
или выход закрываются через `block`; адреса серверов выбранных узлов заранее
направляются в `direct-wan`, чтобы TUN не создавал рекурсивный маршрут.

Финальная Xray-сборка объединяет эти Go-стадии с Go policy DNS в один
канонический candidate и добавляет только один локальный management API.
Единая функция `BuildXrayCandidateFromSchema` выполняет весь путь от
проверенной конфигурации и выбранных runtime-узлов до Xray JSON и policy-DNS
без миграций и сетевого I/O.
Reverse VLESS остаётся leaf исходящего selector и поэтому может быть активным
интернет-маршрутом устройств за MikroTik; отдельный статический outbound с тем
же тегом не создаётся. URLTest получает стабильный SHA-256 prefix без загрузки
запасных вариантов конфигурации в память.

Nginx candidate также рендерится Go-кодом из текущей нормализованной схемы.
Поддерживаются отдельный и совмещённый direct/CDN адрес подписки, объединение
транспортов на одном origin, защита origin секретными заголовками и отдельные
TLS-профили. Старые transport-owned TLS поля и неявная CDN-карточка не
восстанавливаются. В рамках одного render каждый нужный секрет читается не
более одного раза; PEM-содержимое повторно не загружается, используются уже
проверенные пути SecretStore.

`BuildNativeRuntimeArtifacts` собирает единым Go-вызовом полный локальный набор:
`xray.json`, `policy-dns.json`, `nginx.conf`, `watchdog.env`, telemetry nft и
transparent exclusions. Малый cache живёт только во время этой сборки и не
допускает повторного чтения одного секрета разными стадиями; после возврата он
не сохраняется. RouterOS script остаётся отдельным кандидатом и применяется
через RouterOS API, а не публикуется в локальный runtime-каталог.

Нативный process controller держит по одной
долгоживущей goroutine на компонент, не опрашивает здоровые процессы таймером и
перезапускает только явно выбранные компоненты. Неожиданный выход использует
ограниченный backoff 1/2/4/8/16/16 секунд. Apply получает подтверждение restart
только после запуска новой generation, а затем выполняет отдельный bounded
probe; это не допускает ложного commit между остановкой старого и запуском
нового процесса. Production entrypoint передаёт ему PID 1 напрямую.

Команда `sb-gateway appliance` собирает API, policy DNS и monitor как
in-process Go-компоненты, а Xray и Nginx — как изолированные process groups под
тем же нативным controller. API получает controller напрямую в памяти, без
локального RPC, сокета и сериализации restart-команд.

Внешняя команда запускается в отдельной process group и получает `SIGTERM` при
restart или остановке контейнера; через восемь секунд остаётся только bounded
`SIGKILL`, ожидание которого также ограничено двумя секундами. Stdout/stderr
передаются потоково, без накопления логов в Go heap.
Каждая live TCP-проверка делает одну попытку и сразу закрывает соединение. После
restart controller повторяет её раз в 250 мс только пока компонент не готов,
останавливается при первом успехе и ограничен общим 30-секундным deadline Apply;
в штатной работе фонового polling нет.

Runtime store сравнивает candidate с опубликованными файлами один раз и
передаёт валидатору только точный changed set, удерживая единственную apply
границу до атомарной публикации. Поэтому неизменный Xray/Nginx/DNS не проходит
повторную бинарную проверку и не перезапускается. Вывод проверяющих команд
ограничен 64 КиБ и не может разрастись в heap.

Нативный `POST /api/v1/drafts/apply` связывает runtime activation с RouterOS
транзакцией: локальные процессы запускаются и проходят probe под защитой Safe
Mode и scheduler либо scheduler-only guard на 7.24, затем active pointer
фиксируется до disarm независимого scheduler. Исторический
RouterOS candidate рендерится с сохранённым snapshot узлов той generation,
включая корректный пустой snapshot. Для первого Apply без active generation
из подтверждённой топологии строится отдельный fail-open rollback-кандидат без
управляемых клиентов, публичных входов и WireGuard-выходов. Точный откат при
доступной стабильной консоли оставляет за собой SSH Safe Mode. В scheduler-only
режиме RouterOS 7.24 этот ограниченный кандидат гарантирует прямой WAN, а
export и зашифрованный backup остаются точкой полного восстановления; оба
создаются до любых изменений.
После проверки CSRF принятая транзакция получает отдельный пятиминутный
deadline и не зависит от жизни HTTP-соединения. Поэтому краткий разрыв пути к
панели при restart Xray не превращает здоровую активацию в ложный rollback;
операция всё равно завершается commit или ограниченным rollback.

После локального runtime probe выполняется один authenticated
`/rest/system/resource` через тот же bounded REST client. Это проверяет живой
management path после изменения маршрутов без повторного discovery и без retry
loop.

`POST /api/v1/drafts/rollback` требует CSRF, точную фразу `ОТКАТИТЬ` и повторную
проверку текущего пароля. Предыдущая verified generation не копируется особым
путём: она проходит тот же нативный render, runtime activation/probe,
защищённую RouterOS-транзакцию и atomic active commit, после чего становится
новой active/LKG.

Go API нативно изменяет `local_clients`, `networks`, `policies`,
`reverse_vless_exits`, `remote_users` и `subscriptions`. Создание и замена
Reverse VLESS/remote UUID, клиентского subscription path, Hysteria 2 password и
URL источника используют `crypto/rand` и SecretStore; transient значения не
попадают в draft или ответ. Полная конфигурация валидируется до первой записи
секрета, а ошибка durable draft write возвращает затронутые secret-файлы в
исходное состояние. Delete сохраняет секреты для recovery. TLS profiles и
transports также проходят нативный provisioner. TLS pair
проверяется `crypto/tls` и `crypto/x509`, REALITY keypair создаётся стандартным
X25519, пути/short ID/origin header/Hysteria obfs — `crypto/rand`. Форматы,
которые определяет сам Xray (`vlessenc` и `mldsa65`), вызывают его только при
явной генерации, с 30-секундным timeout и выводом не более 64 КиБ. Independent
subscription reserve принимает
ровно одну VLESS URI, строго проверяет server/port/TLS/Reality/transport и
нормализует узел в Go. UUID хранится только в SecretStore; `allowInsecure`
отклоняется, а общая проверка конфигурации выполняется до записи секрета.

`GET /api/v1/reverse-vless-exits/{id}/client-config` также обслуживается Go.
Он читает UUID и transport secrets только в момент запроса, разворачивает все
включённые CDN endpoints и выдаёт отдельный Xray VLESS reverse bridge. На
удалённой стороне `reverse-direct` блокирует literal private/reserved IPv4/IPv6
до catch-all allow, поэтому домашние LAN/management диапазоны через Reverse не
экспортируются в интернет. Варианты client config не кешируются в RAM.

Редакторские reveal-endpoints для subscription URL и HTTP transport path читают
ровно один явно запрошенный secret-файл. URL требует session, а POST раскрытия
path дополнительно требует CSRF; ответ не содержит соседних transport secrets.

Создание и ротация remote-user subscription link также выполняются Go под тем
же configuration lock. Для режима `direct-and-cdn` ответ содержит обе ссылки с
одним opaque 256-bit token и поднимает выбранный primary endpoint первым.
Невалидный hostname отклоняется до генерации token; варианты ссылок не
кешируются. Единственный источник публичного URL — применённый CDN/direct
endpoint конфигурации. Переменные окружения и сторонние сетевые пути не могут
подменить адрес подписки или скрыть отсутствие публичного hostname.

Ручное обновление provider subscription обслуживается Go и сериализуется одним
lock, чтобы два ответа по 8 МиБ не занимали память одновременно. HTTP deadline
учитывает одну уже выполняющуюся bounded-попытку перед собственной: очередь не
обрывает ответ на старом 45-секундном пороге и не превращается в nginx 502. Direct fetch
не использует proxy из окружения, не следует redirect, допускает только HTTPS и
соединяется лишь с проверенным public IP; response header ограничен 64 КиБ.
Парсер принимает VLESS/Hysteria 2 строки и base64-списки, максимум 500 узлов.
Новый набор и его content-addressed secrets записываются только после полного
разбора; ошибка оставляет прежний `subscription-nodes` без изменений. В памяти
не сохраняются старые варианты, а первый refresh после Apply создаёт ровно один
rollback snapshot активной revision.

Если direct refresh выключен или временно недоступен, Go читает подтверждённые
healthy outbounds из одного `selector-health` snapshot, ставит узлы текущего
провайдера последними и пробует не более 12 уникальных каналов. Выбранный
Reverse/VLESS/WireGuard/independent reserve назначается локальному Xray selector,
после чего HTTPS скачивается через `127.0.0.1:19080`. Внешний hostname заранее
разрешается в public IP, а proxy получает именно этот IP с исходным TLS SNI:
повторное DNS-разрешение внутри proxy не может перенаправить запрос в LAN.

Автообновление не использует fixed polling loop. После стартовой задержки Go
вычисляет ближайший `refresh_minutes`/`refresh_hours` deadline и держит один
timer. За пробуждение обновляется не более одной подписки; остальные
просроченные задания разнесены минимум на 10 секунд. Последняя попытка хранится
отдельно от last-known-good nodes, поэтому сломанный provider не опрашивается
повторно до своего следующего интервала. При отсутствии подписок проверка
состояния выполняется не чаще раза в пять минут.

Загруженный набор не перезапускает общий Xray и не ждёт простоя dataplane.
Provider outbounds входят в versioned health-pool contract и одновременно
остаются в полном `xray.json` для следующего cold start. Health worker вычисляет
runtime tag из scoped ID и полного канонического outbound, добавляет новый
handler через `HandlerService`, переключает основной и service selectors через
`RoutingService` и проверяет фактический override через readback. Только после
этого прежний handler выводится из registry; Xray не закрывает уже выданный
соединению handler, поэтому существующий поток заканчивается на старой
generation, а новый сразу идёт через новую.

Cold-start helper восстанавливает versioned handlers и selectors до допуска
трафика. При первом чтении health-agent сопоставляет фактический tag с текущим
контрактом, принимает handler под управление и не вызывает повторный `ado`.
Так же переиспользуется уже выбранный `subscription-update-egress` при
повторном refresh неизменившейся generation.

Control plane считает generation активной только после marker с совпадающими
SHA-256, mtime опубликованного health-pool и PID текущего Xray. Это исключает
ложное подтверждение старым marker при rollback одинакового содержимого.
Ошибка add/switch/readback возвращает прежний pool тем же hot-механизмом, без
рестарта ядра. `subscription-update-egress` также управляется напрямую через
loopback Xray API; отдельного Clash API и его секрета в runtime нет.

Перед Plan/Apply control plane разворачивает per-subscription state в один
scoped provider inventory: выключенные подписки пропускаются, а одинаковые ID
разных провайдеров получают разные runtime tags. Внутри runtime renderer к нему
ровно один раз добавляются configuration-owned Independent Reserve, RouterOS
WireGuard и Reverse VLESS. Поэтому эти выходы нельзя забыть на API-уровне или
случайно сохранить в снапшоте другой generation; rollback восстанавливает
provider snapshot, а configuration-owned узлы пересобираются из его config.

Исходная модель RouterOS candidate также нормализуется из актуальной schema v1
в Go без сетевого I/O и секретов. За один проход собираются IPv4/IPv6 списки
управляемых и fail-closed клиентов, внутренние/management сети, bypass адреса
узлов, доверенные ingress-интерфейсы и стабильные source identity для выбранных
WireGuard-egress. Имена RouterOS, адреса, HTTPS REST origin и порты проверяются
до генерации RSC; WireGuard identity детерминированно размещаются внутри
`198.18.0.0/15`, поэтому Plan и Apply не создают новые адреса при неизменной
конфигурации. Никакие исторические варианты модели не кешируются.

Первая стадия Go RSC renderer использует эту модель и сохраняет тот же секционный контракт
`core/dns/watchdog/address-lists/wireguard-egress/ipv6/finalize`. На Apply
diversion gate сначала выключается, управляемый default route снова указывает
на TUN-контейнер. При очистке списков рассматриваются только объекты с
комментарием `SB-GATEWAY`, а при добавлении уже существующие пользовательские
`list + address` удовлетворяют требуемому членству без захвата ownership и без
дубликата. Для каждого WireGuard-egress создаются отдельные
source-based rule/table/default route и обратный маршрут к контейнеру; удалённые
выходы удаляются по точному owner-prefix. В конце очищаются только соединения с
`connection-mark=sb-managed`, после чего gate возвращается под управление
watchdog. Эта traffic-path стадия пока не подключена к production Apply: перед
переключением остаётся перенести reconciliation публичных входов. Renderer
требует уже настроенный IPv4 full-tunnel peer и не меняет `allowed-address`
пользовательского WireGuard peer.

Для будущего Go Apply RSC сравнивается только по полным renderer-owned
секциям, а не построчно. Изменение core, address-list или WireGuard всегда
добавляет `finalize`; apply и rollback delta строятся симметрично из одной пары
кандидатов. Неизвестный заголовок, нарушенный порядок секций, пустая секция или
delta больше 80% полного RSC автоматически выбирают полный candidate. Это
уменьшает число RouterOS-команд при обычной смене DNS/watchdog и не вводит
неограниченный cache вариантов.

Нативный RouterOS HTTPS adapter держит до двух idle-соединений к одному
роутеру, отключает response compression и ограничивает ответ четырьмя МиБ.
Обычные inventory/health запросы имеют общий timeout 15 секунд; синхронные
command/action endpoints используют тот же connection pool, но ждут завершения
RouterOS script до двух минут. Credentials передаются только Basic Auth внутри TLS и не
попадают в ошибки. Небольшой симметричный delta до 16 КиБ устанавливается как
content-addressed `SB-GATEWAY-apply|rollback-*` script и запускается через REST;
существующий script обновляется только при точном owner-comment. Полный RSC не
проталкивается через ограниченное поле `source`: его потоково передаёт
нативный SCP transport, а короткий import-wrapper запускается выбранным guard.

Нативный SSH transport уже реализует потоковую загрузку полного RSC через
RouterOS legacy SCP sink: один проход `io.Reader`, потолок 2 МиБ и никакой
второй копии candidate в heap. Host key сохраняется при первом соединении в
private `known_hosts`, последующая подмена ключа блокируется. Имя upload строго
content-addressed и owner-scoped; пароль остаётся внутри Go SSH handshake.
SCP, Safe Mode и scheduler guard подключены к единому health-gated Apply;
полный candidate не имеет отдельного менее защищённого пути.

Перед RouterOS connectivity transaction Go REST client создаёт два recovery
артефакта с одним ограниченным именем: обычный `/export` без sensitive-флага и
binary backup с `aes-sha256`. Backup password передаётся только в TLS-запросе и
не сохраняется в client state или тексте ошибки. Возвращаемая metadata содержит
только имена файлов RouterOS. Для command/action endpoints успешными считаются
объект, пустое тело и используемый RouterOS 7.24 пустой JSON-массив; HTTP-ошибка,
невалидный JSON или превышение bounded response по-прежнему отклоняются.
Singleton clock декодируется общим object-or-array путём и остаётся обязан
содержать ровно одну полную пару `date`/`time`.

Live transport factory Go читает актуальные RouterOS username/password,
отдельный backup password и optional CA строго один раз при Apply. HTTPS client
и SSH transport создаются из одной schema-v1 записи; SSH host берётся из
проверенного HTTPS origin, порт — из `routeros.ssh_port`, а private TOFU-файл
создаётся только при первом реальном SSH handshake. Между Apply credentials и
transport objects не кешируются.

Интерактивная SSH Safe Mode транзакция также реализована в Go. Она ждёт
аутентифицированный prompt, включает Safe Mode через Ctrl-X, запускает только
content-addressed managed script внутри `:do/on-error` с уникальным маркером и
возвращает управление лишь после нового `<SAFE>` prompt. Commit требует явного
`Safe Mode released`; любая ошибка, отмена контекста или обычный `Close`
посылает Ctrl-D и закрывает SSH-owner, оставляя RouterOS выполнить rollback.
Вывод консоли ограничен 256 КиБ и никогда не включается в публичную ошибку.
Независимый одноразовый rollback-scheduler также реализован в Go. Он вычисляет
момент срабатывания по локальным часам RouterOS, запускает только точный
content-addressed rollback script, при необходимости возвращает watchdog и
самоудаляется. Снятие защиты сверяет имя и owner-comment и делает один DELETE
без polling/retry loop; отработавшие записи чистятся лишь при отсутствии
floating undo. Эти примитивы использует единый health-gated orchestration
section delta и полного RSC.

RouterOS 7.24 выделен по фактически обнаруженной версии: его SSH-служба может
закрыть консоль сразу после `Taking Safe Mode session... Success!` и создать
автоматический `supout.rif`. На этой ветке control plane не провоцирует сбой и
передаёт владение транзакцией уже вооружённому RouterOS-local scheduler. Точный
apply script запускается через REST, затем выполняются те же runtime и
RouterOS health-check, снятие scheduler и только затем atomic active/LKG commit.
При ошибке до commit сохранённый rollback запускается немедленно; если REST потерян,
scheduler остаётся вооружённым. HTTP write-deadline только для Apply/Rollback
равен шести минутам: он длиннее пятиминутной операции, но не ослабляет короткие
таймауты остальных API. Неожиданный разрыв SSH Safe Mode на других
версиях использует тот же fallback только после подтверждения отсутствия
`floating-undo`.

Для небольших section delta этот orchestration уже собран: rollback и apply
сначала только устанавливаются, затем ставится независимый scheduler и лишь
после этого открывается SSH Safe Mode. Успешный health-check фиксирует Safe
Mode, ждёт исчезновения floating history и снимает scheduler. Ошибка проверки
закрывает активный Safe Mode; если RouterOS уже автофиксировал изменения на
лимите истории, Go немедленно запускает сохранённый LKG rollback. При любой
неопределённости scheduler остаётся вооружённым. Транзакция не создаёт фоновых
goroutine и не держит candidate cache после возврата.

После выхода из Safe Mode scheduler снимается **до** финального commit runtime
LKG и active pointer. Если снять его не удалось, финализация приложения не
запускается: Go немедленно выполняет точный rollback script, а scheduler и
нужный ему import остаются для независимой повторной попытки. Если scheduler
уже снят, но публикация application commit point не удалась, Go возвращает
RouterOS к прежней generation немедленно; неудача этого восстановления явно
помечается как неподтверждённое состояние. `active.json` является единственной
точкой фиксации приложения. Ошибка последующей записи производных LKG/metadata
не откатывает уже опубликованный runtime: документы восстанавливаются из
`active.json` при reconciliation.

Перед первой runtime/RouterOS-мутацией Apply записывает долговечный
`apply-operation.json`. Если процесс завершается после снятия rollback guard,
решение не выводится из промежуточной фазы: единственным решением остаётся
`active.json`. Background reconciler заново строит runtime и RouterOS из этой
generation, фиксирует runtime LKG и только затем очищает journal. Пока journal
активен, readiness и traffic-readiness возвращают `apply_recovery_pending`,
поэтому watchdog не публикует RouterOS lease и промежуточная комбинация не
получает управляемый трафик.

Для самого первого Apply, когда `active.json` ещё не существует, до мутаций
отдельно сохраняется content-addressed `recovery_revision` безопасной
установочной конфигурации. После аварии reconciler применяет и проверяет именно
эту generation вместе с записанным fail-open RouterOS source, фиксирует runtime
LKG, но не публикует `active.json`: первый Apply можно повторить как первый.
Старый журнал без `recovery_revision` совместим только при точном совпадении
заново построенного безопасного RouterOS source с уже сохранённым journal.

Все операции, меняющие runtime или RouterOS, проходят через общий mutation
barrier. Внутрипроцессный lock сериализует Apply, ручной откат, image
update/uninstall, восстановление и активацию подписки; `apply-operation`,
`lifecycle-operation`, `subscription-runtime-operation` и recovery marker
продолжают ту же защиту после рестарта API. Ручной откат использует тот же
порядок lock: mutation barrier, проверка persisted journal, затем config lock.
Read-only status, readiness и diagnostics этим lock не закрываются.
Загрузка/разбор подписки может выполняться в фоне, но публикация нового node
inventory требует свободного mutation barrier.

Перед созданием каждого нового rollback-scheduler control plane читает все
project-owned scheduler. Пока хотя бы один из них ещё не выполнялся
(`run-count=0`), новая изменяющая транзакция останавливается до запуска
candidate и возвращает `recovery_pending`. Поэтому guard, который не удалось
снять после успешного немедленного отката, не может пережить следующий
успешный Apply и позднее вернуть уже подтверждённую новую конфигурацию. После
срабатывания либо подтверждённого удаления прежнего guard новый Apply снова
разрешён; отработавшая one-shot запись не считается активной generation.

Та же транзакция поддерживает полный generated RSC до 2 МиБ. Apply и rollback
проверяются на точный заголовок, полный упорядоченный набор managed sections и
запрещённые команды, получают SHA-256-derived имена и потоково загружаются по
SCP. REST хранит лишь короткие `/import file-name=...` wrappers. После commit
оба inert-файла удаляются одной SSH-командой; ошибка этой необязательной уборки
помечается как `CleanupPending`, но не превращает уже здоровый commit в ложную
ошибку. Candidate source нигде не дублируется в постоянный cache.

Последний PUT image-update scheduler имеет отдельную семантику неопределённого
результата. Явный RouterOS HTTP 4xx считается отказом. При transport error
операция остаётся `preparing` с bounded confirmation window: control plane
читает точный owned scheduler и текущие container roots. Найденный scheduler
переводит операцию в `scheduled`, его отсутствие после окна — в `failed`.
Повторный запрос до подтверждения видит активный persisted journal и не может
заменить уже работающий scheduler.

Go control plane теперь обслуживает read-only `POST /api/v1/drafts/plan` без
записи состояния и без сетевого обращения к RouterOS. Plan делает один
детерминированный обход active/draft, сохраняет стабильные entity paths,
сравнивает RouterOS traffic candidate лишь для изменённой валидной ревизии и
возвращает совместимые `changes`, `steps` и `apply_mode`. Чувствительные before/
after значения редактируются до ответа. Повторное каноническое JSON-хеширование
каждого поддерева не используется.

Исходящая часть source-model теперь также строится из schema v1 в Go. Узлы
VLESS и Hysteria 2 получают секреты только по запросу текущего render; RouterOS
WireGuard превращается в source-bound direct, а Reverse VLESS — во временный
selector placeholder, который удаляет финальная Xray-сборка. Выборы
region/country/city/location/WireGuard/Reverse разворачиваются детерминированно
и ограничиваются максимум десятью активными кандидатами, не вытесняя более
низкий пункт приоритета всеми узлами первого пункта. Reserve-узлы остаются
только в subscription updater и не попадают в пользовательский маршрут.
City-selector сравнивает смысловое имя после удаления ведущих флагов и
служебных emoji-бейджей провайдера. Поэтому изменение оформления подписи узла
не удаляет уже выбранный город или страновой узел из маршрута; само отображаемое
имя подписки при этом остаётся исходным.
Устаревшие `outbounds`/`legacy_selection_key` не читаются: пустой текущий
`selection_order` даёт закрытый selector с `block`, без скрытого восстановления.

Стартовый Xray wrapper использует встроенные команды: `sb-gateway tcp-ready`
проверяет RoutingService, `sb-gateway xray-balancers` извлекает начальные
selector members, а `sb-gateway wireguard-egress-plan` валидирует адреса
`198.18.0.0/15` и выдаёт стабильные policy-rule priorities. Policy DNS всегда
запускает Go-роль из release binary.
Xray API, восстановление startup-selector и kernel TPROXY
используют один общий 15-секундный дедлайн вместо двух последовательных минутных
ожиданий. Поэтому
неисправное ядро не удерживает уже перенаправленный RouterOS-трафик в длинном
black-hole, а исправный старт допускает трафик сразу после подтверждения ранее
измеренного рабочего резерва.

`sb-gateway rulesets` читает встроенный JSON-каталог сервисных пакетов,
формирует offline seeds, а monitor обновляет только пакеты активной generation. Include
graph, размер загрузки и число правил ограничены; redirect запрещён, а новый
JSON публикуется атомарно только после локальной проверки. Ошибка сети оставляет
last-known-good файл без изменений. Суточная задача делит Go heap с watchdog и
телеметрией и не держит отдельный спящий процесс.

Проверенный и заранее распакованный recovery restore до старта data plane
применяет `sb-gateway recovery-apply-pending`. Go-процесс проверяет operation ID,
строгое расположение staging-каталога, тип/размер/SHA-256 каждого файла и
destination root. Хеш вычисляется одновременно с потоковой атомарной копией,
поэтому файл не читается дважды и не загружается целиком в RAM.

Создание, загрузка, скачивание и подготовка recovery теперь также выполняются
в основном Go-процессе. Формат `SBGWREC2` хранит незжатый tar в независимых
AES-256-GCM чанках по 64 КиБ: это сознательно меняет небольшой объём SSD на
низкую нагрузку CPU и ограниченный рабочий набор памяти. Буферы шифрования и
дешифрования переиспользуются, весь архив в heap не попадает. Перед записью
pending-operation проверяются AEAD каждого чанка, первый `manifest.json`,
точный набор обычных файлов, размеры и SHA-256; live state остаётся неизменным.
После staging Go устанавливает через RouterOS REST только фиксированные
project-owned worker и one-shot scheduler. Worker сначала удаляет scheduler,
затем требует ровно один контейнер с комментарием `SB-GATEWAY container` и
перезапускает его. При недоступном RouterOS проверенный staging сохраняется, а
ответ явно требует ручного перезапуска вместо потери подготовленного restore.

При Browser upload контейнерного image Go API одним последовательным проходом
пишет request body на внешний SSD, считает
SHA-256 и пропускает Docker tar через потоковый reader. В heap остаются только
переиспользуемый 64-КиБ буфер и ограниченные четырьмя МиБ метаданные JSON;
layer blobs никогда не копируются в память процесса. Принимается ровно один
`linux/arm64` image с OCI title `sb-gateway` и валидным version label. После
успеха content-addressed файл `sb-gateway-upload-<sha256>.tar` заменяет прежний
кандидат, а state хранит ровно одну verification-запись — варианты «про запас»
не кэшируются и повторный полный hash-pass сразу после upload не выполняется.

Full uninstall также планируется нативно. Перед любой мутацией Go API получает
живой список RouterOS containers, требует ровно один объект с комментарием
`SB-GATEWAY container`, выводит external storage root из его `root-dir` и
сравнивает с явно подтверждённым значением. В RouterOS сначала записывается
фиксированный worker, затем последним REST-запросом создаётся one-shot scheduler.
Worker возвращает исходные WireGuard `allowed-address`, удаляет только объекты с
точными project-owned именами/комментариями, ждёт остановки контейнера и лишь
после этого удаляет проверенный каталог. Пользовательский текст никогда не
становится RouterOS source; единственная подстановка — root после строгой
валидации символов и запрета traversal/flash.

## Потоки трафика

### Управляемый локальный клиент

1. RouterOS проверяет точное попадание источника в `SB_MANAGED_CLIENTS`.
2. Назначения из `SB_INTERNAL_NETWORKS`, адрес самого RouterOS, контейнерные
   сети и VLESS endpoints исключаются.
3. Новое соединение получает `connection-mark=sb-managed` и
   `routing-mark=to-sb-gateway`.
4. До `veth-sb` нет src-nat/masquerade, поэтому transparent listener видит реальный source IP.
5. Xray-core выполняет sniff и DNS-hijack, затем сопоставляет
   client + service.
6. Явные service routes идут по назначенным политикам; пакеты direct-WAN
   остаются прямыми. VPN-политика может выбрать провайдерский VLESS/Hysteria,
   Reverse VLESS или RouterOS WireGuard egress.
7. Для `VLESS + WAN` остальное идёт через выбранную VPN-политику, а сервисные
   исключения — WAN. Для `WAN + VLESS` остальное идёт через WAN, а исключения —
   через выбранную VPN-политику. Пустой список исключений не создаёт скрытых
   правил.
8. Ответ возвращается через RouterOS. Соединение `sb-managed` исключено из
   FastTrack.

Внутренний трафик не проходит через proxy-ядро: LAN/WG/SSTP/OpenVPN обрабатывает
основная таблица RouterOS.

### Удалённый VLESS-пользователь

1. Выбранный CDN передаёт WS/gRPC/HTTPUpgrade/XHTTP на настроенный origin-порт
   MikroTik. Для Cloudflare публичные HTTPS-порты ограничены поддерживаемым
   набором; другой CDN проверяется по его документации. Для отдельной HTTPS-
   подписки `ingress.subscription_public_port` формирует клиентский URL на edge,
   а `ingress.subscription_listen_port` независимо задаёт listener/origin-порт
   MikroTik. Отсутствующее новое поле наследует старый listener-порт только при
   чтении прежнего Draft.
2. RouterOS выполняет dst-nat на подтверждённый container IP. Cloudflare
   ограничивается автоматически обновляемыми официальными CIDR; другой CDN
   использует официальный feed, если он доступен, либо секретный origin-header
   и optional ручной CIDR fallback.
3. Nginx выбирает virtual host и дополнительно проверяет secret path либо gRPC
   service name. Неизвестный SNI не попадает в proxy-ядро.
4. Все включённые транспорты используют один реестр UUID и одинаковый
   `auth_user`.
5. Для `trusted-full` RFC1918-назначения, а для `trusted-limited` только явно
   разрешённые внутренние назначения идут через `direct-wan` в RouterOS.
   Точный клиентский CIDR-набор `trusted-full` берётся из последнего полного
   live-снимка таблицы маршрутов RouterOS и обновляется без Apply.
6. Запрещённые внутренние назначения отклоняются.
7. Любой публичный интернет идёт через назначенную VPN-политику. Она может
   выбрать провайдерский узел, Reverse VLESS или RouterOS WireGuard.
   `direct-wan` в этой ветке отсутствует.

Таким образом, отказ внешних узлов не раскрывает обычный WAN удалённому
пользователю.

Постоянная ссылка клиентской подписки имеет три пользовательских сценария:
CDN, прямой HTTPS или оба адреса. Внутри сценария CDN можно создать отдельный
CDN-домен либо выбрать уже готовое CDN-развёртывание. Повторное использование
готового развёртывания создаёт только отдельный секретный HTTP-путь и не создаёт
новый транспорт, маршрут или WAN-порт. У отдельного CDN endpoint публичный
edge hostname служит только ссылке клиента; отдельный concrete DNS origin
используется Nginx для SNI/Host и `OriginPolicy`, без fallback edge → origin.
Поэтому неполный Draft остаётся редактируемым, но Nginx и RouterOS candidate
fail closed до Apply, пока configured endpoint не получил origin. При
совпадении status hostname с origin secret-header остаётся именно на location
подписки, а `/healthz` сохраняет своё отдельное поведение. Прямой endpoint
получает собственные hostname, TLS-профиль и порт. Публичный `status / health` не
создаётся: MikroTik проверяет
readiness контейнера только по внутреннему veth-адресу на `:9080/healthz`.

`ingress.subscription_endpoint_enabled` по умолчанию включён; только JSON
boolean `false` выключает публикацию. В этом состоянии Nginx, RouterOS,
публичный `/{token}` и выдача/ротация ссылки не обслуживают подписку, а
status, транспорты, remote users, TLS-профили и ACME не меняются. Внутренний
`:9080/healthz` обслуживает lifecycle process probation, а
`:9080/traffic-ready` дополнительно требует свежий selector-readback текущего
процесса перед допуском managed traffic. Пустые DNS,
TLS или origin поля допустимы, пока публикация выключена; строка `"false"` или
число не считаются выключением и отклоняются проверкой типа.

Cloudflare ingress ограничивается официальным RouterOS address-list. Для
другого выбранного CDN отдельный origin-порт принимается с WAN: Nginx пропускает
только точный SNI и секретный path/service name, а доступную у провайдера
фильтрацию origin по IP следует включить в его кабинете.
Старые конфигурации с явно заданным `status_hostname` остаются читаемыми для
безопасной миграции, но мастер и обычный Web UI очищают это поле.

Один secret endpoint умеет отдавать совместимый URI/base64, Xray JSON,
sing-box JSON или Mihomo YAML. Явный `format` имеет наивысший приоритет, затем применяется
`subscription_format` удалённого пользователя, а автоматический режим учитывает
только однозначный `User-Agent`. Общий `Accept: application/json` не переключает
неизвестные приложения со списка узлов на служебный Xray JSON. Для подтверждённых
Happ, v2rayNG и V2Box включённые функции полного профиля выбирают JSON-массив:
сначала общий профиль автовыбора, затем один профиль на каждый транспорт.
Hiddify, Karing и sing-box получают нативный sing-box JSON; Mihomo, Clash и
Stash остаются на отдельной YAML-схеме. Для прочих клиентов полный формат
выбирается явно.
Полные JSON/YAML-профили содержат TUN, sniffing и клиентский fallback. Публичный
Xray JSON, sing-box JSON и Mihomo YAML используют только встроенные доменные/IP/port-правила и
не зависят от внешней `geosite.dat`. Точечные домены передаются отдельными
правилами и включаются только вручную, как и индивидуальная маршрутизация.
JSON-массив для app-managed клиентов заменяет raw TUN inbound локальными
SOCKS/HTTP inbounds и привязывает пользовательские правила к обоим тегам.
Системный VPN/TUN остаётся ответственностью Happ, v2rayNG или V2Box. Одиночный
Xray TUN-профиль не закрепляет имя интерфейса: ядро выбирает его по правилам
фактической ОС, включая формат `utunN` на iOS/macOS.
App-managed вариант заменяет направленный standalone DNS на переносимый список
`8.8.8.8`, `1.1.1.1` и удаляет служебный `client-dns` outbound: доменная политика
остаётся в единственном нормализованном `routing.rules`. Самостоятельные Xray
JSON, sing-box JSON и Mihomo YAML сохраняют полный DNS detour. В sing-box
каталог сервисных доменов сериализуется только в `route.rules`; DNS содержит
resolver-ы и только необходимые внутренние зоны, а transport hostname закреплён
за прямым bootstrap resolver.
App-managed stream selector сериализуется как совместимый `network`, а не новый
`method`, иначе старое embedded-ядро молча принимает gRPC/Hysteria/XHTTP за TCP.
ClientHello fingerprint хранится в `remote_users[].client_fingerprint`, по
умолчанию равен `chrome` и применяется при сборке всех поддерживаемых VLESS,
REALITY и Hysteria 2 представлений пользователя. Серверный transport его не
владеет. Reverse VLESS export намеренно фиксирует `chrome`, поскольку это
отдельный машинный bridge-профиль без пользовательской карточки.
Полный Xray export Hysteria 2 переносит из транспорта клиентские `quicParams`:
`congestion`, Brutal up/down, receive windows, `maxIdleTimeout`,
`keepAlivePeriod` и `disablePathMTUDiscovery`. Эти параметры локальны для
клиентской стороны и не считаются согласованными с inbound автоматически.
Серверные `maxIncomingStreams`, `brutalDisableLossCompensation`, `disableGSO`
и `disableStatelessReset` намеренно не экспортируются. URI, sing-box и Mihomo
используют переносимые возможности своих форматов без Xray-only полей.
Серверный Xray собирается с закреплённой узкой REALITY-поправкой: если ClientHello
не содержит гибридный `X25519MLKEM768`, но содержит единственный классический
`X25519`, аутентификация REALITY продолжается по нему. Это сохраняет выбранный
fingerprint `qq` и совместимость уже установленных клиентов при обновлении
серверного ядра; гибридный key share остаётся предпочтительным.
Для Xray-core 26.9.9 также применяется узкое исправление аварии Vision padding:
полный входной буфер 8192 байта больше не создаёт отрицательную длину padding и
не завершает всё ядро с `slice bounds out of range`. Редкий увеличенный frame
получает буфер требуемого размера без обрезки исходной нагрузки. Patch
накладывается с `--fuzz=0`, а сборочная стадия выполняет регрессионный тест для
кадра с уже переданным UUID и первого кадра с UUID. После перехода на upstream,
содержащий эквивалентное исправление, локальный patch должен быть удалён.
Без client-side routing весь публичный трафик приходит на SB Gateway и
серверный маршрутный лист остаётся единственной точкой принятия решения.

Control plane раскрывает составную карточку через
`service_pack_dependency_ids()`. Клиентский экспорт собирает fallback-домены и
сетевые правила самой карточки и всех её зависимостей, затем нормализует их и
удаляет повторы. `upstream_name` остаётся метаданными серверного каталога и в
клиентский профиль не попадает. Точные соответствия карточек перечислены в
[CLIENTS.md](CLIENTS.md#как-карточки-попадают-в-клиентский-профиль).

Одна и та же модель применяется к карточкам, найденным вручную в доверенном
каталоге: updater рекурсивно компилирует `include`, проверяет непустой результат
и публикует его атомарно. Загруженный каталог объединяется с проверенным
встроенным минимумом карточки: upstream расширяет правила, но не может удалить
региональный домен, API/WebSocket dependency, IP или порт, уже признанный
необходимым для работы карточки. Для известных runtime-зависимостей, которых
нет в upstream graph, применяется узкий reviewed release fallback по ID
карточки. Штатная карточка `binance` закрепляет `binance.com`,
`binance.vision` и `token.awswaf.com`, поэтому document, официальные API и AWS
WAF challenge используют один выбранный egress/DNS, но общий AWS WAF не
становится глобальным исключением. Составная карточка `ru-telecom` аналогично
закрепляет `sibset.ru`, `sibseti.ru`, `lk.sibseti.ru` и `211.ru` поверх
ежедневно обновляемых upstream-пакетов.
При переводе в Xray каждый локальный ruleset обязан
содержать хотя бы одно поддерживаемое условие домена, IP, протокола, сети или
порта. Пустой/повреждённый пакет блокирует candidate; он никогда не
деградирует в правило без условий. `port_range` переводится в Xray-диапазон, а
пакет только с портами не влияет на default policy-DNS.

Standalone-клиентский DNS строится без system resolver: hostname самих узлов имеет узкое
правило на прямой DoH по IP для bootstrap, основной VPN DNS идёт через proxy
group, а доменные исключения получают resolver своего направления. Internal
DNS и remote LAN CIDR экспортируются только согласно выбранному профилю
**Доступ к LAN**. Для полного доступа последний complete snapshot активных
RouterOS routes заменяет статический fallback; interface addresses и внутренний
container gateway не смешиваются с destination inventory, а вложенные CIDR
схлопываются;

REALITY client public key является производным значением: exporter читает
активный приватный ключ из SecretStore и получает X25519 public key при каждом
экспорте. Поле транспорта `public_key` используется для отображения, но не
может рассинхронизировать опубликованную ссылку после ротации секрета. Legacy
import без `reality_private_key` продолжает использовать единственный
сохранённый public key.

Профиль `dns.direct_resolver` является единым источником истины для контейнера
и RouterOS. Renderer записывает в `/ip dns servers` bootstrap-IP выбранного
провайдера и, при протоколе DoH, его же `use-doh-server` с
`verify-doh-cert=yes`. При выборе DoT поле RouterOS DoH очищается, потому что
RouterOS не предоставляет глобальный DoT-клиент; контейнер продолжает работать
по DoT. Смена только провайдера/протокола образует отдельную RouterOS `dns`
delta и не очищает conntrack. Для direct-профиля отказ HTTP/1.1 DoH может
безопасно перейти на DoT того же провайдера; reverse/VPN DNS такого fallback
не получает. Одноразовый ACME worker нормализует этот же applied direct-профиль
в короткоживущий loopback DNS forwarder без cache: он сохраняет DoH/DoT, TLS и
DoT fallback, но не использует отрицательные ответы RouterOS cache. Lego через
него проверяет и recursive, и authoritative DNS-01 propagation. До первого
applied config допустим draft как единственный источник; повреждённый applied
профиль останавливает задачу, а не подменяется draft/local resolver.
Fresh lane не делает public recursive DNS и authoritative NS мгновенно
согласованными: их отрицательные TTL остаются частью строгой проверки. Общий
`acmejob` timing policy задаёт 4 ч 15 мин для REG.RU и automatic ACME-DNS, 90
минут для Cloudflare, Yandex Cloud и Gcore, либо проверенный ручной override
ACME-DNS 1–1440 минут. Она же ограничивает worker (DNS + 5 минут setup + 10
минут/SAN, не более десяти) и control plane (+1 минута); worker не является
resident daemon и сохраняет polling 10 секунд. После завершения неудачи backend
переносит automatic retry на 15 минут от завершения, а не от времени старта;
persisted start deadline сохраняется только для crash recovery. Один `acmeMu`
по-прежнему сериализует все ACME jobs.
Одноразовый worker возвращает в backend только фиксированный код стадии
(DNS API, propagation, регистрация CA, validation либо worker); stderr и тексты
upstream не передаются. Backend отдельно отмечает неудачную локальную установку.
клиентский профиль не может расширить серверную авторизацию.

Порты `11001`–`11004` и другие backend listeners — внутренние порты между
Nginx и Xray в контейнере. Они не публикуются на WAN и не являются портами
CDN→MikroTik. Публичный порт может обслуживать несколько TLS hostname по SNI,
если у них одинаковая RouterOS source-граница. Разные IP-ограничения требуют
разных origin-портов, потому что RouterOS не видит SNI; прямой REALITY и прямой
HTTPS также не могут занимать один TCP IP:port.

Управляемая API-маскировка известных TLS/CDN hostname формируется отдельным
Nginx include. Для direct REALITY локальный listener `127.0.0.1:16448` имеет
default server с `ssl_reject_handshake` и отдельные SNI server blocks с
выбранными TLS-профилями. Xray использует этот listener только как fallback
неподтверждённого REALITY handshake. Hysteria направляет неавторизованный
HTTP/3 fallback на loopback helper `127.0.0.1:18081`; внешний listener у helper
отсутствует.

## Порядок правил proxy-ядра

Порядок является частью контракта и проверяется тестом:

1. route action `sniff`;
2. DNS hijack;
3. защита от маршрутизационной петли;
4. trusted remote user + internal network → `direct-lan`;
5. limited remote user + разрешённые CIDR/ports → `direct-lan`;
6. remote user + запрещённая внутренняя сеть → reject;
7. remote user + public destination → assigned VPN policy;
8. TUN source + internal network → `direct-lan` как defense-in-depth;
9. TUN source + service rule set → client service policy;
10. TUN final → первый выход выбранного режима: VPN selector либо
    `direct-wan`;
11. неизвестный inbound → reject.

Правила `auth_user` всегда расположены до общих сервисных правил. Устаревшие
`geosite`, `geoip` и inbound `sniff=true` не используются в серверном runtime.
Экспортируемые клиентские профили также не содержат ссылок на внешние
`geosite`/`geoip`-наборы.

## DNS и QUIC

- Внутренние зоны направляются на заданный внутренний DNS только для локального
  TUN и remote-профиля `trusted-full`; `trusted-limited`/`internet-only`
  получают только разрешённые назначения либо reject.
- Фоновый 30-секундный RouterOS discovery публикует для `trusted-full` только
  завершённый IPv4 private inventory. Public subscription читает локальный
  снимок и никогда не выполняет RouterOS-запрос в HTTP-критическом пути.
- Публичный DNS управляемого локального клиента перехватывается по UDP/TCP 53
  и попадает в source-aware lane выбранного маршрутного листа.
- WAN lane использует RouterOS/provider resolver либо явно выбранный WAN
  resolver и выходит через `direct-wan`.
- VPN lane использует отдельно выбранный DoH/DoT resolver. Соединение к его
  upstream маршрутизируется тем же selector, что и данные: VLESS/Hysteria,
  Reverse VLESS или RouterOS WireGuard.
- Публичный DNS удалённого пользователя получает отдельную source/auth lane и
  следует его VPN-политике; Reverse VLESS selector применяется и к DNS tunnel.
- Внешний UDP/TCP 53 управляемых клиентов перехватывается TPROXY.
- DoT 853 обрабатывается политикой `strict_dns`.
- DoH/ECH могут снижать точность SNI, поэтому применяются DNS, sniff, доменные
  rule sets и точечные CIDR.
- UDP/443 блокируется только для совпавшего proxy-service и только когда
  `force_tcp_for_proxy_services=true`; глобального запрета QUIC нет.

Опция `force_tcp_for_proxy_services` является явным режимом совместимости и по
умолчанию выключена. При включении она создаёт source/user-scoped reject
UDP/443 перед правилом каждой совпавшей карточки — одинаково для direct-WAN,
VPN/reverse и автоматически выбранного service selector. Браузер повторяет
HTTPS по TCP, а выбранный карточкой выход не меняется. Остальной QUIC не
затрагивается; QUIC-only сервис внутри выбранной карточки может перестать
работать, поэтому режим не включается автоматически.

### WireGuard peer как источник локального клиента

Входящий WireGuard-клиент привязывается к RouterOS peer, а не к интерфейсу и
не к однажды прочитанному адресу. Один интерфейс может обслуживать несколько
peers с разными маршрутными листами.

Конфигурация хранит стабильные `source_peer_refs` с RouterOS `.id`. Поле
`source_cidrs` для такого клиента является производным: live inventory
объединяет все конкретные IPv4-префиксы текущего peer и обновляет их перед
Check, Plan и Apply. `/32` представляет обычного клиента, сети — site-to-site
peer. Только default route `0.0.0.0/0` не принимается за источник клиента.

Изменение public key, имени или `allowed-address` у того же RouterOS объекта
сохраняет `.id`, поэтому существующая карточка остаётся одной, а старый CIDR
заменяется текущим. Удаление и повторное создание peer меняет `.id`; запись
переходит в `wireguard_peer_missing`, а Apply блокируется до явного выбора
нового peer. Сопоставление по похожему имени, ключу или адресу запрещено.

Legacy-запись без `source_peer_refs` может быть привязана автоматически только
к одному однозначному live peer. При сохранении стабильная ссылка становится
обязательной частью записи.

### RouterOS WireGuard как исходящий узел

Web UI показывает только включённые WireGuard-интерфейсы с одним однозначным
включённым peer либо ровно одним peer, уже содержащим full-tunnel
`allowed-address`. Comment интерфейса не используется как имя узла; в списках
показывается `WG · <имя интерфейса>`.

При Apply control plane:

1. сохраняет исходный `allowed-address` выбранного peer в точном project-owned
   state object и при необходимости добавляет `0.0.0.0/0`;
2. создаёт отдельную FIB-таблицу `sb-wg-*` с default route через этот интерфейс;
3. выделяет детерминированный source `/32` из `198.18.0.0/15` только для Xray;
4. добавляет source rule, обратный маршрут к контейнеру и scoped
   masquerade/filter для `SB_WG_EGRESS`;
5. передаёт в эту таблицу только соединения выбранного Xray outbound и его DNS
   upstream.

Default route в `main` не создаётся и не заменяется, поэтому трафик самого
MikroTik и неуправляемых клиентов не начинает автоматически идти через
WireGuard. При снятии выбора project-owned правила удаляются, а исходный
`allowed-address` peer восстанавливается. Несколько неоднозначных peers,
выключенный интерфейс или пересечение `198.18.0.0/15` блокируют Apply.

## Политики узлов

Нормализованный узел содержит transport/TLS/SNI/Reality/UUID/country/city/provider
и тип источника. Провайдерский узел, Reverse VLESS и RouterOS WireGuard
получают scoped tag и проверяются до включения. Страна берётся из явной
metadata/URI или двухбуквенного кода в label. Город берётся из `city` в
Xray JSON/VLESS URI либо из ручного override в Web UI. IP-geolocation не
используется: неизвестный город не включается в городскую группу автоматически.

Поддерживаются два режима:

- `best`: лучший исправный узел из выбранных групп, стран и городов;
- `priority`: первый доступный пункт пользовательского порядка; внутри пункта
  выбирается лучший исправный узел.

Если пользователь меняет порядок `priority`, после публикации нового runtime
agent сразу выбирает поднявшийся выше пункт только при наличии сохранённого
подтверждения его доступности. Неизвестный или ранее неисправный пункт сначала
проходит обычный health/hysteresis, поэтому перестановка не создаёт утечку или
слепое переключение на неработающий маршрут.

Если из маршрутного листа удалён фактически активный узел, это считается штатным
изменением contract, а не неизвестным member Xray. Controller немедленно выбирает
первый подтверждённый рабочий резерв: в `best` — из сохранённого shortlist, в
`priority` — по новому пользовательскому порядку. Выбор получает обычный
cooldown, поэтому тот же цикл не делает второй плановый прыжок. Если ни одного
проверенного резерва нет, selector временно закрывается в `block` и запускает
ограниченный аварийный поиск. Xray при таком Apply не перезапускается, а
`interrupt_exist_connections=false` сохраняет уже установленные сессии.

Для `priority` политика может хранить `candidate_service_ids` и доступ по
стабильному selector каждого пункта в `candidate_service_access`. Renderer
создаёт отдельный fail-closed selector для каждого service pack и направляет в
него совпавшие DNS-запросы и трафик локальных и удалённых клиентов, включая
домены, API, WebSocket/CDN и заявленные протоколы пакета. Controller синхронно с
выбором активного узла переводит service selector в активный outbound, если
service ID присутствует в whitelist этого selector; иначе целью остаётся
выделенный `block`. В интерфейсе эта совместимая whitelist-модель показана как
список запретов: установленная галочка удаляет сервис из whitelist и блокирует
его через конкретный узел, снятая разрешает доступ. Новые узлы и сервисы
добавляются разрешёнными. Перестановка строк не переносит запрет на другой узел,
потому что доступ привязан к стабильному selector, а не к позиции.

Один выбранный узел автоматически работает без резерва. Отдельного режима
закрепления нет. Старые значения `urltest`, `fallback`, `city_priority` и
`select` читаются как совместимые aliases и при следующем сохранении переходят
в `best` или `priority`.

Проверка выполняется реальным HTTPS-запросом через outbound, а не ICMP ping и
не встроенным Xray `leastPing`. Xray исполняет уже выбранный Go-контроллером
outbound; после каждой смены controller читает selector обратно через Xray API
и публикует новое состояние только при полном совпадении. Поэтому переход на
Xray core не превращает `best` в постоянно прыгающий ping-balancer.
Активный узел
проверяется раз в минуту, shortlist резервов — раз в 5 минут, полный обход —
раз в 30 минут партиями не более пяти узлов. Скользящее окно учитывает
неудачные probes и задержку. Плановое переключение требует устойчивого
улучшения по умолчанию одновременно не менее чем на 50 мс по медиане HTTPS и
25% по ограниченному замеру скорости, трёх успешных проверок и
cooldown 600 секунд (если не заданы другие пороги). Скользящие медианы только
выдвигают одного кандидата: перед сменой active он должен дважды подряд выиграть
свежую ограниченную пару HTTPS + throughput. Проверка заменяет обычную порцию,
не охватывает весь список и при batch=1 раскладывается на последовательные
проходы без превышения лимита. Ошибка подтверждения включает cooldown-backoff;
аварийный failover эту очередь полностью обходит.
Отсутствующие JSON-поля получают defaults, явные нули остаются нулями.
Реальная недоступность имеет приоритет над cooldown; деградация доступного
пути — нет, и требует здорового подтверждённого резерва. Выбор и метрики сохраняются в
`/state`, включая ограниченную 24-часовую историю (не более 1440 замеров на
узел). Стартовый native helper восстанавливает подтверждённый текущий `best`
leaf до активации transparent routing; PID-marker не даёт health worker
переписать историю стартовым первым узлом. Существующие соединения при смене
selector всегда сохраняются на прежнем живом выходе, без отдельного UI-флага.
Перезапуск ядра или отказ самого сервера этим не маскируются. UI рассчитывает из
неё доступность, потери, медиану, p95 и относительную/абсолютную разницу между
узлами.

У маршрутного листа технический ID создаётся control plane автоматически из
поля **Название маршрута** и остаётся стабильным внутренним ключом; Web UI
показывает только это название. Новые сервисы-исключения выбираются готовыми
карточками или разрешаются по имени/домену/URL через доверенный каталог. В
режиме `VLESS + WAN` выбранный service pack направляется в WAN, а в режиме
`WAN + VLESS` — в выбранную VPN-политику.

Для обратной совместимости сохранён ключ `direct_domains`, но его смысл зависит
от выбранного порядка выходов. В режиме `VLESS + WAN` совпавший
корневой домен/поддомен и его DNS-запрос используют WAN, а остальной трафик —
выбранную VPN-политику. В режиме `WAN + VLESS` те же выбранные исключения
используют VPN-политику, а
остальной трафик — WAN. Если не выбран ни один домен или сервисный пакет,
исключений нет: весь трафик идёт через первый выход режима. Правило основано на
доменном имени; приложение с жёстко заданным IP или скрытым именем нужно
проверять отдельно. DNS управляемого клиента перехватывается по TCP/UDP 53 и
следует тому же выходу, что и соответствующий трафик.

Пользовательские service packs следуют инверсии выбранного режима так же, как
совместимые старые доменные исключения: WAN в `VLESS + WAN` и VPN selector в
`WAN + VLESS`. Всегда-прямым остаётся только отдельное правило BitTorrent при
включённом **Torrent через WAN**. Серверный renderer, route simulator и
индивидуальные клиентские профили используют один контракт; при выключении
переключателя карточка снова следует инверсии режима.
Можно выбрать несколько категорий одновременно: государственные сайты,
банки/платежи, маркетплейсы/доставка/ритейл, всю экосистему Яндекса,
VK/Mail.ru, поездки, операторов связи, российские медиа,
образовательные/рабочие/ИТ-сервисы, отдельные биржи и их trading API. Каталог
включает популярные сервисы, поэтому пользователь выбирает имя,
а не поддерживает десятки доменов. Для добавления произвольной новой карточки
control plane разрешает запись из доверенного
`v2fly/domain-list-community`, разворачивает recursive includes и сохраняет
полный набор сайта, API, WebSocket и CDN-зависимостей. Отдельный worker раз в
сутки получает whitelist-источник, принимает только
поддерживаемые доменные типы и атомарно заменяет файл. Ошибка обновления не
трогает LKG, а offline seed позволяет стартовать без доступа к источнику.

## Отказ контейнера

```text
BOOT / UNKNOWN
  │  startup-script выключает точный SB-GATEWAY gate
  ▼
BYPASS ── контейнер готов ──→ RECOVERING
                               │  recovery probes + cooldown
                               └────────────────────────────→ HEALTHY

HEALTHY
  │  1–2 ошибки
  ▼
SUSPECT ── успешная проверка ──→ HEALTHY
  │  3-я ошибка
  ▼
BYPASS
  │  mangle SB-GATEWAY для новых локальных соединений выключен
  │  RouterOS auto-restart пытается поднять контейнер каждые 10 s
  ▼
RECOVERING
  │  3 успеха + cooldown 60 s
  └────────────────────────────→ HEALTHY
```

Переход в BYPASS:

- затрагивает только созданное проектом правило route-mark;
- не отключает WAN, основной default route, внутренние сети или чужой
  FastTrack;
- разрешает новым соединениям обычных local fail-open клиентов идти в main/WAN;
- для local `lan_only` оставляет внутренние сети и выбранный персональный
  direct allowlist доступными; проектовый filter drop запрещает любой иной
  публичный обход в main/WAN;
- не создаёт direct fallback для удалённых пользователей: их ingress находится
  в недоступном контейнере и остаётся fail-closed.

Если health flaps, система остаётся в BYPASS до устойчивого восстановления.
Короткоживущая readiness lease обновляется watchdog на каждом успешном цикле;
его смерть или зависание превращает RouterOS health в 503 после TTL. Restart
budget ограничивает crash-loop и сохраняет управление RouterOS.
После исчерпания бюджета process-watchdog не завершает PID 1 повторно:
локальный трафик остаётся в BYPASS, контейнер и логи сохраняются для
диагностики через WebFig. Web UI доступен только пока исправен management API.

## Атомарное применение

До live inventory действует узкий `state_only` fast-path. Он допускает только
замены `display_name`, затем независимо рендерит полный candidate и требует
побайтового совпадения всех live runtime-файлов и RouterOS script с предыдущей
зафиксированной версией. При доказанном совпадении меняются только локальные
generation/active/LKG/draft pointers; при любом сомнении выполняется обычная
последовательность ниже.

1. Web UI записывает candidate во временный каталог.
2. Валидируется YAML/schema, секретные ссылки и зависимости. Независимые
   RouterOS REST inventory-запросы выполняются ограниченным пулом, а не
   последовательно.
3. Генерируются Nginx/Xray candidate.
4. Для изменившихся process-facing файлов выполняются `xray run -test -config
   /config/generated/xray.json` и/или `nginx -t`; байт-в-байт неизменившиеся
   live-артефакты повторно не валидируются.
5. Для RouterOS topology/firewall change создаются свежие export/backup;
   runtime activation сохраняет предыдущие файлы для немедленного rollback.
6. Если RouterOS изменился, renderer сравнивает полные candidate по атомарным
   owner-секциям. Распознанные небольшие изменения получают симметричный
   apply/rollback delta из целых секций; неизвестная схема или delta ≥80%
   автоматически использует полный candidate. REST устанавливает выбранные
   `SB-GATEWAY` apply/rollback scripts и **до** изменения ставит независимый
   одноразовый rollback-scheduler на 10 минут.
   Симметричные apply/rollback delta до 16 КиБ каждый записываются прямо в
   управляемые scripts через REST. Большие delta и полные content-addressed
   apply/rollback imports загружаются одним legacy SCP-сеансом; после commit
   оба временных файла удаляются одной SSH-командой.
   На версиях со стабильной интерактивной консолью control plane затем
   открывает постоянную SSH-сессию к указанному SSH-порту и включает Safe Mode.
7. Обычно интерактивная SSH-консоль остаётся владельцем Safe Mode, а сохранённый
   candidate запускается через `/system script run`. RouterOS помечает
   выполненные им изменения как `floating-undo`; сохранённая копия одновременно
   остаётся аудитируемым артефактом и источником для аварийного scheduler.
   Если RouterOS исчерпывает лимит истории в 100 действий и сам освобождает
   Safe Mode, candidate продолжает работу только под защитой уже вооружённого
   LKG-scheduler; он не снимается до всех health-check.
   Для RouterOS 7.24 candidate запускается по точному ID через REST сразу под
   защитой scheduler, без открытия аварийной SSH Safe Mode-консоли. Этот
   фактический guard возвращается API как `routeros_guard_mode`.
8. Каждый runtime-артефакт сравнивается потоково. Неизменившиеся Xray/Nginx не
   валидируются повторно, не копируются и не перезапускаются; при отсутствии
   process-facing изменений runtime health-check пропускается. Если в
   `xray.json` изменился только `routing.rules`, а в `policy-dns.json` — только
   правила существующих lanes, renderer атомарно публикует файлы, заменяет
   Xray RoutingService через `adrules` и даёт DNS proxy перечитать policy
   in-process. Xray/DNS процессы и установленные соединения не перезапускаются.
   Любое изменение inbound, outbound, balancer, DNS server или topology
   отклоняет hot-path и использует обычный supervised restart. Изменившийся
   runtime candidate проходит соответствующий health-check. RouterOS post-health
   переиспользует полный preflight-снимок и обновляет только строку контейнера:
   управляемый script не может изменить release/capabilities, поэтому второй
   полный inventory не нужен.
9. Только после успешных проверок интерактивный Safe Mode, если он использован,
   фиксируется Ctrl-X, его SSH-сессия закрывается и ожидается исчезновение
   `floating-undo`. Затем снимается scheduler; в scheduler-only режиме он
   снимается непосредственно после тех же health-check. Только после
   подтверждённого снятия guard публикуются application active pointer и
   runtime LKG. Ошибка снятия не вызывает Finalize: немедленный rollback идёт
   при всё ещё вооружённом scheduler. Ошибка последующего application commit
   также вызывает немедленное восстановление RouterOS, но уже возвращается как
   неподтверждённая, если восстановить прежнее состояние не удалось.
10. `active.json` фиксируется до успешного ответа и является commit point;
    производные LKG/metadata восстанавливаются из него и не могут обратить
    опубликованное состояние назад. Создание локального
    зашифрованного `.sbgw`, его зеркалирование в RouterOS Files и удаление старых
    project-owned backup выполняет persisted maintenance; быстрые
    последовательные Apply объединяются в архив последней active generation.
    Их задержка не удерживает Apply. В audit успешного или неуспешного Apply
    сохраняются `critical_path_ms`, `stage_timings_ms`,
    `runtime_changed_files`, `routeros_apply_kind`,
    `routeros_apply_transport` и
    `routeros_delta_sections` без секретов.

Candidate уже прошёл `xray -test` до публикации. Перед supervised restart
renderer атомарно записывает одноразовый SHA-256 marker точного опубликованного
`xray.json`; wrapper удаляет marker до запуска и пропускает только повторный
тест совпавшего файла. При cold/manual restart, несовпадении hash или повторном
запуске после ошибки обязательный `xray -test` сохраняется. Независимые Nginx и
Xray validators запускаются параллельно. Readiness выдерживает окно
стабильности и напрямую проверяет management API, процесс Xray, listeners,
TPROXY TCP/UDP listeners, точный fwmark policy rule, local route и nft. Watchdog не вызывает `supervisorctl`: зависший
XML-RPC-клиент не должен занимать ядро RouterOS и лишать DNS процессорного
времени. Listener inventory из крупных Xray/DNS JSON кэшируется по checksum и
пересчитывается внутри Go watchdog только после публикации нового файла, а не
каждые пять секунд.

RouterOS 7.21.5 может ответить `Releasing Safe Mode... Failure` на Ctrl-X после
большого candidate. Только на стадии commit, когда runtime и RouterOS health уже
подтверждены, control plane заполняет оставшуюся историю служебными add/remove
в неиспользуемом `SB_SAFE_MODE_RELEASE`. Документированный 100-action limit
автоматически освобождает Safe Mode; служебная запись удаляется, а LKG-scheduler
снимается лишь после исчезновения `floating-undo`.

REST остаётся каналом live-инвентаризации, подготовки и точного запуска
управляемых scripts. Транзакционное применение принадлежит SSH Safe Mode плюс
независимому scheduler либо, на RouterOS 7.24, самому scheduler. Host key
хранится отдельно в SecretStore, пароль не записывается в команду или журнал.

Container-only candidate, ротация официальных CDN CIDR и другие операции,
которые не меняют RouterOS topology/firewall, не используют полный SSH Safe
Mode. Данные сначала проверяются, записываются во временный/LKG набор и
заменяются атомарно; существующие соединения не очищаются.

## Обновление контейнера и резервные копии

Web UI принимает один Docker archive `.tar` и без proxy buffering потоково
пишет его сразу в `/data/lifecycle-uploads` на внешнем SSD. Go control plane в
том же единственном проходе вычисляет SHA-256 и читает не больше 4 МиБ Docker
metadata для проверки SB Gateway, `linux/arm64` и версии. После `fsync`
content-addressed private file перед запуском не хешируется повторно. RouterOS сначала полностью распаковывает
candidate на изолированном veth без persistent mount-list, не останавливая
рабочий контейнер. После этого кратко отключает diversion, полностью
останавливает прежний контейнер, снимает с него `/config`, `/data`, `/logs` и
`/state` и только затем назначает эти тома кандидату. Одновременно persistent
томами владеет ровно одна container record. Кандидат запускается и проходит
probation, включая реальные mount flags, а не только RouterOS `mode=rw`. При
ошибке тома сначала снимаются с кандидата и возвращаются прежнему контейнеру;
затем прежняя версия запускается без второго tar. После успеха
удаляются прежняя container record/root, временный veth, worker, export и
upload; остаётся один SB Gateway container.

Перед scheduler Go API обязательно создаёт `.sbgw` recovery archive и сверяет
ровно один live-контейнер, его root и контейнерный IPv4 с черновиком. Архив
сначала получает private `0700` snapshot на SSD отдельный от staging
восстановления: файлы потоково копируются с mode `0600`, а manifest содержит
digest и размер именно скопированной версии. В tar повторно проверяются эти
digest/размеры. Только временный результат собственного atomic write вида
`.target.<random>.tmp` исключается из набора;
rename/delete/изменение источника дают одну повторную попытку и затем оставляют
update несозданным. Любая другая ошибка, лимит, защита, запись или финализация
не ретраятся. Ошибка cleanup plaintext snapshot всегда доминирует над source
churn и также запрещает retry/scheduler. API/audit сообщают лишь allowlisted classifier и действие, без
пути, содержимого или секрета. Fixed
RouterOS worker получает только уже валидированные значения, наследует для
candidate фактические лимиты рабочего контейнера (по умолчанию
`memory-high=224M` и `memory-max=256M`), а затем сам выполняет переключение,
probation и rollback без доступности панели. При следующем чтении lifecycle API
сверяет container/scheduler inventory и переводит операцию в `probation`,
`completed` или `rolled_back`.

Provider outbounds разделены между компактным стартовым `xray.json` и
`urltest-pool.json`. Полный canonical outbound с секретами остаётся только в
локальном защищённом health-contract; Xray HandlerService держит активный leaf,
один probe leaf и короткий retired leaf для безразрывной смены. Balancer-ы
ссылаются на стабильные динамические префиксы, поэтому сокращение startup graph
не меняет семантику priority, service exceptions или subscription refresh.
Перед запуском supervisor upgrade-migration ищет только точные outbound tags,
которые одновременно присутствуют в старом `xray.json` и его защищённом
health-pool. При таком доказательстве активная конфигурация и закреплённый node
snapshot заново рендерятся, валидируются и атомарно публикуются до первого
старта Xray. Другой runtime или неполный snapshot остаётся без изменений.

Snapshot не получает `context` HTTP-запроса. Проверка live inventory и вызов
RouterOS scheduler имеют отдельные bounded `30 s` contexts, поэтому подготовка
архива не расходует deadline следующего RouterOS вызова; HTTP response update
может ждать bounded local archive до пяти минут.

Snapshot не делает `fsync` для каждого plaintext файла: это временная
consistency boundary и cleanup проверяет отсутствие каталога. Перед scheduler
обязателен `fsync` зашифрованного archive file; directory sync после rename
остаётся best effort, как и раньше, чтобы неподдерживающий storage не создавал
новый permanent gate. После чтения источников, snapshot и синхронизации
готового архива Linux runtime best effort помечает соответствующие страницы
как ненужные. Неподдерживаемая файловой системой подсказка игнорируется и не
меняет результат операции.

Пока update находится в `preparing`, `scheduled` или `probation`, новый upload
отклоняется с `409` до чтения тела запроса. Второй большой архив поэтому не
конкурирует за SSD с уже запущенным кандидатом.

Lifecycle-протокол не предполагает последовательную установку версий: новый
root разворачивается целиком из content-addressed archive, а сохраняемая модель
нормализуется идемпотентно из любой поддерживаемой старой формы. Тяжёлые rule-set
проверки и очистка воспроизводимых runtime-candidates выполняются после запуска
API под обновляемым apply guard, а не в критическом startup path. Остальные
фоновые workers ждут завершения одноразовой миграции; heartbeat apply-guard
протухает через 90 секунд без обновления и имеет абсолютный предел 30 минут.
Lifecycle раздельно проверяет process health и traffic-ready. Три успешных
`/healthz` подтверждают исправность образа; свежий `/traffic-ready` независимо
включает diversion сразу после selector-readback текущего процесса. Отсутствие
рабочего VLESS не превращает исправный образ в rollback: gate остаётся выключен,
а локальные клиенты используют свою outage-политику. Restart означает
немедленный rollback, краткий RouterOS fetch timeout
— продолжение ограниченной probation.

Архив состояния `.sbgw` содержит данные, необходимые для восстановления
конфигурации с нового SSD, но не пароль и не администраторские сессии. Архив
шифруется ключом, производным от текущего пароля панели, и обязательно хранится
на SSD. Копия в RouterOS Files — асинхронное best-effort зеркало с повторными
попытками, а не блокирующая зависимость обновления. Ротация оставляет не более
трёх архивов в каждой управляемой точке. Restore требует пароль для расшифровки
и выполняется через контролируемый перезапуск.

## Телеметрия клиентов

Remote users учитываются локальным Xray StatsService. Для local clients
renderer создаёт отдельную nftables-таблицу с named byte counters и
`policy accept`; в ней нет `drop`, `mark`, NAT или redirect действий. При
перекрывающихся scopes longest-prefix-first отделяет трафик отдельного устройства
от общей LAN-карточки независимо от порядка их создания.
Collector считает скорости и месячные дельты, сохраняет компактное состояние
не чаще раза в 60 секунд. Пока экран обзора запрашивает телеметрию, счётчики
опрашиваются раз в 30 секунд; без интереса UI интервал увеличивается до 300
секунд. Кумулятивные Xray/nft counters сохраняют весь объём между выборками.
Панель также запрашивает snapshot раз в 30 секунд: более частый HTTP polling не
может показать новые данные и только будит CPU. Атомарное state-хранилище перед
`fsync` сравнивает канонический payload с существующим файлом и полностью
пропускает неизменившиеся записи.
Payload и RouterOS connection table не сканируются. Ошибка телеметрии даёт
«данные недоступны» и никак не меняет маршрут.

Policy DNS при загрузке один раз компилирует ordered domain rules каждой lane в
exact/suffix indexes с сохранением first-match порядка. На каждом DNS-пакете
JSON-списки доменов заново не нормализуются и не превращаются во временные
set/list, поэтому большие сервисные карточки не создают CPU/RAM churn.
UDP и TCP lanes используют общий bounded worker pool (16 активных запросов по
умолчанию), а не создают неограниченный системный поток для каждого DNS-пакета.
До восьми входящих TCP-сессий учитываются отдельным лимитом; простаивающее
соединение не занимает query worker и не может вытеснить UDP.
Переполнение безопасно отклоняет лишний запрос: клиентский resolver повторит
его, а контейнер останется управляемым. Изменение generated-конфига
обнаруживается в apply path: control plane перезапускает только Policy DNS и
только когда его артефакт действительно изменился. Фоновое чтение и
хеширование файла по таймеру отсутствует.

Кэш ограничен одновременно 4096 ответами и приблизительным бюджетом 4 МиБ по
умолчанию и не прогревается в фоне. Большой DNSSEC-ответ не может обойти
байтовый предел через формально малое число записей. TTL
уменьшается на фактический возраст записи; положительный TTL ограничен пятью
минутами, отрицательный NXDOMAIN/NODATA принимается только из SOA и ограничен
минутой. Истёкшая запись остаётся в том же bounded LRU не более часа и
возвращается с TTL 30 секунд только после ошибки upstream. Это пассивный
serve-stale: он не создаёт prefetch, refresh goroutine или дополнительный
DNS-трафик. Одновременные одинаковые cache miss объединяются в один upstream
запрос. UDP сокеты, TCP/DoT и HTTP/2 DoH соединения переиспользуются; входящий
DNS-over-TCP допускает до 64 последовательных сообщений на соединение.

Параметры выбраны по практике маршрутизаторных резолверов, а не серверного
recursive DNS: OpenWrt по умолчанию использует лёгкий caching forwarder
[dnsmasq](https://openwrt.org/docs/guide-user/base-system/dhcp), RouterOS также
ограничивает cache, concurrent queries и TCP sessions
[явными лимитами](https://help.mikrotik.com/docs/spaces/ROS/pages/37748767/DNS).
Из [AdGuard dnsproxy](https://github.com/AdguardTeam/dnsproxy) переняты bounded
workers, объединение pending requests и TTL 30 для stale-ответа, но не
optimistic refresh. Шардирование кэша не используется: измеренный lookup уже
занимает около 0,1 мкс на одном CPU, а несколько LRU увеличили бы память и
ухудшили предсказуемость вытеснения без практической пользы на роутере.

## TLS-профили транспортов

TLS-сертификат и приватный ключ принадлежат именованному `tls_profile`, а не
WebSocket. Каждое CDN-развёртывание выбирает собственный origin TLS-профиль,
поэтому Cloudflare и Yandex в одном WebSocket/XHTTP шаблоне могут использовать
разные origin-домены и сертификаты. Сертификат публичного distribution domain
настраивается у CDN и не подменяется origin-сертификатом шлюза. Hysteria 2 и
прямой HTTPS endpoint подписки также выбирают подходящий профиль явно.

Control plane проверяет соответствие сертификата ключу до записи, хранит
приватный ключ только в SecretStore и отдаёт Nginx/Xray отдельные пути для
каждого выбранного профиля. UI показывает имя, домены, срок действия и
связанные транспорты, позволяет создать, заменить и удалить неиспользуемый
профиль, но не возвращает приватный ключ в браузер.

Источник `local-ca` генерируется внутри control plane без внешнего процесса:
ECDSA P-256 Root CA действует 20 лет, leaf с единственным конкретным DNS SAN —
10 лет. Leaf и Root имеют разные ключи; сервер получает цепочку leaf+Root,
клиентские экспорты закрепляют SHA-256 leaf. Все четыре PEM сохраняются
атомарно в `tls-profiles/<id>/`. Обычное обновление сущности переиспользует
существующую пару, а явная ротация одновременно заменяет Root и leaf. Частный
материал входит только в зашифрованный `.sbtls` и recovery backup.

Обновление подписок и rule sets использует тот же pipeline с ограничением
размера/времени и SHA256.

## DNS по маршруту и клиентская стратегия домена

Публичный прямой WAN использует Яндекс DNS по DoH по умолчанию; устаревший
профиль RouterOS/UDP мигрирует на него автоматически. DNS RouterOS остаётся
только внутренним резолвером локальных зон. VPN использует отдельный
зашифрованный resolver для VPN. Runtime соединяется с публичным DNS по
фиксированному IP и проверяет TLS по официальному server name; detour закрепляет
каждый resolver за своим выходом. Сохранённые конфигурации не мигрируются на
другого публичного провайдера без действия администратора, кроме удалённого
небезопасного профиля RouterOS/UDP, который переводится на Яндекс DoH.

Клиентский Xray JSON получает `domainStrategy` из маршрутного листа только при
включённой индивидуальной маршрутизации. `IPIfNonMatch` дополняет доменные
правила проверкой IP, `AsIs` оставляет только явные совпадения. Точечные домены
располагаются рядом с карточками сервисов и сохраняются как пользовательский
резерв; они не заменяют обновляемые серверные geosite/geoip-наборы и не
включаются автоматически.

Полный клиентский профиль не содержит имён `geosite`-тегов и не зависит от
`geosite.dat` стороннего приложения. Для пакетов `ru-telecom`,
`ru-marketplaces`, `ru-media` и `ru-education-work-it` генератор объединяет
переносимые fallback-домены всех составляющих, нормализует их и удаляет
повторы. Серверные правила продолжают использовать управляемую геобазу шлюза.

Provider metadata подписки (`expires_at` и агрегированные счётчики трафика)
берётся только из доверенных HTTP response headers и хранится рядом с cache
узлов, но обновляется независимо от него. Ошибка разбора нового списка не
стирает last-known-good узлы и не мешает показать подтверждённый провайдером
срок действия.
