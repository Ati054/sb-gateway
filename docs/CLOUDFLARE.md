# CDN-развёртывания и Cloudflare

Документ соответствует модели CDN-развёртываний SB Gateway 1.6.17.

Документ относится к VLESS WebSocket, gRPC, HTTPUpgrade, XHTTP и выдаче
клиентской HTTPS-подписки. Direct REALITY и Hysteria 2 не являются обычным
HTTP reverse-proxy CDN ingress.

## Общая модель

У транспорта один протокольный шаблон и одно или несколько независимых
CDN-развёртываний. Для каждого задаются:

- provider;
- собственный distribution hostname или технический hostname CDN-ресурса;
- client SNI;
- публичный HTTPS-порт edge;
- собственный origin hostname и origin TCP-порт MikroTik;
- origin TLS-профиль;
- защита origin;
- включение в выдаваемые клиентские профили.

Cloudflare и Yandex в одном WebSocket/XHTTP транспорте могут иметь разные
домены, origin и сертификаты. Кнопка клонирования копирует протокольные
настройки, после чего CDN deployment редактируется независимо.

Публичный сертификат distribution hostname находится на стороне CDN.
TLS-профиль SB Gateway подтверждает участок CDN→origin или прямой endpoint;
его SAN должен соответствовать origin hostname, который реально проверяет
provider.

## Порты

Различайте три уровня:

1. **публичный edge port** — обычно TCP/443, виден клиенту;
2. **origin WAN port MikroTik** — порт, на который CDN приходит к origin;
3. **внутренний backend Xray** — `11001`–`11004` между Nginx и Xray, на WAN не
   публикуется.

Несколько CDN hostname и клиентская подписка могут делить публичный TCP/443 по
SNI и секретным HTTP paths/service names. Выбор существующего CDN-развёртывания
в едином сценарии **Через CDN** не создаёт новый WAN port. Direct HTTPS
подписка, наоборот, занимает выбранный WAN TCP port и
проверяется на конфликт с direct REALITY на том же public IP. Опциональный
[общий TCP 443](shared-tcp-ingress.md) разрешает совместное использование при
разных SNI; разные CDN CIDR на одном origin-порту проверяются отдельно в Nginx.

Для Cloudflare панель предлагает поддерживаемые HTTPS ports `443`, `2053`,
`2083`, `2087`, `2096`, `8443`; публичный gRPC использует `443`. Для других
provider порт разрешается только после проверки в их актуальной документации.

## DNS

Пример:

| Host | Режим | Назначение |
|---|---|---|
| `ws.example.com` | CDN proxied | VLESS WebSocket |
| `xhttp.example.com` | CDN proxied | VLESS XHTTP |
| `sub.example.com` | CDN proxied | отдельный CDN URL подписки |
| `direct.example.com` | DNS only | VLESS REALITY |
| `hy2.example.com` | DNS only | Hysteria 2 UDP |

В режиме **Через CDN** можно выбрать уже настроенное развёртывание: отдельная
запись `sub.example.com` тогда не нужна, а подписка получает другой непрозрачный
path на выбранном deployment.

## Origin-защита

### Cloudflare

RouterOS использует официальные Cloudflare IPv4/IPv6 ranges. Worker ежедневно:

1. получает только official HTTPS endpoints;
2. проверяет timeout, размер, синтаксис и непустой результат;
3. строит временные address lists;
4. добавляет новые ranges и затем удаляет устаревшие;
5. сохраняет LKG при любой ошибке.

Операция не требует Safe Mode/Apply и не очищает established connections.

### Gcore, EdgeCenter/EdgeCDN, CDNetworks, Yandex и custom CDN

Если provider публикует официальный машиночитаемый список и для него есть
проверенный adapter, используется автоматический feed. Во всех остальных
случаях основной способ — статический секретный request header
`X-SB-Origin`, настроенный одновременно у CDN и в deployment. Запрос без
секрета получает 404. Ручные CIDR остаются optional расширенным fallback и не
должны быть обязательным этапом обычной настройки.

Автоматическое обновление не обещается для provider, который не публикует
стабильный официальный feed.

## Cloudflare

1. DNS record включён как proxied.
2. SSL/TLS mode — Full (strict).
3. Origin certificate/private key загружены в отдельный TLS-профиль и подходят
   origin hostname.
4. WebSockets включены; для gRPC включены gRPC и HTTP/2 to origin.
5. Cache bypass для transport/subscription path.
6. Нет Access, CAPTCHA/JS challenge, redirect или rewrite, меняющих path.
7. Rate limiting проверен на долгих WS/gRPC/XHTTP sessions.

Management UI `:9443` и RouterOS-only health `:9080` через Cloudflare не
публикуются.

Официальные источники Cloudflare ranges:

- [IPv4](https://www.cloudflare.com/ips-v4)
- [IPv6](https://www.cloudflare.com/ips-v6)
- [описание IP ranges](https://www.cloudflare.com/ips/)

## Проверка deployment

Для каждого hostname отдельно:

1. DNS возвращает edge, а не origin, если выбран proxied mode.
2. TLS certificate клиента соответствует distribution hostname.
3. Неверный SNI не попадает в transport.
4. Неверный path/service получает нейтральный 404/error без данных шлюза.
5. Правильный WebSocket/HTTPUpgrade/XHTTP или gRPC проходит к Xray.
6. Прямой origin request без разрешённого CIDR/header блокируется.
7. Долгая сессия выдерживает provider/Nginx keepalive.
8. Выданный клиентский профиль содержит именно hostname/SNI/port этого
   deployment.

## Клиентская подписка через CDN

Подписка использует отдельный secret path и не создаёт новый VLESS transport.
Панель показывает три сценария: CDN, прямой HTTPS и оба адреса. Внутри единого
CDN-сценария можно создать отдельный hostname либо выбрать существующее
deployment. В режиме CDN+direct оба URL возвращают одну логическую подписку,
а UI выбирает основной адрес для копирования.

URL запрещает cache/indexing. Ротация path немедленно отзывает прежний URL;
обычное сохранение path не меняет.

## Частые ошибки

| Симптом | Проверка |
|---|---|
| 525/526 | Full strict, origin SAN, срок, certificate/key pair |
| WS/XHTTP 404 | distribution hostname, path, transform/rewrite rules |
| 403/challenge | WAF/Access/bot rule для transport hostname |
| gRPC 502/520 | gRPC toggle, h2 ALPN, origin HTTP/2, service name |
| origin доступен напрямую | CIDR/header protection и RouterOS rule order |
| idle disconnect | client/provider/Nginx keepalive и timeout |
| один CDN работает, второй нет | проверять deployment domain/origin/TLS отдельно |

Полный smoke test выполняется из внешней сети. Hairpin NAT и локальный curl не
доказывают прохождение через edge конкретного CDN.
