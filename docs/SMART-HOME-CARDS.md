# Smart Home Card Routing

The catalog provides separate `ewelink`, `xiaomi-home`, `tuya`, `aqara`
and `shelly` cards. They are independent, inactive until selected, and use the
existing per-card WAN or selectable route-list override. Traffic and
policy-DNS rules use the same card. No shared "all IoT" card forces another
ecosystem onto the selected route.

## Domain Scope

| Card | Domain suffixes |
| --- | --- |
| eWeLink / Sonoff | `coolkit.cc`, `coolkit.cn`, `ewelink.cc`, `ewelink.cn` |
| Xiaomi Home / Mi Home | `io.mi.com`, `iot.mi.com`, `account.xiaomi.com` |
| Tuya / Smart Life | `tuya.com`, `tuyasmart.com`, `tuyacn.com`, `tuyaeu.com`, `tuyaus.com`, `tuyain.com`, `iotbing.com` |
| Aqara Home | `aqara.com`, `aqara.cn`, `aiot-rpc.ankasa.cn` |
| Shelly Smart Control | `shelly.cloud` |

Subdomains cover regional dispatch, API and persistent connections without
pinning changing server IPs. These are release-maintained (`official`) seed
lists, not invented upstream rule-set names. Existing seed data is merged
without deleting other rules; repeating the merge is idempotent.

No card matches an entire shared cloud provider, all Xiaomi shopping domains,
or all connections on ports such as 443, 8080 or 8883. Device connections may
use nonstandard ports; recognizable hostnames still use the selected route.
Local discovery, mDNS, Matter and local device control are not cloud rules.

## Limits And Diagnosis

A domain card requires a hostname available to routing, for example HTTP Host
or TLS SNI. It does not add DNS-to-IP reverse mapping, FakeDNS or a vendor-wide
IP list. Raw IP connections, MQTT/CoAP without a recognizable hostname,
vendor-custom Tuya domains and unrelated CDN endpoints may need a separate
device route or a reviewed explicit rule. Account sign-in services can be
shared with other vendor products, particularly in Xiaomi's ecosystem.

Check/Apply must regenerate runtime rules after installing a build containing
the cards. A successful DNS answer or unauthenticated API response does not
prove an authenticated device cloud session works. Diagnose the actual device
destination, DNS path, selected outbound and server responses separately.
Do not disable TLS verification or substitute arbitrary static cloud IPs.

## Sources

Endpoint scope reviewed against manufacturer documentation on 2026-10-09:

- [CoolKit eWeLink API](https://github.com/CoolKit-Technologies/eWeLink-API/blob/main/en/APICenterV2.md)
  and [SONOFF server-connection troubleshooting](https://sonoff.tech/de-de/blogs/news/blink-blink-sonoff-product-is-talking-to-you).
- [Xiaomi's official endpoint constants](https://github.com/XiaoMi/ha_xiaomi_home/blob/main/custom_components/xiaomi_home/miot/const.py)
  and [Xiaomi IoT platform](https://iot.mi.com/new/doc/home). Only endpoint facts
  are used; no integration code or certificates are incorporated.
- [Tuya MQTT endpoints](https://developer.tuya.com/en/docs/iot/MQTT-protocol?id=Kb65nphxrj8f1),
  [Tuya Smart Control](https://developer.tuya.com/cn/docs/iot/tuya-smart-control-cli?id=Kfne1o38oar84)
  and [custom-domain limitations](https://developer.tuya.com/en/docs/iot/Custom-Domain-new?id=Kd1te5j7ajghz).
- [Aqara regional app/device/API domains](https://opendoc.aqara.com/en/docs/developmanual/apiIntroduction/APIUsageGuide.html).
- [Shelly Cloud API](https://shelly-api-docs.shelly.cloud/cloud-control-api/)
  and [device cloud documentation](https://shelly-api-docs.shelly.cloud/gen1/).

Regression tests cover separate seed scope, upgrade preservation, idempotence,
compiled WAN and selectable-list traffic/DNS routing, and rejection of an
unavailable explicit list. External availability and physical-device account
sessions are not asserted by these reproducible tests.
