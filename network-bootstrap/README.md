# network-bootstrap

Узкий Android library-модуль для bootstrap до создания TUN. Он владеет только:

- выбором текущей non-VPN сети;
- согласованием `NetworkCapabilities` и `LinkProperties`;
- короткой стабилизацией snapshot и одним повтором при реальной смене network identity, validation/Private DNS или списка DNS-серверов;
- системным `DnsResolver`/`Network.getAllByName()`;
- стабильными support-кодами и безопасной технической причиной.

Модуль не знает о профилях, Compose, `libbox`, VPN allowlist, runtime JSON или LKG-кэше. Эти решения остаются в `app`.

| Код | Значение |
|---|---|
| `NET-101` | Android не предоставил underlying-сеть |
| `NET-102` | Сеть менялась во время bootstrap и не стабилизировалась |
| `DNS-101` | DNS timeout |
| `DNS-102` | Имя не найдено / NXDOMAIN |
| `DNS-103` | DNS отказал / REFUSED |
| `DNS-104` | Успешный ответ без адресов |
| `DNS-105` | Системная ошибка Android resolver (`DnsException`/errno) |
| `DNS-106` | Другой DNS RCODE |

Текст ошибки может уточняться, но смысл опубликованного кода не меняется.
