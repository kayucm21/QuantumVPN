# Игровой режим QuantumVPN (GearUP-подобный fast path)

> Этап 9 рабочего плана. Поправка к ADR-003 (маршрутизация): новый runtime-источник
> политики — `GameModeStore`, исполнение — существующие две координаты
> (Android allowlist + runtime route-правило). Хранимый профиль не меняется,
> новых процессов/сервисов/слоёв нет.

## Идея

Трафик выбранных игр идёт напрямую через сеть Android (встроенный outbound
`direct`), минуя VPN-сервер: кратчайший маршрут, минимальный пинг и ноль
нагрузки на VDS. Всё остальное работает как раньше. Это и есть выигрыш
типа GearUP: ускоряется только игра, а не весь интернет.

## Как вписано в архитектуру

| Координата | Было | Стало (game mode ON) |
|---|---|---|
| Android допуск в TUN | `AppSelectionStore` + `VpnAppScopePreflight` | + пакеты игр (только в `Include`; в `All/Exclude/Block` игры уже в TUN) |
| sing-box назначение | правила профиля + runtime-оверлеи | + первое правило `{package_name:[игры], action:route, outbound:direct}` |
| Block-режим | выбранные → `reject` | игры вычитаются из block-списка: игра побеждает блок |

- Правило применяется **последним** в `RuntimeConfigBuilder` → оказывается
  **первым** в `route.rules` → побеждает Block и пресеты (порядок sing-box).
- `direct` — встроенный outbound, существует в любом профиле.
- Ассёрты `AndroidPlatformAdapter.openTun` сходятся: dry-run и адаптер получают
  одну и ту же выборку `tunSelected`.
- Переключение = `restartIfConnected("game-mode")` (та же практика, что у Routing).

## Файлы

- `vpn/GameCatalog.kt` — 16 игр (PUBG/M/MLBB/CODM/Free Fire/Brawl/Genshin/HSR/
  Roblox/Standoff 2/Wild Rift/Minecraft/FC/eFootball/Blitz/Clash-игры).
- `vpn/GameModeStore.kt` — DataStore `game_mode` (enabled + packages).
- `config/RuntimeConfigBuilder.kt` — `gameModePackages` + `applyGameModePackages`.
- `vpn/QuantumVpnService.kt` — допуск в TUN + передача в options + вычет из Block.
- `vpn/AppsViewModel.kt` + `ui/AppPickerScreen.kt` — карточка «Игровой режим»:
  мастер-переключатель, найденные игры с чекбоксами, «выбрать все».
- Тесты: `config/GameModeRuntimeTest` (5), `vpn/GameCatalogTest` (3).

## Gates этапа 9

- [ ] `./gradlew :app:testDebugUnitTest` — новые тесты зелёные.
- [ ] Ручная матрица: игра в каталоге + VPN включён → IP игры = IP провайдера,
  IP браузера = IP VPN (раздельные маршруты за один TUN).
- [ ] Игра НЕ в TUN при выключенном режиме ведёт себя как раньше.

## Следующие этапы (не в этом срезе)

- **Замер пинга до/после**: `IcmpPingProbe` + `VpnController.measurePing` уже есть;
  нужны честные probe-хосты игровых серверов (не выдумывать — взять из
  gearup-mobile `GamePingService` / замерить на устройстве).
- **Серверная вкладка RosPanel**: пинг-статистика и выбор ноды — после второй ноды.
- **Перенос каталога** в gearup-mobile MAUI как общий источник данных.
