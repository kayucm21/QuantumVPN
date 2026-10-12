# Gate 8: состояние проверок и границы измерений

Этот документ восстанавливает ссылку на протокол проверки, используемую README и планом реализации. Он не является отчётом об измеренной пропускной способности или расходе энергии конкретной сборки. Исторические записи MVP в [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) относятся к соответствующим старым сборкам; текущие фоновые возможности описаны в [ARCHITECTURE.md](ARCHITECTURE.md).

## Автоматизированная проверка

- [scripts/verify-project.sh](scripts/verify-project.sh) проверяет структуру модулей, закреплённые зависимости/Actions, manifest permissions и bounded FileProvider paths, лицензионные файлы, локальные ссылки и fixture/rule-set hashes.
- [scripts/verify-runtime-surfaces.py](scripts/verify-runtime-surfaces.py) ограничивает текущих владельцев таймеров, WakeLock, alarms, command streams и явных clipboard actions. Это проверка исходной политики, а не измерение энергии.
- [scripts/verify-gate8-performance.sh](scripts/verify-gate8-performance.sh) и [scripts/verify-gate8-stress.sh](scripts/verify-gate8-stress.sh) сохраняют device evidence. Порог сравнения задаёт [scripts/gate8-performance-summary.jq](scripts/gate8-performance-summary.jq): разница менее 5% не оправдывает смену варианта; значимая разница требует физического подтверждения.
- JVM и Android UI проверки выполняются через Gradle. Компиляция instrumented tests не означает их выполнение на телефоне.

Результаты каждой конкретной APK должны сопровождаться commit, versionCode/versionName, ABI, подписью и SHA-256. Успешный запуск проверяющего скрипта не наследуется новой сборкой автоматически.

Дополнительный [WireGuard Android client-bind fixture](testdata/routing/wireguard-android-client-bind.json), SHA-256 `aba3a561bbb15a8e33c9c168be8eea8b435f0a123d0e25bb74f135dc920f3c87`, содержит reserved example endpoint и явный маршрут health-check приложения через WireGuard. Его наличие и hash проверяет verifier; это не свидетельство работы внешнего сервера или реального throughput.

## Открытые физические проверки

Без приложенных исходных trace/ADB/диагностических данных остаются неподтверждёнными: расход энергии managed idle, per-app изоляция на OEM/API, переход Wi-Fi ↔ mobile, NAT64/IPv6/QUIC, устойчивость DNS, холодный запуск и конечная скорость через VPN на телефоне. Speedtest на VDS измеряет путь самого VDS и не подтверждает скорость клиента.

Проверка на устройстве выполняется по [проектному Android skill](.agents/skills/test-zapret-android/SKILL.md): сначала собираются ADB system evidence и редактированная диагностика приложения, затем изменяется реализация. Для сравнения вариантов нужны одинаковые устройство, сеть, температура, профиль, сервер и объём трафика, минимум пять повторов и исходные результаты каждого прогона.

Локальная публикация ARM64/ARMv7 test prerelease и независимая remote CI проверка следуют [AGENTS.md](AGENTS.md). Test prerelease сам по себе не означает прохождение физических production gates.
