# QuantumVPN

VPN приложение для Android с поддержкой множества протоколов.

## Протоколы

- VLESS (Reality, TLS, WebSocket, gRPC)
- VMess (TLS, WebSocket, gRPC)
- Trojan
- Shadowsocks
- Hysteria2
- TUIC
- WireGuard

## Возможности

- Подключение/Отключение одним нажатием
- Импорт подписок по URL
- Автоматическое обновление подписок
- Проверка пинга серверов
- Фильтрация по протоколам
- Автообновление приложения с GitHub
- Автоподключение при загрузке
- Красивый Material Design 3 интерфейс

## Сборка

### Требования

- Android Studio Arctic Fox или новее
- JDK 17
- Android SDK 34

### Инструкция

1. Откройте проект в Android Studio
2. Дождитесь синхронизации Gradle
3. Запустите сборку:
   ```
   ./gradlew assembleDebug
   ```
4. APK будет в `app/build/outputs/apk/debug/`

### Добавление sing-box ядра

Для работы VPN необходимо добавить бинарный файл sing-box:

1. Скачайте sing-box с [официального сайта](https://sing-box.sagernet.org)
2. Распакуйте бинарники для архитектур:
   - `arm64-v8a/sing-box` (для современных телефонов)
   - `armeabi-v7a/sing-box` (для старых телефонов)
   - `x86_64/sing-box` (для эмуляторов)
3. Поместите файлы в `app/src/main/assets/libs/{архитектура}/`

## Структура проекта

```
app/src/main/java/com/quantumvpn/
├── core/
│   ├── SingBoxCore.kt          # Ядро VPN
│   └── SubscriptionParser.kt   # Парсер подписок
├── data/
│   └── Models.kt               # Модели данных
├── service/
│   ├── VPNService.kt           # VPN сервис
│   └── BootReceiver.kt         # Автозапуск
├── ui/
│   ├── components/
│   │   └── Components.kt       # UI компоненты
│   ├── screens/
│   │   └── MainScreen.kt       # Главный экран
│   └── theme/
│       ├── Theme.kt            # Тема
│       └── Type.kt             # Типографика
├── utils/
│   ├── PingUtils.kt            # Утилита пинга
│   └── UpdateChecker.kt        # Проверка обновлений
├── viewmodel/
│   └── MainViewModel.kt        # ViewModel
├── MainActivity.kt
└── QuantumVPNApp.kt
```

## Формат подписок

Приложение поддерживает стандартные форматы:

```
vless://uuid@host:port?params#name
vmess://base64json
trojan://password@host:port?params#name
ss://base64(method:password)@host:port#name
hysteria2://password@host:port?params#name
tuic://uuid:password@host:port?params#name
```

## Лицензия

MIT License
