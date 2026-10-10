# app-updater

Изолированный модуль обновления APK. Он не зависит от UI, профилей, libbox или
реализации VPN в `app`.

- `GitHubUpdateSource.kt` — HTTPS, GitHub Releases и загрузка.
- `UpdateModels.kt` — release metadata, состояния и строгий JSON parser.
- `ApkUpdateVerifier.kt` — package/version/minSdk/signing policy.
- `UpdateController.kt` — одна проверка, загрузка и очистка частных временных APK.
- `UpdatePreflightPolicy.kt` — проверка свободного места, условия документированной
  самоустановки и чистая политика проверки результата системной сессии.
- `UpdateVpnFallback.kt` — два узких callback-контракта для VPN lease и installer.

Реализация callback-ов находится в `app/src/main/java/com/quantumvpn/updates/`,
потому что только product-модуль владеет `VpnService`, `FileProvider` и
`PackageInstaller`.

## Проверенные пакеты и системная установка

На Android 12+ `SessionApkUpdateInstaller` копирует проверенный APK в системную
сессию и повторно проверяет SHA-256/размер во время копирования. Частный APK
удаляется только после принятого системного handoff; при отмене и ошибке копия
также удаляется. При следующем старте удаляются APK/`.part` только из собственных
каталогов обновления приложения — пользовательские Downloads не затрагиваются.

Для самообновления используется официальный `USER_ACTION_NOT_REQUIRED` при
подходящем target SDK, разрешении установки из этого источника и объявленном
`UPDATE_PACKAGES_WITHOUT_USER_ACTION`. Установщик обновляет свой собственный
package; не требует прав root, Accessibility, Device Owner или изменения Android.
На старом/неизвестном Android и по решению ОС остаётся системное подтверждение.
См. [PackageInstaller.SessionParams](https://developer.android.com/reference/android/content/pm/PackageInstaller.SessionParams#setRequireUserAction(int)).
Ранее установленный APK без нового установщика не меняется сам: переход на эту
версию один раз проходит через его прежнее системное окно установки. Возможность
самоустановки касается последующих проверенных обновлений.

Callback направлен в non-exported receiver явным PendingIntent; результат
принимается только с правильными action, одноразовым nonce и обоими session ID.
STATUS_SUCCESS и Activity.RESULT_OK не считаются доказательством установки:
проверяется фактически установленный package/version. Потерянное после гибели
процесса окно подтверждения не реконструируется из внешних данных; отменяется
только записанная собственная сессия, после чего доступна повторная загрузка.

Unit-проверки этих политик и компиляция инструментальных тестов не доказывают
автоустановку на физическом телефоне. Отдельный device gate — upgrade тем же
ключом, сохранение профилей, подтверждение/отмена, перезапуск процесса и очистка
кэша — остаётся обязательным перед заявлением о проверенной автоустановке.
