# Подпись QuantumVPN Android

Release APK всегда должен быть подписан одним постоянным ключом. GitHub Actions получает
ключ и пароли только через secrets среды `release`; ключ, `.properties` и пароли в Git
не добавляются.

## Однократное создание ключа офлайн

На отключённой от сети машине с JDK 17:

```bash
keytool -genkeypair \
  -keystore zapret-kvn-release.jks \
  -alias zapret-kvn-release \
  -keyalg RSA -keysize 4096 -validity 10000
sha256sum zapret-kvn-release.jks > zapret-kvn-release.jks.sha256
gpg --symmetric --cipher-algo AES256 zapret-kvn-release.jks
keytool -exportcert -rfc -keystore zapret-kvn-release.jks -alias zapret-kvn-release \
  | openssl x509 -outform DER \
  | sha256sum
```

Сделать минимум две офлайн-копии `zapret-kvn-release.jks.gpg` и checksum на разных
носителях. Проверить восстановление на третьем временном носителе командами
`gpg --decrypt` и `sha256sum -c`, затем безопасно удалить расшифрованную проверочную
копию. Потеря ключа означает невозможность обновить уже установленное приложение.

## GitHub environment `release`

Добавить environment с обязательным ручным approval и secrets:

- `ANDROID_SIGNING_KEYSTORE_BASE64` — `base64 -w0 zapret-kvn-release.jks`;
- `ANDROID_SIGNING_STORE_PASSWORD`;
- `ANDROID_SIGNING_KEY_ALIAS` — `zapret-kvn-release`;
- `ANDROID_SIGNING_KEY_PASSWORD`;
- `ANDROID_SIGNING_CERT_SHA256` — 64 hex-символа из команды выше, без имени файла.

Workflow восстанавливает JKS только во временный каталог runner, проверяет подпись
готового APK через pinned Android `apksigner`, сравнивает сертификат с закреплённым
`ANDROID_SIGNING_CERT_SHA256` и удаляет JKS в шаге `always()`.
`scripts/ci-build.sh` автоматически отключает Gradle configuration cache, когда переданы
`ZAPRET_SIGNING_*`, чтобы пароли не попали в повторно используемый Gradle state.

## Финальный approval, версии и публикация

Среда `release` должна иметь обязательного reviewer. Workflow запускается только вручную
для уже существующего tag; оператор ставит `final_gate_approved=true` лишь после закрытия
всех пунктов «Финальный gate» в `IMPLEMENTATION_PLAN.md`, физической матрицы
`GATE8_RESULTS.md` и проверки production-signed ABI-specific APK на реальном устройстве. Push tag
сам по себе ничего не публикует.

- stable tag: `vMAJOR.MINOR.PATCH`;
- beta tag: `vMAJOR.MINOR.PATCH-beta.N`, где `N` от 1 до 98;
- versionCode вычисляется детерминированно; stable получает slot 99 и поэтому новее beta
  той же версии;
- опубликованные assets не заменяются: исправление выпускается только новым tag.

Release workflow публикует подписанные `arm64-v8a`, `armeabi-v7a`, `x86_64` APK, отдельные `.sha256` и
`release-metadata-v2.json` с package, version, точным commit ядра, signing fingerprint и
размером APK.
