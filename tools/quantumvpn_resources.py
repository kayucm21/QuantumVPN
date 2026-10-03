"""Signed, bounded presentation data. Never accepts executable code or remote URLs."""
import base64
import hashlib
import html
import io
import json
from pathlib import Path
import re
import time
import uuid

from cryptography.hazmat.primitives import serialization

KIND = "quantumvpn-resources-v1"
MIN_VERSION = 501101099
MAX_ASSET = 2 * 1024 * 1024
TEXT_LIMITS = {"brand_name": 32, "tagline": 100, "welcome": 120,
               "games_title": 40, "games_subtitle": 100}
HASH = re.compile(r"[0-9a-f]{64}")


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def schema(db):
    db.execute("create table if not exists resource_bundles (id integer primary key autoincrement, document text not null, note text not null, actor text not null, created_at integer not null)")
    db.execute("create table if not exists resource_state (id integer primary key check(id=1), sequence integer not null, production integer, staging integer, percent integer not null)")
    db.execute("insert or ignore into resource_state values (1,0,null,null,0)")
    db.commit()


def validate(document):
    if not isinstance(document, dict) or set(document) != {"texts", "theme", "assets"}:
        raise ValueError("Пакет должен содержать только texts, theme и assets")
    texts, theme, assets = (document[k] for k in ("texts", "theme", "assets"))
    if not isinstance(texts, dict) or set(texts) - set(TEXT_LIMITS):
        raise ValueError("Неизвестный текстовый параметр")
    for key, value in texts.items():
        if not isinstance(value, str) or not 1 <= len(value) <= TEXT_LIMITS[key] or any(ord(c) < 32 for c in value):
            raise ValueError("Недопустимая длина или символы текста")
    if not isinstance(theme, dict) or set(theme) - {"accent", "compact_home"}:
        raise ValueError("Неизвестный параметр оформления")
    if "accent" in theme and (not isinstance(theme["accent"], str) or not re.fullmatch(r"#[0-9A-Fa-f]{6}", theme["accent"])):
        raise ValueError("Цвет должен иметь формат #RRGGBB")
    if "compact_home" in theme and type(theme["compact_home"]) is not bool:
        raise ValueError("compact_home должен быть boolean")
    if not isinstance(assets, dict) or set(assets) - {"background", "logo"}:
        raise ValueError("Разрешены только фон и логотип")
    for value in assets.values():
        if not isinstance(value, dict) or set(value) != {"sha256", "size", "mime", "width", "height"}:
            raise ValueError("Некорректное описание изображения")
        if not isinstance(value["sha256"], str) or not HASH.fullmatch(value["sha256"]) or value["mime"] not in ("image/png", "image/jpeg"):
            raise ValueError("Некорректный хеш или формат изображения")
        if any(type(value[k]) is not int for k in ("size", "width", "height")) or not 1 <= value["size"] <= MAX_ASSET or not 1 <= value["width"] <= 1440 or not 1 <= value["height"] <= 1440:
            raise ValueError("Изображение превышает лимиты")
    if len(canonical(document).encode()) > 16384:
        raise ValueError("Пакет превышает лимит")
    return document


def store_image(root, data, role):
    # Decode and re-encode: strip EXIF/location, appended payloads and animation.
    from PIL import Image, UnidentifiedImageError
    if not 1 <= len(data) <= MAX_ASSET:
        raise ValueError("Изображение: не более 2 МБ")
    try:
        with Image.open(io.BytesIO(data)) as source:
            if source.format not in ("JPEG", "PNG") or getattr(source, "n_frames", 1) != 1 or source.width * source.height > 16000000:
                raise ValueError("Нужен статичный JPG/PNG до 16 мегапикселей")
            source.load()
            image = source.convert("RGBA" if role == "logo" else "RGB")
            image.info.clear()
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError) as exc:
        raise ValueError("Не удалось проверить изображение") from exc
    image.thumbnail((256, 256) if role == "logo" else (1440, 1440))
    out = io.BytesIO()
    mime = "image/png" if role == "logo" else "image/jpeg"
    image.save(out, "PNG" if role == "logo" else "JPEG", **({} if role == "logo" else {"quality": 85}))
    clean = out.getvalue()
    if len(clean) > MAX_ASSET:
        raise ValueError("Обработанное изображение превышает лимит")
    digest = hashlib.sha256(clean).hexdigest()
    directory = Path(root) / "resources" / "assets"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    target = directory / digest
    if not target.exists():
        temporary = directory / (digest + "." + uuid.uuid4().hex + ".part")
        # Identical concurrent uploads yield identical bytes; no arbitrary paths.
        try:
            temporary.write_bytes(clean)
            temporary.replace(target)
        finally:
            temporary.unlink(missing_ok=True)
    return {"sha256": digest, "size": len(clean), "mime": mime, "width": image.width, "height": image.height}


def bundle(db, revision):
    row = db.execute("select * from resource_bundles where id=?", (revision,)).fetchone()
    if row is None:
        raise ValueError("Ревизия не найдена")
    return validate(json.loads(row["document"]))


def asset_bytes(db, root, digest):
    if not HASH.fullmatch(digest):
        raise ValueError("Изображение не найдено")
    # Only assets referenced by an immutable saved bundle can be served.
    descriptor = None
    for row in db.execute("select document from resource_bundles"):
        for value in json.loads(row[0])["assets"].values():
            if value["sha256"] == digest:
                descriptor = value
                break
        if descriptor:
            break
    if descriptor is None:
        raise ValueError("Изображение не найдено")
    path = Path(root) / "resources" / "assets" / digest
    if not path.is_file() or path.stat().st_size != descriptor["size"]:
        raise ValueError("Изображение недоступно")
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("Изображение повреждено")
    return data, descriptor["mime"]


def action(db, root, form, files, actor):
    schema(db)
    value = lambda key, default="": form.get(key, [default])[0]
    operation = value("action")
    if operation == "save":
        revision = int(value("base_revision", "0"))
        document = bundle(db, revision) if revision else {"texts": {}, "theme": {}, "assets": {}}
        if "package" in files and files["package"]["data"]:
            raw = files["package"]["data"]
            if len(raw) > 16384:
                raise ValueError("JSON: не более 16 КБ")
            document = validate(json.loads(raw))
        else:
            document["texts"] = {k: value(k).strip() for k in TEXT_LIMITS if value(k).strip()}
            document["theme"] = {"compact_home": value("compact_home") == "on"}
            if value("accent").strip():
                document["theme"]["accent"] = value("accent").strip()
        for role in ("background", "logo"):
            if value("remove_" + role) == "on":
                document["assets"].pop(role, None)
            if role in files and files[role]["data"]:
                document["assets"][role] = store_image(root, files[role]["data"], role)
        validate(document)
        for asset in document["assets"].values():
            path = Path(root) / "resources" / "assets" / asset["sha256"]
            if not path.is_file() or path.stat().st_size != asset["size"] or hashlib.sha256(path.read_bytes()).hexdigest() != asset["sha256"]:
                raise ValueError("Изображение пакета сначала нужно загрузить в панель")
        result = db.execute("insert into resource_bundles(document,note,actor,created_at) values (?,?,?,?)",
                            (canonical(document), value("note")[:200], actor, int(time.time()))).lastrowid
        return f"Черновик r{result} сохранён. Пользователи пока его не получают."
    revision = int(value("revision", "0"))
    if operation in ("production", "staging", "rollback"):
        document = bundle(db, revision)
        for asset in document["assets"].values():
            asset_bytes(db, root, asset["sha256"])
        if operation == "staging":
            if db.execute("select production from resource_state where id=1").fetchone()[0] is None:
                raise ValueError("Сначала опубликуйте базовую рабочую ревизию для безопасного возврата")
            percent = int(value("percent", "10"))
            if not 1 <= percent <= 100:
                raise ValueError("Охват тестовой группы: 1–100%")
            db.execute("update resource_state set sequence=sequence+1, staging=?,percent=? where id=1", (revision, percent))
        else:
            db.execute("update resource_state set sequence=sequence+1,production=?,staging=null,percent=0 where id=1", (revision,))
        return f"Ревизия r{revision}: " + ("опубликована тестовой группе" if operation == "staging" else "опубликована всем совместимым APK")
    if operation == "stop_test":
        db.execute("update resource_state set sequence=sequence+1, staging=null,percent=0 where id=1")
        return "Тестовая публикация остановлена"
    raise ValueError("Неизвестное действие")


def client_manifest(db, device, version_code, signing_key):
    schema(db)
    if version_code < MIN_VERSION:
        return None
    state = db.execute("select * from resource_state where id=1").fetchone()
    bucket = int(hashlib.sha256(device.encode()).hexdigest()[:8], 16) % 100
    revision = state["staging"] if state["staging"] and bucket < state["percent"] else state["production"]
    if revision is None:
        return None
    payload = {"kind": KIND, "sequence": state["sequence"], "revision": revision,
               "min_version_code": MIN_VERSION, **bundle(db, revision)}
    data = canonical(payload).encode()
    encode = lambda value: base64.urlsafe_b64encode(value).decode().rstrip("=")
    key = signing_key()
    return {"schema": 1, "signature_algorithm": "ed25519", "payload": payload,
            "sha256": hashlib.sha256(data).hexdigest(), "signature": encode(key.sign(data)),
            "public_key": encode(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))}


def render(db):
    schema(db)
    rows = db.execute("select * from resource_bundles order by id desc limit 30").fetchall()
    state = db.execute("select * from resource_state where id=1").fetchone()
    latest = rows[0] if rows else None
    document = bundle(db, latest["id"]) if latest else {"texts": {}, "theme": {}, "assets": {}}
    escape = lambda x: html.escape(str(x), quote=True)
    inputs = "".join(f'<label>{escape(label)}<input name="{key}" maxlength="{TEXT_LIMITS[key]}" value="{escape(document["texts"].get(key,""))}"></label>' for key, label in
                     (("brand_name", "Название"), ("tagline", "Подпись на главной"), ("welcome", "Приветствие при запуске"), ("games_title", "Заголовок игр"), ("games_subtitle", "Подпись игр")))
    previews = "".join(f'<figure><img style="max-width:200px;max-height:160px" src="/api/client/resources/assets/{v["sha256"]}" alt="{role}"><figcaption>{role} · {v["size"] // 1024} КБ</figcaption></figure>' for role, v in document["assets"].items())
    history = ""
    for row in rows:
        forms = "".join(f'<form method=post action=/operator/resources style="display:inline"><input type=hidden name=revision value="{row["id"]}"><input type=hidden name=action value="{op}">' + ('<input name=percent type=number min=1 max=100 value=10 style="width:70px" aria-label="Охват тестовой группы">' if op == "staging" else "") + f'<button class=secondary>{label}</button></form>' for op, label in (("staging", "Тест"), ("production", "Опубликовать"), ("rollback", "Откатить сюда")))
        doc = bundle(db, row["id"])
        status = "Рабочая" if row["id"] == state["production"] else "Тест" if row["id"] == state["staging"] else "Сохранена"
        history += f'<tr><td>r{row["id"]}</td><td>{status}</td><td>{escape(row["note"])}</td><td><details><summary>Предпросмотр</summary><pre>{escape(json.dumps(doc,ensure_ascii=False,indent=2))}</pre></details></td><td>{forms}</td></tr>'
    return f'''<section class=card><h2>Ресурсы и исправления</h2><p>Рабочая: r{state['production'] or '—'} · Тест: r{state['staging'] or '—'} ({state['percent']}%) · Публикация: {state['sequence']}</p>
    <p class=muted>Нужен APK 5.11.1 или новее. Дальше ресурсы обновляются без переустановки. Только тексты, цвет, статичные фон и логотип, компактная главная. Код, разрешения и VPN-движок так не обновляются. Личное фото пользователя сохраняется.</p>
    <details open><summary>Новый черновик</summary><form method=post action=/operator/resources enctype=multipart/form-data>
    <input type=hidden name=action value=save><input type=hidden name=base_revision value="{latest['id'] if latest else 0}">
    <div class=grid>{inputs}<label>Акцент #RRGGBB<input name=accent pattern="#[0-9A-Fa-f]{{6}}" value="{escape(document['theme'].get('accent',''))}" placeholder="#58F4CE"></label></div>
    <label><input type=checkbox name=compact_home {'checked' if document['theme'].get('compact_home') else ''}> Компактная главная (без изменения размера кнопок навигации)</label>
    <div class=grid><label>Фон JPG/PNG, до 2 МБ<input type=file name=background accept="image/jpeg,image/png"></label><label>Логотип PNG/JPG, до 2 МБ<input type=file name=logo accept="image/jpeg,image/png"></label></div>
    <label><input type=checkbox name=remove_background> Убрать фон из пакета</label><label><input type=checkbox name=remove_logo> Убрать логотип из пакета</label>
    <details><summary>Импорт JSON-пакета (не код, до 16 КБ)</summary><input type=file name=package accept=application/json></details>
    <label>Описание<input name=note maxlength=200></label><button>Сохранить черновик</button></form>{previews}</details></section>
    <section class=card><h2>Публикации и откат</h2><p class=muted>Тестовая группа определяется устойчиво по идентификатору устройства. Откат получает новый номер публикации; старые ответы не принимаются APK. Для возврата встроенного оформления опубликуйте пакет с пустыми текстами/цветом и удалёнными изображениями.</p>
    <div class=table-wrap><table><thead><tr><th>Ревизия</th><th>Статус</th><th>Описание</th><th>Состав</th><th>Действия</th></tr></thead><tbody>{history}</tbody></table></div>
    <form method=post action=/operator/resources><input type=hidden name=action value=stop_test><button class=secondary>Остановить тестовую публикацию</button></form></section>'''
