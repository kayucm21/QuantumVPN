"""Bounded, read-only presentation of the approved Quantum 4.0 roadmap."""
from __future__ import annotations

import html
from urllib.parse import urlencode


def render_roadmap(snapshot: dict, query: str = "", group: str = "") -> str:
    esc = lambda value: html.escape(str(value), quote=True)
    counts = snapshot["counts"]
    options = '<option value="">Все направления</option>' + "".join(
        f'<option value="{esc(item["id"])}" {"selected" if item["id"] == group else ""}>{esc(item["title"])}</option>'
        for item in snapshot["groups"]
    )
    rows = "".join(
        f'<tr><td class=four-id>{int(item["id"])}</td><td><b>{esc(item["title"])}</b><small>{esc(item["description"])}</small></td>'
        f'<td><span class="badge {"ok" if item["status"] == "verified" else "warn" if item["status"] == "partial" else ""}">{esc(item["status_label"])}</span>'
        f'<small>{esc(item["note"])}</small></td></tr>'
        for item in snapshot["items"]
    ) or '<tr><td colspan=3 class=empty-state>По этому запросу пунктов нет.</td></tr>'
    def page_link(offset: int, label: str) -> str:
        target = "/operator?" + urlencode({"tab": "roadmap", "q": query, "roadmap_group": group,
                                          "roadmap_offset": offset, "roadmap_limit": snapshot["limit"]})
        return f'<a class="button secondary" href="{esc(target)}">{esc(label)}</a>'
    previous = page_link(max(0, snapshot["offset"] - snapshot["limit"]), "← Назад") if snapshot["offset"] else ""
    next_page = page_link(snapshot["next_offset"], "Далее →") if snapshot["next_offset"] is not None else ""
    start = snapshot["offset"] + 1 if snapshot["items"] else 0
    end = snapshot["offset"] + len(snapshot["items"]) if snapshot["items"] else 0
    return f"""<style>
    .four-roadmap .four-notice{{margin:0 0 14px;padding:10px 12px;border:1px solid #35566a;border-radius:8px;background:#132a39;color:#bed9e5;font-size:12px}}
    .four-roadmap .four-counts{{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 14px}}
    .four-roadmap .four-filter{{display:flex;flex-wrap:wrap;align-items:flex-end;gap:9px;margin-bottom:13px}}
    .four-roadmap .four-filter label{{flex:1 1 190px;min-width:0;margin:0}}
    .four-roadmap .four-filter label:first-of-type{{flex:2 1 260px}}
    .four-roadmap .four-filter button{{flex:0 0 auto}}
    .four-roadmap .four-table{{max-height:min(48svh,520px);overflow:auto;border:1px solid #2a4057;border-radius:8px}}
    .four-roadmap table{{width:100%;border:0;table-layout:fixed}}
    .four-roadmap th:first-child{{width:48px}}.four-roadmap th:last-child{{width:29%}}
    .four-roadmap th{{position:sticky;top:0;z-index:1;background:#152b3d}}
    .four-roadmap td{{padding:10px 12px;overflow-wrap:anywhere}}.four-roadmap td b{{font-size:12px}}
    .four-roadmap td small{{display:block;margin-top:4px;line-height:1.4;font-size:11px}}
    .four-roadmap .four-id{{font-variant-numeric:tabular-nums;color:#84b7c5}}
    .four-roadmap .four-pager{{display:flex;flex-wrap:wrap;align-items:center;gap:9px;margin-top:12px}}
    .four-roadmap .four-pager small{{margin-right:auto}}
    @media(min-width:761px){{
      .four-content{{display:flex;flex-direction:column;height:100vh;height:100svh;overflow:hidden}}
      .four-content>.reference-heading,.four-content>.aurora-subnav{{flex-shrink:0}}
      .four-roadmap{{display:flex;flex-direction:column;min-height:0;flex:1}}
      .four-roadmap>:not(.four-table){{flex-shrink:0}}
      .four-roadmap .four-table{{flex:1;min-height:0;max-height:none}}
    }}
    @media(max-width:650px){{.four-roadmap th:last-child{{width:34%}}.four-roadmap td{{padding:9px 7px}}.four-roadmap table{{display:table;white-space:normal;font-size:11px}}}}
    </style><section class=four-roadmap>
    <p class=four-notice>Это план развития, а не заявление о готовности всех функций. «Проверено» означает подтверждённый объём из заметки; существующие возможности не считаются автоматически завершёнными пунктами 4.0.</p>
    <div class=four-counts><span class=badge>Всего: {snapshot['total']}</span><span class=badge>В плане: {counts['planned']}</span><span class="badge warn">Частично: {counts['partial']}</span><span class="badge ok">Проверено: {counts['verified']}</span></div>
    <form class=four-filter method=get action=/operator><input type=hidden name=tab value=roadmap><input type=hidden name=roadmap_limit value={snapshot['limit']}>
      <label>Поиск по плану<input name=q maxlength=128 value="{esc(query)}" placeholder="Номер, название или описание"></label>
      <label>Направление<select name=roadmap_group>{options}</select></label><button>Найти</button></form>
    <div class=four-table role=region aria-label="План Quantum 4.0" tabindex=0><table><thead><tr><th>№</th><th>Возможность</th><th>Состояние</th></tr></thead><tbody>{rows}</tbody></table></div>
    <div class=four-pager><small>Показано {start}–{end} из {snapshot['matched']} найденных · {len(snapshot['items'])} пунктов на этой странице</small>{previous}{next_page}</div>
    </section>"""
