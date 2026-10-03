"""Aurora presentation layer for the existing Quantum Control operator panel.

Append ``aurora_css()`` after the panel's current CSS and include
``aurora_script()`` once, after its existing scripts.  The script returns a full
script element.  This module has no network, storage, routing, or policy logic.
"""


def aurora_css() -> str:
    """Return an opaque navy and mint theme for the existing panel markup."""
    return r"""
    /* Aurora 2.0: data and controls remain owned by the operator panel. */
    :root {
      color-scheme: dark;
      --bg: #08121f; --surface: #0c1929; --card: #101e30;
      --line: #25394f; --line2: #37516c; --text: #e9f1f8;
      --muted: #a0b3c8; --blue: #64e9cd; --cyan: #64e9cd;
      --blue-dark: #35bca4; --ok: #64e9b0; --amber: #ffd08a;
      --off: #ff98ad; --violet: #b9a6f6;
      --shadow: 0 6px 20px #02091320;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0; color: var(--text); background: var(--bg);
      background-image: radial-gradient(ellipse at 70% -25%, #163446 0, transparent 55%);
      font: 13px/1.5 "Segoe UI", system-ui, -apple-system, sans-serif;
      -webkit-font-smoothing: antialiased;
    }
    main { width: 100%; max-width: 1840px; margin: auto; padding: 0 24px 24px 0; }
    .panel-shell { display: grid; grid-template-columns: 216px minmax(0, 1fr); gap: 24px; align-items: start; }
    .panel-content { min-width: 0; max-width: none; padding: 0; }
    .sidebar {
      position: sticky; top: 0; height: 100vh; height: 100svh; min-height: 0;
      overflow-y: auto; overflow-x: hidden; padding: 24px 12px 18px;
      background: #0a1625; border: 0; border-right: 1px solid #203348;
      border-radius: 0; box-shadow: none; scrollbar-width: thin;
      scrollbar-color: #37516c transparent;
    }
    .sidebar:after { display: none; }
    .sidebar-brand {
      position: relative; margin: 0 2px 20px; padding: 0 3px 20px 43px;
      color: #f2f8fd; border-bottom: 1px solid #203348;
      font-size: 16px; line-height: 1.35; letter-spacing: -.02em;
      white-space: normal; font-weight: 700;
    }
    .sidebar-brand:before {
      content: "Q"; position: absolute; top: 0; left: 2px; float: none;
      display: grid; place-items: center; width: 32px; height: 32px;
      margin: 0; border: 1px solid #2b665f; border-radius: 10px;
      background: #12342f; color: var(--cyan); font-size: 22px;
      font-weight: 750; line-height: 1; text-shadow: none;
    }
    .sidebar-brand span { display: block; margin: 5px 0 0; font-size: 9px; color: #91adc1; letter-spacing: .08em; }
    .sidebar nav.tabs { display: flex; flex-direction: column; gap: 4px; overflow: visible; }
    .aurora-nav { list-style: none; margin: 0; padding: 0; }
    .aurora-group { list-style: none; margin: 0; padding: 0; min-width: 0; }
    .aurora-nav-section { min-width: 0; margin: 0 0 8px; }
    .aurora-nav-label { margin: 8px 10px 6px; color: #8ca5bc; font-size: 9px; font-weight: 650; letter-spacing: .12em; text-transform: uppercase; }
    .sidebar nav.tabs a, .panel-shell:has(.quality-page) .tabs>a {
      display: flex; align-items: center; gap: 9px; min-height: 39px;
      padding: 9px 11px; margin: 2px 0; color: #b3c4d7;
      border: 1px solid transparent; border-radius: 7px;
      background: transparent; box-shadow: none; text-decoration: none;
      font-size: 12px; font-weight: 500; line-height: 1.35;
      white-space: normal; transition: background .15s, color .15s, border-color .15s;
    }
    .sidebar nav.tabs a:hover { color: #edf9f7; background: #14283a; border-color: #2a4359; text-decoration: none; }
    .sidebar nav.tabs a.active { color: #9cf7df; background: #14382f; border-color: #2b6b5c; box-shadow: inset 3px 0 #64e9cd; font-weight: 650; }
    .sidebar nav.tabs a[href$='cards'] { margin: 2px 0; border-color: transparent; color: #b3c4d7; background: transparent; }
    .sidebar nav.tabs a[href$='cards'].active { color: #9cf7df; background: #14382f; border-color: #2b6b5c; }
    .nav-ico { flex: 0 0 17px; width: 17px; margin: 0; color: #92b8c3; font-size: 16px; text-align: center; }
    nav.tabs a.active .nav-ico { color: #78edd2; }
    .nav-group { margin: 2px 0; padding-top: 5px; border-top: 1px solid #203348; }
    .nav-group summary { padding: 11px 10px; color: #a6bfd0; font-size: 10px; letter-spacing: .08em; cursor: pointer; }
    .nav-group summary:before { color: #6bc9b7; }
    .nav-group a { padding: 8px 12px 8px 27px !important; font-size: 11px !important; }
    .aurora-group.active > a { color: #9cf7df; background: #14382f; border-color: #2b6b5c; box-shadow: inset 3px 0 #64e9cd; font-weight: 650; }
    .aurora-subnav { display: flex; flex-wrap: wrap; gap: 7px; list-style: none; margin: -5px 0 20px; padding: 0 0 14px; border-bottom: 1px solid #26394d; }
    .aurora-subnav a, .panel-content .aurora-subnav a { display: inline-flex; align-items: center; min-height: 32px; padding: 6px 10px; color: #adc5d6; background: #112239; border: 1px solid #2b425a; border-radius: 5px; font-size: 11px; text-decoration: none; }
    .aurora-subnav a:hover, .panel-content .aurora-subnav a:hover { background: #20384b; color: #e8f8f4; text-decoration: none; }
    .aurora-subnav a.active, .aurora-subnav [aria-current=page], .aurora-subnav .active > a { background: #163b32; border-color: #3b7564; color: #9ef0d8; }
    .sidebar nav.tabs a[href='/operator/logout'] { margin-top: 12px; padding-top: 12px; border-top: 1px solid #203348; border-radius: 0; color: #92a9bf; }
    .aurora-logout { display: block; margin: 20px 4px 0; padding: 12px 8px; color: #a6bbce; border-top: 1px solid #25394d; font-size: 12px; text-decoration: none; }
    .aurora-logout:hover { color: #edf8ff; background: #14283a; }
    .aurora-sidebar-badge, .sidebar-badge { display: inline-block; margin: 12px 10px 0; padding: 4px 8px; color: #a5dccc; background: #143128; border: 1px solid #34584b; border-radius: 5px; font-size: 9px; letter-spacing: .06em; }
    .panel-content > .hero {
      height: auto; min-height: 73px; padding: 17px 0; margin: 0 0 22px;
      background: transparent; border: 0; border-bottom: 1px solid #22364b;
      border-radius: 0; box-shadow: none; overflow: visible;
    }
    .hero:after, .hero-top:before { display: none; }
    .hero-top { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 12px; height: auto; }
    .control-search { display: flex; flex: 1 1 300px; gap: 8px; width: auto; max-width: 440px; margin: 0; }
    .control-search input { flex: 1; min-width: 0; height: 36px; padding: 8px 12px; background: #101e30; border-color: #2a4158; font-size: 12px; }
    .control-search button { padding: 7px 12px; min-height: 36px; }
    .system-pill { color: var(--ok); background: #12312c; border: 1px solid #2c5c50; border-radius: 999px; padding: 6px 10px; font-size: 10px; font-weight: 600; white-space: normal; }
    .system-pill.off { color: var(--off); border-color: #704455; background: #352435; }
    .system-pill:after { display: none; }
    .top-date { min-width: 114px; color: #b4c5d7; font-size: 11px; line-height: 1.45; }
    .top-date small { color: #8ca5bc; font-size: 10px; }
    .reference-heading { display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; margin: 0 0 20px; }
    .reference-heading h1 { margin: 0 0 4px; color: #f0f6fb; font-size: 25px; font-weight: 650; line-height: 1.25; text-transform: none; }
    .reference-heading p { max-width: 720px; margin: 0; color: #a0b4c9; font-size: 12px; }
    .reference-heading > small { flex: 0 0 auto; padding: 5px 9px; color: #9bb8c8; font-size: 10px; border: 1px solid #294355; border-radius: 5px; }
    h2 { margin: 0 0 12px; color: #eaf2f8; font-size: 15px; font-weight: 650; line-height: 1.35; }
    h3 { color: #dce7f1; font-size: 13px; }
    .muted, .stat small { color: var(--muted); }
    small { color: #a0b3c8; }
    .accent, .ok { color: var(--ok); }
    .warn { color: var(--amber); }
    .off { color: var(--off); }
    .panel-content a:not(.button) { color: #7ddbcf; text-decoration: none; }
    .panel-content a:not(.button):hover { color: #abf4e5; text-decoration: underline; }
    .card, .dashboard .card, .panel-content .quality-page .card {
      min-width: 0; padding: 18px; margin: 0 0 16px; color: var(--text);
      background: var(--card); border: 1px solid var(--line); border-radius: 10px;
      box-shadow: var(--shadow); overflow: visible;
    }
    .dashboard { padding: 0; margin: 0; background: transparent; border: 0; box-shadow: none; }
    .dashboard .card { margin: 0; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 310px), 1fr)); gap: 16px; align-items: start; }
    .grid .card { margin: 0; }
    .panel-content > .grid { grid-template-columns: repeat(2, minmax(0, 1fr)); margin-bottom: 16px; }
    .reference-kpis, .stats { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 13px; margin-bottom: 16px; }
    .reference-kpi { display: flex; align-items: center; gap: 12px; min-height: 106px; padding: 16px !important; }
    .reference-kpi > div { min-width: 0; }
    .reference-kpi i { display: grid; place-items: center; flex: 0 0 36px; width: 36px; height: 38px; background: #163c39; color: #7fe9d0; border: 1px solid #245850; border-radius: 9px; font-style: normal; font-size: 20px; }
    .reference-kpi:nth-child(4) i { color: #ffd08a; background: #3b3228; border-color: #655340; }
    .reference-kpi span, .stat { color: #a8bed1; font-size: 11px; }
    .reference-kpi b { display: block; margin: 5px 0; color: #f0f7fd; font-size: 25px; line-height: 1.15; font-weight: 650; font-variant-numeric: tabular-nums; overflow-wrap: anywhere; }
    .reference-kpi small { font-size: 10px; color: #93aabf; }
    .stat { min-width: 0; padding: 14px; background: #101e30; border: 1px solid #2a4057; border-radius: 8px; box-shadow: none; }
    .stat b { display: block; margin: 5px 0 2px; color: #e9f3fb; font-size: 22px; line-height: 1.25; overflow-wrap: anywhere; font-variant-numeric: tabular-nums; }
    .stat b.ok { color: var(--ok); } .stat b.off { color: var(--off); }
    .reference-top { display: grid; grid-template-columns: minmax(0, 1.3fr) minmax(0, 1fr); gap: 16px; margin-bottom: 16px; }
    .reference-bottom { display: grid; grid-template-columns: minmax(0, 1.4fr) minmax(0, .9fr) minmax(0, .9fr); gap: 16px; }
    .reference-top > *, .reference-bottom > *, .reference-stack > *, .routing-top-grid > * { min-width: 0; }
    .reference-stack { display: grid; gap: 16px; align-content: start; }
    .section-head { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 9px; margin: 0 0 14px; }
    .section-head h2 { margin: 0; }
    .section-head a { font-size: 11px; }
    .reference-map { min-height: 245px; background: #0e1c2d; border-radius: 7px; }
    .reference-map svg { display: block; width: 100%; height: auto; max-height: 260px; }
    .reference-map-note { margin-top: 12px; color: #a0b4c9; font-size: 10px; line-height: 1.6; text-align: left; }
    .reference-node-strip { display: flex; flex-wrap: wrap; gap: 7px; margin-top: 12px; }
    .reference-node-strip span { padding: 5px 8px; background: #0b1929; border: 1px solid #294256; border-radius: 5px; color: #bfd2e1; font-size: 10px; }
    .reference-node-strip b { margin-left: 7px; color: var(--ok); }
    .reference-node-strip b.off { color: var(--off); }
    .event-row { display: grid; grid-template-columns: 7px 40px 70px minmax(0, 1fr); gap: 9px; min-height: 43px; padding: 7px 0; border-bottom: 1px solid #26394c; font-size: 11px; }
    .event-row time { color: #97adc3; }
    .event-row b { color: #dce9f3; }
    .event-row span:not(.event-dot) { color: #b1c3d3; }
    .event-row i { display: none; }
    .event-dot { background: var(--ok); box-shadow: none; }
    .event-dot.warn { background: var(--amber); }
    .empty-state, .routing-empty { color: #a4b8ca; }
    .reference-game { padding: 16px; margin-bottom: 14px; background: #1d2940; border: 1px solid #405374; border-radius: 7px; }
    .reference-game strong { color: #e4e4fd; font-size: 24px; overflow-wrap: anywhere; }
    .reference-game p { color: #bbc6e1; font-size: 11px; }
    .reference-audit { padding: 10px 0; border-bottom-color: #26394c; color: #c1d0dd; font-size: 11px; }
    .reference-audit time { color: #9fb4ca; }
    .reference-node-grid { grid-template-columns: repeat(auto-fit, minmax(min(100%, 230px), 1fr)); gap: 16px; }
    .reference-node .latency { color: var(--ok); font-size: 22px; margin: 14px 0; }
    .reference-node small { color: #a5bdd0; }
    .badge, .pill { display: inline-block; padding: 3px 8px; font-size: 10px; font-weight: 600; line-height: 1.5; color: #c0d3e5; background: #1c3045; border: 1px solid #39516b; border-radius: 999px; }
    .badge.ok, .pill.ok { background: #123a2f; color: #8ff0c8; border-color: #306552; }
    .badge.warn, .pill.warn { background: #3d3222; color: #ffd69c; border-color: #786044; }
    .badge.off, .pill.off { background: #3b2635; color: #ffb0c0; border-color: #734455; }
    label { margin: 12px 0; color: #c3d2df; font-size: 12px; line-height: 1.55; }
    textarea, input, select { max-width: 100%; min-width: 0; padding: 9px 11px; color: #eaf3fa; background: #0b1828; border: 1px solid #38516b; border-radius: 6px; font: inherit; }
    input:not([type=checkbox]):not([type=radio]):not([type=hidden]), select { min-height: 38px; }
    textarea { min-height: 80px; line-height: 1.55; resize: vertical; }
    input::placeholder, textarea::placeholder { color: #91a7bd; opacity: 1; }
    input[type=checkbox], input[type=radio] { width: 16px; height: 16px; min-height: 0; margin: 0 7px 0 0; padding: 0; vertical-align: -3px; accent-color: #64e9cd; }
    input[type=file] { padding: 7px; overflow: hidden; font-size: 11px; }
    input[type=file]::file-selector-button { padding: 6px 9px; margin-right: 9px; color: #d6ede8; background: #223b42; border: 1px solid #4a6a6d; border-radius: 4px; cursor: pointer; }
    input:focus, textarea:focus, select:focus { border-color: #70e8ce; box-shadow: 0 0 0 3px #64e9cd20; outline: none; }
    :is(a, button, input, textarea, select, summary):focus-visible { outline: 2px solid #a2ffe5; outline-offset: 3px; }
    button, .button, a.button {
      display: inline-flex; align-items: center; justify-content: center; gap: 6px;
      min-height: 36px; max-width: 100%; padding: 8px 12px;
      color: #08251e; background: #64e9cd; border: 1px solid #80eed9;
      border-radius: 6px; box-shadow: none; font: 600 12px/1.45 "Segoe UI", system-ui, sans-serif;
      text-align: center; text-decoration: none; white-space: normal;
      cursor: pointer; transition: background .15s, border-color .15s;
    }
    button:hover, a.button:hover { color: #06231b; background: #91f0db; filter: none; transform: none; text-decoration: none; }
    button.secondary, a.secondary { background: #17293c; color: #c2dfeb; border-color: #3e5a73; box-shadow: none; }
    button.secondary:hover, a.secondary:hover { background: #22394e; color: #e8f8ff; border-color: #64859c; }
    button.danger { background: #412735; color: #ffc0c9; border-color: #885163; }
    button.danger:hover { background: #573041; color: #ffe1e8; border-color: #b47081; }
    button:disabled, input:disabled, select:disabled { opacity: .6; cursor: not-allowed; }
    .actions, .toolbar { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
    .actions input:not([type=hidden]) { flex: 1 1 180px; width: auto; }
    .toolbar input { flex: 1 1 160px; min-width: 0; }
    .panel-content button[aria-busy=true] { opacity: .8; cursor: progress; }
    .panel-content button[aria-busy=true]:after { content: ""; width: 12px; height: 12px; flex: 0 0 12px; border: 2px solid currentColor; border-right-color: transparent; border-radius: 50%; animation: aurora-spin .8s linear infinite; }
    @keyframes aurora-spin { to { transform: rotate(360deg); } }
    .aurora-submit-status { display: block; margin: 8px 0 0; color: #c3e9df; font-size: 11px; }
    .flash { margin: 0 0 18px; padding: 12px 14px; background: #14372e; color: #b5f3d4; border: 1px solid #356a56; border-radius: 8px; }
    .notice { padding: 11px 12px; color: #c3d3e2; background: #13293c; border: 1px solid #35516b; border-radius: 6px; font-size: 12px; }
    .hero code, .card code { color: #b5e5de; overflow-wrap: anywhere; }
    .aurora-table-scroll, .reference-table, .quality-table, .table-wrap { max-width: 100%; overflow: auto; scrollbar-width: thin; scrollbar-color: #3c5970 #0d1b2c; }
    .aurora-table-scroll { margin: 2px 0; border: 1px solid #2a4057; border-radius: 7px; }
    .aurora-table-scroll:focus-visible { outline: 2px solid #8deed6; outline-offset: 3px; }
    table { display: table; width: 100%; max-width: none; margin: 0; color: #c8d8e5; background: #101e30; border: 0; border-radius: 0; border-collapse: collapse; font-size: 11px; line-height: 1.5; white-space: normal; }
    .aurora-table-scroll table { min-width: 480px; }
    .aurora-table-scroll[data-wide=true] table { min-width: 720px; }
    th { padding: 11px 10px; color: #adc3d6; background: #15263a; font-size: 10px; font-weight: 600; text-transform: none; letter-spacing: .01em; white-space: nowrap; border-bottom: 1px solid #30475f; }
    td, .reference-table td { padding: 11px 10px; border-bottom: 1px solid #26394d; vertical-align: middle; overflow-wrap: anywhere; }
    tr:last-child td { border-bottom: 0; }
    tr:hover td { background: #162c40; }
    td .actions { gap: 6px; }
    td button, td a.button { min-height: 30px; padding: 5px 8px; font-size: 10px; }
    .routing-heading { padding: 0 0 16px; gap: 14px; }
    .routing-heading h1 { font-size: 23px !important; margin: 4px 0 !important; }
    .routing-kicker { color: #79d7c4; font-size: 9px; letter-spacing: .1em; }
    .routing-heading p { font-size: 12px; }
    .routing-health { padding-top: 0; }
    .routing-top-grid { grid-template-columns: minmax(0, .92fr) minmax(0, 1.1fr) minmax(0, 1fr); gap: 16px; }
    .routing-card { height: auto; margin: 0 !important; }
    .routing-subtitle, .routing-switch small, .routing-notice p, .scan-result small { color: #a6bace; }
    .route-group { background: #0c1a29; border-color: #2c445b; border-left-color: #7bdcc8; padding: 10px; margin: 10px 0; }
    .route-group.proxy { border-left-color: #7de8b5; } .route-group.direct { border-left-color: #8fc6fb; } .route-group.block { border-left-color: #f5a4b5; }
    .route-group textarea { min-height: 54px; background: #0a1726; }
    .route-group-head span, .route-advanced { color: #a0b8cb; }
    .routing-switch { border-bottom-color: #2c4054; padding: 11px 0; }
    .routing-switch input { flex: 0 0 40px; width: 40px; height: 22px; padding: 0; margin: 3px 0 0; background: #314b60; border-color: #5b768d; }
    .routing-switch input:checked { background: #5ce2b8; border-color: #91f0d1; }
    .routing-switch input:after { background: #e1eaf4; }
    .routing-switch input:checked:after { background: #092b21; }
    .routing-actions { display: flex; flex-wrap: wrap; gap: 8px; padding-top: 16px; }
    .routing-actions button { flex: 1 1 115px; min-width: 0; min-height: 39px; }
    .routing-actions .secondary { color: #c3dfeb; }
    .routing-footer { grid-template-columns: minmax(0, .75fr) minmax(0, 1.25fr); gap: 16px; margin-top: 16px; }
    .routing-revision i { color: #91e8d4; background: #16372f; border-color: #386454; }
    .routing-revision small { color: #a8bccc; }
    .routing-revision b { font-size: 15px; }
    .routing-notice b { color: #d9e7f0; font-size: 12px; }
    .routing-history { margin-top: 16px !important; }
    details summary { color: #bfd5e6; line-height: 1.5; cursor: pointer; }
    .panel-content .quality-page .quality-details { grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 0 16px; }
    .panel-content .quality-page p { color: #b4c7d8; font-size: 12px; line-height: 1.6; }
    .panel-content .quality-page p.warn { color: var(--amber); }
    .panel-content .quality-page p.off { color: var(--off); }
    .panel-content .quality-page p.ok { color: var(--ok); }
    .panel-content .quality-page form { flex-wrap: wrap; gap: 9px; }
    .panel-content .quality-page form label { flex: 1 1 220px; }
    .panel-content .quality-page form button { max-width: 100%; flex-shrink: 1; }
    .panel-content .quality-page .stat { padding: 14px; }
    .panel-content .quality-page .card { margin-bottom: 16px; }
    .panel-content .quality-page .grid .card { margin-bottom: 0; }
    .panel-content .quality-page h2 { font-size: 15px; }
    .quality-protocols { display: flex; flex-wrap: wrap; gap: 6px; margin: 12px 0; }
    .live-log, .logs-card pre { background: #091524 !important; color: #c6e1e7; border-color: #36546b !important; text-shadow: none; font: 12px/1.65 "Cascadia Code", Consolas, monospace; overflow-wrap: anywhere; }
    .aurora-live-dock { min-width: 0; margin-top: 20px; padding: 0; background: #0b1828; border: 1px solid #2b455c; border-radius: 8px; color: #b3cbd9; font-size: 11px; overflow: hidden; }
    .aurora-live-toolbar { display: flex; align-items: center; flex-wrap: wrap; gap: 10px; min-width: 0; padding: 10px 13px; }
    .aurora-live-dock > summary.aurora-live-toolbar { list-style: none; cursor: pointer; }
    .aurora-live-dock > summary.aurora-live-toolbar::-webkit-details-marker { display: none; }
    .aurora-live-dock > summary.aurora-live-toolbar:before { content: "▸"; color: #7bddc7; }
    .aurora-live-dock[open] > summary.aurora-live-toolbar:before { content: "▾"; }
    .aurora-live-toolbar > a, .aurora-live-toolbar > strong { flex: 0 0 auto; font-size: 11px; font-weight: 650; white-space: nowrap; }
    .aurora-live-toolbar .pill { margin-left: auto; }
    .aurora-live-toolbar button { min-height: 28px; padding: 4px 9px; font-size: 10px; background: #162c40; color: #cbe0ec; border-color: #38556e; }
    .aurora-live-toolbar button:hover { background: #254056; color: #e7f9ff; }
    .aurora-live-summary { flex: 1 1 220px; min-width: 0; margin: 0; color: #acc2d3; font-size: 10px; overflow-wrap: anywhere; }
    .aurora-live-dock details { border-top: 1px solid #263d53; }
    .aurora-live-dock summary { padding: 8px 13px; font-size: 10px; color: #a5ccce; }
    .aurora-live-output { max-width: 100%; max-height: 210px; overflow: auto; padding: 12px 13px; margin: 0; background: #081423; border-top: 1px solid #263d53; color: #c5dce5; font: 11px/1.65 "Cascadia Code", Consolas, monospace; white-space: pre-wrap; overflow-wrap: anywhere; scrollbar-width: thin; scrollbar-color: #3b5a70 #081423; }
    .aurora-skip-link { position: fixed; top: 10px; left: 10px; z-index: 100; padding: 10px 14px; color: #08241f; background: #b3ffe9; border-radius: 5px; transform: translateY(-160%); text-decoration: none; }
    .aurora-skip-link:focus { transform: translateY(0); }
    .login { max-width: 450px; padding: 16px; margin: clamp(12px, 8vh, 80px) auto 24px; }
    .login .hero { height: auto; padding: 26px; background: #101e30; border: 1px solid #2b435a; border-radius: 12px; box-shadow: var(--shadow); overflow: visible; }
    .login .hero h1, .login .hero p, .login .hero .accent { display: block; }
    .login .hero h1 { font-size: 24px; margin: 14px 0 6px; }
    .login .hero p { font-size: 12px; line-height: 1.6; }
    .login form { margin-top: 20px; }
    .login button { width: 100%; min-height: 42px; }
    @media (min-width: 1500px) { .panel-shell { grid-template-columns: 226px minmax(0, 1fr); gap: 28px; } }
    @media (max-width: 1250px) {
      main { padding-right: 18px; } .panel-shell { grid-template-columns: 196px minmax(0, 1fr); gap: 18px; }
      .sidebar { padding-left: 9px; padding-right: 9px; }
      .sidebar-brand { padding-left: 38px; font-size: 14px; } .sidebar-brand span { font-size: 8px; }
      .reference-kpi { gap: 9px; } .reference-kpi i { display: none; }
      .reference-kpi b { font-size: 23px; }
      .reference-bottom { grid-template-columns: minmax(0, 1.2fr) minmax(0, 1fr); }
      .reference-bottom > .card:first-child { grid-column: 1 / -1; }
      .routing-top-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .routing-dns { grid-column: 1 / -1; } .routing-dns .routing-actions { max-width: none; }
    }
    @media (max-width: 1040px) {
      .reference-top { grid-template-columns: 1fr; } .reference-map { min-height: 210px; }
      .reference-kpis, .stats { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .reference-kpi i { display: grid; }
      .panel-content > .grid { grid-template-columns: 1fr; }
      .routing-footer { grid-template-columns: 1fr; }
      .top-date { text-align: left; }
      .panel-content .quality-page .quality-details { grid-template-columns: 1fr; }
      .split, .dashboard .split, .topology-layout { grid-template-columns: 1fr; }
    }
    @media (max-width: 760px) {
      main { padding: 12px; } .panel-shell { grid-template-columns: minmax(0, 1fr); gap: 18px; }
      .sidebar { position: static; width: 100%; height: auto; padding: 12px; border: 1px solid #263e53; border-radius: 9px; overflow: visible; }
      .sidebar-brand { display: block; margin: 0 0 9px; padding: 0 0 12px 42px; font-size: 16px; }
      .sidebar-brand span { font-size: 9px; }
      .sidebar nav.tabs { flex-direction: row; align-items: flex-start; flex-wrap: wrap; gap: 7px; }
      .aurora-nav-section { display: contents; }
      .aurora-nav-label { display: none; }
      .sidebar nav.tabs a { flex: 0 1 auto; min-height: 35px; padding: 7px 10px; margin: 0; font-size: 11px; }
      .nav-ico { font-size: 14px; width: 15px; flex-basis: 15px; }
      .nav-group { flex: 1 1 100%; margin: 4px 0 0; padding: 0; }
      .nav-group[open] { display: block; }
      .nav-group summary { padding: 9px 3px; }
      .nav-group a { display: inline-flex !important; margin: 3px !important; padding: 7px 10px !important; }
      .sidebar nav.tabs a[href='/operator/logout'] { margin: 0 0 0 auto; border: 0; padding: 7px 10px; }
      .aurora-logout { margin: 10px 0 0; padding: 9px 8px; font-size: 11px; }
      .panel-content > .hero { min-height: 0; padding: 0 0 14px; margin-bottom: 18px; }
      .control-search { flex-basis: 100%; max-width: none; width: 100%; }
      .hero-top { gap: 10px; } .system-pill { font-size: 10px; } .top-date { margin-left: auto; text-align: right; }
      .reference-heading { margin-bottom: 16px; gap: 10px; } .reference-heading h1 { font-size: 22px; }
      .reference-heading > small { display: none; }
      .reference-kpis, .stats { gap: 10px; } .reference-kpi { min-height: 97px; padding: 13px !important; }
      .reference-kpi i { display: none; } .reference-kpi b { font-size: 22px; }
      .reference-bottom { grid-template-columns: 1fr; } .reference-bottom > .card:first-child { grid-column: auto; }
      .reference-top, .reference-stack, .reference-bottom, .grid { gap: 12px; }
      .card, .dashboard .card, .panel-content .quality-page .card { padding: 15px; border-radius: 8px; }
      .routing-top-grid { grid-template-columns: 1fr; gap: 12px; } .routing-dns { grid-column: auto; }
      .routing-heading { flex-direction: column; } .routing-heading h1 { font-size: 21px !important; }
      .routing-health { padding: 0; } .routing-footer { gap: 12px; }
      .event-row { grid-template-columns: 7px 38px 60px minmax(0, 1fr); gap: 7px; }
      .aurora-subnav { margin: -3px 0 16px; padding-bottom: 12px; }
      .aurora-live-dock { margin-top: 16px; }
      .aurora-live-toolbar { padding: 10px 12px; }
      .aurora-live-summary { flex-basis: 100%; order: 3; }
      .login { padding: 0; margin: 12px auto; } .login .hero { padding: 20px; }
    }
    @media (max-width: 390px) {
      main { padding: 9px; } .sidebar { padding: 10px; }
      .sidebar nav.tabs a { gap: 5px; padding: 7px 8px; }
      .reference-kpis, .stats { grid-template-columns: 1fr; }
      .reference-kpi { min-height: 83px; } .reference-kpi i { display: grid; }
      .top-date { margin-left: 0; text-align: left; } .card { padding: 13px; }
      .actions > button, .actions > a.button { flex: 1 1 auto; }
    }
    /* Keep the overview useful on laptop displays. Records remain accessible
       in local scroll areas; other tabs retain their regular form spacing. */
    @media (min-width: 1100px) and (max-height: 900px) {
      .panel-content:has(> .dashboard:not([style*="display:none"])) > .hero {
        min-height: 54px; padding: 9px 0; margin-bottom: 12px;
      }
      .panel-content:has(> .dashboard:not([style*="display:none"])) > .reference-heading {
        margin-bottom: 10px; gap: 12px;
      }
      .panel-content:has(> .dashboard:not([style*="display:none"])) > .reference-heading h1 {
        font-size: 23px; margin-bottom: 3px;
      }
      .panel-content:has(> .dashboard:not([style*="display:none"])) > .reference-heading p {
        font-size: 11px;
      }
      .panel-content:has(> .dashboard:not([style*="display:none"])) > .aurora-subnav {
        margin: 0 0 12px; padding-bottom: 9px; gap: 6px;
      }
      .panel-content:has(> .dashboard:not([style*="display:none"])) > .aurora-subnav a {
        min-height: 28px; padding: 4px 9px;
      }
      .dashboard:not([style*="display:none"]) .reference-kpis {
        gap: 11px; margin-bottom: 12px;
      }
      .dashboard:not([style*="display:none"]) .reference-kpi {
        min-height: 84px; padding: 12px 14px !important;
      }
      .dashboard:not([style*="display:none"]) .reference-kpi b {
        margin: 3px 0; font-size: 23px;
      }
      .dashboard:not([style*="display:none"]) .reference-kpi i {
        width: 32px; height: 34px; flex-basis: 32px; font-size: 18px;
      }
      .dashboard:not([style*="display:none"]) .card { padding: 12px 14px; }
      .dashboard:not([style*="display:none"]) .section-head {
        gap: 6px; margin-bottom: 9px;
      }
      .dashboard:not([style*="display:none"]) h2 { font-size: 13px; }
      .dashboard:not([style*="display:none"]) .reference-top {
        gap: 12px; margin-bottom: 12px;
      }
      .dashboard:not([style*="display:none"]) .reference-map {
        min-height: 0; height: clamp(150px, 20vh, 180px);
      }
      .dashboard:not([style*="display:none"]) .reference-map svg {
        height: 100%; max-height: 180px;
      }
      .dashboard:not([style*="display:none"]) .reference-map-note {
        margin-top: 7px; font-size: 10px; line-height: 1.5;
      }
      .dashboard:not([style*="display:none"]) .reference-node-strip {
        margin-top: 8px; gap: 5px; max-height: 54px; overflow: auto;
        scrollbar-width: thin; scrollbar-color: #3c5970 #0d1b2c;
      }
      .dashboard:not([style*="display:none"]) .reference-node-strip span {
        padding: 3px 7px; font-size: 10px;
      }
      .dashboard:not([style*="display:none"]) .event-list {
        max-height: 206px; overflow: auto;
        scrollbar-width: thin; scrollbar-color: #3c5970 #0d1b2c;
      }
      .dashboard:not([style*="display:none"]) .event-row {
        min-height: 35px; padding: 5px 0; font-size: 10px;
      }
      .dashboard:not([style*="display:none"]) .reference-bottom {
        grid-template-columns: minmax(0, 1.4fr) minmax(0, .9fr) minmax(0, .9fr);
        gap: 12px;
      }
      .dashboard:not([style*="display:none"]) .reference-bottom > .card:first-child {
        grid-column: auto;
      }
      .dashboard:not([style*="display:none"]) .reference-bottom .aurora-table-scroll {
        max-height: 190px;
      }
      .dashboard:not([style*="display:none"]) .reference-bottom table { min-width: 0; }
      .dashboard:not([style*="display:none"]) .reference-bottom th,
      .dashboard:not([style*="display:none"]) .reference-bottom td {
        padding: 7px 8px;
      }
      .dashboard:not([style*="display:none"]) .reference-stack { gap: 12px; }
      .dashboard:not([style*="display:none"]) .reference-bottom p {
        margin: 6px 0; font-size: 11px; line-height: 1.5;
      }
      .dashboard:not([style*="display:none"]) .reference-game {
        padding: 12px; margin-bottom: 10px;
      }
      .dashboard:not([style*="display:none"]) .reference-game strong { font-size: 22px; }
      .dashboard:not([style*="display:none"]) .reference-game .button { min-height: 28px; padding: 4px 8px; }
      .dashboard:not([style*="display:none"]) .reference-bottom > .card > .stat {
        display: flex; align-items: center; justify-content: space-between; padding: 7px 10px;
      }
      .dashboard:not([style*="display:none"]) .reference-bottom > .card > .stat b { margin: 0; font-size: 18px; }
      .dashboard:not([style*="display:none"]) .reference-bottom > .card > p.muted { margin-bottom: 0; font-size: 10px; }
      .dashboard:not([style*="display:none"]) .reference-stack > .card { max-height: 180px; overflow: auto; }
      .dashboard:not([style*="display:none"]) .reference-game a.button {
        min-height: 31px; padding: 6px 9px; font-size: 11px;
      }
      .dashboard:not([style*="display:none"]) .reference-bottom .stat { padding: 9px 10px; }
      .dashboard:not([style*="display:none"]) .reference-bottom .stat b { font-size: 20px; }
      .dashboard:not([style*="display:none"]) .reference-audit {
        padding: 6px 0; font-size: 10px;
      }
      .panel-content:has(> .dashboard:not([style*="display:none"])) > .aurora-live-dock {
        margin-top: 12px;
      }
      .panel-content:has(> .dashboard:not([style*="display:none"])) > .aurora-live-dock > summary {
        padding: 8px 12px;
      }
    }
    @media (prefers-reduced-motion: reduce) {
      *, *:before, *:after { scroll-behavior: auto !important; transition: none !important; animation: none !important; }
    }
    """


def aurora_script() -> str:
    """Return accessible DOM enhancements; all real forms submit normally."""
    return r"""<script>
    (() => {
      'use strict';
      const start = () => {
        const panel = document.querySelector('.panel-content');
        if (!panel || panel.dataset.auroraReady === 'true') return;
        panel.dataset.auroraReady = 'true';
        panel.id = panel.id || 'aurora-content';
        panel.tabIndex = -1;
        const skip = document.createElement('a');
        skip.className = 'aurora-skip-link';
        skip.href = '#' + panel.id;
        skip.textContent = 'К содержимому';
        document.body.prepend(skip);

        const nav = document.querySelector('.sidebar nav.tabs');
        if (nav) {
          nav.setAttribute('aria-label', 'Разделы панели');
          nav.querySelectorAll('.nav-ico').forEach(icon => icon.setAttribute('aria-hidden', 'true'));
        }

        const search = panel.querySelector('.control-search input[name=q]');
        if (search) {
          search.setAttribute('aria-keyshortcuts', 'Control+k Meta+k');
          search.setAttribute('title', 'Поиск пользователей · Ctrl+K');
          document.addEventListener('keydown', event => {
            if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
              event.preventDefault();
              search.focus();
              search.select();
            }
          });
        }

        const tableWatches = new Map();
        const wrapTables = scope => {
          // A replaced overview no longer needs its old observers or listeners.
          // Existing wrappers are skipped, so each keeps exactly one observer.
          tableWatches.forEach((cleanup, container) => {
            if (!panel.contains(container)) {
              cleanup();
              tableWatches.delete(container);
            }
          });
          if (!scope) return;
          scope.querySelectorAll('table').forEach(table => {
            if (table.parentElement.classList.contains('aurora-table-scroll')) return;
            const container = document.createElement('div');
            container.className = 'aurora-table-scroll';
            container.dataset.wide = String(Array.from(table.rows).some(row => row.cells.length >= 5));
            table.before(container);
            container.append(table);
            const card = table.closest('.card');
            const title = card && card.querySelector('h2, summary');
            container.setAttribute('role', 'region');
            container.setAttribute('aria-label', title ? title.textContent.trim() + ' — таблица' : 'Данные раздела');
            // Both horizontal and compact-overview vertical scroll regions must
            // remain reachable without adding a tab stop to every short table.
            const updateScroll = () => {
              if (container.scrollWidth > container.clientWidth + 1 || container.scrollHeight > container.clientHeight + 1) container.tabIndex = 0;
              else container.removeAttribute('tabindex');
            };
            updateScroll();
            let observer = null;
            if ('ResizeObserver' in window) {
              observer = new ResizeObserver(updateScroll);
              observer.observe(container);
            } else {
              window.addEventListener('resize', updateScroll);
            }
            const disclosure = container.closest('details');
            if (disclosure) disclosure.addEventListener('toggle', updateScroll);
            tableWatches.set(container, () => {
              if (observer) observer.disconnect();
              else window.removeEventListener('resize', updateScroll);
              if (disclosure) disclosure.removeEventListener('toggle', updateScroll);
            });
          });
        };
        wrapTables(panel);
        panel.addEventListener('aurora:refresh', () => wrapTables(panel.querySelector('.dashboard')));

        const flash = panel.querySelector('.flash');
        if (flash) { flash.setAttribute('role', 'status'); flash.setAttribute('aria-live', 'polite'); }
        const pill = document.getElementById('system-pill');
        if (pill && pill.textContent.includes('Есть открытые')) pill.classList.add('off');

        // Visual feedback follows a valid native submit. Do not disable buttons:
        // their name/value and external form associations are part of the request.
        document.addEventListener('submit', event => {
          const form = event.target;
          if (!(form instanceof HTMLFormElement) || !panel.contains(form)) return;
          const submitter = event.submitter;
          const method = ((submitter && submitter.getAttribute('formmethod')) || form.method || 'get').toLowerCase();
          if (method !== 'post' || event.defaultPrevented) return;
          if (!form.noValidate && !(submitter && submitter.formNoValidate) && !form.checkValidity()) return;
          queueMicrotask(() => {
            if (event.defaultPrevented) return;
            form.classList.add('aurora-submitting');
            form.setAttribute('aria-busy', 'true');
            if (submitter) submitter.setAttribute('aria-busy', 'true');
            let status = form.querySelector('.aurora-submit-status');
            if (!status) {
              status = document.createElement('span');
              status.className = 'aurora-submit-status';
              status.setAttribute('role', 'status');
              form.append(status);
            }
            status.textContent = 'Запрос отправляется…';
          });
        });
        window.addEventListener('pageshow', () => {
          document.querySelectorAll('.aurora-submitting').forEach(form => {
            form.classList.remove('aurora-submitting');
            form.removeAttribute('aria-busy');
            form.querySelectorAll('[aria-busy=true]').forEach(button => button.removeAttribute('aria-busy'));
            document.querySelectorAll('[form]').forEach(button => {
              if (button.form === form) button.removeAttribute('aria-busy');
            });
            const status = form.querySelector('.aurora-submit-status');
            if (status) status.remove();
          });
        });

      };
      if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start, {once: true});
      else start();
    })();
    </script>"""
