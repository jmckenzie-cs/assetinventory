#!/usr/bin/env python3
"""
CrowdStrike Falcon — Executive Asset Inventory Report (HTML)
Generates a self-contained HTML report from a falcon_hosts_inventory_*.json file.

Usage:
    python3 generate_report.py [inventory.json] [output.html]
"""
import json, sys, os, glob, math
from datetime import datetime, timezone
from collections import Counter

# ── PALETTE ────────────────────────────────────────────────────
RED    = '#C8001A'
ORANGE = '#D96A00'
GREEN  = '#007A4B'
CYAN   = '#0090B0'
DARK   = '#0D1520'
GREY1  = '#1E2B3C'
GREY2  = '#3A4A60'
GREY3  = '#6A7A99'
GREY4  = '#A0AABA'
GREY5  = '#D0D6E0'
GREY6  = '#F0F2F5'

# ── UTILITIES ──────────────────────────────────────────────────
def _rc(pct):
    return RED if pct < 40 else (ORANGE if pct < 70 else GREEN)

def _fmt(n):
    try: return f"{int(n):,}"
    except: return str(n)

def _pct(part, total):
    if not total: return '—'
    return f"{part/total*100:.1f}%"

def _format_ts(ts):
    if not ts: return ''
    try:
        dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
        return dt.strftime('%Y-%m-%d %H:%M UTC')
    except:
        if len(ts) >= 16 and 'T' in ts:
            return f"{ts[0:4]}-{ts[4:6]}-{ts[6:8]} {ts[9:11]}:{ts[11:13]} UTC"
    return ts

def _compute_container_status(hosts):
    _CP = {'AWS_EKS_FARGATE', 'AZURE_CONTAINER_APPS', 'AWS_ECS_FARGATE'}
    c = {'container': 0, 'k8s_node': 0, 'none': 0}
    for h in hosts:
        pt = h.get('product_type_desc', '')
        dt = h.get('deployment_type', '')
        sp = h.get('service_provider', '')
        tags = ' '.join(h.get('tags') or []).lower()
        if pt == 'Pod' or sp in _CP:
            c['container'] += 1
        elif (pt == 'Kubernetes Cluster' or dt == 'DaemonSet' or h.get('pod_namespace')
              or 'k8s-worker' in tags or 'k8s-master' in tags or 'cluster/' in tags):
            c['k8s_node'] += 1
        else:
            c['none'] += 1
    return c

def _container_hint(r):
    provider = (r.get('cloud_provider') or '').upper()
    resource = (r.get('cloud_resource_id') or '').lower()
    hostname = (r.get('hostname') or '').lower()
    os_ver   = (r.get('os_version') or '').lower()
    if any(x in resource for x in ('ecs','eks','fargate','container','/pods/','task')):
        return 'likely'
    if any(x in hostname for x in ('fargate','ecs','eks','.k8s.','pod','container')):
        return 'likely'
    if any(x in os_ver for x in ('cos ','coreos','bottlerocket','talos','alpine')):
        return 'likely'
    if provider in ('AWS','AZURE','GCP') and r.get('platform_name') == 'Linux':
        return 'possible'
    return '—'

def _recommendations(coverage, unmanaged, unsupported, managed, by_status, gap_by_plat, k8s_total):
    recs = []
    if coverage < 40:
        recs.append(('CRITICAL', 'Expand Falcon Sensor Coverage Immediately',
            f"Coverage is at {coverage:.0f}%, well below the recommended 95%+ threshold. "
            f"{_fmt(unmanaged)} sensor-eligible assets have no protection. "
            f"Prioritize deployment to Windows and Linux servers in the unmanaged gap list."))
    elif coverage < 70:
        recs.append(('HIGH', 'Improve Sensor Coverage',
            f"Coverage at {coverage:.0f}% leaves {_fmt(unmanaged)} assets unprotected. "
            f"Target 95%+ coverage by reviewing and deploying sensors to unmanaged assets."))
    contained = (by_status or {}).get('contained', 0)
    if contained:
        recs.append(('HIGH', f'Investigate {_fmt(contained)} Contained Hosts',
            f"{_fmt(contained)} managed hosts are in network containment, indicating active incident response. "
            f"Ensure each containment is intentional and that remediation is in progress."))
    top_gap = sorted(gap_by_plat.items(), key=lambda x:-x[1])[:1] if gap_by_plat else []
    if top_gap:
        plat, cnt = top_gap[0]
        recs.append(('MEDIUM', f'Address {plat} Sensor Gap ({_fmt(cnt)} assets)',
            f"{plat} has the largest unmanaged asset count ({_fmt(cnt)} devices). "
            f"Review deployment blockers (group policy, packaging, connectivity) and create a remediation plan."))
    if unsupported > 1000:
        recs.append(('MEDIUM', 'Implement Compensating Controls for Unsupported Devices',
            f"{_fmt(unsupported)} devices cannot run the Falcon sensor. "
            f"Segment these on isolated network zones, apply stricter firewall rules, "
            f"and consider third-party IoT security monitoring."))
    if k8s_total:
        recs.append(('LOW', 'Validate Kubernetes Coverage Completeness',
            f"{_fmt(k8s_total)} Kubernetes pods have the sensor. "
            f"Verify this matches expected pod counts across all namespaces and clusters. "
            f"New deployments may not automatically inherit sensor coverage."))
    return recs

# ── HTML COMPONENTS ────────────────────────────────────────────
def _gauge(pct, size=130):
    r = int(size * 0.37)
    circ = 2 * math.pi * r
    filled = (min(max(pct, 0), 100) / 100) * circ
    color = _rc(pct)
    cx = cy = size // 2
    return (
        f'<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}">'
        f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{GREY5}" stroke-width="12"/>'
        f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{color}" stroke-width="12"'
        f' stroke-dasharray="{filled:.2f} {circ:.2f}" transform="rotate(-90 {cx} {cy})"'
        f' stroke-linecap="round"/>'
        f'<text x="{cx}" y="{cy+9}" text-anchor="middle"'
        f' font-family="system-ui,sans-serif" font-size="{int(size*0.18)}" font-weight="700" fill="{color}">{pct:.0f}%</text>'
        f'<text x="{cx}" y="{cy+int(size*0.2)}" text-anchor="middle"'
        f' font-family="system-ui,sans-serif" font-size="{int(size*0.073)}" fill="{GREY3}" letter-spacing="1">COVERAGE</text>'
        f'</svg>'
    )

def _stat_grid(items, cols=4):
    cards = ''.join(
        f'<div class="sc"><div class="sc-v" style="color:{c}">{v}</div>'
        f'<div class="sc-l">{l}</div></div>'
        for l, v, c in items
    )
    return f'<div class="stat-grid" style="grid-template-columns:repeat({cols},1fr)">{cards}</div>'

def _bar(label, count, total, color, truncate=40):
    p = (count / total * 100) if total else 0
    safe_label = str(label)[:truncate]
    return (
        f'<div class="br"><span class="br-l" title="{label}">{safe_label}</span>'
        f'<span class="br-n">{_fmt(count)}</span>'
        f'<div class="br-t"><div class="br-f" style="width:{p:.1f}%;background:{color}"></div></div>'
        f'</div>'
    )

def _rank(title, items, total, color, max_rows=10):
    rows = ''.join(_bar(k, v, total, color) for k, v in list(items)[:max_rows])
    return f'<div class="rank"><div class="rank-hd">{title}</div>{rows}</div>'

def _sh(num, title, color=RED):
    return (
        f'<div class="sh" style="border-color:{color}">'
        f'<span class="sh-n" style="color:{color}">{num:02d}</span>'
        f'<span class="sh-t">{title.upper()}</span>'
        f'</div>'
    )

def _callout(title, body, color):
    bg = color + '15'
    return (
        f'<div class="callout" style="border-color:{color};background:{bg}">'
        f'<div class="callout-t" style="color:{color}">{title}</div>'
        f'<div class="callout-b">{body}</div>'
        f'</div>'
    )

def _badge(label, color):
    return f'<span class="badge" style="background:{color};color:white">{label}</span>'

def _api_panel(apis, logic_items, fql=None, conflicts=None):
    """
    apis       : list[str]  — API service.method names
    logic_items: list[str]  — logic/calculation bullets (may include inline HTML)
    fql        : str|None   — FQL filter to show in monospace
    conflicts  : list[str]  — known count conflicts/discrepancies between APIs
    """
    apis_html = ''.join(f'<li><strong>{a}</strong></li>' for a in apis)
    logic_html = ''.join(f'<li>{l}</li>' for l in logic_items)
    fql_html = (
        f'<div style="margin-top:8px"><h4>FQL Filter</h4>'
        f'<span class="api-fql">{fql}</span></div>'
    ) if fql else ''
    conflict_html = ''
    if conflicts:
        items = ''.join(f'<li>{c}</li>' for c in conflicts)
        conflict_html = (
            f'<div class="api-conflict">'
            f'<h4>&#9888; Known Count Conflicts</h4>'
            f'<ul>{items}</ul>'
            f'</div>'
        )
    tag = f'<span class="api-tag">{len(apis)} API{"s" if len(apis)>1 else ""}</span>'
    return (
        f'<details class="api-panel">'
        f'<summary>{tag} &nbsp; API &amp; Data Sources</summary>'
        f'<div class="api-panel-body">'
        f'<div class="api-panel-col"><h4>APIs Called</h4><ul>{apis_html}</ul></div>'
        f'<div class="api-panel-col"><h4>Logic &amp; Calculations</h4>'
        f'<ul>{logic_html}</ul>{fql_html}</div>'
        f'{conflict_html}'
        f'</div></details>'
    )

def _legend(terms):
    """
    terms: list of (term, definition) tuples — rendered as an always-visible
           inline legend bar directly below the section header.
    """
    items = ''.join(
        f'<span class="legend-item">'
        f'<span class="legend-term">{t}</span>'
        f'<span class="legend-sep">—</span>'
        f'<span class="legend-def">{d}</span>'
        f'</span>'
        for t, d in terms
    )
    return f'<div class="legend">{items}</div>'

def _glossary(terms):
    """
    terms: list of (term, definition) — rendered as a two-column definition
           grid inside a collapsible panel, intended for the cover page.
    """
    rows = ''.join(
        f'<div class="glossary-row">'
        f'<span class="glossary-term">{t}</span>'
        f'<span class="glossary-def">{d}</span>'
        f'</div>'
        for t, d in terms
    )
    return (
        f'<details class="glossary">'
        f'<summary>&#128218; &nbsp; Key Terms &amp; Acronyms</summary>'
        f'<div class="glossary-body">{rows}</div>'
        f'</details>'
    )

def _table(headers, rows, col_align=None, row_classes=None):
    ths = ''.join(f'<th>{h}</th>' for h in headers)
    tbody = ''
    for i, row in enumerate(rows):
        rc = (row_classes[i] if row_classes else '') + (' alt' if i % 2 else '')
        tds = ''.join(
            f'<td style="text-align:{(col_align or {}).get(j,"left")}">{cell}</td>'
            for j, cell in enumerate(row)
        )
        tbody += f'<tr class="{rc.strip()}">{tds}</tr>'
    return f'<table class="dt"><thead><tr>{ths}</tr></thead><tbody>{tbody}</tbody></table>'

def _rec(priority, title, body):
    pc = RED if priority == 'CRITICAL' else (ORANGE if priority == 'HIGH' else (CYAN if priority == 'MEDIUM' else GREY3))
    return (
        f'<div class="rec" style="border-color:{pc}">'
        f'<div class="rec-p" style="color:{pc};border-color:{pc}">{priority}</div>'
        f'<div class="rec-t">{title}</div>'
        f'<div class="rec-b">{body}</div>'
        f'</div>'
    )

# ── CSS ────────────────────────────────────────────────────────
CSS = """
*{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;font-size:14px;color:#1E2B3C;background:#EAECF0;line-height:1.5}

/* NAV */
.nav{position:sticky;top:0;z-index:200;background:#0D1520;display:flex;align-items:center;justify-content:space-between;padding:10px 28px;border-bottom:3px solid #C8001A;print-color-adjust:exact}
.nav-brand{color:white;font-size:15px;font-weight:700;display:flex;align-items:center;gap:10px;letter-spacing:.3px}
.nav-links{display:flex;gap:4px}
.nav-links a{color:#A0AABA;text-decoration:none;font-size:11px;padding:4px 10px;border-radius:4px;transition:all .15s}
.nav-links a:hover{color:white;background:#1E2B3C}

/* COVER */
.cover{background:white;margin:20px auto;max-width:1200px;border-radius:8px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,.12)}
.cover-hdr{background:#0D1520;padding:22px 32px;display:flex;align-items:center;justify-content:space-between;border-top:4px solid #C8001A}
.cover-brand{display:flex;align-items:center;gap:14px}
.brand-nm{color:white;font-size:21px;font-weight:700;letter-spacing:.3px}
.brand-sb{color:#A0AABA;font-size:13px;margin-top:3px}
.cover-meta{color:#6A7A99;font-size:11px;text-align:right}
.cover-body{padding:28px 32px}
.exec-sum{color:#3A4A60;font-size:13px;line-height:1.75;margin-bottom:24px;max-width:900px}

/* STAT GRID */
.stat-grid{display:grid;gap:12px;margin-bottom:24px}
.sc{background:#F0F2F5;border-radius:6px;padding:14px 16px;border:1px solid #D0D6E0}
.sc-v{font-size:28px;font-weight:700;line-height:1;margin-bottom:5px}
.sc-l{font-size:10px;color:#6A7A99;text-transform:uppercase;letter-spacing:.7px}

/* GAUGE ROW */
.gauge-row{display:flex;align-items:center;gap:24px;margin-top:8px}
.gauge-wrap{flex-shrink:0}
.callout{flex:1;padding:18px 22px;border-radius:6px;border:1.5px solid}
.callout-t{font-size:18px;font-weight:700;margin-bottom:6px;display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.callout-b{font-size:13px;color:#3A4A60}
.badge{display:inline-block;padding:2px 10px;border-radius:12px;font-size:11px;font-weight:700;vertical-align:middle}

/* SECTIONS */
section{background:white;margin:0 auto 20px;max-width:1200px;padding:28px 32px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,.07)}
.sh{display:flex;align-items:center;gap:12px;padding:12px 16px;background:#F0F2F5;border-left:4px solid;border-radius:4px;margin-bottom:22px}
.sh-n{font-size:10px;font-weight:700;letter-spacing:1.5px}
.sh-t{font-size:13px;font-weight:700;color:#0D1520;letter-spacing:.5px}

/* TWO-COL */
.two-col{display:grid;grid-template-columns:1fr 1fr;gap:28px;margin-bottom:20px;align-items:start}

/* TYPOGRAPHY */
.lead{font-size:13px;color:#1E2B3C;margin-bottom:16px}
.note{font-size:11px;color:#6A7A99;margin-top:8px;margin-bottom:16px;line-height:1.6}
.sub-t{font-size:11px;font-weight:700;color:#0D1520;text-transform:uppercase;letter-spacing:.7px;margin:22px 0 10px;padding-bottom:6px;border-bottom:1px solid #D0D6E0}

/* RANK BARS */
.rank{min-width:0}
.rank-hd{font-size:10px;font-weight:700;color:#6A7A99;text-transform:uppercase;letter-spacing:.7px;margin-bottom:8px}
.br{display:flex;align-items:center;gap:8px;padding:5px 0;border-bottom:1px solid #F0F2F5;font-size:12px}
.br-l{flex:1;color:#3A4A60;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0}
.br-n{font-weight:700;color:#0D1520;min-width:44px;text-align:right;font-size:12px;flex-shrink:0}
.br-t{width:110px;height:8px;background:#D0D6E0;border-radius:4px;overflow:hidden;flex-shrink:0}
.br-f{height:100%;border-radius:4px;transition:width .3s}

/* DATA TABLE */
.dt{width:100%;border-collapse:collapse;font-size:12px}
.dt thead tr{background:#0D1520}
.dt thead th{padding:9px 11px;font-weight:700;font-size:11px;color:white;text-align:left;white-space:nowrap}
.dt tbody td{padding:8px 11px;border-bottom:1px solid #F0F2F5;vertical-align:middle}
.dt tbody tr.alt td{background:#F8F9FB}
.dt tbody tr:hover td{background:#EEF4FF}
.chip-g{display:inline-block;padding:2px 8px;border-radius:3px;font-size:11px;background:#E0F4EC;color:#007A4B;font-weight:600}
.chip-o{display:inline-block;padding:2px 8px;border-radius:3px;font-size:11px;background:#FFF3E0;color:#D96A00;font-weight:600}
.chip-c{display:inline-block;padding:2px 8px;border-radius:3px;font-size:11px;background:#E0F4F8;color:#0090B0;font-weight:600}
.mono{font-family:'SF Mono',Consolas,monospace;font-size:11px}

/* ALERT */
.alert{background:#FFE5E8;color:#C8001A;padding:10px 16px;border-radius:4px;border-left:3px solid #C8001A;font-size:13px;margin:16px 0}

/* RECOMMENDATIONS */
.recs{display:flex;flex-direction:column;gap:10px}
.rec{padding:14px 16px 14px 18px;border-left:4px solid;background:#F8F9FB;border-radius:4px}
.rec-p{display:inline-block;font-size:10px;font-weight:700;letter-spacing:1px;padding:2px 9px;border:1px solid;border-radius:10px;margin-bottom:7px}
.rec-t{font-size:13px;font-weight:700;color:#0D1520;margin-bottom:4px}
.rec-b{font-size:12px;color:#3A4A60;line-height:1.65}

/* APPENDIX */
.app-scroll{overflow-x:auto;border-radius:4px}
.app-table{font-size:11px}
.app-table td{padding:6px 9px}
.app-table th{padding:8px 9px;font-size:10px}
tr.cloud-row td{background:#FFF3E0!important}
tr.cloud-row.alt td{background:#FFE8C6!important}

/* EXPORT BUTTON */
.export-btn{display:inline-flex;align-items:center;gap:6px;padding:5px 12px;font-size:11px;font-weight:600;color:#0090B0;background:white;border:1.5px solid #0090B0;border-radius:4px;cursor:pointer;text-decoration:none;transition:all .15s;float:right;margin-top:-2px}
.export-btn:hover{background:#0090B0;color:white}
@media print{.export-btn{display:none}}

/* FOOTER */
footer{text-align:center;padding:20px;color:#A0AABA;font-size:11px;border-top:1px solid #D0D6E0;margin:0 auto;max-width:1200px}

/* CSA DETAILS */
.csa-details{margin-top:4px;margin-bottom:2px}
.csa-details summary{cursor:pointer;font-size:12px;font-weight:700;color:#0090B0;padding:5px 0;user-select:none;list-style:none}
.csa-details summary::-webkit-details-marker{display:none}
.csa-details summary::before{content:"▸ ";font-size:10px}
details[open].csa-details summary::before{content:"▾ "}
.csa-details .dt{margin-top:6px;margin-bottom:8px}

/* API CALLOUT PANEL */
.api-panel{margin:0 0 16px 0;border-radius:4px;border:1px solid #3A4A60;background:#131F2E}
.api-panel summary{
  cursor:pointer;display:flex;align-items:center;gap:8px;
  padding:7px 14px;font-size:11px;font-weight:700;color:#0090B0;
  letter-spacing:.4px;text-transform:uppercase;user-select:none;list-style:none
}
.api-panel summary::-webkit-details-marker{display:none}
.api-panel summary::before{content:"▸ ";font-size:10px;color:#6A7A99}
details[open].api-panel summary::before{content:"▾ ";color:#0090B0}
.api-panel summary .api-tag{
  display:inline-block;padding:1px 7px;border-radius:3px;
  font-size:10px;font-weight:700;background:#0090B015;
  color:#0090B0;border:1px solid #0090B040;letter-spacing:.2px
}
.api-panel-body{
  padding:10px 16px 14px;border-top:1px solid #1E2B3C;
  display:grid;grid-template-columns:1fr 1fr;gap:12px 24px
}
.api-panel-col h4{
  font-size:10px;font-weight:700;color:#6A7A99;text-transform:uppercase;
  letter-spacing:.7px;margin:0 0 6px
}
.api-panel-col ul{margin:0;padding:0 0 0 14px}
.api-panel-col li{font-size:11px;color:#A0AABA;line-height:1.7;margin:0}
.api-panel-col li strong{color:#D0D6E0}
.api-fql{
  font-family:'SF Mono',Consolas,monospace;font-size:10px;
  background:#0D1520;color:#7EC8D8;padding:2px 6px;border-radius:3px
}
.api-conflict{
  grid-column:1/-1;margin-top:8px;padding:8px 12px;
  border-radius:4px;border-left:3px solid #E8A030;background:#E8A03010
}
.api-conflict h4{color:#E8A030;margin:0 0 5px}
.api-conflict ul{margin:0;padding:0 0 0 14px}
.api-conflict li{font-size:11px;color:#C0A070;line-height:1.7}
@media print{.api-panel{display:none}}

/* TERM LEGEND */
.legend{display:flex;flex-wrap:wrap;gap:6px 10px;margin:0 0 18px 0;padding:10px 14px;
  background:#131F2E;border:1px solid #1E2B3C;border-radius:4px}
.legend-item{display:flex;align-items:baseline;gap:5px;font-size:11px;line-height:1.4}
.legend-term{font-weight:700;color:#D0D6E0;white-space:nowrap}
.legend-sep{color:#3A4A60;font-size:10px}
.legend-def{color:#A0AABA}
.legend-item+.legend-item::before{content:"";display:inline-block;
  width:1px;height:11px;background:#2A3A50;margin-right:4px;align-self:center}
@media print{.legend{background:white;border-color:#ccc}
  .legend-term{color:#111}.legend-def{color:#555}.legend-item+.legend-item::before{background:#bbb}}

/* GLOSSARY PANEL */
.glossary{margin:16px 0 0;border-radius:4px;border:1px solid #D0D6E0;background:#F8F9FB}
.glossary summary{
  cursor:pointer;display:flex;align-items:center;gap:8px;
  padding:8px 14px;font-size:11px;font-weight:700;color:#3A4A60;
  letter-spacing:.4px;text-transform:uppercase;user-select:none;list-style:none
}
.glossary summary::-webkit-details-marker{display:none}
.glossary summary::before{content:"▸ ";font-size:10px;color:#6A7A99}
details[open].glossary summary::before{content:"▾ ";color:#0090B0}
.glossary-body{
  padding:12px 16px 16px;border-top:1px solid #D0D6E0;
  display:grid;grid-template-columns:1fr 1fr;gap:4px 32px
}
.glossary-row{display:flex;gap:8px;padding:4px 0;border-bottom:1px solid #F0F2F5;align-items:baseline}
.glossary-row:last-child{border-bottom:none}
.glossary-term{font-size:11px;font-weight:700;color:#0D1520;white-space:nowrap;min-width:110px;flex-shrink:0}
.glossary-def{font-size:11px;color:#3A4A60;line-height:1.5}
@media print{.glossary{display:none}}

/* PAGE BREAK */
.pb{display:none}

/* PRINT */
@media print{
  body{background:white;font-size:11px}
  .nav{display:none}
  .cover,.section,section{max-width:100%;margin:0;border-radius:0;box-shadow:none;padding:20px 24px}
  .pb{display:block;break-after:page}
  .stat-grid{grid-template-columns:repeat(4,1fr)}
  .sc-v{font-size:20px}
  .app-table{font-size:9px}
  .app-table td,.app-table th{padding:3px 6px}
  .gauge-row{break-inside:avoid}
  .rec{break-inside:avoid}
}
"""

# ── BUILD ──────────────────────────────────────────────────────
def build_html(json_path, out_path):
    print(f"Loading {json_path}…")
    with open(json_path) as f:
        data = json.load(f)

    meta       = data.get('_meta', {})
    h_sum      = data.get('host_summary', {})
    cl_sum     = data.get('cloud_summary', {})
    k8s_sum    = data.get('kubernetes_summary', {})
    cov_sum    = data.get('coverage_summary', {})
    disc_hosts = data.get('discover_hosts', [])
    gaps       = data.get('coverage_gaps', {})
    raw_hosts  = data.get('hosts', [])
    csa_cov    = data.get('csa_coverage', {})

    csc = h_sum.get('by_container_status') or _compute_container_status(raw_hosts)
    container_hosts = csc.get('container', 0)
    k8s_node_hosts  = csc.get('k8s_node', 0)

    state_counts  = Counter(h.get('state','unknown') for h in data.get('online_state',[]))
    online_count  = state_counts.get('online', 0)
    offline_count = state_counts.get('offline', 0)

    now = datetime.now(timezone.utc)
    age_bkts = {'&lt; 24h':0,'1–7 days':0,'8–30 days':0,'31–90 days':0,'&gt; 90 days':0}
    for h in raw_hosts:
        ls = h.get('last_seen')
        if not ls: continue
        try:
            seen = datetime.fromisoformat(ls.replace('Z','+00:00'))
            if seen.tzinfo is None: seen = seen.replace(tzinfo=timezone.utc)
            age = (now - seen).days
            if   age < 1:  age_bkts['&lt; 24h'] += 1
            elif age < 7:  age_bkts['1–7 days'] += 1
            elif age < 30: age_bkts['8–30 days'] += 1
            elif age < 90: age_bkts['31–90 days'] += 1
            else:          age_bkts['&gt; 90 days'] += 1
        except: pass

    ts_display  = _format_ts(meta.get('generated_at',''))
    cloud_name  = meta.get('cloud','us-1').upper()
    managed     = cov_sum.get('managed_count', 0)
    unmanaged   = cov_sum.get('unmanaged_count', 0)
    unsupported = cov_sum.get('unsupported_count', 0)
    manageable  = cov_sum.get('manageable_total', managed + unmanaged)
    coverage    = cov_sum.get('sensor_coverage_pct', 0)
    total_disc  = len(disc_hosts)
    cloud_total = cl_sum.get('total', 0)
    k8s_total   = k8s_sum.get('total', 0)
    rc          = _rc(coverage)
    risk_label  = 'CRITICAL' if coverage < 40 else ('MODERATE' if coverage < 70 else 'GOOD')

    # ── COVER ──────────────────────────────────────────────────
    summary = (
        f"This report summarizes the Falcon sensor deployment posture as of <strong>{ts_display}</strong>. "
        f"Of the <strong>{_fmt(manageable)}</strong> sensor-eligible assets, "
        f"<strong>{_fmt(managed)}</strong> are currently protected "
        f"({coverage:.1f}% coverage). "
        f"<strong>{_fmt(unmanaged)}</strong> have no sensor installed, "
        f"representing a <strong>{100-coverage:.0f}% coverage gap</strong>. "
        f"Additionally, <strong>{_fmt(unsupported)}</strong> unsupported devices (IoT, network gear) "
        f"were discovered that cannot run the Falcon sensor."
    )
    cover = f"""
<div class="cover">
  <div class="cover-hdr">
    <div class="cover-brand">
      <svg viewBox="0 0 40 46" width="30" height="35" style="flex-shrink:0">
        <polygon points="20,1 38,11 38,35 20,45 2,35 2,11" fill="{RED}"/>
      </svg>
      <div>
        <div class="brand-nm">CrowdStrike Falcon</div>
        <div class="brand-sb">Asset Inventory — Executive Report</div>
      </div>
    </div>
    <div class="cover-meta">Generated {ts_display}<br>Cloud: {cloud_name} &nbsp;·&nbsp; CONFIDENTIAL</div>
  </div>
  <div class="cover-body">
    <p class="exec-sum">{summary}</p>
    {_stat_grid([
        ('Managed Hosts',    _fmt(managed),         GREEN),
        ('Unmanaged Gap',    _fmt(unmanaged),        ORANGE),
        ('Cloud Hosts',      _fmt(cloud_total),      CYAN),
        ('Unsupported',      _fmt(unsupported),      RED),
        ('Container Hosts',  _fmt(container_hosts),  CYAN),
        ('K8s Nodes',        _fmt(k8s_node_hosts),   CYAN),
        ('Standard Hosts',   _fmt(max(managed - container_hosts - k8s_node_hosts, 0)), GREY2),
        ('Managed Hosts Online Now',  f'{_fmt(online_count)} / {_fmt(managed)}', GREEN),
        ('Total Discovered', _fmt(total_disc),       GREY2),
    ], cols=3)}
    <div class="gauge-row">
      <div class="gauge-wrap">{_gauge(coverage, 140)}</div>
      {_callout(
          f'Sensor Coverage: {coverage:.1f}% &nbsp; {_badge(risk_label, rc)}',
          f'{_fmt(managed)} of {_fmt(manageable)} sensor-eligible assets are protected &nbsp;·&nbsp; '
          f'Coverage gap: <strong>{100-coverage:.1f}%</strong>',
          rc
      )}
    </div>
    {_glossary([
        ('Falcon Sensor',    'Lightweight agent installed on a host that provides detection, prevention, and telemetry to CrowdStrike cloud'),
        ('Managed',          'Host or asset with a Falcon sensor installed and actively checking in'),
        ('Unmanaged',        'Asset discovered by Falcon on the network but with no sensor — can accept one'),
        ('Unsupported',      'Asset Falcon has discovered but cannot protect — no sensor build exists (IoT, network gear, legacy OS)'),
        ('Sensor-Eligible',  'Managed + Unmanaged; the denominator for coverage % calculations'),
        ('Coverage %',       'Managed ÷ Sensor-Eligible × 100; unsupported assets are excluded'),
        ('Discover API',     'Falcon API that surfaces shadow IT and network-discovered assets without requiring a sensor'),
        ('Hosts API',        'Falcon API for sensor-registered managed devices — the authoritative source for managed host data'),
        ('CSPM',             'Cloud Security Posture Management — monitors cloud infrastructure for misconfigurations and compliance drift'),
        ('CSA',              'Cloud Security Assets — the API service name (CloudSecurityAssets) and dataset that backs CSPM in Falcon'),
        ('KAC',              'Kubernetes Admission Controller — Falcon webhook that intercepts workloads at deploy time to enforce policy'),
        ('IAR',              'Image Assessment at Runtime — continuously scans running container images for vulnerabilities'),
        ('FQL',              'Falcon Query Language — SQL-like filter syntax used across Falcon APIs (e.g. managed_by:\'Sensor\')'),
        ('ECS',              'Amazon Elastic Container Service — AWS managed container orchestration platform'),
        ('EKS',              'Amazon Elastic Kubernetes Service — AWS managed Kubernetes'),
        ('AKS',              'Azure Kubernetes Service — Microsoft Azure managed Kubernetes'),
        ('GKE',              'Google Kubernetes Engine — Google Cloud managed Kubernetes'),
        ('Fargate',          'AWS serverless compute engine for containers (ECS/EKS); no persistent VM to install a sensor on'),
        ('Containment',      'Network isolation applied by Falcon to a host — all traffic blocked except communication to Falcon cloud'),
        ('CID',              'Customer ID — unique identifier for your CrowdStrike tenant'),
    ])}
  </div>
</div>
<div class="pb"></div>"""

    # ── S1: SENSOR COVERAGE ────────────────────────────────────
    gap_by_plat = cov_sum.get('gap', {}).get('by_platform', {})
    top_plat    = sorted(gap_by_plat.items(), key=lambda x:-x[1])[:10]

    _s1_cov_table = _table(
        ['Asset Category','Count','% of Sensor-Eligible'],
        [
            [f'<span class="chip-g">Managed (Falcon installed)</span>',  f'<strong>{_fmt(managed)}</strong>',    f'<strong>{coverage:.1f}%</strong>'],
            [f'<span class="chip-o">Unmanaged (no sensor)</span>',        _fmt(unmanaged),   _pct(unmanaged, manageable)],
            [f'<strong>Sensor-Eligible Total</strong>',                   f'<strong>{_fmt(manageable)}</strong>', '100%'],
            ['Unsupported (IoT/network)',                                  _fmt(unsupported), 'N/A'],
            ['All Discovered Assets',                                      _fmt(total_disc),  '—'],
        ],
        col_align={1:'center', 2:'center'}
    )

    s1 = f"""
<section id="s1">
  {_sh(1, "Sensor Coverage Analysis")}
  {_api_panel(
      apis=['Discover.query_hosts', 'Discover.get_hosts', 'Hosts.query_devices_by_filter_scroll'],
      logic_items=[
          '<strong>sensor_coverage_pct</strong> = managed &divide; (managed + unmanaged)',
          'Unsupported assets excluded from the denominator',
          'Unmanaged = Discover assets where <code>managed_by</code> &ne; Supported/Not Supported',
      ],
      fql="managed_by:'Not Supported'",
      conflicts=[
          'Hosts API and Discover API are queried independently — <strong>no cross-deduplication</strong> by hostname, IP, or MAC. A host recently de-sensored may appear as "managed" in Hosts API and "unmanaged" in Discover API simultaneously (delayed sync), inflating both counts.',
          '<strong>manageable_total = managed + unmanaged</strong> assumes zero overlap. Any overlap causes double-counting, making coverage_pct appear lower than reality.',
      ]
  )}
  {_legend([
      ('Managed',          'Host has a Falcon sensor installed and is actively checked in'),
      ('Unmanaged',        'Discovered by Falcon but no sensor installed — can accept one'),
      ('Unsupported',      'Cannot run the Falcon sensor (IoT, network gear, etc.) — excluded from coverage math'),
      ('Sensor-Eligible',  'Managed + Unmanaged; the denominator for coverage %'),
      ('Coverage %',       'Managed ÷ Sensor-Eligible × 100'),
  ])}
  <div class="two-col">
    <div>
      {_s1_cov_table}
    </div>
    <div>
      {_rank('Unmanaged Assets by Platform', top_plat, unmanaged, ORANGE)}
    </div>
  </div>
</section>
<div class="pb"></div>"""

    # ── S2: MANAGED HOSTS ──────────────────────────────────────
    by_plat = h_sum.get('by_platform', {})
    by_prod = h_sum.get('by_product_type', {})
    by_os   = h_sum.get('by_os_version', {})
    by_stat = h_sum.get('by_status', {})

    contained = by_stat.get('contained', 0)
    alert_html = (
        f'<div class="alert">⚠ <strong>{_fmt(contained)} hosts are currently in network containment</strong>'
        f' ({_pct(contained, managed)} of managed fleet).</div>'
    ) if contained else ''

    unknown_count = state_counts.get('unknown', 0)
    _s2_online_table = _table(
        ['Status','Count','% of Managed'],
        [
            [f'<span class="chip-g">Online</span>', _fmt(online_count),  _pct(online_count, managed)],
            ['Offline',                              _fmt(offline_count), _pct(offline_count, managed)],
            *([[f'<span style="color:{GREY3}">Unknown</span>', _fmt(unknown_count), _pct(unknown_count, managed)]] if unknown_count else []),
        ],
        col_align={1:'center', 2:'center'}
    )
    _s2_age_table = _table(
        ['Last Check-in','Hosts'],
        [[k, _fmt(v)] for k, v in age_bkts.items() if v],
        col_align={1:'center'}
    )
    _s2_cont_table = _table(
        ['Asset Role','Count','% of Managed'],
        [
            [f'<span class="chip-c">Pods / Containers (IS a container)</span>', _fmt(container_hosts), _pct(container_hosts, managed)],
            [f'<span class="chip-c">Kubernetes Nodes (runs containers)</span>',  _fmt(k8s_node_hosts),  _pct(k8s_node_hosts, managed)],
        ],
        col_align={1:'center', 2:'center'}
    )

    s2 = f"""
<section id="s2">
  {_sh(2, "Managed Hosts (Falcon Protected)")}
  {_api_panel(
      apis=['Hosts.query_devices_by_filter_scroll', 'Hosts.get_device_details', 'Hosts.get_online_state'],
      logic_items=[
          'Age buckets derived from <code>last_seen</code> field',
          'Container classification: <code>product_type=Pod</code> or EKS/ECS <code>service_provider</code>',
          'K8s node: <code>product_type_desc=\'Kubernetes Cluster\'</code>',
          '<strong>Standard Hosts</strong> = managed &minus; containers &minus; k8s_nodes',
          'Containment status from <code>filesystem_containment_status</code>',
      ],
      fql="product_type_desc:!'Mobile'",
      conflicts=[
          '<strong>Online Now vs Managed count may disagree:</strong> <code>get_online_state</code> is called in batches of 100; if any batch fails silently, the online count reflects fewer devices than the actual managed total. No completeness validation is performed.',
          '<strong>Container vs K8s Node classification is mutually exclusive in code</strong> but edge cases exist: a host with <code>service_provider=\'AWS_EKS_FARGATE\'</code> AND <code>product_type=\'Kubernetes Cluster\'</code> is classified as "container" (first <code>if</code> wins). "Standard Hosts" is reduced by any misclassified host.',
      ]
  )}
  {_legend([
      ('Managed Host',     'Any device with a live Falcon sensor; the source of truth for this section'),
      ('Standard Host',    'Managed host that is neither a container/pod nor a Kubernetes node'),
      ('Container / Pod',  'Managed host classified as a running container (product_type=Pod or EKS/ECS/ACA provider)'),
      ('K8s Node',         'Managed host that acts as a Kubernetes worker node or cluster object'),
      ('Online',           'Sensor heartbeat confirmed active at time of inventory pull'),
      ('Offline',          'No recent heartbeat — sensor may be dormant, not decommissioned'),
      ('Contained',        'Host network-isolated by Falcon; all traffic blocked except to Falcon cloud'),
      ('Last Check-in',    'Age bucket based on last_seen timestamp from the Hosts API'),
  ])}
  <div class="two-col">
    {_rank('By Platform', sorted(by_plat.items(), key=lambda x:-x[1])[:8], managed, CYAN)}
    {_rank('By Product Type', sorted(by_prod.items(), key=lambda x:-x[1])[:8], managed, GREEN)}
  </div>
  <p class="note"><strong>K8S platform / Kubernetes Cluster product type</strong> = hosts where the Falcon sensor is registered as a cluster-level object via the Hosts API. This count may be lower than the total cluster count in the Container Security section, which sources data from the Kubernetes Protection API and includes clusters visible via cloud integration without a deployed sensor.</p>

  <div class="sub-t">Online Status</div>
  <div class="two-col">
    {_s2_online_table}
    {_s2_age_table}
  </div>
  <p class="note"><strong>Offline</strong> = host not currently connected to Falcon cloud; does not indicate decommission. Last check-in tracks most recent sensor heartbeat.</p>

  <div class="sub-t">Container &amp; Kubernetes Involvement</div>
  {_s2_cont_table}
  <p class="note"><strong>Container:</strong> product_type=Pod or EKS/ECS/ACA provider &nbsp;·&nbsp; <strong>K8s Node:</strong> DaemonSet, Kubernetes Cluster tag, or K8s worker</p>

  {alert_html}

  <div class="sub-t">Top OS Versions</div>
  {''.join(_bar(k,v,managed,CYAN) for k,v in sorted(by_os.items(),key=lambda x:-x[1])[:12])}
</section>
<div class="pb"></div>"""

    # ── S3: CLOUD & K8S ────────────────────────────────────────
    by_provider = cl_sum.get('by_provider', {})
    by_cl_plat  = cl_sum.get('by_platform', {})
    by_acct     = cl_sum.get('by_account', {})
    k8s_ns      = k8s_sum.get('by_namespace', {})
    cloud_pct   = cloud_total / managed * 100 if managed else 0

    s3 = f"""
<section id="s3">
  {_sh(3, "Cloud & Kubernetes Coverage", CYAN)}
  {_api_panel(
      apis=['Hosts.query_devices_by_filter (cloud hosts)', 'Hosts.query_devices_by_filter (K8s pods)'],
      logic_items=[
          'Cloud host = managed host with <code>service_provider</code> in AWS/Azure/GCP set',
          'K8s pod = managed host with <code>pod_namespace</code> populated',
          '<strong>cloud_pct</strong> = cloud_total &divide; managed',
      ],
      fql="service_provider:['AWS_EC2','AZURE','GCP','AWS_EKS_FARGATE',...]",
      conflicts=[
          '<strong>Cloud host count here &ne; CSA total in S4.</strong> This section counts only managed hosts with Falcon sensors running in cloud. S4 counts all cloud resources (managed or not) via the CloudSecurityAssets API — fundamentally different denominators.',
          '<strong>K8s pod count here &ne; container count in S5.</strong> This section counts Falcon-instrumented pods via Hosts API (<code>pod_namespace</code> filter). S5 uses the KubernetesProtection API and counts all containers/pods cluster-wide, regardless of sensor presence. Expect S3 to be much lower than S5\'s "Total Containers."',
      ]
  )}
  {_legend([
      ('Cloud Host',         'Managed host (Falcon sensor present) whose service_provider is AWS, Azure, or GCP'),
      ('K8s Pod (here)',     'Falcon-instrumented pod identified via pod_namespace field in the Hosts API — sensor must be present'),
      ('Cloud Provider',     'The hyperscaler platform: AWS, Azure, or GCP as reported by the sensor'),
      ('Cloud Account',      'AWS account ID, Azure subscription, or GCP project containing the host'),
      ('NOT CSA count',      'These counts reflect sensored hosts only — S4 shows all cloud resources including unsensored'),
  ])}
  <p class="lead"><strong>{_fmt(cloud_total)}</strong> of {_fmt(managed)} managed hosts ({cloud_pct:.0f}%) run in cloud environments.</p>

  <div class="two-col">
    {_rank('By Cloud Provider', sorted(by_provider.items(),key=lambda x:-x[1]), cloud_total, CYAN)}
    {_rank('By Platform', sorted(by_cl_plat.items(),key=lambda x:-x[1]), cloud_total, GREEN)}
  </div>

  {'<div class="sub-t">Top Cloud Accounts by Host Count</div>' + "".join(_bar(k,v,cloud_total,CYAN) for k,v in sorted(by_acct.items(),key=lambda x:-x[1])[:12]) if by_acct else ''}

  <div class="sub-t">Kubernetes Pods with Falcon Sensor</div>
  <p class="lead"><strong>{_fmt(k8s_total)}</strong> Kubernetes pods are instrumented with the Falcon sensor.</p>
  {''.join(_bar(k,v,k8s_total,CYAN) for k,v in sorted(k8s_ns.items(),key=lambda x:-x[1])[:12]) if k8s_ns else '<p class="note">No namespace data available.</p>'}
</section>
<div class="pb"></div>"""

    # ── S4: CLOUD ASSET COVERAGE (CSPM) ────────────────────────
    _csa_csv_rows     = [['Asset Type','Resource ID','Resource Name','Account ID','Region','Status']]
    _csa_mgd_csv_rows = [['Asset Type','Resource ID','Resource Name','Account ID','Region','Status']]
    s4_csa = ''
    if csa_cov and csa_cov.get('rows'):
        csa_rows         = csa_cov.get('rows', [])
        csa_details      = csa_cov.get('details', {})
        csa_mgd_details  = csa_cov.get('managed_details', {})
        csa_total_a      = csa_cov.get('total_assets', 0)

        # Overall coverage: sum(with_sensors) / sum(total) for non-KAC rows
        _csa_non_kac = [r for r in csa_rows if r.get('name') != 'K8s Clusters with KAC']
        _csa_sum_w   = sum(r.get('with_sensors', 0) for r in _csa_non_kac)
        _csa_sum_t   = sum(r.get('total_count', 0) for r in _csa_non_kac)
        _csa_pct     = round(_csa_sum_w / _csa_sum_t * 100, 1) if _csa_sum_t else 0.0
        _csa_pc      = _rc(_csa_pct)
        _csa_gap     = _csa_sum_t - _csa_sum_w

        # Coverage table rows
        def _csa_row(row):
            name   = row.get('name', '')
            total  = row.get('total_count', 0)
            with_s = row.get('with_sensors', 0)
            wout_s = row.get('without_sensors', 0)
            rate   = row.get('coverage_rate', 0.0)
            est    = row.get('estimated', False)
            errs   = row.get('errors', [])
            rate_c = _rc(rate)
            est_m  = '*' if est else ''
            err_html = (f'<tr><td colspan="5" style="font-size:10px;color:{RED};padding:2px 11px 8px">'
                        f'API error: {errs[0].get("errors") or errs}</td></tr>') if errs else ''
            return (
                f'<tr style="border-bottom:1px solid #F0F2F5">'
                f'<td style="padding:10px 11px;font-weight:700">{name}</td>'
                f'<td style="padding:10px 11px;text-align:center">{_fmt(total)}{est_m}</td>'
                f'<td style="padding:10px 11px;text-align:center;color:{GREEN}">{_fmt(with_s)}{est_m}</td>'
                f'<td style="padding:10px 11px;text-align:center;color:{ORANGE if wout_s else GREY3}">{_fmt(wout_s)}</td>'
                f'<td style="padding:10px 11px;text-align:center;color:{rate_c};font-weight:700">{rate:.1f}%{est_m}</td>'
                f'</tr>{err_html}'
            )

        _csa_table_rows = ''.join(_csa_row(r) for r in csa_rows)
        _csa_has_k8s    = any(r.get('name','').startswith('K8s Clusters') for r in csa_rows)
        _csa_has_est    = any(r.get('estimated') for r in csa_rows)
        _csa_has_td     = any(r.get('name') == 'AWS ECS Task Definitions' for r in csa_rows)

        _csa_drilldown = ''
        _csa_notes     = ''
        _csa_csv_rows  = [['Asset Type','Resource ID','Resource Name','Account ID','Region','Status']]
        for row in csa_rows:
            name = row.get('name','')
            if name == 'K8s Clusters with KAC':
                continue
            td = csa_details.get(name, {})
            assets = td.get('assets', [])
            total_d = td.get('total', 0)
            shown_d = td.get('shown', 0)
            if not total_d:
                continue
            for a in assets:
                _csa_csv_rows.append([
                    name,
                    a.get('resource_id') or '',
                    a.get('resource_name') or '',
                    a.get('account_id') or '',
                    a.get('region') or '',
                    a.get('status') or '',
                ])
            cap_note = (f'<p style="font-size:11px;color:{GREY3};margin:4px 0 6px 0">'
                        f'Showing first {_fmt(shown_d)} of {_fmt(total_d)}</p>') if total_d > shown_d else ''
            tbl = _table(
                ['Resource ID','Name','Account','Region','Status'],
                [[f'<span class="mono">{a.get("resource_id") or "—"}</span>',
                  a.get('resource_name') or '—',
                  a.get('account_id') or '—',
                  a.get('region') or '—',
                  a.get('status') or '—'] for a in assets],
            )
            _csa_drilldown += (
                f'<details class="csa-details">'
                f'<summary>{name} — {_fmt(total_d)} unmanaged</summary>'
                f'{cap_note}{tbl}'
                f'</details>'
            )

        # Managed asset drilldown
        _csa_mgd_drilldown = ''
        for row in csa_rows:
            name = row.get('name','')
            if name == 'K8s Clusters with KAC':
                continue
            td = csa_mgd_details.get(name, {})
            assets = td.get('assets', [])
            total_d = td.get('total', 0)
            shown_d = td.get('shown', 0)
            if not total_d:
                continue
            for a in assets:
                _csa_mgd_csv_rows.append([
                    name,
                    a.get('resource_id') or '',
                    a.get('resource_name') or '',
                    a.get('account_id') or '',
                    a.get('region') or '',
                    a.get('status') or '',
                ])
            cap_note = (f'<p style="font-size:11px;color:{GREY3};margin:4px 0 6px 0">'
                        f'Showing first {_fmt(shown_d)} of {_fmt(total_d)}</p>') if total_d > shown_d else ''
            tbl = _table(
                ['Resource ID','Name','Account','Region','Status'],
                [[f'<span class="mono">{a.get("resource_id") or "—"}</span>',
                  a.get('resource_name') or '—',
                  a.get('account_id') or '—',
                  a.get('region') or '—',
                  a.get('status') or '—'] for a in assets],
            )
            _csa_mgd_drilldown += (
                f'<details class="csa-details">'
                f'<summary>{name} — {_fmt(total_d)} managed</summary>'
                f'{cap_note}{tbl}'
                f'</details>'
            )
        if _csa_has_est:
            _csa_notes += '<p class="note">* Count exceeds one page of API results and may be estimated.</p>'
        if _csa_has_k8s:
            _csa_notes += (
                '<p class="note">† K8s AWS/Azure sensor coverage counts clusters with ≥1 '
                'sensor-equipped worker node, limited to clusters with KAC registered. '
                'Clusters without KAC are counted as unprotected.</p>'
            )
        if _csa_has_td:
            _csa_notes += (
                '<p class="note">‡ AWS ECS Task Definitions coverage is determined by '
                'inspecting the container configuration for Falcon sidecar indicators '
                '(image name, environment variables, volume mounts). '
                'Does not rely on <code>managed_by:\'Sensor\'</code>.</p>'
            )

        s4_csa = f"""
<section id="s4">
  {_sh(4, "Cloud Asset Coverage (CSPM)", CYAN)}
  {_api_panel(
      apis=[
          'CloudSecurityAssets.query_assets (total per asset type)',
          'CloudSecurityAssets.query_assets (managed_by:Sensor — managed assets)',
          'Hosts.query_devices_by_filter (K8s cluster KAC workaround)',
      ],
      logic_items=[
          'Each asset type row: <strong>coverage_rate</strong> = with_sensor &divide; total',
          'ECS Task Defs: container config inspection (image names, env vars, volume mounts)',
          'K8s clusters: uses Hosts API <code>product_type_desc:\'Kubernetes Cluster\'</code> as proxy',
          'Counts marked <strong>*</strong> are capped at pagination offset limit (9,900)',
      ],
      fql="managed_by:'Sensor'",
      conflicts=[
          '<strong>CSA K8s cluster totals vs KAC workaround totals may disagree.</strong> If CSA returns 0 for a cloud\'s K8s clusters, the report falls back to the KAC workaround count as the total — meaning sensor count = total = 100% coverage artificially.',
          '<strong>ECS Task Definition coverage uses a different methodology</strong> than all other rows. Standard rows use <code>managed_by:\'Sensor\'</code>; ECS Task Defs inspect container image names, env vars, and volume mounts — a heuristic that can produce false positives or miss newly structured deployments.',
          '<strong>Estimated counts (*):</strong> When an asset type exceeds the API pagination offset limit (9,900 records), total count is capped. Actual totals and coverage rates are approximate.',
          '<strong>KAC K8s cluster row is NOT added to total_assets</strong> to avoid double-counting clusters already counted in per-cloud K8s rows. Manual summation of the table will exceed the "Total Cloud Assets" headline.',
      ]
  )}
  {_legend([
      ('Cloud Asset',      'Any cloud resource (VM, container, bucket, function, cluster, etc.) visible in Falcon CSPM — includes unmanaged ones'),
      ('Managed',          'Cloud asset where Falcon detects a sensor via managed_by:Sensor — actively protected'),
      ('Unmanaged',        'Cloud asset visible in CSPM but no sensor detected — blind spot'),
      ('Coverage %',       'Managed ÷ Total for each asset type row'),
      ('* Estimated',      'Total count capped at API pagination limit (9,900); actual total and coverage % are approximate'),
      ('KAC',              'Kubernetes Admission Controller — Falcon admission webhook deployed to a cluster'),
      ('ECS Task Def',     'AWS ECS Task Definition; coverage detected via image/env/volume heuristic, not managed_by:Sensor'),
  ])}
  <p class="lead">
    Sensor coverage across cloud resource types visible in Falcon Cloud Security (CSPM/CSA),
    using the CloudSecurityAssets API.
    <strong>{_fmt(csa_total_a)}</strong> total cloud assets tracked.
  </p>
  {_stat_grid([
      ('Total Cloud Assets',  _fmt(csa_total_a), GREY2),
      ('Managed',             _fmt(_csa_sum_w),  GREEN),
      ('Unmanaged',           _fmt(_csa_gap),    RED if _csa_gap else GREY2),
      ('Overall Coverage',    f'{_csa_pct:.1f}%', _csa_pc),
  ], cols=4)}
  <table class="dt" style="margin-bottom:16px">
    <thead><tr>
      <th>Asset Type</th>
      <th style="text-align:center">Total</th>
      <th style="text-align:center">Managed</th>
      <th style="text-align:center">Unmanaged</th>
      <th style="text-align:center">Coverage</th>
    </tr></thead>
    <tbody>{_csa_table_rows}</tbody>
  </table>
  {_csa_notes}
  <div class="sub-t" style="margin-top:20px">
    Unmanaged Assets
    <button class="export-btn" onclick="exportCSV('csa_unprotected')" style="float:right;margin-top:-2px">&#8595; Export CSV</button>
  </div>
  {_csa_drilldown if _csa_drilldown else '<p class="note">No unmanaged cloud assets found.</p>'}
  <div class="sub-t" style="margin-top:20px">
    Managed Assets
    <button class="export-btn" onclick="exportCSV('csa_managed_assets')" style="float:right;margin-top:-2px">&#8595; Export CSV</button>
  </div>
  <p class="note">Per-asset drilldown for cloud resources with a Falcon sensor detected via <code>managed_by:'Sensor'</code>. &nbsp;
    <strong>AWS ECS Task Definitions</strong> are excluded — their coverage is determined by container config inspection (image name / env vars / volume mounts), not the <code>managed_by</code> field, so a per-asset list is not available here. &nbsp;
    <strong>K8s cluster</strong> managed lists are derived from Hosts API hostname correlation and may be incomplete where CSA cluster names differ from Hosts API hostnames.
  </p>
  {_csa_mgd_drilldown if _csa_mgd_drilldown else '<p class="note">No managed cloud asset details available.</p>'}
</section>
<div class="pb"></div>"""

    # ── S5: CONTAINER SECURITY ─────────────────────────────────
    _kac_csv_rows = [['Cluster','Cloud','Region','KAC','IAR','KAC Last Seen','Build']]
    k8s_inv         = data.get('k8s_nodes', {})
    k8s_inv_summary = k8s_inv.get('summary', {}) if isinstance(k8s_inv, dict) else {}
    s5 = ''
    if k8s_inv_summary:
        cov_data      = k8s_inv_summary.get('sensor_coverage', {})
        mgd_ctrs      = k8s_inv_summary.get('managed_containers', {})
        by_cloud      = k8s_inv_summary.get('nodes_by_cloud', {})
        by_runtime    = k8s_inv_summary.get('nodes_by_runtime', {})
        total_ctrs    = cov_data.get('total_containers', 0)
        covered_ctrs  = cov_data.get('covered_containers', 0)
        ctr_pct       = cov_data.get('coverage_pct', 0)
        unmanaged_ctrs= mgd_ctrs.get('Unmanaged', 0)
        ctr_color     = _rc(ctr_pct)
        ctr_risk      = 'CRITICAL' if ctr_pct < 40 else ('HIGH' if ctr_pct < 70 else 'GOOD')

        nodes_list   = k8s_inv.get('nodes', [])
        active_nodes = [n for n in nodes_list if n.get('resource_status') != 'deleted']
        display_nodes= sorted(active_nodes, key=lambda n:(n.get('cluster_name') or '', n.get('node_name') or ''))[:25]

        nodes_tbl = ''
        if display_nodes:
            nodes_tbl = (
                '<div class="sub-t">Active K8s Nodes</div>'
                + _table(
                    ['Node','Cluster','Cloud','Region','Runtime','Sensor'],
                    [
                        [
                            f'<span class="mono" title="{n.get("node_name") or ""}">{n.get("node_name") or ""}</span>',
                            (n.get('cluster_name') or '')[:30],
                            n.get('cloud_name') or '—',
                            (n.get('cloud_region') or '—')[:18],
                            (n.get('container_runtime_version') or '—').split('://')[0],
                            f'<span style="color:{GREEN};font-weight:700">✓</span>' if n.get('linux_sensor_coverage')
                            else f'<span style="color:{RED};font-weight:700">✗</span>',
                        ]
                        for n in display_nodes
                    ],
                    col_align={2:'center',3:'center',5:'center'}
                )
            )

        # ── KAC / IAR coverage ──────────────────────────────────
        clusters_list  = k8s_inv.get('clusters', [])
        cluster_total  = len(clusters_list)
        kac_clusters   = [c for c in clusters_list if c.get('agent_coverage', {}).get('kac_coverage')]
        iar_clusters   = [c for c in clusters_list if c.get('agent_coverage', {}).get('iar_coverage')]
        kac_count      = len(kac_clusters)
        iar_count      = len(iar_clusters)
        kac_pct        = kac_count / cluster_total * 100 if cluster_total else 0
        iar_pct        = iar_count / cluster_total * 100 if cluster_total else 0
        kac_gap        = cluster_total - kac_count
        kac_color      = _rc(kac_pct)
        iar_color      = _rc(iar_pct)

        gap_clusters   = [c for c in clusters_list if not c.get('agent_coverage', {}).get('kac_coverage')]
        gap_by_cloud   = Counter(c.get('cloud_provider_info', {}).get('cloud_provider') or 'Unknown'
                                 for c in gap_clusters)
        kac_builds     = Counter(c['agent_coverage'].get('kac_config_build', 'unknown')
                                 for c in kac_clusters)

        _kac_funnel = _table(
            ['Stage', 'Clusters', '% of Total'],
            [
                ['All K8s Clusters',                                        _fmt(cluster_total), '100%'],
                [f'<span style="color:{GREEN}">KAC Deployed</span>',  f'<strong>{_fmt(kac_count)}</strong>', f'<strong>{kac_pct:.1f}%</strong>'],
                [f'<span style="color:{CYAN}">IAR Enabled</span>',    f'<strong>{_fmt(iar_count)}</strong>', f'<strong>{iar_pct:.1f}%</strong>'],
                [f'<span style="color:{RED}">No KAC (gap)</span>',    f'<strong>{_fmt(kac_gap)}</strong>',   f'<strong>{(100-kac_pct):.1f}%</strong>'],
            ],
            col_align={1: 'center', 2: 'center'}
        )

        _gap_cloud_rows = sorted(gap_by_cloud.items(), key=lambda x: -x[1])
        _kac_gap_tbl = _table(
            ['Cloud Provider', 'Clusters Missing KAC'],
            [[cp, _fmt(cnt)] for cp, cnt in _gap_cloud_rows],
            col_align={1: 'center'}
        ) if _gap_cloud_rows else ''

        _build_rows = sorted(kac_builds.items(), key=lambda x: -x[1])
        _kac_build_tbl = _table(
            ['KAC Config Build', 'Clusters'],
            [[b, _fmt(cnt)] for b, cnt in _build_rows],
            col_align={1: 'center'}
        ) if _build_rows else ''

        def _check(v):
            return f'<span style="color:{GREEN};font-weight:700">✓</span>' if v else f'<span style="color:{RED}">✗</span>'

        _covered_rows = sorted(
            [c for c in clusters_list if c.get('agent_coverage', {}).get('kac_coverage') or c.get('agent_coverage', {}).get('iar_coverage')],
            key=lambda c: c.get('cluster_name') or ''
        )
        _kac_cluster_tbl = _table(
            ['Cluster', 'Cloud', 'Region', 'KAC', 'IAR', 'KAC Last Seen', 'Build'],
            [
                [
                    f'<span class="mono">{c.get("cluster_name") or c.get("cluster_id","")[:16]}</span>',
                    c.get('cloud_provider_info', {}).get('cloud_provider') or '—',
                    (c.get('cloud_provider_info', {}).get('cloud_region') or '—')[:22],
                    _check(c['agent_coverage'].get('kac_coverage')),
                    _check(c['agent_coverage'].get('iar_coverage')),
                    (c['agent_coverage'].get('kac_last_seen') or '—')[:10],
                    f'<span class="mono" style="font-size:10px">{c["agent_coverage"].get("kac_config_build","—")}</span>',
                ]
                for c in _covered_rows
            ],
            col_align={1:'center', 3:'center', 4:'center', 5:'center'}
        ) if _covered_rows else ''

        # Build CSV data for KAC cluster export
        _kac_csv_rows = [['Cluster', 'Cloud', 'Region', 'KAC', 'IAR', 'KAC Last Seen', 'Build']]
        for c in _covered_rows:
            ac = c.get('agent_coverage', {})
            cp = c.get('cloud_provider_info', {})
            _kac_csv_rows.append([
                c.get('cluster_name') or c.get('cluster_id', '')[:16],
                cp.get('cloud_provider') or '',
                cp.get('cloud_region') or '',
                'Yes' if ac.get('kac_coverage') else 'No',
                'Yes' if ac.get('iar_coverage') else 'No',
                (ac.get('kac_last_seen') or '')[:10],
                ac.get('kac_config_build') or '',
            ])

        kac_section = f"""
  <div class="sub-t">Admission Control &amp; Image Assessment at Runtime</div>
  <p class="note">
    <strong>KAC</strong> (Kubernetes Admission Controller) — enforces policy at workload admission time,
    blocking or alerting on non-compliant images before they run.&nbsp;
    <strong>IAR</strong> (Image Assessment at Runtime) — continuously assesses running container images
    for vulnerabilities and misconfigurations.
  </p>
  {_stat_grid([
      ('Clusters w/ KAC',  _fmt(kac_count),   kac_color),
      ('KAC Coverage',     f'{kac_pct:.1f}%', kac_color),
      ('Clusters w/ IAR',  _fmt(iar_count),   iar_color),
      ('IAR Coverage',     f'{iar_pct:.1f}%', iar_color),
      ('KAC Gap',          _fmt(kac_gap),     RED if kac_gap else GREY2),
      ('KAC Builds',       _fmt(len(kac_builds)), GREY2),
  ], cols=3)}
  <div class="gauge-row" style="margin-top:8px">
    <div class="gauge-wrap">
      {_gauge(kac_pct, 130)}
      <div style="text-align:center;font-size:10px;color:{GREY3};margin-top:4px">KAC</div>
    </div>
    <div class="gauge-wrap">
      {_gauge(iar_pct, 130)}
      <div style="text-align:center;font-size:10px;color:{GREY3};margin-top:4px">IAR</div>
    </div>
    <div style="flex:1">
      {_callout(
          f'KAC deployed on {kac_count} of {cluster_total} clusters &nbsp; {_badge("GAP" if kac_gap else "FULL COVERAGE", kac_color)}',
          f'IAR enabled on {iar_count} clusters ({iar_pct:.1f}%). &nbsp;'
          f'{kac_gap} clusters have no admission controller — workloads can deploy without policy enforcement.',
          kac_color
      )}
    </div>
  </div>
  <div class="two-col" style="margin-top:16px">
    <div>
      <div class="sub-t" style="font-size:11px;margin-bottom:8px">Coverage Funnel</div>
      {_kac_funnel}
    </div>
    <div>
      <div class="sub-t" style="font-size:11px;margin-bottom:8px">Gap Clusters by Cloud</div>
      {_kac_gap_tbl if _kac_gap_tbl else '<p class="note">No gap clusters.</p>'}
    </div>
  </div>
  {'<div class="sub-t" style="font-size:11px;margin-top:16px;margin-bottom:8px">KAC Agent Build Versions</div>' + _kac_build_tbl if _kac_build_tbl else ''}
  {'<div style="display:flex;align-items:center;justify-content:space-between;margin-top:20px;margin-bottom:8px"><span class="sub-t" style="font-size:11px;margin:0">Clusters with KAC / IAR Deployed</span><button class="export-btn" onclick="exportCSV(\'kac_clusters\')">&#8595; Export CSV</button></div>' + _kac_cluster_tbl if _kac_cluster_tbl else ''}
"""

        s5 = f"""
<section id="s5">
  {_sh(5, "Container Security Coverage (Kubernetes Protection)", CYAN)}
  {_api_panel(
      apis=[
          'KubernetesProtection.read_nodes_combined',
          'KubernetesProtection.read_clusters_combined_v2',
          'KubernetesProtection.read_sensor_coverage',
          'KubernetesProtection.group_managed_containers',
          'KubernetesProtection.read_pod_counts',
          'KubernetesProtection.read_container_counts',
          'KubernetesProtection.read_node_counts_by_cloud',
          'KubernetesProtection.read_nodes_by_container_engine_version',
      ],
      logic_items=[
          '<strong>container_coverage_pct</strong> = managed_containers &divide; total_containers',
          'KAC coverage = clusters with admission controller &divide; total clusters',
          'IAR = clusters with image assessment &divide; total clusters',
          'Includes clusters visible via cloud integration even without a Falcon sensor',
      ],
      conflicts=[
          '<strong>S5 cluster count vs S3 K8s count:</strong> KubernetesProtection API includes clusters visible via cloud integration even without a Falcon sensor. S3\'s K8s pod count (Hosts API <code>pod_namespace</code> filter) only reflects Falcon-instrumented pods. These are not comparable.',
          '<strong>S5 cluster count vs S4 CSA K8s rows:</strong> CSA counts K8s clusters as cloud resources (EKS, AKS, GKE). KubernetesProtection API counts registered K8s clusters. These may differ if a cluster is registered with KubernetesProtection but not yet synced to CSA, or vice versa.',
          '<strong>"Managed containers" definition differs from "managed pods" in S2/S3.</strong> <code>read_sensor_coverage</code> returns containers where the Falcon sensor is detected at runtime. S2/S3 pod counts are from the Hosts API device registry. The same container may be counted in both or neither depending on timing.',
      ]
  )}
  {_legend([
      ('K8s Cluster',           'A registered Kubernetes cluster — may be cloud-managed (EKS/AKS/GKE) or self-hosted; visible via cloud integration or direct sensor registration'),
      ('K8s Node',              'A worker VM inside a cluster that runs pods; may or may not have a Falcon sensor'),
      ('Pod',                   'A Kubernetes scheduling unit (one or more containers sharing network/storage); counted cluster-wide regardless of sensor'),
      ('Managed Container',     'A running container where the Falcon sensor has been detected at runtime via read_sensor_coverage'),
      ('Unmanaged Container',   'Running container with no detected Falcon sensor — full blind spot'),
      ('KAC',                   'Kubernetes Admission Controller — Falcon webhook that inspects workloads at deploy time'),
      ('IAR',                   'Image Assessment & Response — Falcon scans container images before they run'),
  ])}
  {_stat_grid([
      ('Total Containers',       _fmt(total_ctrs),                                              GREY2),
      ('Managed Containers',     _fmt(covered_ctrs),   GREEN),
      ('Unmanaged Containers',   _fmt(unmanaged_ctrs), RED if unmanaged_ctrs else GREY2),
      ('K8s Clusters',           _fmt(k8s_inv_summary.get('cluster_count',0)),                  CYAN),
      ('K8s Nodes',              _fmt(k8s_inv_summary.get('node_count',0)),                     CYAN),
      ('Pods',                   _fmt(k8s_inv_summary.get('pod_count',0)),                      CYAN),
  ], cols=3)}
  <p class="note"><strong>K8s Clusters</strong> sourced from the Kubernetes Protection API — includes all clusters visible via cloud integration or deployed sensor. This may differ from the <em>K8S platform</em> count in Managed Hosts, which only reflects clusters with a Falcon sensor registered through the Hosts API.</p>
  <div class="gauge-row">
    <div class="gauge-wrap">{_gauge(ctr_pct, 140)}</div>
    {_callout(
        f'Container Coverage: {ctr_pct:.1f}% &nbsp; {_badge(ctr_risk, ctr_color)}',
        f'{_fmt(covered_ctrs)} of {_fmt(total_ctrs)} containers are managed &nbsp;·&nbsp; '
        f'{_fmt(unmanaged_ctrs)} containers are unmanaged',
        ctr_color
    )}
  </div>
  <div class="two-col" style="margin-top:20px">
    {_rank('Nodes by Cloud', sorted(by_cloud.items(),key=lambda x:-x[1]), k8s_inv_summary.get('node_count',1) or 1, CYAN)}
    {_rank('Container Runtime', sorted(by_runtime.items(),key=lambda x:-x[1])[:8], k8s_inv_summary.get('node_count',1) or 1, GREEN)}
  </div>
  {nodes_tbl}
  {kac_section}
</section>
<div class="pb"></div>"""

    # ── S6: UNSUPPORTED ────────────────────────────────────────
    unsp      = cov_sum.get('unsupported', {})
    unsp_plat = unsp.get('by_platform', {})
    unsp_prod = unsp.get('by_product_type', {})

    s6 = f"""
<section id="s6">
  {_sh(6, "Unsupported Assets (Cannot be Managed)", GREY2)}
  {_api_panel(
      apis=['Discover.query_hosts', 'Discover.get_hosts'],
      logic_items=[
          'Filter <code>managed_by:\'Not Supported\'</code> returns devices Falcon cannot protect',
          'These assets are excluded from the sensor coverage denominator in S1',
          'Includes IoT devices, network infrastructure, and unidentified endpoints',
      ],
      fql="managed_by:'Not Supported'",
      conflicts=[
          'No deduplication against Hosts API. If an asset transitions from "managed" to "unsupported" (e.g., OS downgrade or product change), it could briefly appear in both the Managed Hosts count (S2) and here due to API sync delay.',
      ]
  )}
  {_legend([
      ('Unsupported',      'Device Falcon has discovered but cannot protect — no sensor build exists for its OS/product type'),
      ('managed_by: Not Supported', 'The Discover API field value that identifies these devices; set by Falcon, not manually'),
      ('Coverage impact',  'These hosts are NOT in the coverage denominator — they do not lower your sensor coverage %'),
      ('Alternative controls', 'Compensating measures needed: network segmentation, EDR-agnostic monitoring, physical security'),
  ])}
  <p class="lead"><strong>{_fmt(unsupported)}</strong> assets cannot run the Falcon sensor (IoT devices, network infrastructure, unidentified endpoints). These represent known blind spots that require alternative security controls.</p>
  <div class="two-col">
    {_rank('By Platform', sorted(unsp_plat.items(),key=lambda x:-x[1])[:8], unsupported, GREY3) if unsp_plat else ''}
    {_rank('By Product Type', sorted(unsp_prod.items(),key=lambda x:-x[1])[:8], unsupported, GREY3) if unsp_prod else ''}
  </div>
</section>
<div class="pb"></div>"""

    # ── S7: RECOMMENDATIONS ────────────────────────────────────
    recs = _recommendations(coverage, unmanaged, unsupported, managed, by_stat, gap_by_plat, k8s_total)
    s7 = f"""
<section id="s7">
  {_sh(7, "Recommendations", RED)}
  {_api_panel(
      apis=['(No direct API calls — computed from collected summary data)'],
      logic_items=[
          'Threshold rules applied to aggregated summaries from S1&ndash;S6',
          'coverage &lt; 40% &rarr; CRITICAL; &lt; 70% &rarr; HIGH',
          'contained &gt; 0 &rarr; HIGH',
          'unmanaged gap present &rarr; MEDIUM',
          'unsupported &gt; 1,000 &rarr; MEDIUM',
          'k8s present &rarr; LOW',
      ],
      conflicts=[
          'Recommendation thresholds are applied to summary counts that themselves may carry conflicts noted in S1&ndash;S6. For example, a "HIGH: Improve Coverage" recommendation triggered at 68% coverage could be an artifact of the Hosts/Discover API overlap inflating the unmanaged count.',
      ]
  )}
  {_legend([
      ('CRITICAL',    'Coverage below 40% — immediate action required'),
      ('HIGH',        'Coverage 40–69%, or hosts actively contained — urgent remediation'),
      ('MEDIUM',      'Unmanaged gap present, or >1,000 unsupported assets — planned remediation'),
      ('LOW',         'Kubernetes workloads detected — review KAC / IAR deployment'),
      ('Threshold',   'Severity is rule-based on the numbers above; it is not a risk score or weighted model'),
  ])}
  <div class="recs">{''.join(_rec(p,t,b) for p,t,b in recs)}</div>
</section>
<div class="pb"></div>"""

    # ── S8: APPENDIX ───────────────────────────────────────────
    IS_CLOUD = {'AWS_EC2_V2','AWS_EC2','AWS_EKS_FARGATE','AWS_ECS_FARGATE',
                'AZURE','AZURE_CONTAINER_APPS','GCP'}
    unmanaged_records = gaps.get('unmanaged', [])

    def _sort_key(r):
        return (0 if r.get('hostname') else 1,
                r.get('platform_name') or 'ZZZ',
                r.get('last_seen_timestamp') or '')

    # Build CSV data for unmanaged assets export
    _unmanaged_csv_rows = [['Hostname','Discoverer','Platform','OS Version','IP Address','Cloud Provider','Confidence','Container Signal','First Seen','Last Seen']]
    rows_html = ''
    for i, r in enumerate(sorted(unmanaged_records, key=_sort_key)):
        _raw_id    = r.get('id', '')
        _cid       = r.get('cid', '')
        _id_suffix = _raw_id.replace(_cid + '_', '', 1) if _raw_id.startswith(_cid + '_') else _raw_id
        _disc_host = r.get('last_discoverer_hostname') or (r.get('discoverer_hostnames') or [None])[0]
        hostname   = (r.get('hostname')
                      or (_disc_host and f'<em title="Discovered by {_disc_host}" class="mono">{_disc_host}</em>')
                      or f'<em class="mono">{_id_suffix[:20]}…</em>')
        platform   = r.get('platform_name') or '—'
        os_ver     = (r.get('os_version') or '—')[:32]
        ip         = r.get('current_local_ip') or (r.get('local_ip_addresses') or [''])[0] or '—'
        provider   = r.get('cloud_provider') or '—'
        confidence = r.get('confidence', '')
        hint       = _container_hint(r)
        is_cloud   = (r.get('cloud_provider') or '') in IS_CLOUD
        hint_color = CYAN if hint == 'likely' else (GREY3 if hint == 'possible' else GREY5)
        row_cls    = ('cloud-row' if is_cloud else '') + (' alt' if i % 2 else '')
        rows_html += (
            f'<tr class="{row_cls.strip()}">'
            f'<td>{hostname}</td>'
            f'<td style="text-align:center">{platform}</td>'
            f'<td>{os_ver}</td>'
            f'<td><span class="mono">{ip}</span></td>'
            f'<td style="color:{"" + ORANGE if is_cloud else GREY3}">{provider}</td>'
            f'<td style="text-align:center">{confidence}%' if confidence != '' else '<td style="text-align:center">—'
            f'</td>'
            f'<td style="text-align:center;color:{hint_color};font-weight:{"700" if hint=="likely" else "400"}">{hint}</td>'
            f'</tr>'
        )
        _unmanaged_csv_rows.append([
            r.get('hostname') or _disc_host or _id_suffix[:32],
            _disc_host or '',
            r.get('platform_name') or '',
            r.get('os_version') or '',
            ip,
            r.get('cloud_provider') or '',
            str(confidence) + '%' if confidence != '' else '',
            hint,
            (r.get('first_seen_timestamp') or '')[:10],
            (r.get('last_seen_timestamp') or '')[:10],
        ])

    # Build CSV data and HTML for unsupported assets
    unsupported_records = gaps.get('unsupported', [])
    _unsupported_csv_rows = [['Hostname / ID','Platform','OS Version','IP Address',
                              'Cloud Provider','Product Type','First Seen','Last Seen']]
    unsp_rows_html = ''
    for i, r in enumerate(sorted(unsupported_records, key=_sort_key)):
        _raw_id    = r.get('id', '')
        _cid       = r.get('cid', '')
        _id_suffix = _raw_id.replace(_cid + '_', '', 1) if _raw_id.startswith(_cid + '_') else _raw_id
        _disc_host = r.get('last_discoverer_hostname') or (r.get('discoverer_hostnames') or [None])[0]
        hostname   = (r.get('hostname')
                      or (_disc_host and f'<em title="Discovered by {_disc_host}" class="mono">{_disc_host}</em>')
                      or f'<em class="mono">{_id_suffix[:20]}…</em>')
        platform   = r.get('platform_name') or '—'
        os_ver     = (r.get('os_version') or '—')[:32]
        ip         = r.get('current_local_ip') or (r.get('local_ip_addresses') or [''])[0] or '—'
        provider   = r.get('cloud_provider') or '—'
        prod_type  = r.get('product_type_desc') or '—'
        row_cls    = 'alt' if i % 2 else ''
        unsp_rows_html += (
            f'<tr class="{row_cls}">'
            f'<td>{hostname}</td>'
            f'<td style="text-align:center">{platform}</td>'
            f'<td>{os_ver}</td>'
            f'<td><span class="mono">{ip}</span></td>'
            f'<td style="color:{GREY3}">{provider}</td>'
            f'<td style="color:{GREY2}">{prod_type}</td>'
            f'</tr>'
        )
        _unsupported_csv_rows.append([
            r.get('hostname') or _disc_host or _id_suffix[:32],
            r.get('platform_name') or '',
            r.get('os_version') or '',
            ip,
            r.get('cloud_provider') or '',
            r.get('product_type_desc') or '',
            (r.get('first_seen_timestamp') or '')[:10],
            (r.get('last_seen_timestamp') or '')[:10],
        ])

    s8 = f"""
<section id="s8">
  <div style="display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:6px">
    {_sh(8, "Appendix — Asset Detail Lists", ORANGE)}
  </div>
  {_api_panel(
      apis=['Discover.query_hosts', 'Discover.get_hosts'],
      logic_items=[
          'Full dump of <code>coverage_gaps</code> JSON from inventory collection',
          'Amber row = cloud-hosted unmanaged asset (<code>service_provider</code> in cloud set)',
          'Container signal heuristic from <code>resource_id</code>, <code>hostname</code>, <code>os_version</code> fields',
          'Unmanaged list: <code>managed_by</code> not "Supported" and not "Not Supported"',
          'Unsupported list: <code>managed_by:\'Not Supported\'</code>',
      ],
      fql="managed_by:!'Supported' (unmanaged) / managed_by:'Not Supported' (unsupported)",
      conflicts=[
          'These lists are sourced entirely from the Discover API and are <strong>not cross-referenced against the Hosts API</strong>. A host appearing in the unmanaged list may already be managed (sensor installed) but not yet de-listed from Discover due to API sync delay. Confirming sensor deployment for a listed host requires checking the Hosts API separately.',
      ]
  )}
  {_legend([
      ('Unmanaged (amber)',   'Host discovered by Falcon with no sensor; amber row = cloud-hosted; these can accept a sensor'),
      ('Unsupported (grey)',  'Host that cannot run the Falcon sensor at all — IoT, network device, or unsupported OS'),
      ('Discoverer',          'The Falcon-managed host that detected this unmanaged asset via network scan or ARP'),
      ('Confidence',          'Falcon\'s confidence score for the asset discovery — higher = more reliable identification'),
      ('Container signal',    'Heuristic flag: hostname, resource_id, or OS version pattern suggests this is a container'),
      ('Sync lag',            'Asset may already be managed in the Hosts API but not yet removed from Discover — verify before deploying sensors'),
  ])}
  <div style="display:flex;gap:8px;margin-bottom:4px">
    <a href="#s8-unmanaged" style="font-size:11px;padding:3px 10px;border-radius:3px;background:#FFF3E0;color:{ORANGE};text-decoration:none;font-weight:600">&#9660; Unmanaged ({_fmt(unmanaged)})</a>
    <a href="#s8-unsupported" style="font-size:11px;padding:3px 10px;border-radius:3px;background:#F5F5F5;color:{GREY2};text-decoration:none;font-weight:600">&#9660; Unsupported ({_fmt(unsupported)})</a>
  </div>

  <div id="s8-unmanaged" style="display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:4px;margin-top:16px">
    <h3 style="margin:0;font-size:14px;font-weight:700;color:{ORANGE}">
      Unmanaged Assets — {_fmt(unmanaged)} hosts (can accept sensor)
    </h3>
    <button class="export-btn" onclick="exportCSV('unmanaged_assets')">&#8595; Export CSV</button>
  </div>
  <p class="note">
    Assets capable of running the Falcon sensor with no sensor installed. &nbsp;
    <span style="background:#FFF3E0;padding:1px 6px;border-radius:3px;color:{ORANGE}">Amber rows</span> = cloud-hosted. &nbsp;
    <strong>Ctrs</strong>: <strong style="color:{CYAN}">likely</strong> = container OS/provider/hostname detected,
    <strong>possible</strong> = Linux VM in cloud,
    <strong>—</strong> = no signal. &nbsp;
    <strong>Conf</strong> = discovery confidence %.
  </p>
  <div class="app-scroll">
    <table class="dt app-table">
      <thead><tr>
        <th>Hostname / ID</th><th>Platform</th><th>OS Version</th>
        <th>IP Address</th><th>Cloud Provider</th><th>Conf</th><th>Ctrs</th>
      </tr></thead>
      <tbody>{rows_html}</tbody>
    </table>
  </div>

  <div style="border-top:1px solid #eee;margin:24px 0 16px"></div>

  <div id="s8-unsupported" style="display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:4px">
    <h3 style="margin:0;font-size:14px;font-weight:700;color:{GREY2}">
      Unsupported Assets — {_fmt(unsupported)} hosts (cannot run sensor)
    </h3>
    <button class="export-btn" onclick="exportCSV('unsupported_assets')">&#8595; Export CSV</button>
  </div>
  <p class="note">
    Devices that cannot run the Falcon sensor (IoT, routers, network appliances, unidentified endpoints).
    These are permanent blind spots requiring alternative security controls.
  </p>
  <div class="app-scroll">
    <table class="dt app-table">
      <thead><tr>
        <th>Hostname / ID</th><th>Platform</th><th>OS Version</th>
        <th>IP Address</th><th>Cloud Provider</th><th>Product Type</th>
      </tr></thead>
      <tbody>{unsp_rows_html if unsupported_records else '<tr><td colspan="6" style="text-align:center;color:#aaa">No unsupported assets found</td></tr>'}</tbody>
    </table>
  </div>
</section>"""

    # ── ASSEMBLE ───────────────────────────────────────────────
    nav = f"""
<nav class="nav">
  <div class="nav-brand">
    <svg viewBox="0 0 40 46" width="18" height="21">
      <polygon points="20,1 38,11 38,35 20,45 2,35 2,11" fill="{RED}"/>
    </svg>
    CrowdStrike Falcon
  </div>
  <div class="nav-links">
    <a href="#s1">Coverage</a>
    <a href="#s2">Managed Hosts</a>
    <a href="#s3">Cloud &amp; K8s</a>
    <a href="#s4">Cloud Coverage</a>
    <a href="#s5">Containers</a>
    <a href="#s6">Unsupported</a>
    <a href="#s7">Recommendations</a>
    <a href="#s8">Appendix</a>
  </div>
</nav>"""

    footer = (
        f'<footer>Data sourced from CrowdStrike Falcon API ({cloud_name}) &nbsp;·&nbsp; '
        f'Generated {ts_display} &nbsp;·&nbsp; '
        f'CONFIDENTIAL — authorized personnel only</footer>'
    )

    _js_data = json.dumps({
        'unmanaged_assets':   {'filename': 'unmanaged_assets.csv',      'rows': _unmanaged_csv_rows},
        'kac_clusters':       {'filename': 'kac_iar_clusters.csv',       'rows': _kac_csv_rows},
        'csa_unprotected':    {'filename': 'csa_unprotected_assets.csv', 'rows': _csa_csv_rows},
        'csa_managed_assets': {'filename': 'csa_managed_assets.csv',     'rows': _csa_mgd_csv_rows},
        'unsupported_assets': {'filename': 'unsupported_assets.csv',     'rows': _unsupported_csv_rows},
    }, ensure_ascii=False)

    _js = f"""<script>
var CSV_DATA = {_js_data};
function exportCSV(key) {{
    var d = CSV_DATA[key];
    if (!d) return;
    var csv = d.rows.map(function(row) {{
        return row.map(function(cell) {{
            var s = String(cell == null ? '' : cell).replace(/"/g, '""');
            return /[,\\n"]/.test(s) ? '"' + s + '"' : s;
        }}).join(',');
    }}).join('\\n');
    var blob = new Blob([csv], {{type: 'text/csv'}});
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = d.filename;
    a.click();
    URL.revokeObjectURL(a.href);
}}
</script>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CrowdStrike Falcon — Asset Inventory Report — {ts_display}</title>
<style>{CSS}</style>
</head>
<body>
{nav}
{cover}
{s1}
{s2}
{s3}
{s4_csa}
{s5}
{s6}
{s7}
{s8}
{footer}
{_js}
</body>
</html>"""

    print("Building HTML…")
    with open(out_path, 'w', encoding='utf-8') as fh:
        fh.write(html)
    size_kb = os.path.getsize(out_path) / 1024
    print(f"✓ Report written to: {out_path}  ({size_kb:.0f} KB)")


# ── ENTRY POINT ────────────────────────────────────────────────
if __name__ == '__main__':
    if len(sys.argv) >= 2:
        json_path = sys.argv[1]
    else:
        matches = sorted(glob.glob('falcon_hosts_inventory_*.json'), reverse=True)
        if not matches:
            print("ERROR: no falcon_hosts_inventory_*.json found.")
            print("Usage: python3 generate_report.py [inventory.json] [output.html]")
            sys.exit(1)
        json_path = matches[0]
        print(f"Using most recent inventory: {json_path}")

    if not os.path.exists(json_path):
        print(f"ERROR: file not found: {json_path}")
        sys.exit(1)

    if len(sys.argv) >= 3:
        out_path = sys.argv[2]
    else:
        base = os.path.splitext(os.path.basename(json_path))[0]
        ts   = base.split('_')[-1]
        out_path = f"falcon_asset_report_{ts}.html"

    build_html(json_path, out_path)
