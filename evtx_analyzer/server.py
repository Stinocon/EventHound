import os
import json
import sqlite3
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, Query, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

DB_PATH = os.path.join(os.getcwd(), 'outputs', 'events.db')

app = FastAPI(title='Win EVTX Analyzer')
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _get_db() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = _get_db()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY,
                timestamp TEXT,
                channel TEXT,
                event_id TEXT,
                computer TEXT,
                provider TEXT,
                record_id TEXT,
                user_sid TEXT,
                data_json TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY,
                event_timestamp TEXT,
                channel TEXT,
                event_id TEXT,
                rule_id TEXT,
                severity TEXT,
                description TEXT,
                tags TEXT,
                event_ref INTEGER
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


@app.get('/api/events')
def list_events(
    q: Optional[str] = Query(default=None),
    channel: Optional[str] = Query(default=None),
    event_id: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    sort_by: str = Query(default='timestamp'),
    sort_dir: str = Query(default='desc'),
):
    conn = _get_db()
    try:
        clauses = []
        params: List[Any] = []
        if q:
            clauses.append('(data_json LIKE ? OR computer LIKE ? OR provider LIKE ? OR user_sid LIKE ?)')
            like = f'%{q}%'
            params += [like, like, like, like]
        if channel:
            clauses.append('channel = ?')
            params.append(channel)
        if event_id:
            clauses.append('event_id = ?')
            params.append(event_id)
        where = 'WHERE ' + ' AND '.join(clauses) if clauses else ''
        allowed_cols = {'timestamp','channel','event_id','computer','provider','user_sid'}
        if sort_by not in allowed_cols:
            sort_by = 'timestamp'
        sort_dir = 'ASC' if str(sort_dir).lower() == 'asc' else 'DESC'
        sql = f"SELECT * FROM events {where} ORDER BY {sort_by} {sort_dir} LIMIT ? OFFSET ?"
        params_w_limit = params + [limit, offset]
        rows = [dict(r) for r in conn.execute(sql, params_w_limit)]
        for r in rows:
            if isinstance(r.get('data_json'), str):
                try:
                    r['data'] = json.loads(r['data_json'])
                except Exception:
                    r['data'] = None
        total = conn.execute(f"SELECT COUNT(*) as c FROM events {where}", params).fetchone()['c'] if where else conn.execute("SELECT COUNT(*) as c FROM events").fetchone()['c']
        return {"items": rows, "total": total}
    finally:
        conn.close()


@app.get('/api/events/{event_pk}')
def get_event(event_pk: int):
    conn = _get_db()
    try:
        row = conn.execute("SELECT * FROM events WHERE id = ?", (event_pk,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail='Not found')
        data = dict(row)
        if isinstance(data.get('data_json'), str):
            try:
                data['data'] = json.loads(data['data_json'])
            except Exception:
                data['data'] = None
        return data
    finally:
        conn.close()


@app.get('/api/events/{event_pk}/download')
def download_event(event_pk: int):
    conn = _get_db()
    try:
        row = conn.execute("SELECT * FROM events WHERE id = ?", (event_pk,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail='Not found')
        data = dict(row)
        if isinstance(data.get('data_json'), str):
            try:
                data['data'] = json.loads(data['data_json'])
            except Exception:
                data['data'] = None
        payload = {k: v for k, v in data.items() if k != 'data_json'}
        headers = {"Content-Disposition": f"attachment; filename=event_{event_pk}.json"}
        return JSONResponse(content=payload, headers=headers)
    finally:
        conn.close()


@app.get('/api/findings')
def list_findings(
    q: Optional[str] = Query(default=None),
    rule_id: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    channel: Optional[str] = Query(default=None),
    event_id: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    sort_by: str = Query(default='event_timestamp'),
    sort_dir: str = Query(default='desc'),
):
    conn = _get_db()
    try:
        clauses = []
        params: List[Any] = []
        if q:
            like = f'%{q}%'
            clauses.append('(description LIKE ? OR tags LIKE ? OR rule_id LIKE ?)')
            params += [like, like, like]
        if rule_id:
            clauses.append('rule_id = ?')
            params.append(rule_id)
        if severity:
            clauses.append('severity = ?')
            params.append(severity)
        if channel:
            clauses.append('channel = ?')
            params.append(channel)
        if event_id:
            clauses.append('event_id = ?')
            params.append(event_id)
        where = 'WHERE ' + ' AND '.join(clauses) if clauses else ''
        allowed_cols = {'event_timestamp','channel','event_id','rule_id','severity'}
        if sort_by not in allowed_cols:
            sort_by = 'event_timestamp'
        sort_dir = 'ASC' if str(sort_dir).lower() == 'asc' else 'DESC'
        sql = f"SELECT * FROM findings {where} ORDER BY {sort_by} {sort_dir} LIMIT ? OFFSET ?"
        params_w_limit = params + [limit, offset]
        rows = [dict(r) for r in conn.execute(sql, params_w_limit)]
        total = conn.execute(f"SELECT COUNT(*) as c FROM findings {where}", params).fetchone()['c'] if where else conn.execute("SELECT COUNT(*) as c FROM findings").fetchone()['c']
        return {"items": rows, "total": total}
    finally:
        conn.close()


@app.get('/api/stats/top_event_ids')
def stats_top_event_ids(limit: int = Query(default=10, ge=1, le=100)):
    conn = _get_db()
    try:
        rows = conn.execute(
            "SELECT event_id as label, COUNT(*) as value FROM events GROUP BY event_id ORDER BY value DESC LIMIT ?",
            (limit,)
        ).fetchall()
        return {"items": [dict(r) for r in rows]}
    finally:
        conn.close()


@app.get('/api/stats/top_channels')
def stats_top_channels(limit: int = Query(default=10, ge=1, le=100)):
    conn = _get_db()
    try:
        rows = conn.execute(
            "SELECT channel as label, COUNT(*) as value FROM events GROUP BY channel ORDER BY value DESC LIMIT ?",
            (limit,)
        ).fetchall()
        return {"items": [dict(r) for r in rows]}
    finally:
        conn.close()


@app.get('/api/stats/trend')
def stats_trend(bucket: str = Query(default='hour')):
    if bucket not in ('hour','day'):
        bucket = 'hour'
    if bucket == 'hour':
        select = "substr(timestamp,1,13) || ':00:00Z'"
    else:
        select = "substr(timestamp,1,10)"
    conn = _get_db()
    try:
        rows = conn.execute(
            f"SELECT {select} as ts, COUNT(*) as value FROM events GROUP BY ts ORDER BY ts ASC"
        ).fetchall()
        return {"items": [dict(r) for r in rows]}
    finally:
        conn.close()


@app.get('/', response_class=HTMLResponse)
def index():
    return """
<!doctype html>
<html>
<head>
  <meta charset='utf-8'>
  <title>EventHound</title>
  <style>
    :root { --bg:#ffffff; --fg:#111; --muted:#666; --card:#fff; --border:#ddd; --pill:#eef; --accent:#2b7; }
    .dark { --bg:#0f1217; --fg:#e8edf2; --muted:#9aa7b2; --card:#111722; --border:#223; --pill:#1e2636; --accent:#4ad; }
    body { background: var(--bg); color: var(--fg); font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 24px; }
    input, select, button { background: var(--card); color: var(--fg); border:1px solid var(--border); border-radius:6px; padding: 6px 8px; margin-right: 8px; }
    table { border-collapse: collapse; width: 100%; margin-top: 12px; }
    th, td { text-align: left; border-bottom: 1px solid var(--border); padding: 6px 8px; }
    th.sortable { user-select:none; }
    tr:hover { background: rgba(127,127,127,0.08); cursor: pointer; }
    .toolbar { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
    .pill { padding: 2px 8px; border-radius: 999px; background:var(--pill); font-size:12px; }
    .grid { display: grid; grid-template-columns: 2fr 1fr; gap: 16px; }
    .card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 12px; }
    pre { background: #0b1021; color: #e0e6f1; padding: 12px; border-radius: 6px; overflow: auto; }
    .charts { display:grid; grid-template-columns:1fr 1fr; gap:16px; margin-top:16px; }
    .row { display:flex; align-items:center; gap:8px; flex-wrap:wrap; }
    label { color: var(--muted); font-size: 12px; }
    .tabs { display:flex; gap: 8px; margin-bottom: 12px; }
    .tab { padding:6px 10px; border:1px solid var(--border); border-radius:6px; cursor:pointer; }
    .tab.active { background: var(--pill); }
    .hidden { display:none; }
  </style>
  <script src='https://cdn.jsdelivr.net/npm/chart.js'></script>
</head>
<body>
  <div class='row' style='justify-content: space-between;'>
    <h2>EventHound</h2>
    <div>
      <button onclick='toggleTheme()' id='themeBtn'>Dark mode</button>
    </div>
  </div>

  <div class='tabs'>
    <div class='tab active' id='tabEvents' onclick='showTab("events")'>Events</div>
    <div class='tab' id='tabFindings' onclick='showTab("findings")'>Findings</div>
  </div>

  <div id='viewEvents'>
    <div class='toolbar'>
      <input id='q' placeholder='Search text...' />
      <input id='channel' placeholder='Channel (e.g., Security)' />
      <input id='event' placeholder='Event ID (e.g., 4624)' />
      <button onclick='load(0)'>Search</button>
      <span id='total' class='pill'></span>
    </div>
    <div class='grid'>
      <div class='card'>
        <table>
          <thead>
            <tr>
              <th class='sortable' onclick="setSort('timestamp')">Timestamp</th>
              <th class='sortable' onclick="setSort('channel')">Channel</th>
              <th class='sortable' onclick="setSort('event_id')">Event ID</th>
              <th class='sortable' onclick="setSort('computer')">Computer</th>
              <th class='sortable' onclick="setSort('provider')">Provider</th>
              <th class='sortable' onclick="setSort('user_sid')">User SID</th>
            </tr>
          </thead>
          <tbody id='rows'></tbody>
        </table>
        <div style='margin-top:8px; display:flex; justify-content: space-between; align-items:center;'>
          <div>
            <button onclick='prevPage()'>Prev</button>
            <button onclick='nextPage()'>Next</button>
          </div>
          <div class='pill' id='pageinfo'></div>
        </div>
        <div class='charts'>
          <div class='card'>
            <h3>Trend</h3>
            <canvas id='chartTrend' height='120'></canvas>
          </div>
          <div class='card'>
            <h3>Top Event IDs</h3>
            <canvas id='chartTopIds' height='120'></canvas>
          </div>
          <div class='card'>
            <h3>Top Channels</h3>
            <canvas id='chartTopChannels' height='120'></canvas>
          </div>
        </div>
      </div>
      <div class='card'>
        <h3>Event detail</h3>
        <div id='detail'>Select a row to view details.</div>
        <div style='margin-top:8px;'>
          <button id='downloadBtn' style='display:none;' onclick='downloadCurrent()'>Download JSON</button>
        </div>
      </div>
    </div>
  </div>

  <div id='viewFindings' class='hidden'>
    <div class='toolbar'>
      <input id='fq' placeholder='Search text (rule/tags/desc)...' />
      <input id='frule' placeholder='Rule ID' />
      <input id='fsev' placeholder='Severity (info/low/med/high)' />
      <input id='fchan' placeholder='Channel' />
      <input id='feid' placeholder='Event ID' />
      <button onclick='loadFindings(0)'>Search</button>
      <span id='ftotal' class='pill'></span>
    </div>
    <div class='card'>
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Channel</th>
            <th>Event</th>
            <th>Rule</th>
            <th>Severity</th>
            <th>Description</th>
            <th>Tags</th>
          </tr>
        </thead>
        <tbody id='frows'></tbody>
      </table>
      <div style='margin-top:8px; display:flex; justify-content: space-between; align-items:center;'>
        <div>
          <button onclick='prevFindings()'>Prev</button>
          <button onclick='nextFindings()'>Next</button>
        </div>
        <div class='pill' id='fpageinfo'></div>
      </div>
    </div>
  </div>

  <script>
    // THEME
    function toggleTheme() {
      document.body.classList.toggle('dark');
      const mode = document.body.classList.contains('dark') ? 'dark' : 'light';
      localStorage.setItem('theme', mode);
      document.getElementById('themeBtn').innerText = mode === 'dark' ? 'Light mode' : 'Dark mode';
    }
    (function(){ const mode = localStorage.getItem('theme') || 'light'; if (mode==='dark') document.body.classList.add('dark'); document.getElementById('themeBtn').innerText = mode==='dark' ? 'Light mode' : 'Dark mode'; })();

    // TABS
    function showTab(name) {
      const isEvents = name === 'events';
      document.getElementById('viewEvents').classList.toggle('hidden', !isEvents);
      document.getElementById('viewFindings').classList.toggle('hidden', isEvents);
      document.getElementById('tabEvents').classList.toggle('active', isEvents);
      document.getElementById('tabFindings').classList.toggle('active', !isEvents);
      if (!isEvents) { loadFindings(0); }
    }

    // EVENTS VIEW (existing)
    let limit = 50;
    let offset = 0;
    let sortBy = 'timestamp';
    let sortDir = 'desc';
    let currentId = null;
    let chartTrend, chartTopIds, chartTopChannels;

    function qs(obj) { return Object.entries(obj).map(([k,v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&'); }

    function paramsObj() {
      const q = document.getElementById('q').value;
      const channel = document.getElementById('channel').value;
      const event_id = document.getElementById('event').value;
      const obj = { limit, offset, sort_by: sortBy, sort_dir: sortDir };
      if (q) obj.q = q;
      if (channel) obj.channel = channel;
      if (event_id) obj.event_id = event_id;
      return obj;
    }

    async function load(newOffset) {
      if (newOffset !== undefined) offset = newOffset;
      const p = paramsObj();
      const res = await fetch('/api/events?' + qs(p));
      const data = await res.json();
      document.getElementById('total').innerText = 'Total: ' + data.total;
      document.getElementById('pageinfo').innerText = `offset ${offset} • showing ${data.items.length} • sort ${sortBy} ${sortDir}`;
      const rows = document.getElementById('rows'); rows.innerHTML='';
      for (const it of data.items) {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${it.timestamp||''}</td><td>${it.channel||''}</td><td>${it.event_id||''}</td><td>${it.computer||''}</td><td>${it.provider||''}</td><td>${it.user_sid||''}</td>`;
        tr.onclick = () => showDetail(it.id);
        rows.appendChild(tr);
      }
      loadCharts();
    }

    function setSort(col) { if (sortBy===col) { sortDir = (sortDir==='asc')?'desc':'asc'; } else { sortBy=col; sortDir='asc'; } load(0); }
    function nextPage() { offset += limit; load(offset); }
    function prevPage() { offset = Math.max(0, offset - limit); load(offset); }

    async function showDetail(id) {
      const res = await fetch('/api/events/' + id); const data = await res.json();
      const detail = document.getElementById('detail');
      detail.innerHTML = `<div><b>ID</b>: ${data.id}</div>
        <div><b>Timestamp</b>: ${data.timestamp||''}</div>
        <div><b>Channel</b>: ${data.channel||''}</div>
        <div><b>Event ID</b>: ${data.event_id||''}</div>
        <div><b>Computer</b>: ${data.computer||''}</div>
        <div><b>Provider</b>: ${data.provider||''}</div>
        <div><b>User SID</b>: ${data.user_sid||''}</div>
        <div style='margin-top:8px;'><b>EventData</b>:</div>
        <pre>${JSON.stringify(data.data, null, 2)}</pre>`;
      currentId = id; document.getElementById('downloadBtn').style.display='inline-block';
    }

    async function downloadCurrent() {
      if (!currentId) return;
      const res = await fetch('/api/events/' + currentId + '/download');
      const blob = await res.blob(); const url = URL.createObjectURL(blob);
      const a = document.createElement('a'); a.href=url; a.download=`event_${currentId}.json`;
      document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
    }

    async function loadCharts() {
      const tRes = await fetch('/api/stats/trend?bucket=hour'); const tData = await tRes.json();
      const idRes = await fetch('/api/stats/top_event_ids'); const idData = await idRes.json();
      const chRes = await fetch('/api/stats/top_channels'); const chData = await chRes.json();
      const tLabels = tData.items.map(x=>x.ts); const tValues = tData.items.map(x=>x.value);
      const idLabels = idData.items.map(x=>x.label||'(null)'); const idValues = idData.items.map(x=>x.value);
      const chLabels = chData.items.map(x=>x.label||'(null)'); const chValues = chData.items.map(x=>x.value);
      if (chartTrend) chartTrend.destroy(); if (chartTopIds) chartTopIds.destroy(); if (chartTopChannels) chartTopChannels.destroy();
      chartTrend = new Chart(document.getElementById('chartTrend').getContext('2d'), { type:'line', data:{ labels:tLabels, datasets:[{ label:'Events/hour', data:tValues, borderColor:'#2b7', fill:false }] }, options:{ responsive:true, scales:{ y:{ beginAtZero:true } } } });
      chartTopIds = new Chart(document.getElementById('chartTopIds').getContext('2d'), { type:'bar', data:{ labels:idLabels, datasets:[{ label:'Count', data:idValues, backgroundColor:'#58f' }] }, options:{ responsive:true, indexAxis:'y', scales:{ x:{ beginAtZero:true } } } });
      chartTopChannels = new Chart(document.getElementById('chartTopChannels').getContext('2d'), { type:'bar', data:{ labels:chLabels, datasets:[{ label:'Count', data:chValues, backgroundColor:'#fa5' }] }, options:{ responsive:true, indexAxis:'y', scales:{ x:{ beginAtZero:true } } } });
    }

    // FINDINGS VIEW
    let flimit = 50; let foffset = 0;
    async function loadFindings(newOffset) {
      if (newOffset !== undefined) foffset = newOffset;
      const fq = document.getElementById('fq').value;
      const frule = document.getElementById('frule').value;
      const fsev = document.getElementById('fsev').value;
      const fchan = document.getElementById('fchan').value;
      const feid = document.getElementById('feid').value;
      const params = { limit: flimit, offset: foffset };
      if (fq) params.q=fq; if (frule) params.rule_id=frule; if (fsev) params.severity=fsev; if (fchan) params.channel=fchan; if (feid) params.event_id=feid;
      const res = await fetch('/api/findings?' + qs(params)); const data = await res.json();
      document.getElementById('ftotal').innerText = 'Total: ' + data.total;
      document.getElementById('fpageinfo').innerText = `offset ${foffset} • showing ${data.items.length}`;
      const rows = document.getElementById('frows'); rows.innerHTML='';
      for (const it of data.items) {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${it.event_timestamp||''}</td><td>${it.channel||''}</td><td>${it.event_id||''}</td><td>${it.rule_id||''}</td><td>${it.severity||''}</td><td>${it.description||''}</td><td>${it.tags||''}</td>`;
        rows.appendChild(tr);
      }
    }
    function nextFindings(){ foffset+=flimit; loadFindings(foffset); }
    function prevFindings(){ foffset=Math.max(0, foffset-flimit); loadFindings(foffset); }

    // initial load
    load(0);
  </script>
</body>
</html>
"""
