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
        conn.commit()
    finally:
        conn.close()


@app.get('/api/events')
def list_events(
    q: Optional[str] = Query(default=None),
    channel: Optional[str] = Query(default=None),
    event_id: Optional[str] = Query(default=None),
    user_sid: Optional[str] = Query(default=None),
    provider: Optional[str] = Query(default=None),
    since: Optional[str] = Query(default=None),
    until: Optional[str] = Query(default=None),
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
        if user_sid:
            clauses.append('user_sid = ?')
            params.append(user_sid)
        if provider:
            clauses.append('provider = ?')
            params.append(provider)
        if since:
            clauses.append('timestamp >= ?')
            params.append(since)
        if until:
            clauses.append('timestamp <= ?')
            params.append(until)
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
  <title>Win EVTX Analyzer</title>
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
  </style>
  <script src='https://cdn.jsdelivr.net/npm/chart.js'></script>
</head>
<body>
  <div class='row' style='justify-content: space-between;'>
    <h2>Win EVTX Analyzer</h2>
    <div>
      <button onclick='toggleTheme()' id='themeBtn'>Dark mode</button>
      <button onclick='saveQuery()'>Save query</button>
      <button onclick='loadQuery()'>Load query</button>
      <select id='savedSelect'></select>
      <button onclick='deleteQuery()'>Delete</button>
    </div>
  </div>
  <div class='toolbar'>
    <input id='q' placeholder='Search text...' />
    <input id='channel' placeholder='Channel (es. Security)' />
    <input id='event' placeholder='Event ID (es. 4624)' />
    <input id='user_sid' placeholder='User SID' />
    <input id='provider' placeholder='Provider' />
    <label>Since</label><input id='since' placeholder='YYYY-MM-DDTHH:MM:SSZ' />
    <label>Until</label><input id='until' placeholder='YYYY-MM-DDTHH:MM:SSZ' />
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
      <div id='detail'>Seleziona una riga per vedere i dettagli.</div>
      <div style='margin-top:8px;'>
        <button id='downloadBtn' style='display:none;' onclick='downloadCurrent()'>Download JSON</button>
      </div>
    </div>
  </div>
  <script>
    let limit = 50;
    let offset = 0;
    let lastQuery = {};
    let sortBy = 'timestamp';
    let sortDir = 'desc';
    let currentId = null;
    let chartTrend, chartTopIds, chartTopChannels;

    function paramsObj() {
      const q = document.getElementById('q').value;
      const channel = document.getElementById('channel').value;
      const event_id = document.getElementById('event').value;
      const user_sid = document.getElementById('user_sid').value;
      const provider = document.getElementById('provider').value;
      const since = document.getElementById('since').value;
      const until = document.getElementById('until').value;
      const obj = { limit, offset, sort_by: sortBy, sort_dir: sortDir };
      if (q) obj.q = q;
      if (channel) obj.channel = channel;
      if (event_id) obj.event_id = event_id;
      if (user_sid) obj.user_sid = user_sid;
      if (provider) obj.provider = provider;
      if (since) obj.since = since;
      if (until) obj.until = until;
      return obj;
    }

    function qs(obj) {
      return Object.entries(obj).map(([k,v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&');
    }

    function setSort(col) {
      if (sortBy === col) {
        sortDir = (sortDir === 'asc') ? 'desc' : 'asc';
      } else {
        sortBy = col;
        sortDir = 'asc';
      }
      load(0);
    }

    async function load(newOffset) {
      if (newOffset !== undefined) offset = newOffset;
      const p = paramsObj();
      lastQuery = p;
      const res = await fetch('/api/events?' + qs(p));
      const data = await res.json();
      document.getElementById('total').innerText = 'Total: ' + data.total;
      document.getElementById('pageinfo').innerText = `offset ${offset} • showing ${data.items.length} • sort ${sortBy} ${sortDir}`;
      const rows = document.getElementById('rows');
      rows.innerHTML = '';
      for (const it of data.items) {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${it.timestamp||''}</td><td>${it.channel||''}</td><td>${it.event_id||''}</td><td>${it.computer||''}</td><td>${it.provider||''}</td><td>${it.user_sid||''}</td>`;
        tr.onclick = () => showDetail(it.id);
        rows.appendChild(tr);
      }
      loadCharts();
    }

    async function showDetail(id) {
      const res = await fetch('/api/events/' + id);
      const data = await res.json();
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
      currentId = id;
      document.getElementById('downloadBtn').style.display = 'inline-block';
    }

    async function downloadCurrent() {
      if (!currentId) return;
      const res = await fetch('/api/events/' + currentId + '/download');
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `event_${currentId}.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    }

    function nextPage() {
      offset += limit;
      load(offset);
    }
    function prevPage() {
      offset = Math.max(0, offset - limit);
      load(offset);
    }

    async function loadCharts() {
      const tRes = await fetch('/api/stats/trend?bucket=hour');
      const tData = await tRes.json();
      const tLabels = tData.items.map(x => x.ts);
      const tValues = tData.items.map(x => x.value);
      if (chartTrend) chartTrend.destroy();
      chartTrend = new Chart(document.getElementById('chartTrend').getContext('2d'), {
        type: 'line',
        data: { labels: tLabels, datasets: [{ label: 'Events/hour', data: tValues, borderColor: '#2b7', fill: false }] },
        options: { responsive: true, scales: { y: { beginAtZero: true } } }
      });

      const idRes = await fetch('/api/stats/top_event_ids');
      const idData = await idRes.json();
      const idLabels = idData.items.map(x => x.label || '(null)');
      const idValues = idData.items.map(x => x.value);
      if (chartTopIds) chartTopIds.destroy();
      chartTopIds = new Chart(document.getElementById('chartTopIds').getContext('2d'), {
        type: 'bar',
        data: { labels: idLabels, datasets: [{ label: 'Count', data: idValues, backgroundColor: '#58f' }] },
        options: { responsive: true, indexAxis: 'y', scales: { x: { beginAtZero: true } } }
      });

      const chRes = await fetch('/api/stats/top_channels');
      const chData = await chRes.json();
      const chLabels = chData.items.map(x => x.label || '(null)');
      const chValues = chData.items.map(x => x.value);
      if (chartTopChannels) chartTopChannels.destroy();
      chartTopChannels = new Chart(document.getElementById('chartTopChannels').getContext('2d'), {
        type: 'bar',
        data: { labels: chLabels, datasets: [{ label: 'Count', data: chValues, backgroundColor: '#fa5' }] },
        options: { responsive: true, indexAxis: 'y', scales: { x: { beginAtZero: true } } }
      });
    }

    function toggleTheme() {
      document.body.classList.toggle('dark');
      const mode = document.body.classList.contains('dark') ? 'dark' : 'light';
      localStorage.setItem('theme', mode);
      document.getElementById('themeBtn').innerText = mode === 'dark' ? 'Light mode' : 'Dark mode';
    }

    function applyThemeFromStorage() {
      const mode = localStorage.getItem('theme') || 'light';
      if (mode === 'dark') document.body.classList.add('dark');
      document.getElementById('themeBtn').innerText = mode === 'dark' ? 'Light mode' : 'Dark mode';
    }

    function refreshSaved() {
      const sel = document.getElementById('savedSelect');
      sel.innerHTML = '';
      const saved = JSON.parse(localStorage.getItem('savedQueries') || '{}');
      Object.keys(saved).forEach(name => {
        const opt = document.createElement('option');
        opt.value = name; opt.text = name; sel.appendChild(opt);
      });
    }

    function saveQuery() {
      const name = prompt('Nome query da salvare:');
      if (!name) return;
      const saved = JSON.parse(localStorage.getItem('savedQueries') || '{}');
      saved[name] = paramsObj();
      localStorage.setItem('savedQueries', JSON.stringify(saved));
      refreshSaved();
    }

    function loadQuery() {
      const sel = document.getElementById('savedSelect');
      const name = sel.value; if (!name) return;
      const saved = JSON.parse(localStorage.getItem('savedQueries') || '{}');
      const q = saved[name]; if (!q) return;
      document.getElementById('q').value = q.q || '';
      document.getElementById('channel').value = q.channel || '';
      document.getElementById('event').value = q.event_id || '';
      document.getElementById('user_sid').value = q.user_sid || '';
      document.getElementById('provider').value = q.provider || '';
      document.getElementById('since').value = q.since || '';
      document.getElementById('until').value = q.until || '';
      sortBy = q.sort_by || 'timestamp';
      sortDir = q.sort_dir || 'desc';
      load(0);
    }

    function deleteQuery() {
      const sel = document.getElementById('savedSelect');
      const name = sel.value; if (!name) return;
      const saved = JSON.parse(localStorage.getItem('savedQueries') || '{}');
      delete saved[name];
      localStorage.setItem('savedQueries', JSON.stringify(saved));
      refreshSaved();
    }

    applyThemeFromStorage();
    refreshSaved();
    load(0);
  </script>
</body>
</html>
"""
