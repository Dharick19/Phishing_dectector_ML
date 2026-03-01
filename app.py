#!/usr/bin/env python3
"""
🌐 Phishing Detector — Flask Web Dashboard
"""

import json
import os
from flask import Flask, render_template_string, request, jsonify, send_file
from detector import PhishingDetector, get_history, get_stats
from report_generator import generate_html_report

app = Flask(__name__)

# ── Load config ──────────────────────────────────────────────────
VT_API_KEY = os.environ.get("VT_API_KEY", "")
detector   = PhishingDetector(vt_api_key=VT_API_KEY)

# ── HTML Template ─────────────────────────────────────────────────
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>🎣 Phishing Detector</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
<style>
  :root {
    --bg:      #0d1117;
    --card:    #161b22;
    --border:  #30363d;
    --text:    #e6edf3;
    --muted:   #7d8590;
    --red:     #f85149;
    --yellow:  #d29922;
    --green:   #3fb950;
    --blue:    #58a6ff;
    --purple:  #bc8cff;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; }

  /* Nav */
  nav { background: var(--card); border-bottom: 1px solid var(--border); padding: 14px 32px;
        display: flex; align-items: center; gap: 12px; position: sticky; top: 0; z-index: 100; }
  nav h1 { font-size: 20px; font-weight: 700; }
  nav span { color: var(--muted); font-size: 13px; margin-left: auto; }

  /* Layout */
  .container { max-width: 1200px; margin: 0 auto; padding: 32px 20px; }

  /* Scanner card */
  .scanner { background: var(--card); border: 1px solid var(--border); border-radius: 12px;
             padding: 28px; margin-bottom: 28px; }
  .scanner h2 { font-size: 18px; margin-bottom: 18px; color: var(--blue); }
  .input-row { display: flex; gap: 10px; flex-wrap: wrap; }
  .input-row input { flex: 1; min-width: 280px; padding: 12px 16px;
                     background: var(--bg); border: 1px solid var(--border);
                     border-radius: 8px; color: var(--text); font-size: 14px; }
  .input-row input:focus { outline: none; border-color: var(--blue); }
  .btn { padding: 12px 24px; border: none; border-radius: 8px; cursor: pointer;
         font-size: 14px; font-weight: 600; transition: opacity .2s; }
  .btn:hover { opacity: .85; }
  .btn-primary { background: var(--blue); color: #000; }
  .btn-secondary { background: var(--border); color: var(--text); }
  .vt-toggle { display: flex; align-items: center; gap: 8px; margin-top: 12px;
               color: var(--muted); font-size: 13px; cursor: pointer; }
  .vt-toggle input { cursor: pointer; }

  /* Result */
  .result-box { margin-top: 20px; padding: 20px; border-radius: 10px;
                border: 1px solid var(--border); display: none; }
  .result-box.show { display: block; }
  .verdict-badge { display: inline-block; padding: 6px 18px; border-radius: 20px;
                   font-weight: 700; font-size: 15px; margin-bottom: 14px; }
  .PHISHING    { background: #f8514922; color: var(--red);    border: 1px solid var(--red); }
  .SUSPICIOUS  { background: #d2992222; color: var(--yellow); border: 1px solid var(--yellow); }
  .SAFE        { background: #3fb95022; color: var(--green);  border: 1px solid var(--green); }

  .score-bar-wrap { margin: 12px 0; }
  .score-bar-bg { background: var(--border); border-radius: 6px; height: 10px; overflow: hidden; }
  .score-bar-fill { height: 100%; border-radius: 6px; transition: width .6s ease; }

  .reasons-list { margin-top: 14px; }
  .reason-item { display: flex; align-items: center; gap: 10px; padding: 7px 0;
                 border-bottom: 1px solid var(--border); font-size: 13px; }
  .reason-pts { background: #f8514933; color: var(--red); padding: 2px 8px;
                border-radius: 4px; font-weight: 700; font-size: 12px; min-width: 36px; text-align: center; }

  .vt-block { margin-top: 16px; padding: 14px; background: var(--bg);
              border-radius: 8px; border: 1px solid var(--border); }
  .vt-stats { display: flex; gap: 16px; flex-wrap: wrap; margin-top: 8px; }
  .vt-stat  { text-align: center; }
  .vt-stat .num { font-size: 22px; font-weight: 700; }
  .vt-stat .lbl { font-size: 11px; color: var(--muted); }

  /* Stats row */
  .stats-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
               gap: 16px; margin-bottom: 28px; }
  .stat-card { background: var(--card); border: 1px solid var(--border); border-radius: 10px;
               padding: 18px; text-align: center; }
  .stat-card .big { font-size: 32px; font-weight: 800; }
  .stat-card .lbl { font-size: 12px; color: var(--muted); margin-top: 4px; }

  /* Charts */
  .charts-row { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 28px; }
  @media(max-width:700px) { .charts-row { grid-template-columns: 1fr; } }
  .chart-card { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 20px; }
  .chart-card h3 { font-size: 14px; color: var(--muted); margin-bottom: 14px; }

  /* History table */
  .history-card { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 20px; }
  .history-card h3 { font-size: 16px; margin-bottom: 16px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { text-align: left; padding: 10px 12px; color: var(--muted); border-bottom: 1px solid var(--border);
       font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: .5px; }
  td { padding: 10px 12px; border-bottom: 1px solid #21262d; }
  tr:hover td { background: #21262d44; }
  .url-cell { max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

  .tag { padding: 2px 10px; border-radius: 12px; font-size: 11px; font-weight: 700; }
  .tag-PHISHING   { background: #f8514922; color: var(--red); }
  .tag-SUSPICIOUS { background: #d2992222; color: var(--yellow); }
  .tag-SAFE       { background: #3fb95022; color: var(--green); }

  .loader { display: none; text-align: center; padding: 20px; color: var(--muted); }
  .loader.show { display: block; }

  .report-btn { margin-top: 14px; }
</style>
</head>
<body>

<nav>
  <span>🎣</span>
  <h1>Phishing Detector</h1>
  <span>ML + Rules + VirusTotal</span>
</nav>

<div class="container">

  <!-- Scanner -->
  <div class="scanner">
    <h2>🔍 Scan a URL</h2>
    <div class="input-row">
      <input type="text" id="urlInput" placeholder="Enter URL to scan... e.g. http://suspicious-login.tk/verify"
             onkeydown="if(event.key==='Enter') scanUrl()">
      <button class="btn btn-primary" onclick="scanUrl()">Scan Now</button>
      <button class="btn btn-secondary" onclick="clearResult()">Clear</button>
    </div>
    <label class="vt-toggle">
      <input type="checkbox" id="vtCheck"> Enable VirusTotal check
      <span style="color:#f85149;font-size:11px;">(requires API key in config.py)</span>
    </label>

    <div class="loader" id="loader">⏳ Analyzing URL...</div>

    <div class="result-box" id="resultBox">
      <div id="verdictBadge" class="verdict-badge"></div>
      <div style="color:var(--muted);font-size:13px;" id="urlDisplay"></div>

      <div class="score-bar-wrap" style="margin-top:14px;">
        <div style="display:flex;justify-content:space-between;font-size:12px;color:var(--muted);margin-bottom:6px;">
          <span>Risk Score</span><span id="scoreText"></span>
        </div>
        <div class="score-bar-bg"><div class="score-bar-fill" id="scoreFill" style="width:0%"></div></div>
      </div>

      <div style="display:flex;gap:20px;margin-top:14px;flex-wrap:wrap;font-size:13px;">
        <div>🤖 <span style="color:var(--muted)">ML Score:</span> <span id="mlScore"></span></div>
        <div>📏 <span style="color:var(--muted)">Rule Score:</span> <span id="ruleScore"></span></div>
      </div>

      <div class="vt-block" id="vtBlock" style="display:none">
        <div style="font-size:13px;font-weight:600;margin-bottom:4px;">🌐 VirusTotal Results</div>
        <div class="vt-stats" id="vtStats"></div>
        <a id="vtLink" href="#" target="_blank"
           style="font-size:12px;color:var(--blue);margin-top:8px;display:inline-block;">
          View full report on VirusTotal →
        </a>
      </div>

      <div class="reasons-list" id="reasonsList"></div>

      <button class="btn btn-secondary report-btn" onclick="downloadReport()">📊 Download HTML Report</button>
    </div>
  </div>

  <!-- Stats -->
  <div class="stats-row" id="statsRow"></div>

  <!-- Charts -->
  <div class="charts-row">
    <div class="chart-card">
      <h3>Verdict Distribution</h3>
      <canvas id="donutChart" height="200"></canvas>
    </div>
    <div class="chart-card">
      <h3>Score Distribution</h3>
      <canvas id="barChart" height="200"></canvas>
    </div>
  </div>

  <!-- History -->
  <div class="history-card">
    <h3>📋 Scan History</h3>
    <table>
      <thead>
        <tr>
          <th>Time</th><th>URL</th><th>Verdict</th><th>Score</th><th>ML</th>
        </tr>
      </thead>
      <tbody id="historyBody"></tbody>
    </table>
  </div>

</div>

<script>
let lastResult = null;
let donutChart = null, barChart = null;

async function scanUrl() {
  const url = document.getElementById('urlInput').value.trim();
  if (!url) return;
  const useVt = document.getElementById('vtCheck').checked;

  document.getElementById('loader').classList.add('show');
  document.getElementById('resultBox').classList.remove('show');

  try {
    const res  = await fetch('/scan', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({url, use_vt: useVt})
    });
    const data = await res.json();
    lastResult = data;
    showResult(data);
    loadDashboard();
  } catch(e) {
    alert('Error scanning URL: ' + e);
  }
  document.getElementById('loader').classList.remove('show');
}

function showResult(data) {
  const box = document.getElementById('resultBox');
  box.classList.add('show');

  // Verdict badge
  const badge = document.getElementById('verdictBadge');
  const icons = {PHISHING: '🔴', SUSPICIOUS: '🟡', 'LIKELY SAFE': '🟢'};
  const cls   = data.verdict === 'LIKELY SAFE' ? 'SAFE' : data.verdict;
  badge.className = `verdict-badge ${cls}`;
  badge.textContent = `${icons[data.verdict] || ''} ${data.verdict}`;

  document.getElementById('urlDisplay').textContent = data.url;

  // Score bar
  const score = data.final_score;
  const color = score >= 70 ? '#f85149' : score >= 40 ? '#d29922' : '#3fb950';
  document.getElementById('scoreFill').style.width  = score + '%';
  document.getElementById('scoreFill').style.background = color;
  document.getElementById('scoreText').textContent  = score + '/100';

  document.getElementById('mlScore').textContent   = data.ml_score != null ? data.ml_score + '%' : 'N/A';
  document.getElementById('ruleScore').textContent = data.rule_score + '/100';

  // VirusTotal
  const vtBlock = document.getElementById('vtBlock');
  if (data.virustotal && data.virustotal.available) {
    const vt = data.virustotal;
    vtBlock.style.display = 'block';
    document.getElementById('vtStats').innerHTML = `
      <div class="vt-stat"><div class="num" style="color:#f85149">${vt.malicious}</div><div class="lbl">Malicious</div></div>
      <div class="vt-stat"><div class="num" style="color:#d29922">${vt.suspicious}</div><div class="lbl">Suspicious</div></div>
      <div class="vt-stat"><div class="num" style="color:#3fb950">${vt.harmless}</div><div class="lbl">Harmless</div></div>
      <div class="vt-stat"><div class="num" style="color:#7d8590">${vt.undetected}</div><div class="lbl">Undetected</div></div>
      <div class="vt-stat"><div class="num" style="color:#58a6ff">${vt.detection_rate}%</div><div class="lbl">Detection Rate</div></div>
    `;
    document.getElementById('vtLink').href = vt.link;
  } else {
    vtBlock.style.display = 'none';
  }

  // Reasons
  const list = document.getElementById('reasonsList');
  if (data.reasons && data.reasons.length) {
    list.innerHTML = '<div style="font-size:13px;font-weight:600;color:var(--muted);margin:14px 0 8px">⚠️ Risk Factors</div>' +
      [...data.reasons].sort((a,b) => b.pts - a.pts).map(r =>
        `<div class="reason-item">
          <span class="reason-pts">+${r.pts}</span>
          <span>${r.msg}</span>
        </div>`
      ).join('');
  } else {
    list.innerHTML = '<div style="color:var(--green);margin-top:14px;font-size:13px;">✅ No risk factors detected</div>';
  }
}

async function downloadReport() {
  if (!lastResult) return;
  const res = await fetch('/report', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(lastResult)
  });
  const blob = await res.blob();
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'phishing_report.html';
  a.click();
}

function clearResult() {
  document.getElementById('urlInput').value = '';
  document.getElementById('resultBox').classList.remove('show');
  lastResult = null;
}

async function loadDashboard() {
  const [statsRes, histRes] = await Promise.all([
    fetch('/stats').then(r => r.json()),
    fetch('/history').then(r => r.json()),
  ]);

  // Stats cards
  const sr = document.getElementById('statsRow');
  sr.innerHTML = `
    <div class="stat-card"><div class="big">${statsRes.total}</div><div class="lbl">Total Scans</div></div>
    <div class="stat-card"><div class="big" style="color:var(--red)">${statsRes.phishing}</div><div class="lbl">Phishing</div></div>
    <div class="stat-card"><div class="big" style="color:var(--yellow)">${statsRes.suspicious}</div><div class="lbl">Suspicious</div></div>
    <div class="stat-card"><div class="big" style="color:var(--green)">${statsRes.safe}</div><div class="lbl">Safe</div></div>
    <div class="stat-card"><div class="big" style="color:var(--blue)">${statsRes.avg_score}</div><div class="lbl">Avg Score</div></div>
  `;

  // Donut chart
  if (donutChart) donutChart.destroy();
  donutChart = new Chart(document.getElementById('donutChart'), {
    type: 'doughnut',
    data: {
      labels: ['Phishing', 'Suspicious', 'Safe'],
      datasets: [{ data: [statsRes.phishing, statsRes.suspicious, statsRes.safe],
        backgroundColor: ['#f85149', '#d29922', '#3fb950'], borderWidth: 0 }]
    },
    options: { plugins: { legend: { labels: { color: '#e6edf3' } } }, cutout: '65%' }
  });

  // Bar chart — score buckets
  const buckets = [0,0,0,0,0];
  histRes.forEach(r => {
    const s = r.final_score;
    if (s < 20) buckets[0]++;
    else if (s < 40) buckets[1]++;
    else if (s < 60) buckets[2]++;
    else if (s < 80) buckets[3]++;
    else buckets[4]++;
  });
  if (barChart) barChart.destroy();
  barChart = new Chart(document.getElementById('barChart'), {
    type: 'bar',
    data: {
      labels: ['0-19', '20-39', '40-59', '60-79', '80-100'],
      datasets: [{ label: 'URLs', data: buckets,
        backgroundColor: ['#3fb950','#3fb950','#d29922','#f85149','#f85149'], borderRadius: 4 }]
    },
    options: {
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: '#7d8590' }, grid: { color: '#21262d' } },
        y: { ticks: { color: '#7d8590' }, grid: { color: '#21262d' } }
      }
    }
  });

  // History table
  const tbody = document.getElementById('historyBody');
  tbody.innerHTML = histRes.slice(0, 20).map(r => {
    const tag = r.verdict === 'LIKELY SAFE' ? 'SAFE' : r.verdict;
    return `<tr>
      <td style="color:var(--muted);white-space:nowrap">${r.timestamp}</td>
      <td class="url-cell" title="${r.url}">${r.url}</td>
      <td><span class="tag tag-${tag}">${r.verdict}</span></td>
      <td style="color:${r.final_score>=70?'#f85149':r.final_score>=40?'#d29922':'#3fb950'}">${r.final_score}/100</td>
      <td style="color:var(--muted)">${r.ml_score != null ? r.ml_score+'%' : '—'}</td>
    </tr>`;
  }).join('');
}

// Load on page start
loadDashboard();
</script>
</body>
</html>
"""


# ── Routes ────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template_string(DASHBOARD_HTML)


@app.route("/scan", methods=["POST"])
def scan():
    data   = request.get_json()
    url    = data.get("url", "").strip()
    use_vt = data.get("use_vt", False)
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    result = detector.analyze(url, check_vt=use_vt)
    return jsonify(result)


@app.route("/stats")
def stats():
    return jsonify(get_stats())


@app.route("/history")
def history():
    return jsonify(get_history())


@app.route("/report", methods=["POST"])
def report():
    result = request.get_json()
    path   = generate_html_report(result)
    return send_file(path, as_attachment=True, download_name="phishing_report.html")


if __name__ == "__main__":
    print("\n  🎣 Phishing Detector Dashboard")
    print("  ─────────────────────────────")
    print("  🌐 Open: http://localhost:5000")
    print("  Press Ctrl+C to stop\n")
    app.run(debug=False, port=5000)