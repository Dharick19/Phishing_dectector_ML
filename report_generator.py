#!/usr/bin/env python3
"""
📊 HTML Report Generator for Phishing Detector
"""

import os
from datetime import datetime


def generate_html_report(result: dict, output_dir="reports") -> str:
    os.makedirs(output_dir, exist_ok=True)

    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(output_dir, f"phishing_report_{ts}.html")
    score    = result["final_score"]
    verdict  = result["verdict"]
    vt       = result.get("virustotal", {})

    if score >= 70:
        verdict_color = "#f85149"
        verdict_bg    = "#f8514915"
        verdict_icon  = "🔴"
    elif score >= 40:
        verdict_color = "#d29922"
        verdict_bg    = "#d2992215"
        verdict_icon  = "🟡"
    else:
        verdict_color = "#3fb950"
        verdict_bg    = "#3fb95015"
        verdict_icon  = "🟢"

    score_pct   = score
    score_color = verdict_color

    reasons_html = ""
    for r in sorted(result.get("reasons", []), key=lambda x: -x["pts"]):
        bar = "█" * min(r["pts"], 25)
        reasons_html += f"""
        <tr>
          <td><span style="background:#f8514922;color:#f85149;padding:2px 8px;border-radius:4px;font-weight:700;font-size:12px;">+{r['pts']}</span></td>
          <td style="color:#e6edf3;padding:8px 12px;">{r['msg']}</td>
          <td style="color:#f85149;font-size:13px;letter-spacing:-1px;">{bar}</td>
        </tr>"""

    features = result.get("features", {})
    features_html = ""
    for k, v in features.items():
        label = k.replace("_", " ").title()
        val   = str(v) if not isinstance(v, float) else f"{v:.2f}"
        flag  = "⚠️" if (k == "has_ip" and v) or (k == "suspicious_tld" and v) or \
                        (k == "has_at_symbol" and v) or (k == "is_shortened" and v) else ""
        features_html += f"""
        <tr>
          <td style="color:#7d8590;padding:6px 12px;font-size:12px;">{label}</td>
          <td style="color:#e6edf3;padding:6px 12px;font-size:12px;">{val} {flag}</td>
        </tr>"""

    vt_html = ""
    if vt.get("available"):
        vt_html = f"""
        <div style="background:#161b22;border:1px solid #30363d;border-radius:10px;padding:20px;margin-top:24px;">
          <h3 style="color:#58a6ff;margin-bottom:16px;">🌐 VirusTotal Results</h3>
          <div style="display:flex;gap:24px;flex-wrap:wrap;margin-bottom:14px;">
            <div style="text-align:center"><div style="font-size:28px;font-weight:800;color:#f85149">{vt['malicious']}</div><div style="color:#7d8590;font-size:12px">Malicious</div></div>
            <div style="text-align:center"><div style="font-size:28px;font-weight:800;color:#d29922">{vt['suspicious']}</div><div style="color:#7d8590;font-size:12px">Suspicious</div></div>
            <div style="text-align:center"><div style="font-size:28px;font-weight:800;color:#3fb950">{vt['harmless']}</div><div style="color:#7d8590;font-size:12px">Harmless</div></div>
            <div style="text-align:center"><div style="font-size:28px;font-weight:800;color:#7d8590">{vt['undetected']}</div><div style="color:#7d8590;font-size:12px">Undetected</div></div>
            <div style="text-align:center"><div style="font-size:28px;font-weight:800;color:#58a6ff">{vt['detection_rate']}%</div><div style="color:#7d8590;font-size:12px">Detection Rate</div></div>
          </div>
          <div style="background:#0d1117;border-radius:6px;height:10px;overflow:hidden;margin-bottom:10px;">
            <div style="width:{vt['detection_rate']}%;height:100%;background:linear-gradient(90deg,#f85149,#d29922);"></div>
          </div>
          <a href="{vt.get('link','#')}" target="_blank" style="color:#58a6ff;font-size:13px;">
            View full VirusTotal report →
          </a>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Phishing Report — {result['url'][:50]}</title>
<style>
  body {{ background:#0d1117; color:#e6edf3; font-family:'Segoe UI',system-ui,sans-serif; margin:0; padding:32px 16px; }}
  .container {{ max-width:860px; margin:0 auto; }}
  h1 {{ font-size:24px; margin-bottom:4px; }}
  h2 {{ font-size:16px; color:#7d8590; margin-bottom:24px; font-weight:400; }}
  h3 {{ font-size:15px; margin-bottom:12px; }}
  table {{ width:100%; border-collapse:collapse; }}
  .card {{ background:#161b22; border:1px solid #30363d; border-radius:10px; padding:20px; margin-bottom:20px; }}
  .watermark {{ text-align:center; color:#30363d; font-size:12px; margin-top:40px; }}
</style>
</head>
<body>
<div class="container">

  <!-- Header -->
  <div style="display:flex;align-items:center;gap:12px;margin-bottom:28px;padding-bottom:20px;border-bottom:1px solid #30363d;">
    <span style="font-size:36px;">🎣</span>
    <div>
      <h1>Phishing Detection Report</h1>
      <h2>Generated: {result.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}</h2>
    </div>
  </div>

  <!-- Verdict -->
  <div class="card" style="background:{verdict_bg};border-color:{verdict_color}44;">
    <div style="display:flex;align-items:center;gap:16px;flex-wrap:wrap;">
      <div>
        <div style="font-size:13px;color:#7d8590;margin-bottom:4px;">VERDICT</div>
        <div style="font-size:28px;font-weight:800;color:{verdict_color};">{verdict_icon} {verdict}</div>
      </div>
      <div style="margin-left:auto;text-align:right;">
        <div style="font-size:13px;color:#7d8590;margin-bottom:4px;">RISK SCORE</div>
        <div style="font-size:36px;font-weight:900;color:{verdict_color};">{score}<span style="font-size:18px;color:#7d8590;">/100</span></div>
      </div>
    </div>
    <div style="background:#0d1117;border-radius:6px;height:12px;overflow:hidden;margin-top:16px;">
      <div style="width:{score_pct}%;height:100%;background:linear-gradient(90deg,#3fb950,{score_color});transition:width .6s;"></div>
    </div>
  </div>

  <!-- URL Info -->
  <div class="card">
    <h3>🔗 URL Details</h3>
    <table>
      <tr><td style="color:#7d8590;padding:6px 0;font-size:13px;width:140px;">Full URL</td>
          <td style="color:#e6edf3;font-size:13px;word-break:break-all;">{result['url']}</td></tr>
      <tr><td style="color:#7d8590;padding:6px 0;font-size:13px;">ML Score</td>
          <td style="color:#e6edf3;font-size:13px;">{result.get('ml_score','N/A')}% phishing probability</td></tr>
      <tr><td style="color:#7d8590;padding:6px 0;font-size:13px;">Rule Score</td>
          <td style="color:#e6edf3;font-size:13px;">{result['rule_score']}/100</td></tr>
      <tr><td style="color:#7d8590;padding:6px 0;font-size:13px;">ML Label</td>
          <td style="color:#e6edf3;font-size:13px;">{result.get('ml_label','N/A')}</td></tr>
    </table>
  </div>

  <!-- Risk Factors -->
  <div class="card">
    <h3>⚠️ Risk Factors ({len(result.get('reasons',[]))} detected)</h3>
    {"<p style='color:#3fb950;font-size:13px;'>✅ No risk factors detected — URL appears safe.</p>" if not result.get('reasons') else f"<table>{reasons_html}</table>"}
  </div>

  {vt_html}

  <!-- Features -->
  <div class="card">
    <h3>🔬 Extracted Features</h3>
    <table>{features_html}</table>
  </div>

  <div class="watermark">
    Generated by 🎣 Phishing Detector — For educational & research use only
  </div>
</div>
</body>
</html>"""

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)

    return filename