# reports/report_generator.py
"""
Simple HTML report with key MobSF findings + classifier verdict.
"""
from pathlib import Path
import datetime as dt
import json
from utils.config import REPORTS_DIR

HTML_TEMPLATE = """<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Fake Banking APK Detector Report</title>
<style>
 body{font-family:Arial,Helvetica,sans-serif;margin:24px;color:#222;}
 h1{margin-top:0}
 .badge{display:inline-block;padding:4px 8px;border-radius:6px;color:#fff}
 .bad{background:#d9534f}.ok{background:#5cb85c}
 pre{background:#f8f8f8;padding:12px;border-radius:6px;overflow:auto}
 table{border-collapse:collapse;margin-top:12px}
 td,th{border:1px solid #ddd;padding:6px 10px}
 .small{color:#666;font-size:12px}
</style>
</head>
<body>
<h1>Fake Banking APK Detector — Report</h1>
<p class="small">Generated: {{generated}}</p>

<h2>Summary</h2>
<p>
  APK: <b>{{apk_name}}</b><br>
  SHA256: <code>{{sha256}}</code><br>
  Verdict:
  {% if verdict == 1 %}
    <span class="badge bad">LIKELY FAKE / MALICIOUS</span>
  {% else %}
    <span class="badge ok">LIKELY GENUINE</span>
  {% endif %}
  {% if prob is not none %}(prob_fake = {{prob}}){% endif %}
</p>

<h2>Key Features</h2>
<table>
<tr><th>Feature</th><th>Value</th></tr>
{% for k,v in features.items() %}
<tr><td>{{k}}</td><td>{{v}}</td></tr>
{% endfor %}
</table>

<h2>MobSF Static Findings (excerpt)</h2>
<pre>{{mobsf_excerpt}}</pre>

</body>
</html>
"""

def _render(template: str, ctx: dict) -> str:
    # tiny placeholder renderer (avoid external deps)
    out = template
    # very basic {{var}} replacements and loops/ifs
    # For brevity, we’ll do minimal formatting: inject simple fields and dump JSON in pre.
    # (If you prefer Jinja2, add it to requirements and use a proper template.)
    out = out.replace("{{apk_name}}", ctx.get("apk_name",""))
    out = out.replace("{{sha256}}", ctx.get("sha256",""))
    out = out.replace("{{generated}}", ctx.get("generated",""))
    out = out.replace("{{prob}}", f"{ctx.get('prob'):.4f}" if ctx.get("prob") is not None else "N/A")
    verdict_html = "1" if ctx.get("verdict")==1 else "0"
    out = out.replace("{{verdict}}", verdict_html)
    # crude features table rendering
    feat_rows = ""
    for k,v in (ctx.get("features") or {}).items():
        feat_rows += f"<tr><td>{k}</td><td>{v}</td></tr>\n"
    out = out.replace(
        "<tr><th>Feature</th><th>Value</th></tr>\n{% for k,v in features.items() %}\n<tr><td>{{k}}</td><td>{{v}}</td></tr>\n{% endfor %}",
        "<tr><th>Feature</th><th>Value</th></tr>\n" + feat_rows
    )
    mobsf_excerpt = json.dumps(ctx.get("mobsf_excerpt", {}), indent=2)[:8000]
    out = out.replace("{{mobsf_excerpt}}", mobsf_excerpt)
    # handle the badge if/else crudely (we already replaced {{verdict}})
    out = out.replace("{% if verdict == 1 %}", "")
    out = out.replace("{% else %}", "")
    out = out.replace("{% endif %}", "")
    out = out.replace("{% if prob is not none %}", "")
    out = out.replace("{% endif %}", "")
    out = out.replace("{% for k,v in features.items() %}", "")
    out = out.replace("{% endfor %}", "")
    return out

def generate_html_report(apk_name: str,
                         sha256: str,
                         verdict: int,
                         prob: float | None,
                         features: dict,
                         mobsf_excerpt: dict,
                         out_dir: Path = REPORTS_DIR) -> Path:
    ctx = {
        "apk_name": apk_name,
        "sha256": sha256,
        "verdict": verdict,
        "prob": prob,
        "features": features,
        "mobsf_excerpt": mobsf_excerpt,
        "generated": dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
    }
    html = _render(HTML_TEMPLATE, ctx)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"report_{apk_name.replace('.apk','')}.html"
    out_path.write_text(html, encoding="utf-8")
    return out_path
