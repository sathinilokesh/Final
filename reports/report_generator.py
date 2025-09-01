from jinja2 import Template
from pathlib import Path
from utils.config import REPORTS_DIR

REPORT_TEMPLATE = """
<html>
<head><title>Fake APK Report</title></head>
<body>
<h2>Scan Report: {{ apk_name }}</h2>
<p><b>SHA256:</b> {{ sha256 }}</p>
<p><b>Verdict:</b> {{ verdict }}</p>
{% if prob %}<p><b>Probability Fake:</b> {{ prob }}</p>{% endif %}
<h3>Extracted Features</h3>
<ul>
{% for k,v in features.items() %}
<li>{{ k }}: {{ v }}</li>
{% endfor %}
</ul>
</body>
</html>
"""

def generate_report(apk_name, sha256, verdict, prob, features, mobsf_excerpt=None):
    template = Template(REPORT_TEMPLATE)
    html = template.render(apk_name=apk_name, sha256=sha256, verdict=verdict, prob=prob, features=features)
    report_path = REPORTS_DIR / f"{apk_name}.html"
    Path(REPORTS_DIR).mkdir(parents=True, exist_ok=True)
    report_path.write_text(html)
    return report_path
