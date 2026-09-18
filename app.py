"""
SAT-SA Demo — Supervisory Analytics Tool for SOC Assessment
Smart India Hackathon 2026 | Problem Statement 26157 (NCIIPC)

A single-file Flask demo. Generates realistic synthetic SOC alert data for
several fictional "Critical Sector Entities" (CSEs), runs execution-gap
and negative-space detection, computes risk scores, and shows an
explainable supervisory dashboard.

Run:
    pip install -r requirements.txt
    python app.py
Then open http://127.0.0.1:5000
"""

import random
import statistics
from datetime import datetime, timedelta

from flask import Flask, jsonify, render_template_string

app = Flask(__name__)
random.seed(42)

# ----------------------------------------------------------------------
# 1. SYNTHETIC DATA GENERATION
#    (In real life this comes from CSV/JSON/DB exports submitted by CSEs)
# ----------------------------------------------------------------------

ENTITIES = [
    "Alpha Power Grid", "Beta National Bank", "Gamma Telecom",
    "Delta Health Systems", "Epsilon Finance Corp", "Zeta Energy Ltd",
    "Eta Logistics Hub", "Theta Metro Water", "Iota Insurance Co",
]

# Entities we deliberately make "weak" so the detector has something to find
BAD_ENTITIES = {"Beta National Bank", "Zeta Energy Ltd", "Theta Metro Water"}

SEVERITIES = ["Low", "Medium", "High", "Critical"]
CLOSURE_REASONS = ["False Positive", "Remediated", "Duplicate", "Risk Accepted", "Escalated - Resolved"]

TEMPLATE_NOTES = [
    "Reviewed alert, no further action required.",
    "Checked logs, closing as false positive.",
    "Standard investigation completed, no threat found.",
]

GENUINE_NOTES = [
    "Traced source IP to internal vuln-scan host, confirmed authorized activity, whitelisted.",
    "Correlated with EDR telemetry; process hash matched known malware family, isolated endpoint 10.2.4.18.",
    "User confirmed phishing click, reset credentials, forced MFA re-enrollment, notified 3 affected mailboxes.",
    "Firewall log cross-check showed blocked outbound C2 beacon; asset reimaged and patched CVE-2024-1122.",
    "Escalated to L3, root cause traced to misconfigured VPN ACL, ticket closed after config fix verified.",
]


def rand_time(days_back_max=180):
    return datetime.now() - timedelta(
        days=random.randint(0, days_back_max),
        hours=random.randint(0, 23),
        minutes=random.randint(0, 59),
    )


def generate_alerts():
    alerts = []
    alert_id = 1000

    for entity in ENTITIES:
        is_bad = entity in BAD_ENTITIES
        assets = [f"{entity[:3].upper()}-SRV-{i}" for i in range(1, 6)]

        # Negative space injection: a bad entity silently drops one critical asset
        # (it exists in inventory but produces ~no alerts -> monitoring blind spot)
        silent_asset = assets[-1] if is_bad else None
        active_assets = assets[:-1] if is_bad else assets

        n_alerts = random.randint(15, 25) if is_bad else random.randint(60, 100)

        for _ in range(n_alerts):
            severity = random.choices(SEVERITIES, weights=[40, 30, 20, 10])[0]
            asset = random.choice(active_assets)
            detected = rand_time()

            if is_bad:
                # Execution gap patterns
                invest_delay_min = random.choice([0, 1, 2])  # near-instant "investigation"
                close_delay_min = random.choice([1, 2, 3, 4])
                escalated = False if severity == "Critical" and random.random() < 0.8 else (severity == "Critical")
                note = random.choice(TEMPLATE_NOTES)  # copy-paste boilerplate
                closure_reason = "False Positive" if random.random() < 0.7 else random.choice(CLOSURE_REASONS)
            else:
                invest_delay_min = random.randint(15, 240)
                close_delay_min = random.randint(30, 600)
                escalated = severity == "Critical"  # good entities escalate criticals properly
                note = random.choice(GENUINE_NOTES)
                closure_reason = random.choice(CLOSURE_REASONS)

            investigated = detected + timedelta(minutes=invest_delay_min)
            closed = investigated + timedelta(minutes=close_delay_min)

            alert_id += 1
            alerts.append({
                "alert_id": alert_id,
                "entity": entity,
                "asset_id": asset,
                "severity": severity,
                "detected_time": detected,
                "investigated_time": investigated,
                "closed_time": closed,
                "escalated": escalated,
                "closure_reason": closure_reason,
                "notes": note,
            })

        # A few alerts on the "silent" asset just before it went dark, to prove
        # it used to report and then stopped (real blind-spot signature)
        if silent_asset:
            for _ in range(2):
                detected = datetime.now() - timedelta(days=random.randint(150, 179))
                alert_id += 1
                alerts.append({
                    "alert_id": alert_id,
                    "entity": entity,
                    "asset_id": silent_asset,
                    "severity": "Medium",
                    "detected_time": detected,
                    "investigated_time": detected + timedelta(minutes=20),
                    "closed_time": detected + timedelta(minutes=90),
                    "escalated": False,
                    "closure_reason": "Remediated",
                    "notes": random.choice(GENUINE_NOTES),
                })

    return alerts, {e: ([f"{e[:3].upper()}-SRV-{i}" for i in range(1, 6)]) for e in ENTITIES}


ALERTS, ASSET_INVENTORY = generate_alerts()


# ----------------------------------------------------------------------
# 2. FEATURE ENGINEERING + DETECTION + RISK SCORING
# ----------------------------------------------------------------------

def analyze():
    by_entity = {}
    for e in ENTITIES:
        by_entity[e] = [a for a in ALERTS if a["entity"] == e]

    results = {}
    for entity, alerts in by_entity.items():
        n = len(alerts)
        criticals = [a for a in alerts if a["severity"] == "Critical"]
        n_crit = len(criticals)

        # --- Execution gap features ---
        close_times_min = [(a["closed_time"] - a["detected_time"]).total_seconds() / 60 for a in alerts]
        avg_close_min = statistics.mean(close_times_min) if close_times_min else 0

        fast_closures = [a for a in alerts if
                          (a["closed_time"] - a["detected_time"]).total_seconds() / 60 < 5
                          and a["severity"] in ("High", "Critical")]

        crit_no_escalation = [a for a in criticals if not a["escalated"]]
        escalation_ratio = (n_crit - len(crit_no_escalation)) / n_crit if n_crit else 1.0

        note_texts = [a["notes"] for a in alerts]
        unique_notes = len(set(note_texts))
        repetition_ratio = 1 - (unique_notes / n) if n else 0  # higher = more copy-paste

        false_positive_rate = sum(1 for a in alerts if a["closure_reason"] == "False Positive") / n if n else 0

        # --- Negative space ---
        assets_seen = set(a["asset_id"] for a in alerts)
        assets_expected = set(ASSET_INVENTORY[entity])
        silent_assets = assets_expected - assets_seen
        # also catch "went silent recently" - last alert older than 100 days
        recently_silent = []
        for asset in assets_expected:
            asset_alerts = [a for a in alerts if a["asset_id"] == asset]
            if asset_alerts:
                last_seen = max(a["detected_time"] for a in asset_alerts)
                if (datetime.now() - last_seen).days > 100:
                    recently_silent.append(asset)

        results[entity] = {
            "total_alerts": n,
            "avg_close_minutes": round(avg_close_min, 1),
            "fast_closures": fast_closures,
            "fast_closure_count": len(fast_closures),
            "escalation_ratio": round(escalation_ratio, 2),
            "crit_no_escalation_count": len(crit_no_escalation),
            "crit_no_escalation": crit_no_escalation,
            "repetition_ratio": round(repetition_ratio, 2),
            "false_positive_rate": round(false_positive_rate, 2),
            "silent_assets": sorted(silent_assets | set(recently_silent)),
        }

    # --- Peer benchmarking (percentile-style z-score vs peer mean) ---
    close_vals = [r["avg_close_minutes"] for r in results.values()]
    esc_vals = [r["escalation_ratio"] for r in results.values()]
    fp_vals = [r["false_positive_rate"] for r in results.values()]
    rep_vals = [r["repetition_ratio"] for r in results.values()]

    def z(val, arr):
        m = statistics.mean(arr)
        s = statistics.pstdev(arr) or 1
        return (val - m) / s

    # --- Composite risk score (0-100, higher = more supervisory concern) ---
    for entity, r in results.items():
        gap_score = 0
        gap_score += min(r["fast_closure_count"] * 4, 30)                     # fast rubber-stamp closures
        gap_score += min(r["crit_no_escalation_count"] * 8, 30)               # hidden criticals
        gap_score += min(r["repetition_ratio"] * 100 * 0.3, 20)               # copy-paste investigations
        gap_score += min(max(z(r["false_positive_rate"], fp_vals), 0) * 5, 10)  # abnormal FP rate vs peers

        neg_space_score = min(len(r["silent_assets"]) * 15, 30)

        total = round(min(gap_score + neg_space_score, 100), 1)
        r["execution_gap_score"] = round(gap_score, 1)
        r["negative_space_score"] = round(neg_space_score, 1)
        r["risk_score"] = total
        r["risk_band"] = ("High" if total >= 55 else "Medium" if total >= 25 else "Low")

    return results


ANALYSIS = analyze()


# ----------------------------------------------------------------------
# 3. API ROUTES
# ----------------------------------------------------------------------

@app.route("/api/leaderboard")
def leaderboard():
    rows = []
    for entity, r in ANALYSIS.items():
        rows.append({
            "entity": entity,
            "risk_score": r["risk_score"],
            "risk_band": r["risk_band"],
            "total_alerts": r["total_alerts"],
            "execution_gap_score": r["execution_gap_score"],
            "negative_space_score": r["negative_space_score"],
        })
    rows.sort(key=lambda x: -x["risk_score"])
    return jsonify(rows)


@app.route("/api/entity/<entity>")
def entity_detail(entity):
    r = ANALYSIS.get(entity)
    if not r:
        return jsonify({"error": "not found"}), 404

    def fmt(a):
        return {
            "alert_id": a["alert_id"],
            "asset_id": a["asset_id"],
            "severity": a["severity"],
            "detected_time": a["detected_time"].strftime("%Y-%m-%d %H:%M"),
            "closed_time": a["closed_time"].strftime("%Y-%m-%d %H:%M"),
            "escalated": a["escalated"],
            "closure_reason": a["closure_reason"],
            "notes": a["notes"],
        }

    findings = []
    if r["fast_closure_count"]:
        findings.append({
            "type": "Execution Gap",
            "title": f"{r['fast_closure_count']} High/Critical alerts closed in under 5 minutes",
            "explanation": "Alerts of this severity typically require meaningful investigation. "
                            "Closure within minutes suggests alerts are being dismissed without review.",
            "evidence": [fmt(a) for a in r["fast_closures"][:5]],
        })
    if r["crit_no_escalation_count"]:
        findings.append({
            "type": "Execution Gap",
            "title": f"{r['crit_no_escalation_count']} Critical alerts closed without escalation",
            "explanation": "Critical-severity alerts should be escalated per standard SOC practice. "
                            "These were closed without any escalation record.",
            "evidence": [fmt(a) for a in r["crit_no_escalation"][:5]],
        })
    if r["repetition_ratio"] > 0.3:
        findings.append({
            "type": "Execution Gap",
            "title": f"High repetition in investigation notes ({int(r['repetition_ratio']*100)}% duplicated)",
            "explanation": "A large share of investigation notes are near-identical boilerplate text, "
                            "suggesting superficial or template-driven investigations rather than genuine analysis.",
            "evidence": [],
        })
    if r["silent_assets"]:
        findings.append({
            "type": "Negative Space",
            "title": f"{len(r['silent_assets'])} inventoried asset(s) with no recent alert activity",
            "explanation": "These assets exist in the entity's inventory but show little or no recent "
                            "security telemetry — a potential monitoring blind spot rather than a genuinely secure system.",
            "evidence": [{"asset_id": a} for a in r["silent_assets"]],
        })

    return jsonify({
        "entity": entity,
        "summary": r,
        "findings": findings,
    })


# ----------------------------------------------------------------------
# 4. FRONTEND (single-page dashboard, inline for a zero-build demo)
# ----------------------------------------------------------------------

PAGE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>SAT-SA — Supervisory Analytics Tool for SOC Assessment</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.4/chart.umd.min.js"></script>
<style>
  :root{
    --bg:#0f1420; --panel:#161d2e; --panel2:#1d2740; --text:#e6ebf5; --muted:#8b96ad;
    --accent:#4f8cff; --high:#ff5d6c; --medium:#ffb84f; --low:#37d67a; --border:#293552;
  }
  *{box-sizing:border-box;}
  body{margin:0;font-family:'Segoe UI',Arial,sans-serif;background:var(--bg);color:var(--text);}
  header{padding:22px 32px;border-bottom:1px solid var(--border);}
  header h1{margin:0;font-size:20px;}
  header p{margin:4px 0 0;color:var(--muted);font-size:13px;}
  .wrap{display:flex;gap:20px;padding:24px 32px;align-items:flex-start;}
  .col-left{flex:0 0 420px;}
  .col-right{flex:1;min-width:0;}
  .card{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:18px;margin-bottom:18px;}
  .card h2{margin:0 0 12px;font-size:15px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;}
  table{width:100%;border-collapse:collapse;font-size:13px;}
  th,td{padding:8px 6px;text-align:left;border-bottom:1px solid var(--border);}
  th{color:var(--muted);font-weight:600;font-size:11px;text-transform:uppercase;}
  tr.row{cursor:pointer;transition:background .15s;}
  tr.row:hover{background:var(--panel2);}
  tr.row.active{background:var(--panel2);outline:1px solid var(--accent);}
  .badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:600;}
  .band-High{background:rgba(255,93,108,.15);color:var(--high);}
  .band-Medium{background:rgba(255,184,79,.15);color:var(--medium);}
  .band-Low{background:rgba(55,214,122,.15);color:var(--low);}
  .score{font-size:22px;font-weight:700;}
  .finding{border:1px solid var(--border);border-radius:8px;padding:14px;margin-bottom:12px;background:var(--panel2);}
  .finding .tag{font-size:10px;text-transform:uppercase;letter-spacing:.05em;color:var(--accent);font-weight:700;}
  .finding h3{margin:6px 0;font-size:14px;}
  .finding p{margin:0 0 10px;color:var(--muted);font-size:13px;line-height:1.5;}
  .ev-table{margin-top:8px;font-size:12px;}
  .ev-table th,.ev-table td{padding:5px 4px;}
  .empty{color:var(--muted);font-style:italic;padding:20px 0;text-align:center;}
  .kpis{display:flex;gap:14px;margin-bottom:6px;}
  .kpi{flex:1;background:var(--panel2);border-radius:8px;padding:12px;text-align:center;}
  .kpi .num{font-size:20px;font-weight:700;}
  .kpi .lbl{font-size:11px;color:var(--muted);margin-top:2px;}
  .subtitle{color:var(--muted);font-size:12px;margin-bottom:10px;}
  canvas{max-height:220px;}
</style>
</head>
<body>
<header>
  <h1>🛡️ SAT-SA — Supervisory Analytics Tool for SOC Assessment</h1>
  <p>NCIIPC Problem Statement 26157 · Demo build with synthetic data · Click an entity to see evidence-backed findings</p>
</header>

<div class="wrap">
  <div class="col-left">
    <div class="card">
      <h2>Entity Risk Leaderboard</h2>
      <canvas id="riskChart"></canvas>
    </div>
    <div class="card">
      <h2>Entities (sorted by risk)</h2>
      <table id="leaderTable">
        <thead><tr><th>Entity</th><th>Risk</th><th>Score</th></tr></thead>
        <tbody></tbody>
      </table>
    </div>
  </div>

  <div class="col-right">
    <div class="card" id="detailCard">
      <h2 id="detailTitle">Select an entity</h2>
      <div class="empty" id="detailEmpty">Click any row on the left to drill into evidence-backed supervisory findings.</div>
      <div id="detailBody" style="display:none;">
        <div class="kpis" id="kpis"></div>
        <div id="findings"></div>
      </div>
    </div>
  </div>
</div>

<script>
let chart;
let activeRow = null;

async function loadLeaderboard(){
  const res = await fetch('/api/leaderboard');
  const data = await res.json();

  const tbody = document.querySelector('#leaderTable tbody');
  tbody.innerHTML = '';
  data.forEach(row => {
    const tr = document.createElement('tr');
    tr.className = 'row';
    tr.innerHTML = `<td>${row.entity}</td>
                     <td><span class="badge band-${row.risk_band}">${row.risk_band}</span></td>
                     <td>${row.risk_score}</td>`;
    tr.onclick = () => selectEntity(row.entity, tr);
    tbody.appendChild(tr);
  });

  const ctx = document.getElementById('riskChart');
  const labels = data.map(d => d.entity.split(' ')[0]);
  const scores = data.map(d => d.risk_score);
  const colors = data.map(d => d.risk_band === 'High' ? '#ff5d6c' : d.risk_band === 'Medium' ? '#ffb84f' : '#37d67a');
  if (chart) chart.destroy();
  chart = new Chart(ctx, {
    type: 'bar',
    data: { labels, datasets: [{ label: 'Risk Score', data: scores, backgroundColor: colors, borderRadius: 4 }] },
    options: {
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: '#8b96ad', font: { size: 10 } }, grid: { display:false } },
        y: { beginAtZero: true, max: 100, ticks: { color: '#8b96ad' }, grid: { color: '#293552' } }
      }
    }
  });

  // auto-select the top risk entity on load
  if (data.length) selectEntity(data[0].entity, tbody.querySelector('tr'));
}

async function selectEntity(entity, rowEl){
  if (activeRow) activeRow.classList.remove('active');
  if (rowEl) { rowEl.classList.add('active'); activeRow = rowEl; }

  const res = await fetch(`/api/entity/${encodeURIComponent(entity)}`);
  const data = await res.json();
  const s = data.summary;

  document.getElementById('detailTitle').textContent = entity;
  document.getElementById('detailEmpty').style.display = 'none';
  document.getElementById('detailBody').style.display = 'block';

  document.getElementById('kpis').innerHTML = `
    <div class="kpi"><div class="num">${s.risk_score}</div><div class="lbl">Risk Score / 100</div></div>
    <div class="kpi"><div class="num">${s.total_alerts}</div><div class="lbl">Total Alerts</div></div>
    <div class="kpi"><div class="num">${s.execution_gap_score}</div><div class="lbl">Execution Gap Score</div></div>
    <div class="kpi"><div class="num">${s.negative_space_score}</div><div class="lbl">Negative Space Score</div></div>
  `;

  const findingsEl = document.getElementById('findings');
  if (!data.findings.length) {
    findingsEl.innerHTML = '<div class="empty">No significant supervisory concerns detected for this entity.</div>';
    return;
  }

  findingsEl.innerHTML = data.findings.map(f => {
    let evidenceHtml = '';
    if (f.evidence.length) {
      const keys = Object.keys(f.evidence[0]);
      evidenceHtml = `<table class="ev-table"><thead><tr>${keys.map(k=>`<th>${k}</th>`).join('')}</tr></thead>
        <tbody>${f.evidence.map(row => `<tr>${keys.map(k=>`<td>${row[k]}</td>`).join('')}</tr>`).join('')}</tbody></table>`;
    }
    return `<div class="finding">
      <span class="tag">${f.type}</span>
      <h3>${f.title}</h3>
      <p>${f.explanation}</p>
      ${evidenceHtml}
    </div>`;
  }).join('');
}

loadLeaderboard();
</script>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(PAGE)


if __name__ == "__main__":
    app.run(debug=True, port=5000)
