import ast
import json
from datetime import datetime

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from fimwatch.db import Database


# -----------------------------------------------------------------------------
# Page configuration
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="FIMWATCH • Ransomware Early Warning",
    page_icon="🛰️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# -----------------------------------------------------------------------------
# Visual system — deliberately different from a stock Streamlit dashboard.
# -----------------------------------------------------------------------------
st.markdown(
    """
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=Space+Grotesk:wght@400;500;600;700&display=swap');

:root {
  --bg: #070b12;
  --panel: #0d131d;
  --panel-2: #101925;
  --line: #1d2a3a;
  --text: #e8eef7;
  --muted: #8290a5;
  --cyan: #43d9ff;
  --green: #50e3a4;
  --amber: #ffc857;
  --red: #ff5c70;
  --purple: #9b8cff;
}

.stApp {
  background:
    radial-gradient(circle at 80% 0%, rgba(67,217,255,.08), transparent 28%),
    radial-gradient(circle at 0% 30%, rgba(155,140,255,.05), transparent 25%),
    var(--bg);
  color: var(--text);
  font-family: 'Space Grotesk', sans-serif;
}

.block-container { padding-top: 1.5rem; max-width: 1500px; }
[data-testid="stSidebar"] { background: #090e16; border-right: 1px solid var(--line); }
[data-testid="stSidebar"] * { font-family: 'Space Grotesk', sans-serif; }

h1, h2, h3 { letter-spacing: -.02em; }
code, pre, .mono { font-family: 'IBM Plex Mono', monospace !important; }

.hero {
  border: 1px solid var(--line);
  border-radius: 18px;
  padding: 22px 24px;
  margin-bottom: 18px;
  background: linear-gradient(135deg, rgba(16,25,37,.95), rgba(9,14,22,.96));
  box-shadow: 0 18px 50px rgba(0,0,0,.25);
}
.hero-kicker { color: var(--cyan); font: 600 12px 'IBM Plex Mono'; letter-spacing: .16em; text-transform: uppercase; }
.hero-title { font-size: 34px; font-weight: 700; margin: 5px 0 2px; }
.hero-sub { color: var(--muted); font-size: 14px; }
.pill {
  display:inline-block; padding: 5px 10px; border-radius: 999px;
  font: 600 11px 'IBM Plex Mono'; letter-spacing: .04em;
  border: 1px solid var(--line); margin-right: 6px;
}
.pill-green { color: var(--green); background: rgba(80,227,164,.08); border-color: rgba(80,227,164,.25); }
.pill-cyan { color: var(--cyan); background: rgba(67,217,255,.08); border-color: rgba(67,217,255,.25); }
.pill-amber { color: var(--amber); background: rgba(255,200,87,.08); border-color: rgba(255,200,87,.25); }

.metric-card {
  background: linear-gradient(145deg, #0e1621, #0b111a);
  border: 1px solid var(--line); border-radius: 15px;
  padding: 16px 18px; min-height: 112px;
}
.metric-label { color: var(--muted); font: 500 11px 'IBM Plex Mono'; text-transform: uppercase; letter-spacing: .09em; }
.metric-value { color: var(--text); font-size: 30px; font-weight: 700; margin-top: 8px; }
.metric-foot { color: var(--muted); font-size: 12px; margin-top: 2px; }

.section-title { margin: 18px 0 8px; font-size: 16px; font-weight: 700; }
.section-note { color: var(--muted); font-size: 12px; margin-bottom: 10px; }

.alert-card {
  border: 1px solid rgba(255,92,112,.28); border-left: 4px solid var(--red);
  background: linear-gradient(90deg, rgba(255,92,112,.09), rgba(13,19,29,.92));
  border-radius: 12px; padding: 14px 16px; margin-bottom: 10px;
}
.alert-title { font-weight: 700; }
.alert-meta { color: var(--muted); font: 11px 'IBM Plex Mono'; margin-top: 4px; }

.status-dot { width: 8px; height: 8px; border-radius: 50%; display:inline-block; margin-right: 6px; }
.dot-green { background: var(--green); box-shadow: 0 0 12px rgba(80,227,164,.65); }
.dot-red { background: var(--red); box-shadow: 0 0 12px rgba(255,92,112,.65); }
.dot-amber { background: var(--amber); box-shadow: 0 0 12px rgba(255,200,87,.65); }

div[data-testid="stDataFrame"] { border: 1px solid var(--line); border-radius: 12px; overflow: hidden; }
.stButton > button { border-radius: 10px; border: 1px solid var(--line); background: #101925; }
.stButton > button:hover { border-color: var(--cyan); color: var(--cyan); }
</style>
""",
    unsafe_allow_html=True,
)


# -----------------------------------------------------------------------------
# Data helpers
# -----------------------------------------------------------------------------
EVENT_COLS = ["id", "ts", "event_type", "path", "old_path", "is_directory", "size", "sha256", "process_json"]
ALERT_COLS = ["id", "ts", "severity", "score", "reason", "event_count", "unique_files", "affected_paths", "process_json"]


def safe_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def severity_score(severity):
    return {"critical": 100, "high": 75, "medium": 45, "low": 20}.get(str(severity).lower(), 0)


def posture(alert_df):
    if alert_df.empty:
        return "NOMINAL", 0, "No suspicious activity recorded"
    latest = alert_df.iloc[0]
    raw = safe_int(latest.get("score", 0))
    score = max(0, min(100, raw))
    sev = str(latest.get("severity", "")).lower()
    if sev in {"critical", "high"} or score >= 75:
        return "ELEVATED", score, "Investigate the latest detection"
    if sev == "medium" or score >= 40:
        return "WATCH", score, "Telemetry warrants review"
    return "NOMINAL", score, "No high-confidence threat signal"


def parse_process(raw):
    if not raw:
        return "—"
    try:
        obj = json.loads(raw) if isinstance(raw, str) else raw
        if isinstance(obj, dict):
            name = obj.get("name") or obj.get("process_name")
            pid = obj.get("pid")
            if name and pid:
                return f"{name} · PID {pid}"
            if name:
                return str(name)
    except Exception:
        pass
    return str(raw)[:80]


def compact_path(value, limit=72):
    value = str(value or "—")
    return value if len(value) <= limit else "…" + value[-(limit - 1):]


def chart_layout(fig, height=300):
    fig.update_layout(
        height=height,
        margin=dict(l=10, r=10, t=28, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Space Grotesk", color="#aab6c8", size=11),
        xaxis=dict(gridcolor="#172230", zeroline=False),
        yaxis=dict(gridcolor="#172230", zeroline=False),
        legend=dict(bgcolor="rgba(0,0,0,0)"),
    )
    return fig


# -----------------------------------------------------------------------------
# Sidebar
# -----------------------------------------------------------------------------
st.sidebar.markdown("### 🛰️ FIMWATCH")
st.sidebar.caption("Endpoint telemetry console")

db_path = st.sidebar.text_input("Evidence store", "fimwatch.db")
limit = st.sidebar.slider("Telemetry window", 50, 2000, 500, step=50)
if st.sidebar.button("↻ Refresh telemetry", use_container_width=True):
    st.rerun()

st.sidebar.markdown("---")
st.sidebar.markdown("**Safe lab controls**")
st.sidebar.caption("This console visualizes the prototype's SQLite evidence store. It does not perform automatic containment.")
st.sidebar.markdown("`monitor`  →  `detect`  →  `alert`  →  `verify`")

# -----------------------------------------------------------------------------
# Load data
# -----------------------------------------------------------------------------
try:
    db = Database(db_path)
    events = db.fetch_events(limit)
    alerts = db.fetch_alerts(200)
    baseline = db.fetch_baseline()
except Exception as exc:
    st.error(f"Could not open the evidence store: {exc}")
    st.stop()

edf = pd.DataFrame(events, columns=EVENT_COLS)
adf = pd.DataFrame(alerts, columns=ALERT_COLS)

if not edf.empty:
    edf["time"] = pd.to_datetime(edf["ts"], unit="s", errors="coerce")
    edf = edf.sort_values("time")
if not adf.empty:
    adf["time"] = pd.to_datetime(adf["ts"], unit="s", errors="coerce")
    adf = adf.sort_values("time", ascending=False)

state, risk, state_note = posture(adf)
latest_event = edf["time"].max() if not edf.empty else None

# -----------------------------------------------------------------------------
# Hero
# -----------------------------------------------------------------------------
state_class = "pill-green" if state == "NOMINAL" else "pill-amber" if state == "WATCH" else "pill-red"
st.markdown(
    f"""
<div class="hero">
  <div class="hero-kicker">FIMWATCH / ENDPOINT DEFENSE CONSOLE</div>
  <div class="hero-title">Ransomware Early-Warning</div>
  <div class="hero-sub">File integrity + behavioral telemetry for an isolated, non-destructive lab.</div>
  <div style="margin-top:14px">
    <span class="pill {state_class}"><span class="status-dot {'dot-green' if state == 'NOMINAL' else 'dot-amber' if state == 'WATCH' else 'dot-red'}"></span>{state}</span>
    <span class="pill pill-cyan">SHA-256 FIM</span>
    <span class="pill pill-green">SAFE SIMULATION</span>
  </div>
</div>
""",
    unsafe_allow_html=True,
)

# -----------------------------------------------------------------------------
# Executive metrics
# -----------------------------------------------------------------------------
metric_cols = st.columns(5)
metrics = [
    ("Telemetry", f"{len(edf):,}", "filesystem events"),
    ("Detections", f"{len(adf):,}", "recorded alerts"),
    ("Baseline", f"{len(baseline):,}", "protected files"),
    ("Risk score", f"{risk}/100", state_note),
    ("Last signal", latest_event.strftime("%H:%M:%S") if latest_event is not None else "—", "latest event"),
]
for col, (label, value, foot) in zip(metric_cols, metrics):
    col.markdown(
        f'<div class="metric-card"><div class="metric-label">{label}</div><div class="metric-value">{value}</div><div class="metric-foot">{foot}</div></div>',
        unsafe_allow_html=True,
    )

# -----------------------------------------------------------------------------
# Main telemetry view
# -----------------------------------------------------------------------------
st.markdown('<div class="section-title">Live telemetry picture</div>', unsafe_allow_html=True)
st.markdown('<div class="section-note">A compact view of activity velocity and the signals driving the detector.</div>', unsafe_allow_html=True)

left, middle, right = st.columns([1.55, 1, 1])

with left:
    if edf.empty:
        st.info("No telemetry yet. Start the monitor and run the safe simulator.")
    else:
        timeline = edf.set_index("time").resample("1s").size().reset_index(name="events")
        fig = px.area(timeline, x="time", y="events")
        fig.update_traces(line=dict(color="#43d9ff", width=2), fillcolor="rgba(67,217,255,.10)")
        fig.update_layout(title="Event velocity", xaxis_title=None, yaxis_title="events / sec")
        st.plotly_chart(chart_layout(fig, 310), use_container_width=True, config={"displayModeBar": False})

with middle:
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=risk,
        number={"suffix": "/100", "font": {"size": 32, "color": "#e8eef7"}},
        title={"text": "Threat posture", "font": {"size": 13, "color": "#8290a5"}},
        gauge={
            "axis": {"range": [0, 100], "tickcolor": "#536276", "tickfont": {"color": "#8290a5"}},
            "bar": {"color": "#ff5c70" if risk >= 75 else "#ffc857" if risk >= 40 else "#50e3a4", "thickness": .18},
            "bgcolor": "#0d131d",
            "borderwidth": 1,
            "bordercolor": "#1d2a3a",
            "steps": [
                {"range": [0, 39], "color": "rgba(80,227,164,.06)"},
                {"range": [40, 74], "color": "rgba(255,200,87,.06)"},
                {"range": [75, 100], "color": "rgba(255,92,112,.06)"},
            ],
        },
    ))
    st.plotly_chart(chart_layout(fig, 310), use_container_width=True, config={"displayModeBar": False})

with right:
    if edf.empty:
        st.info("No event mix available.")
    else:
        mix = edf["event_type"].fillna("unknown").value_counts().reset_index()
        mix.columns = ["event_type", "count"]
        fig = px.pie(mix, names="event_type", values="count", hole=.68)
        fig.update_traces(textposition="outside", textinfo="label+percent", marker=dict(line=dict(color="#0d131d", width=2)))
        fig.update_layout(title="Event composition", showlegend=False)
        st.plotly_chart(chart_layout(fig, 310), use_container_width=True, config={"displayModeBar": False})

# -----------------------------------------------------------------------------
# Detection center
# -----------------------------------------------------------------------------
st.markdown('<div class="section-title">Detection center</div>', unsafe_allow_html=True)

if adf.empty:
    st.success("✓ No suspicious burst has been recorded in the current evidence store.")
else:
    latest = adf.iloc[0]
    sev = str(latest.get("severity", "unknown")).upper()
    score = safe_int(latest.get("score", 0))
    st.markdown(
        f"""
<div class="alert-card">
  <div class="alert-title">🚨 Latest signal · {sev} · score {score}</div>
  <div style="margin-top:6px">{latest.get('reason', 'No reason recorded')}</div>
  <div class="alert-meta">{latest['time'].strftime('%Y-%m-%d %H:%M:%S')} · {safe_int(latest.get('event_count')):,} events · {safe_int(latest.get('unique_files')):,} unique files</div>
</div>
""",
        unsafe_allow_html=True,
    )

    tab1, tab2 = st.tabs(["Alert history", "Latest evidence"])
    with tab1:
        alert_show = adf.copy()
        alert_show["time"] = alert_show["time"].dt.strftime("%Y-%m-%d %H:%M:%S")
        alert_show["process"] = alert_show["process_json"].apply(parse_process)
        st.dataframe(
            alert_show[["time", "severity", "score", "reason", "event_count", "unique_files", "process"]],
            use_container_width=True,
            hide_index=True,
            height=300,
        )
    with tab2:
        c1, c2 = st.columns(2)
        c1.metric("Affected paths", safe_int(latest.get("unique_files")))
        c2.metric("Events in burst", safe_int(latest.get("event_count")))
        st.caption("Affected paths")
        st.code(str(latest.get("affected_paths", "—"))[:12000], language="text")
        st.caption("Process context (best-effort prototype telemetry)")
        st.code(str(latest.get("process_json", "—"))[:6000], language="json")

# -----------------------------------------------------------------------------
# Integrity and activity workspace
# -----------------------------------------------------------------------------
st.markdown('<div class="section-title">Integrity workspace</div>', unsafe_allow_html=True)

integrity_tab, activity_tab = st.tabs(["🔐 Baseline integrity", "📡 Recent filesystem activity"])

with integrity_tab:
    if not baseline:
        st.info("No baseline found. Run: `python -m fimwatch.cli baseline --path ./lab_data`")
    else:
        bdf = pd.DataFrame(baseline, columns=["path", "size", "mtime_ns", "sha256", "captured_ts"])
        q = st.text_input("Filter baseline paths", placeholder="e.g. documents/report")
        if q:
            bdf = bdf[bdf["path"].astype(str).str.contains(q, case=False, na=False)]
        st.caption(f"Showing {len(bdf):,} of {len(baseline):,} baseline entries")
        st.dataframe(
            bdf[["path", "size", "sha256"]],
            use_container_width=True,
            hide_index=True,
            height=360,
        )

with activity_tab:
    if edf.empty:
        st.info("No filesystem activity recorded yet.")
    else:
        activity = edf.sort_values("time", ascending=False).head(250).copy()
        activity["time"] = activity["time"].dt.strftime("%H:%M:%S")
        activity["path"] = activity["path"].apply(compact_path)
        activity["old_path"] = activity["old_path"].apply(compact_path)
        activity["sha256"] = activity["sha256"].fillna("—").apply(lambda x: compact_path(x, 18))
        activity["process"] = activity["process_json"].apply(parse_process)
        st.dataframe(
            activity[["time", "event_type", "path", "old_path", "size", "sha256", "process"]],
            use_container_width=True,
            hide_index=True,
            height=420,
        )

# -----------------------------------------------------------------------------
# Footer
# -----------------------------------------------------------------------------
st.markdown("---")
st.caption(
    "FIMWATCH prototype • Detection is scored from multiple behavioral signals. "
    "Process attribution is best-effort; production deployments should use OS-native EDR/ETW/eBPF/Endpoint Security telemetry."
)
