"""
Analytics Page - Severity trends, attack distribution, top IPs, risk heatmap.
Week 4 Day 4.
"""

import streamlit as st
import pandas as pd
import requests
from collections import defaultdict
from datetime import datetime
from dashboard.components.cards import metric_card
from dashboard.rbac import SEVERITY_EMOJI

API_BASE = "http://localhost:8000/api/v1"


def api_get(endpoint, params=None):
    try:
        r = requests.get(f"{API_BASE}{endpoint}", params=params, timeout=5)
        return r.json() if r.status_code == 200 else None
    except Exception:
        return None


def render():
    st.title("📈 Alert Analytics")
    st.caption("Visual threat intelligence — severity trends, attack patterns, top attackers")
    st.divider()

    alerts = api_get("/alerts", params={"limit": 500}) or []

    if not alerts:
        st.info("No alert data yet. Run the SIEM simulator to generate test data.")
        st.code("python simulator/siem_simulator.py --count 20 --type all")
        return

    # ── Summary Metrics ───────────────────────────────────────────────────────
    total = len(alerts)
    critical_count = sum(1 for a in alerts if a.get("severity") == "critical")
    high_count = sum(1 for a in alerts if a.get("severity") == "high")
    unique_ips = len(set(a.get("source_ip") for a in alerts))

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        metric_card("Total Alerts", total, "analyzed", "#60a5fa")
    with col2:
        metric_card("Critical", critical_count, "immediate action", "#ff4444")
    with col3:
        metric_card("High", high_count, "urgent", "#ff8c00")
    with col4:
        metric_card("Unique IPs", unique_ips, "distinct attackers", "#fb923c")

    st.divider()

    # ── Severity Distribution ─────────────────────────────────────────────────
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("🎯 Severity Distribution")
        severity_counts = defaultdict(int)
        for alert in alerts:
            severity_counts[alert.get("severity", "unknown")] += 1

        df_sev = pd.DataFrame(
            list(severity_counts.items()),
            columns=["Severity", "Count"]
        ).sort_values("Count", ascending=False)
        st.bar_chart(df_sev.set_index("Severity"))

        for _, row in df_sev.iterrows():
            pct = round(row["Count"] / total * 100, 1)
            emoji = SEVERITY_EMOJI.get(row["Severity"], "⚪")
            st.write(f"{emoji} **{row['Severity'].upper()}**: {row['Count']} alerts ({pct}%)")

    with col2:
        st.subheader("⚔️ Attack Type Distribution")
        attack_counts = defaultdict(int)
        for alert in alerts:
            attack_counts[alert.get("attack_type", "unknown").replace("_", " ").title()] += 1

        df_atk = pd.DataFrame(
            list(attack_counts.items()),
            columns=["Attack Type", "Count"]
        ).sort_values("Count", ascending=False)
        st.bar_chart(df_atk.set_index("Attack Type"))

        for _, row in df_atk.iterrows():
            pct = round(row["Count"] / total * 100, 1)
            st.write(f"🔸 **{row['Attack Type']}**: {row['Count']} ({pct}%)")

    st.divider()

    # ── Top Attacking IPs ─────────────────────────────────────────────────────
    st.subheader("🌐 Top Attacking IPs")
    ip_counts = defaultdict(int)
    ip_severity = defaultdict(set)
    for alert in alerts:
        ip = alert.get("source_ip", "unknown")
        ip_counts[ip] += 1
        ip_severity[ip].add(alert.get("severity", "unknown"))

    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    if top_ips:
        df_ip = pd.DataFrame(top_ips, columns=["Source IP", "Alert Count"])
        df_ip["Severities"] = df_ip["Source IP"].apply(
            lambda ip: ", ".join(sorted(ip_severity[ip]))
        )
        df_ip["Threat Level"] = df_ip["Severities"].apply(
            lambda s: "🔴 Critical" if "critical" in s
            else "🟠 High" if "high" in s
            else "🟡 Medium" if "medium" in s
            else "🟢 Low"
        )

        st.dataframe(
            df_ip[["Source IP", "Alert Count", "Threat Level", "Severities"]],
            use_container_width=True,
            hide_index=True,
        )

        st.bar_chart(df_ip.set_index("Source IP")["Alert Count"])

    st.divider()

    # ── Alerts Over Time ──────────────────────────────────────────────────────
    st.subheader("📅 Alerts Over Time")

    time_buckets = defaultdict(int)
    for alert in alerts:
        received = alert.get("received_at", "")
        if received:
            try:
                dt = datetime.fromisoformat(received.replace("Z", "+00:00"))
                bucket = dt.strftime("%Y-%m-%d %H:00")
                time_buckets[bucket] += 1
            except Exception:
                pass

    if time_buckets:
        df_time = pd.DataFrame(
            sorted(time_buckets.items()),
            columns=["Hour", "Alert Count"]
        )
        st.line_chart(df_time.set_index("Hour"))
    else:
        st.info("Not enough time data to show trends.")

    st.divider()

    # ── Attack Type × Severity Matrix ─────────────────────────────────────────
    st.subheader("🔥 Attack Type × Severity Matrix")

    severity_order = ["critical", "high", "medium", "low", "unknown"]
    attack_types = list(set(a.get("attack_type", "unknown") for a in alerts))

    matrix = {}
    for attack in attack_types:
        matrix[attack] = {}
        for sev in severity_order:
            matrix[attack][sev] = sum(
                1 for a in alerts
                if a.get("attack_type") == attack and a.get("severity") == sev
            )

    df_matrix = pd.DataFrame(matrix).T
    df_matrix = df_matrix[[s for s in severity_order if s in df_matrix.columns]]
    df_matrix.index = [i.replace("_", " ").title() for i in df_matrix.index]

    st.dataframe(
        df_matrix.style.background_gradient(cmap="Reds", axis=None),
        use_container_width=True,
    )

    st.divider()

    # ── Alert Status Breakdown ────────────────────────────────────────────────
    st.subheader("📊 Alert Status Breakdown")
    statuses = api_get("/alerts/statuses") or {}

    if statuses:
        status_counts = defaultdict(int)
        for s in statuses.values():
            status_counts[s] += 1

        df_status = pd.DataFrame(
            list(status_counts.items()),
            columns=["Status", "Count"]
        ).sort_values("Count", ascending=False)

        st.bar_chart(df_status.set_index("Status"))

        total_tracked = len(statuses)
        resolved = status_counts.get("resolved", 0) + status_counts.get("false_positive", 0)
        resolution_rate = round(resolved / max(total_tracked, 1) * 100, 1)
        st.metric("Resolution Rate", f"{resolution_rate}%")
    else:
        st.info("No status data yet.")