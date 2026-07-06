"""
Incidents Page - Polished chronological timeline view per alert.
"""

import streamlit as st
import requests
from dashboard.auth import get_current_user
from dashboard.components.cards import stat_card, timeline_event_row
from dashboard.components.styles import page_header, section_header, empty_state

API_BASE = "http://localhost:8000/api/v1"


def api_get(endpoint, params=None):
    try:
        r = requests.get(f"{API_BASE}{endpoint}", params=params, timeout=5)
        return r.json() if r.status_code == 200 else None
    except Exception:
        return None


def render():
    user = get_current_user()
    api_key = user["api_key"]

    page_header("Incident Timelines", "Chronological view of all automated SOAR actions per alert", "📋")
    st.divider()

    ts = api_get("/timeline/stats") or {}
    col1, col2, col3 = st.columns(3)
    with col1:
        stat_card("Alerts Tracked", ts.get("total_alerts_tracked", 0), "", "#60a5fa", "🔍")
    with col2:
        stat_card("Total Events", ts.get("total_events_recorded", 0), "", "#4ade80", "📌")
    with col3:
        avg = 0
        if ts.get("total_alerts_tracked", 0) > 0:
            avg = round(ts.get("total_events_recorded", 0) / ts["total_alerts_tracked"], 1)
        stat_card("Avg Events/Alert", avg, "", "#fb923c", "📊")

    st.divider()

    timelines = api_get("/timeline")
    if not timelines:
        empty_state("No timelines yet", "Ingest alerts to start tracking automated actions.")
        return

    section_header(f"All Incident Timelines", f"{len(timelines)} alerts tracked")

    for timeline in timelines:
        alert_id     = timeline["alert_id"]
        total_events = timeline["total_events"]
        first_seen   = timeline["first_seen"][:19].replace("T", " ")
        last_updated = timeline["last_updated"][:19].replace("T", " ")

        with st.expander(f"🔍 `{alert_id}` · {total_events} events · Last: {last_updated}"):
            st.markdown("<p style='color:#475569; font-size:11px; font-weight:600; text-transform:uppercase; letter-spacing:0.08em; margin:0 0 8px;'>Event Log</p>", unsafe_allow_html=True)

            for event in timeline["events"]:
                timeline_event_row(event)
                if event.get("details"):
                    with st.expander("⋯ Details", expanded=False):
                        st.json(event["details"])

            st.divider()

            st.markdown("<p style='color:#475569; font-size:11px; font-weight:600; text-transform:uppercase; letter-spacing:0.08em; margin:0 0 8px;'>Add Analyst Note</p>", unsafe_allow_html=True)

            col1, col2 = st.columns([4, 1])
            with col1:
                note = st.text_input("Note", key=f"note_{alert_id}", placeholder="Enter investigation finding, action taken, or observation...", label_visibility="collapsed")
            with col2:
                if st.button("Add", key=f"add_{alert_id}", use_container_width=True):
                    if note and api_key:
                        try:
                            r = requests.post(
                                f"{API_BASE}/timeline/{alert_id}/note",
                                params={"note": note},
                                headers={"X-API-Key": api_key},
                                timeout=5,
                            )
                            if r.status_code == 200:
                                st.success("Note added.")
                                st.rerun()
                            else:
                                st.error(r.json().get("detail", "Error"))
                        except Exception as e:
                            st.error(str(e))
                    elif not api_key:
                        st.warning("API key required.")
                    else:
                        st.warning("Enter a note first.")

            st.markdown(f"<p style='color:#334155; font-size:11px; margin:8px 0 0; font-family:JetBrains Mono,monospace;'>First seen: {first_seen}</p>", unsafe_allow_html=True)