"""
Incidents Page - Full chronological timeline view per alert.
"""

import streamlit as st
import requests
from dashboard.auth import get_current_user
from dashboard.components.cards import timeline_event_row

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

    st.title("📋 Incident Timelines")
    st.caption("Chronological view of all automated SOAR actions per alert")
    st.divider()

    timeline_stats = api_get("/timeline/stats") or {}
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Alerts Tracked", timeline_stats.get("total_alerts_tracked", 0))
    with col2:
        st.metric("Total Events", timeline_stats.get("total_events_recorded", 0))
    with col3:
        avg = 0
        if timeline_stats.get("total_alerts_tracked", 0) > 0:
            avg = round(timeline_stats.get("total_events_recorded", 0) / timeline_stats["total_alerts_tracked"], 1)
        st.metric("Avg Events/Alert", avg)

    st.divider()

    timelines = api_get("/timeline")
    if not timelines:
        st.info("No timelines yet. Ingest alerts to start tracking.")
        return

    st.subheader(f"All Incident Timelines ({len(timelines)})")

    for timeline in timelines:
        alert_id = timeline["alert_id"]
        total_events = timeline["total_events"]
        first_seen = timeline["first_seen"][:19]
        last_updated = timeline["last_updated"][:19]

        with st.expander(f"🔍 `{alert_id}` | {total_events} events | First: {first_seen} | Last: {last_updated}"):
            for event in timeline["events"]:
                timeline_event_row(event)
                if event.get("details"):
                    with st.expander("View details", expanded=False):
                        st.json(event["details"])

            st.divider()
            st.markdown("**✍️ Add Analyst Note:**")
            col1, col2 = st.columns([3, 1])
            with col1:
                note = st.text_input("Note", key=f"note_input_{alert_id}", placeholder="Enter investigation note...", label_visibility="collapsed")
            with col2:
                if st.button("Add Note", key=f"add_{alert_id}", use_container_width=True):
                    if note and api_key:
                        try:
                            r = requests.post(
                                f"{API_BASE}/timeline/{alert_id}/note",
                                params={"note": note},
                                headers={"X-API-Key": api_key},
                                timeout=5,
                            )
                            if r.status_code == 200:
                                st.success("Note added!")
                                st.rerun()
                            else:
                                st.error(r.json().get("detail", "Error"))
                        except Exception as e:
                            st.error(str(e))
                    elif not api_key:
                        st.warning("API key required.")
                    else:
                        st.warning("Enter a note first.")