import streamlit as st
import pandas as pd
import plotly.express as px
import os
import time
import threading
import sys

# Import our backend logic
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from collector.sniffer import start_sniffing
from analysis.detect_leaks import detect_leaks
from analysis.ai_diagnosis import diagnosis_leak

from streamlit.runtime.scriptrunner import add_script_run_ctx  # type: ignore # Add this import at the top

# --- Page Config & Styling ---
st.set_page_config(page_title="Guardian eBPF", layout="wide", page_icon="🛡️")

# Custom CSS for a "Dark Mode Terminal" aesthetic
st.markdown(
    """
    <style>
    .main { background-color: #0e1117; }
    .stMetric { background-color: #161b22; border-radius: 10px; padding: 15px; border: 1px solid #30363d; }
    .stButton>button { width: 100%; border-radius: 5px; height: 3em; background-color: #238636; color: white; }
    </style>
""",
    unsafe_allow_html=True,
)

# --- State Management ---
if "is_sniffing" not in st.session_state:
    st.session_state.is_sniffing = False

# --- Sidebar: Configuration ---
with st.sidebar:
    st.title("🛡️ Guardian eBPF")
    st.info("AI-Powered Runtime Memory Analysis")
    st.divider()

    st.header("1. Target Configuration")
    target_pid = st.number_input("Target PID", min_value=1, value=111589, step=1)
    duration = st.slider("Scan Duration (seconds)", 10, 300, 60)

    st.header("2. AI Analysis")
    src_path = st.text_input("Source Code Path", value="/app/targets/leaker.cpp")
    os.environ["TARGET_SOURCE_PATH"] = src_path

# --- Main UI Layout ---
col_stats, col_controls = st.columns([3, 1])

with col_controls:
    st.subheader("Controls")

    if not st.session_state.is_sniffing:
        if st.button("🚀 Start Live Capture", type="primary"):
            st.session_state.is_sniffing = True
            DATA_PATH = "./data/memory_telemetry.csv"

            # 1. Clean up old data to prevent "Zigzag" bugs
            if os.path.exists(DATA_PATH):
                os.remove(DATA_PATH)

            # 2. Start Sniffer in a background thread
            def run_capture():
                start_sniffing(target_pid, duration, DATA_PATH)

            thread = threading.Thread(target=run_capture)
            add_script_run_ctx(thread)  # Keep Streamlit context inside the thread
            thread.start()

            # 3. UI Sync & Progress Bar
            with col_stats:
                st.write(f"### 📡 Capturing PID `{target_pid}`...")
                progress_bar = st.progress(0, text="Initializing eBPF Probe...")

                start_t = time.time()
                # Block the main UI thread here to update the progress bar smoothly
                while thread.is_alive():
                    elapsed = time.time() - start_t
                    pct = min(int((elapsed / duration) * 100), 100)
                    progress_bar.progress(
                        pct, text=f"Capturing Data... ({int(elapsed)}s / {duration}s)"
                    )
                    time.sleep(1)  # Refresh UI every 1 second

                progress_bar.progress(100, text="Capture Complete!")
                time.sleep(1)  # Brief pause for UX so user sees 100%

            st.session_state.is_sniffing = False
            st.rerun()  # Refresh the page to show results
    else:
        st.warning("⚠️ Sniffer is currently locking the kernel...")

# --- Visualization Section ---
DATA_PATH = "./data/memory_telemetry.csv"
if os.path.exists(DATA_PATH) and os.path.getsize(DATA_PATH) > 0:
    df = pd.read_csv(
        DATA_PATH, names=["timestamp", "stack_id", "alloc_count", "symbol_path"]
    )

    # Real-time Metrics
    m1, m2, m3 = st.columns(3)
    m1.metric("Capture Points", len(df))
    m2.metric("Unique Call-sites", df["symbol_path"].nunique())
    m3.metric("Last Update", time.strftime("%H:%M:%S"))

    # Chart
    fig = px.line(
        df,
        x="timestamp",
        y="alloc_count",
        color="symbol_path",
        template="plotly_dark",
        title="Allocation Velocity Trend",
    )
    st.plotly_chart(fig, use_container_width=True)

    # --- Analysis Section ---
    st.divider()
    if st.button("🧠 Run AI Diagnosis"):
        with st.spinner("🤖 Consulting AI Agent..."):
            leaks = detect_leaks(DATA_PATH)
            if leaks:
                st.error(f"Leak Found in {len(leaks)} paths!")
                diagnosis = diagnosis_leak(leaks[0])  # Get the primary leak
                st.markdown("### 📝 Root Cause Report")
                st.info(diagnosis)
            else:
                st.success("No linear memory growth patterns detected.")
else:
    st.empty()
    if not st.session_state.is_sniffing:
        st.info("Please enter a PID and start capture to begin.")
