import streamlit as st
import requests
import time
import pandas as pd
import plotly.express as px

# --- PAGE CONFIGURATION ---
st.set_page_config(
    page_title="CodeRed | AI Safety Gateway",
    page_icon="🛡️",
    layout="wide"
)

# --- SESSION STATE (Memory) ---
# This keeps track of data while the app runs
if 'history' not in st.session_state:
    st.session_state.history = []
if 'stats' not in st.session_state:
    st.session_state.stats = {"safe": 0, "unsafe": 0, "redacted": 0}

# --- SIDEBAR (The Control Panel) ---
with st.sidebar:
    st.image("https://cdn-icons-png.flaticon.com/512/9563/9563317.png", width=100)
    st.title("CodeRed Gateway")
    st.markdown("---")
    st.write("### 📡 Live Monitor")
    
    # Dynamic Metrics
    col1, col2 = st.columns(2)
    col1.metric("Total Scans", len(st.session_state.history))
    col2.metric("Threats Blocked", st.session_state.stats["unsafe"], delta_color="inverse")
    st.metric("PII Redactions", st.session_state.stats["redacted"])
    
    st.markdown("---")
    st.caption("🟢 System Status: ONLINE")
    st.caption("⚡ Latency Target: < 50ms")

# --- MAIN HEADER ---
st.title("🛡️ Real-Time LLM Firewall")
st.markdown("""
**Problem:** LLMs are vulnerable to prompt injection and data leakage.  
**Solution:** A <50ms CPU-based gateway that sanitizes inputs before they reach the model.
""")

# --- TABS LAYOUT ---
tab1, tab2 = st.tabs(["🚀 Live Test Lab", "📊 Threat Analytics"])

# === TAB 1: LIVE TESTING ===
with tab1:
    col_input, col_output = st.columns([1, 1])
    
    with col_input:
        st.subheader("Input Stream")
        prompt = st.text_area("User Prompt:", height=200, placeholder="Enter text to test the gateway...")
        
        if st.button("🛡️ Scan & Forward", type="primary", use_container_width=True):
            if not prompt:
                st.warning("Enter a prompt first.")
            else:
                with st.spinner("Running Layer 1 (Regex) -> Layer 2 (Math) -> Layer 3 (AI)..."):
                    start_t = time.time()
                    try:
                        # REQUEST TO BACKEND
                        response = requests.post("http://127.0.0.1:8000/validate", json={"text": prompt})
                        data = response.json()
                        latency = float(data.get("latency_ms", 0))
                        
                        # UPDATE STATS
                        if response.status_code == 200:
                            st.session_state.stats["safe"] += 1
                            status = "SAFE"
                            if "[REDACTED]" in data['sanitized_text']:
                                st.session_state.stats["redacted"] += 1
                        else:
                            st.session_state.stats["unsafe"] += 1
                            status = "BLOCKED"
                            
                        # LOG HISTORY
                        st.session_state.history.insert(0, {
                            "Time": time.strftime("%H:%M:%S"),
                            "Status": status,
                            "Latency (ms)": latency,
                            "Prompt Fragment": prompt[:50] + "..."
                        })
                        
                        # --- DISPLAY RESULTS ---
                        with col_output:
                            st.subheader("Gateway Decision")
                            
                            # 1. Latency Card
                            st.metric("Processing Latency", f"{latency} ms")
                            
                            if response.status_code == 200:
                                # SAFE CASE
                                st.success("✅ APPROVED: Request Forwarded to LLM")
                                
                                # PII VISUALIZER
                                st.markdown("#### 🔒 Data Privacy Layer")
                                c1, c2 = st.columns(2)
                                with c1:
                                    st.caption("Original Input")
                                    st.info(data['original_text'])
                                with c2:
                                    st.caption("Sanitized Output")
                                    st.code(data['sanitized_text'], language="text")
                                    
                            else:
                                # BLOCKED CASE
                                st.error("⛔ BLOCKED: Security Violation Detected")
                                error_detail = data.get("detail", "Unknown Error")
                                st.warning(f"**Reason:** {error_detail}")
                                
                    except Exception as e:
                        st.error(f"Connection Error: {e}")

# === TAB 2: ANALYTICS ===
with tab2:
    st.subheader("🛡️ Threat Intelligence Dashboard")
    
    if len(st.session_state.history) > 0:
        # Chart 1: Pie Chart
        df = pd.DataFrame(st.session_state.history)
        
        c1, c2 = st.columns([1, 2])
        with c1:
            # Donut Chart
            stats_df = pd.DataFrame({
                "Category": ["Safe", "Unsafe"],
                "Count": [st.session_state.stats["safe"], st.session_state.stats["unsafe"]]
            })
            fig = px.pie(stats_df, values="Count", names="Category", hole=0.4, color="Category",
                         color_discrete_map={"Safe": "#00CC96", "Unsafe": "#EF553B"})
            st.plotly_chart(fig, use_container_width=True)
            
        with c2:
            # Data Table
            st.dataframe(df, use_container_width=True)
    else:
        st.info("No data yet. Go to the 'Live Test Lab' and run some scans!")