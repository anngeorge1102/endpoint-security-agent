# SOC Agent - Streamlit Dashboard
import streamlit as st
from groq import Groq
from rag_engine import setup_rag, get_intel_for_alert
import json
import time

st.set_page_config(
    page_title="SOC Alert Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# Custom CSS
st.markdown("""
<style>
.critical-card {
    border-left: 4px solid #ff4444;
    background: #1a0000;
    padding: 15px;
    border-radius: 5px;
    margin: 8px 0;
}
.high-card {
    border-left: 4px solid #ff8800;
    background: #1a0a00;
    padding: 15px;
    border-radius: 5px;
    margin: 8px 0;
}
.suppressed-card {
    border-left: 4px solid #44aa44;
    background: #001a00;
    padding: 10px;
    border-radius: 5px;
    margin: 5px 0;
}
.metric-box {
    text-align: center;
    padding: 20px;
    border-radius: 10px;
    border: 1px solid #333;
}
</style>
""", unsafe_allow_html=True)

# ============================================
# LOAD AND PROCESS ALERTS
# ============================================

@st.cache_data
def load_alerts():
    with open("alerts/crowdstrike_alerts_dataset.json", "r") as f:
        return json.load(f)

def is_false_positive(alert):
    TRUSTED_PROCESSES = [
        "svchost.exe", "chrome.exe", "outlook.exe",
        "teams.exe", "zoom.exe", "acrobat.exe",
        "robocopy.exe", "git.exe"
    ]
    TRUSTED_DOMAINS = [
        "windowsupdate.microsoft.com", "outlook.office365.com",
        "teams.microsoft.com", "zoom.us", "github.com",
        "drive.google.com", "acroipm2.adobe.com",
        "internal-sccm.company.com", "internal-devops.company.com",
        "backup-srv.company.com", "internal-rates-api.company.com"
    ]
    TRUSTED_PARENTS = [
        "backup_agent.exe", "sccm_agent.exe",
        "task_scheduler.exe", "gpo_update.exe"
    ]

    process = alert["process"]["name"]
    domain = alert["network"]["domain"]
    parent = alert["process"]["parent_process"]
    severity = alert["severity"]

    if process in TRUSTED_PROCESSES and domain in TRUSTED_DOMAINS:
        return True, "Trusted process communicating with trusted domain"
    if parent in TRUSTED_PARENTS and severity == "Low":
        return True, f"Legitimate parent process: {parent}"
    if domain == "None" and severity == "Low":
        return True, "Low severity with no network activity"

    return False, None

def correlate_alerts(alerts):
    incidents = {}
    for alert in alerts:
        hostname = alert["device"]["hostname"]
        c2_ip = alert["network"]["destination_ip"]

        if hostname not in incidents:
            incidents[hostname] = {
                "hostname": hostname,
                "department": alert["device"]["department"],
                "username": alert["device"]["username"],
                "alerts": [],
                "c2_ips": set(),
                "categories": set(),
                "highest_severity": "Low"
            }

        incidents[hostname]["alerts"].append(alert)
        incidents[hostname]["categories"].add(alert["category"])

        if c2_ip != "0.0.0.0" and c2_ip != "10.0.0.0":
            incidents[hostname]["c2_ips"].add(c2_ip)

        severity_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
        current = incidents[hostname]["highest_severity"]
        if severity_rank.get(alert["severity"], 0) > severity_rank.get(current, 0):
            incidents[hostname]["highest_severity"] = alert["severity"]

    return incidents

# ============================================
# AI ANALYSIS ENGINE WITH RAG
# ============================================

def analyze_incident(client, incident_summary, rag_collection):

    # Get threat intel for first alert in incident
    threat_intel = ""
    if incident_summary["alerts"]:
        first_alert = incident_summary["alerts"][0]
        threat_intel = get_intel_for_alert(
            rag_collection,
            first_alert
        )

    system_prompt = """
    You are an expert SOC analyst helping triage 
    endpoint security alerts from CrowdStrike.
    
    You have access to a threat intelligence knowledge base.
    Use the provided threat intel to make more accurate decisions.
    Reference specific threat groups, MITRE techniques, and 
    known IOCs from the intel when relevant.
    
    Analyze the incident and respond ONLY in this exact 
    JSON format, nothing else, no extra text:
    
    {
        "verdict": "True Positive" or "False Positive" or "Needs Review",
        "confidence": number between 0 and 100,
        "incident_title": "short title describing what happened",
        "what_happened": "explain in simple terms what happened",
        "attack_story": "full story of what attacker did step by step",
        "threat_intel_match": "what threat intel matched this incident, mention specific threat groups or MITRE techniques found",
        "risk": "risk to organization if not acted on",
        "action": "exact steps analyst should take right now",
        "priority": "Critical" or "High" or "Medium" or "Low"
    }
    """

    full_prompt = f"""
    INCIDENT DATA:
    {json.dumps(incident_summary, indent=2)}
    
    {threat_intel}
    """

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Analyze this incident:\n\n{full_prompt}"}
        ],
        temperature=0.1
    )

    response_text = response.choices[0].message.content.strip()
    if "```json" in response_text:
        response_text = response_text.split("```json")[1].split("```")[0].strip()
    elif "```" in response_text:
        response_text = response_text.split("```")[1].split("```")[0].strip()

    return json.loads(response_text)

# ============================================
# MAIN DASHBOARD
# ============================================

# Header
st.markdown("# 🛡️ SOC Alert Dashboard")
st.markdown("**Endpoint Security Agent** — Built for SOC L1 & L2 Analysts")
st.divider()

# API Key from secrets
api_key = st.secrets["GROQ_API_KEY"]

# Run Analysis Button
run_button = st.sidebar.button(
    "🚀 Run Analysis",
    use_container_width=True,
    type="primary"
)

st.sidebar.divider()
st.sidebar.markdown("### About")
st.sidebar.markdown("""
This SOC agent:
- Auto suppresses false positives
- Correlates related alerts
- Uses AI + Threat Intel to analyze threats
- Prioritizes analyst workload
""")

# ============================================
# ANALYSIS AND DISPLAY
# ============================================

if run_button:
    # Load alerts
    alerts = load_alerts()
    client = Groq(api_key=api_key)

    # Setup RAG
    with st.spinner("Loading threat intel knowledge base..."):
        rag_collection = setup_rag()
    st.success("✅ Knowledge base loaded!")

    # Run suppression
    suppressed = []
    needs_analysis = []
    for alert in alerts:
        is_fp, reason = is_false_positive(alert)
        if is_fp:
            alert["suppression_reason"] = reason
            suppressed.append(alert)
        else:
            needs_analysis.append(alert)

    # Run correlation
    incidents = correlate_alerts(needs_analysis)

    # Show metrics
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("📥 Total Alerts", len(alerts))
    with col2:
        st.metric("✅ Auto Suppressed", len(suppressed))
    with col3:
        st.metric("🔗 Incidents", len(incidents))
    with col4:
        st.metric("🤖 Sent for Analysis", len(needs_analysis))

    st.divider()

    # Run AI analysis
    critical_incidents = []
    high_incidents = []
    medium_incidents = []
    low_incidents = []

    progress = st.progress(0, text="Starting AI analysis...")
    total = len(incidents)

    for i, (hostname, incident) in enumerate(incidents.items()):
        progress.progress(
            int((i / total) * 100),
            text=f"Analyzing {hostname}..."
        )

        incident_summary = {
            "hostname": hostname,
            "department": incident["department"],
            "username": incident["username"],
            "highest_severity": incident["highest_severity"],
            "number_of_alerts": len(incident["alerts"]),
            "attack_categories": list(incident["categories"]),
            "c2_ips_contacted": list(incident["c2_ips"]),
            "alerts": incident["alerts"]
        }

        try:
            # Pass rag_collection to analyze_incident
            result = analyze_incident(client, incident_summary, rag_collection)
            result["hostname"] = hostname
            result["department"] = incident["department"]
            result["username"] = incident["username"]
            result["alert_count"] = len(incident["alerts"])
            result["c2_ips"] = list(incident["c2_ips"])

            priority = result.get("priority", "Low")
            if priority == "Critical":
                critical_incidents.append(result)
            elif priority == "High":
                high_incidents.append(result)
            elif priority == "Medium":
                medium_incidents.append(result)
            else:
                low_incidents.append(result)

            time.sleep(2)

        except Exception as e:
            st.warning(f"Could not analyze {hostname}: {e}")
            time.sleep(5)

    progress.progress(100, text="Analysis complete!")

    # Final metrics
    st.divider()
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("🔴 Critical", len(critical_incidents))
    with col2:
        st.metric("🟠 High", len(high_incidents))
    with col3:
        st.metric("🟡 Medium", len(medium_incidents))
    with col4:
        st.metric("🟢 Low", len(low_incidents))

    st.divider()

    # Critical Incidents
    if critical_incidents:
        st.markdown("## 🔴 Critical — Act Immediately")
        for inc in critical_incidents:
            with st.expander(
                f"🔴 {inc.get('incident_title', inc['hostname'])} | {inc['department']} | {inc['confidence']}% confidence"
            ):
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown(f"**Host:** {inc['hostname']}")
                    st.markdown(f"**Department:** {inc['department']}")
                    st.markdown(f"**User:** {inc['username']}")
                    st.markdown(f"**Alerts:** {inc['alert_count']} related alerts")
                with col2:
                    st.markdown(f"**Verdict:** {inc['verdict']}")
                    st.markdown(f"**Confidence:** {inc['confidence']}%")
                    if inc['c2_ips']:
                        st.markdown(f"**C2 IPs:** {', '.join(inc['c2_ips'])}")

                st.markdown("---")
                st.markdown("**What Happened:**")
                st.info(inc['what_happened'])
                st.markdown("**Attack Story:**")
                st.warning(inc['attack_story'])
                if "threat_intel_match" in inc:
                    st.markdown("**🧠 Threat Intel Match:**")
                    st.info(inc['threat_intel_match'])
                st.markdown("**Risk:**")
                st.error(inc['risk'])
                st.markdown("**Action:**")
                st.success(inc['action'])

    # High Incidents
    if high_incidents:
        st.markdown("## 🟠 High Priority — Act Today")
        for inc in high_incidents:
            with st.expander(
                f"🟠 {inc.get('incident_title', inc['hostname'])} | {inc['department']} | {inc['confidence']}% confidence"
            ):
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown(f"**Host:** {inc['hostname']}")
                    st.markdown(f"**User:** {inc['username']}")
                    st.markdown(f"**Alerts:** {inc['alert_count']} related alerts")
                with col2:
                    st.markdown(f"**Verdict:** {inc['verdict']}")
                    st.markdown(f"**Confidence:** {inc['confidence']}%")

                st.markdown("---")
                st.markdown("**What Happened:**")
                st.info(inc['what_happened'])
                if "threat_intel_match" in inc:
                    st.markdown("**🧠 Threat Intel Match:**")
                    st.info(inc['threat_intel_match'])
                st.markdown("**Action:**")
                st.success(inc['action'])

    # Medium Incidents
    if medium_incidents:
        st.markdown("## 🟡 Medium Priority — Act This Week")
        for inc in medium_incidents:
            with st.expander(
                f"🟡 {inc.get('incident_title', inc['hostname'])} | {inc['department']}"
            ):
                st.markdown(f"**Host:** {inc['hostname']}")
                st.markdown(f"**What Happened:** {inc['what_happened']}")
                st.markdown(f"**Action:** {inc['action']}")

    # Low Incidents
    if low_incidents:
        st.markdown("## 🟢 Low Priority — Monitor Only")
        for inc in low_incidents:
            with st.expander(
                f"🟢 {inc.get('incident_title', inc['hostname'])} | {inc['department']}"
            ):
                st.markdown(f"**Host:** {inc['hostname']}")
                st.markdown(f"**What Happened:** {inc['what_happened']}")

    # Suppressed Alerts
    st.divider()
    st.markdown("## ✅ Auto Suppressed — No Action Needed")
    st.markdown(f"Agent automatically handled **{len(suppressed)} alerts**")
    for alert in suppressed:
        with st.expander(
            f"✅ {alert['alert_id']} | {alert['device']['hostname']} | {alert['suppression_reason']}"
        ):
            st.markdown(f"**Process:** {alert['process']['name']}")
            st.markdown(f"**Domain:** {alert['network']['domain']}")
            st.markdown(f"**Reason suppressed:** {alert['suppression_reason']}")

    # Final Summary
    st.divider()
    st.success(f"""
    **Analysis Complete!**
    - Your analysts need to review **{len(critical_incidents) + len(high_incidents)} incidents**
    - Agent automatically handled **{len(suppressed)} alerts**
    - Alert workload reduced by **{int((len(suppressed)/len(alerts))*100)}%**
    """)