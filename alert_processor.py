# SOC Agent - Alert Processor
# This is the core of alert fatigue elimination

from groq import Groq
import json
import time

# Configure Groqgsk_BY3aw0nyCVc6NE6QCeHDWGdyb3FYX4eFQZ8lIj6NtINO2jYwFK2U
import os
client = Groq(api_key=os.environ.get("GROQ_API_KEY"))

# Load all 50 alerts
with open("alerts/crowdstrike_alerts_dataset.json", "r") as f:
    alerts = json.load(f)

print("="*60)
print("🛡️  SOC ALERT PROCESSOR - STARTING ANALYSIS")
print("="*60)
print(f"📥 Total alerts received: {len(alerts)}")
print("-"*60)

# ============================================
# STEP 1 - AUTO SUPPRESSION ENGINE
# Known safe patterns that don't need AI
# ============================================

# These are trusted processes we know are safe
TRUSTED_PROCESSES = [
    "svchost.exe",
    "chrome.exe",
    "outlook.exe",
    "teams.exe",
    "zoom.exe",
    "acrobat.exe",
    "robocopy.exe",
    "git.exe"
]

# These are trusted domains we know are safe
TRUSTED_DOMAINS = [
    "windowsupdate.microsoft.com",
    "outlook.office365.com",
    "teams.microsoft.com",
    "zoom.us",
    "github.com",
    "drive.google.com",
    "acroipm2.adobe.com",
    "internal-sccm.company.com",
    "internal-devops.company.com",
    "backup-srv.company.com",
    "internal-rates-api.company.com"
]

# These are trusted parent processes
TRUSTED_PARENTS = [
    "backup_agent.exe",
    "sccm_agent.exe",
    "task_scheduler.exe",
    "gpo_update.exe"
]

def is_false_positive(alert):
    """
    Check if alert matches known safe patterns
    Returns True if it should be auto suppressed
    """
    process = alert["process"]["name"]
    domain = alert["network"]["domain"]
    parent = alert["process"]["parent_process"]
    severity = alert["severity"]

    # Rule 1 - Trusted process talking to trusted domain
    if process in TRUSTED_PROCESSES and domain in TRUSTED_DOMAINS:
        return True, "Trusted process communicating with trusted domain"

    # Rule 2 - Trusted parent process (SCCM, backup, GPO)
    if parent in TRUSTED_PARENTS and severity == "Low":
        return True, f"Legitimate parent process: {parent}"

    # Rule 3 - No network activity and low severity
    if domain == "None" and severity == "Low":
        return True, "Low severity with no network activity"

    return False, None

# Run suppression on all alerts
suppressed = []
needs_analysis = []

for alert in alerts:
    is_fp, reason = is_false_positive(alert)
    if is_fp:
        alert["suppression_reason"] = reason
        suppressed.append(alert)
    else:
        needs_analysis.append(alert)

print(f"✅ Auto suppressed:        {len(suppressed)} alerts")
print(f"🤖 Sent for AI analysis:   {len(needs_analysis)} alerts")
print("-"*60)

# ============================================
# STEP 2 - CORRELATION ENGINE
# Group related alerts into single incidents
# ============================================

def correlate_alerts(alerts):
    """
    Groups related alerts together by:
    - Same hostname
    - Same C2 IP address
    """
    incidents = {}

    for alert in alerts:
        hostname = alert["device"]["hostname"]
        c2_ip = alert["network"]["destination_ip"]

        # Group by hostname first
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

        # Add alert to the incident
        incidents[hostname]["alerts"].append(alert)
        incidents[hostname]["categories"].add(alert["category"])

        # Track C2 IPs
        if c2_ip != "0.0.0.0" and c2_ip != "10.0.0.0":
            incidents[hostname]["c2_ips"].add(c2_ip)

        # Track highest severity
        severity_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
        current = incidents[hostname]["highest_severity"]
        new = alert["severity"]
        if severity_rank.get(new, 0) > severity_rank.get(current, 0):
            incidents[hostname]["highest_severity"] = new

    return incidents

# Run correlation
print("\n🔗 Running correlation engine...")
incidents = correlate_alerts(needs_analysis)
print(f"📊 {len(needs_analysis)} alerts grouped into {len(incidents)} incidents")
print("-"*60)

# ============================================
# STEP 3 - AI ANALYSIS ENGINE
# Send each incident to AI for deep analysis
# ============================================

system_prompt = """
You are an expert SOC analyst helping triage 
endpoint security alerts from CrowdStrike.

You will receive a security incident that may contain 
multiple related alerts from the same machine.

Analyze everything and respond ONLY in this exact 
JSON format, nothing else, no extra text:

{
    "verdict": "True Positive" or "False Positive" or "Needs Review",
    "confidence": number between 0 and 100,
    "incident_title": "short title describing what happened",
    "what_happened": "explain in simple terms what happened, like explaining to a junior analyst",
    "attack_story": "tell the full story of what the attacker did step by step",
    "risk": "what is the risk to the organization if this is not acted on",
    "action": "exact steps the analyst should take right now",
    "priority": "Critical" or "High" or "Medium" or "Low"
}
"""

print("\n🤖 Starting AI analysis of incidents...")
print("-"*60)

# Store results
critical_incidents = []
high_incidents = []
medium_incidents = []
low_incidents = []

# Analyze each incident
for hostname, incident in incidents.items():
    print(f"Analyzing {hostname}...")

    # Build incident summary for AI
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

    # Send to AI
    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {
                    "role": "system",
                    "content": system_prompt
                },
                {
                    "role": "user",
                    "content": f"Analyze this incident:\n\n{json.dumps(incident_summary, indent=2)}"
                }
            ],
            temperature=0.1
        )

        # Parse response
        response_text = response.choices[0].message.content.strip()
        if "```json" in response_text:
            response_text = response_text.split("```json")[1].split("```")[0].strip()
        elif "```" in response_text:
            response_text = response_text.split("```")[1].split("```")[0].strip()

        result = json.loads(response_text)
        result["hostname"] = hostname
        result["department"] = incident["department"]
        result["username"] = incident["username"]
        result["alert_count"] = len(incident["alerts"])
        result["c2_ips"] = list(incident["c2_ips"])

        # Sort into priority buckets
        priority = result.get("priority", "Low")
        if priority == "Critical":
            critical_incidents.append(result)
        elif priority == "High":
            high_incidents.append(result)
        elif priority == "Medium":
            medium_incidents.append(result)
        else:
            low_incidents.append(result)

        # Small delay to avoid rate limiting
        time.sleep(2)

    except Exception as e:
        print(f"  ⚠️ Error analyzing {hostname}: {e}")
        time.sleep(5)

# ============================================
# STEP 4 - SOC DASHBOARD OUTPUT
# Display everything in a clear format
# ============================================

print("\n")
print("="*60)
print("🛡️  SOC ALERT DASHBOARD - FINAL REPORT")
print("="*60)
print(f"📥 Total alerts received:      {len(alerts)}")
print(f"✅ Auto suppressed:            {len(suppressed)}")
print(f"🔗 Incidents after correlation: {len(incidents)}")
print(f"🔴 Critical incidents:         {len(critical_incidents)}")
print(f"🟠 High incidents:             {len(high_incidents)}")
print(f"🟡 Medium incidents:           {len(medium_incidents)}")
print(f"🟢 Low incidents:              {len(low_incidents)}")
print("="*60)

# Show Critical Incidents
if critical_incidents:
    print("\n🔴 CRITICAL - ACT IMMEDIATELY")
    print("-"*60)
    for i, inc in enumerate(critical_incidents, 1):
        print(f"\n[{i}] {inc.get('incident_title', 'Unknown')}")
        print(f"    🖥️  Host:       {inc['hostname']}")
        print(f"    🏢 Department: {inc['department']}")
        print(f"    👤 User:       {inc['username']}")
        print(f"    📊 Alerts:     {inc['alert_count']} related alerts")
        print(f"    🎯 Confidence: {inc['confidence']}%")
        if inc['c2_ips']:
            print(f"    🌐 C2 IPs:     {', '.join(inc['c2_ips'])}")
        print(f"\n    📖 WHAT HAPPENED:")
        print(f"    {inc['what_happened']}")
        print(f"\n    ⚔️  ATTACK STORY:")
        print(f"    {inc['attack_story']}")
        print(f"\n    ⚠️  RISK:")
        print(f"    {inc['risk']}")
        print(f"\n    ✅ ACTION:")
        print(f"    {inc['action']}")
        print("-"*60)

# Show High Incidents
if high_incidents:
    print("\n🟠 HIGH PRIORITY - ACT TODAY")
    print("-"*60)
    for i, inc in enumerate(high_incidents, 1):
        print(f"\n[{i}] {inc.get('incident_title', 'Unknown')}")
        print(f"    🖥️  Host:       {inc['hostname']}")
        print(f"    🏢 Department: {inc['department']}")
        print(f"    👤 User:       {inc['username']}")
        print(f"    📊 Alerts:     {inc['alert_count']} related alerts")
        print(f"    🎯 Confidence: {inc['confidence']}%")
        print(f"\n    📖 WHAT HAPPENED:")
        print(f"    {inc['what_happened']}")
        print(f"\n    ✅ ACTION:")
        print(f"    {inc['action']}")
        print("-"*60)

# Show Medium Incidents
if medium_incidents:
    print("\n🟡 MEDIUM PRIORITY - ACT THIS WEEK")
    print("-"*60)
    for i, inc in enumerate(medium_incidents, 1):
        print(f"\n[{i}] {inc.get('incident_title', 'Unknown')}")
        print(f"    🖥️  Host:       {inc['hostname']}")
        print(f"    🏢 Department: {inc['department']}")
        print(f"    👤 User:       {inc['username']}")
        print(f"    📊 Alerts:     {inc['alert_count']} related alerts")
        print(f"    🎯 Confidence: {inc['confidence']}%")
        print(f"\n    📖 WHAT HAPPENED:")
        print(f"    {inc['what_happened']}")
        print(f"\n    ✅ ACTION:")
        print(f"    {inc['action']}")
        print("-"*60)

# Show Low Incidents
if low_incidents:
    print("\n🟢 LOW PRIORITY - MONITOR ONLY")
    print("-"*60)
    for i, inc in enumerate(low_incidents, 1):
        print(f"\n[{i}] {inc.get('incident_title', 'Unknown')}")
        print(f"    🖥️  Host:       {inc['hostname']}")
        print(f"    🏢 Department: {inc['department']}")
        print(f"    📊 Alerts:     {inc['alert_count']} related alerts")
        print("-"*60)

# Show suppressed alerts summary
print("\n✅ AUTO SUPPRESSED ALERTS - NO ACTION NEEDED")
print("-"*60)
for alert in suppressed:
    print(f"  • {alert['alert_id']} | {alert['device']['hostname']} | {alert['suppression_reason']}")

print("\n")
print("="*60)
print("  ANALYSIS COMPLETE")
print(f"  Your analysts need to review {len(critical_incidents) + len(high_incidents)} incidents")
print(f" Agent handled {len(suppressed)} alerts automatically")
print("="*60)