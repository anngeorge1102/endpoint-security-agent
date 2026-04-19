# SOC Agent - Triage Agent using Groq
from groq import Groq
import json

# Configure Groq
import os
client = Groq(api_key=os.environ.get("GROQ_API_KEY"))

# Load your alerts dataset
with open("alerts/crowdstrike_alerts_dataset.json", "r") as f:
    alerts = json.load(f)

# Pick the first alert to test with
alert = alerts[0]
print(f"Testing with alert: {alert['alert_id']}")
print(f"Category: {alert['category']}")
print(f"True Label: {alert['true_label']}")
print("-" * 50)

# This is the agent's job description
system_prompt = """
You are an expert SOC analyst helping triage 
endpoint security alerts from CrowdStrike.

Analyze the alert and respond ONLY in this exact 
JSON format, nothing else, no extra text:

{
    "verdict": "True Positive" or "False Positive" or "Needs Review",
    "confidence": number between 0 and 100,
    "what_happened": "explain in simple terms what happened in this alert, like you are explaining to a junior analyst",
    "why_this_verdict": "explain clearly why you classified it as True Positive, False Positive or Needs Review. mention specific evidence from the alert",
    "attack_story": "tell the full story of what the attacker did or tried to do step by step",
    "risk": "what is the risk to the organization if this is not acted on",
    "action": "exact steps the analyst should take right now"
}
"""

# Send alert to Groq
print("Sending alert to AI...")
response = client.chat.completions.create(
    model="llama-3.3-70b-versatile",
    messages=[
        {
            "role": "system",
            "content": system_prompt
        },
        {
            "role": "user",
            "content": f"Triage this alert:\n\n{json.dumps(alert, indent=2)}"
        }
    ],
    temperature=0.1
)

# Get the response text
response_text = response.choices[0].message.content
print("\nAI Raw Response:")
print(response_text)

# Clean and parse the JSON
clean_response = response_text.strip()
if "```json" in clean_response:
    clean_response = clean_response.split("```json")[1].split("```")[0].strip()
elif "```" in clean_response:
    clean_response = clean_response.split("```")[1].split("```")[0].strip()

result = json.loads(clean_response)

print("\n" + "="*60)
print(f"ALERT ID:       {alert['alert_id']}")
print(f"VERDICT:        {result['verdict']}")
print(f"CONFIDENCE:     {result['confidence']}%")
print(f"\nWHAT HAPPENED:\n{result['what_happened']}")
print(f"\nWHY THIS VERDICT:\n{result['why_this_verdict']}")
print(f"\nATTACK STORY:\n{result['attack_story']}")
print(f"\nRISK:\n{result['risk']}")
print(f"\nACTION:\n{result['action']}")
print("="*60)