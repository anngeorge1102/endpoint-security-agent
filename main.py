import anthropic
import chromadb
import pandas
import requests
import json

print("Anthropic Loaded!")
print("ChromaDB loaded!")
print("Pandas loaded!")
print("Requests loaded!")

with open("alerts/crowdstrike_alerts_dataset.json","r") as f:
    alerts = json.load(f)

print(f"✅ Dataset loaded: {len(alerts)} alerts ready!")
print(f"   First alert: {alerts[0]['alert_id']}")
print(f"   Last alert: {alerts[-1]['alert_id']}")
print("")
print("🎉 Environment ready! Lets build this agent!")