# SOC Agent - RAG Engine
# This gives our agent a threat intel knowledge base

import chromadb
import json
import os

# ============================================
# SETUP CHROMADB
# ============================================

def setup_rag():
    """
    Sets up ChromaDB and loads threat intel
    Returns a collection ready for searching
    """
    # Create ChromaDB client
    chroma_client = chromadb.PersistentClient(
        path="knowledge_base/chroma_db"
    )

    # Create or get collection
    collection = chroma_client.get_or_create_collection(
        name="threat_intel",
        metadata={"hnsw:space": "cosine"}
    )

    # Only load data if collection is empty
    if collection.count() == 0:
        print("Loading threat intel into knowledge base...")
        load_threat_intel(collection)
        print(f"Loaded {collection.count()} threat intel records!")
    else:
        print(f"Knowledge base ready with {collection.count()} records!")

    return collection

def load_threat_intel(collection):
    """
    Loads threat intel from JSON file into ChromaDB
    """
    with open("knowledge_base/threat_intel.json", "r") as f:
        threat_intel = json.load(f)

    documents = []
    metadatas = []
    ids = []

    for item in threat_intel:
        # Build searchable text for each intel item
        if item["type"] == "mitre_technique":
            text = f"""
            MITRE Technique: {item['name']}
            ID: {item['id']}
            Description: {item['description']}
            Indicators: {', '.join(item['indicators'])}
            Threat Groups: {', '.join(item['threat_groups'])}
            Severity: {item['severity']}
            """
        elif item["type"] == "malicious_ip":
            text = f"""
            Malicious IP: {item['ip']}
            Description: {item['description']}
            Threat Groups: {', '.join(item['threat_groups'])}
            Severity: {item['severity']}
            """
        elif item["type"] == "malicious_domain":
            text = f"""
            Malicious Domain: {item['domain']}
            Description: {item['description']}
            Threat Groups: {', '.join(item['threat_groups'])}
            Severity: {item['severity']}
            """
        elif item["type"] == "false_positive_pattern":
            text = f"""
            False Positive Pattern: {item['name']}
            Description: {item['description']}
            Indicators: {', '.join(item['indicators'])}
            Severity: {item['severity']}
            """

        documents.append(text.strip())
        metadatas.append({
            "id": item["id"],
            "type": item["type"],
            "severity": item["severity"]
        })
        ids.append(item["id"])

    # Add to ChromaDB
    collection.add(
        documents=documents,
        metadatas=metadatas,
        ids=ids
    )

# ============================================
# SEARCH KNOWLEDGE BASE
# ============================================

def search_threat_intel(collection, query, n_results=3):
    """
    Searches knowledge base for relevant threat intel
    Returns matching intel as formatted text
    """
    results = collection.query(
        query_texts=[query],
        n_results=n_results
    )

    if not results["documents"][0]:
        return "No relevant threat intel found."

    # Format results
    intel_text = "RELEVANT THREAT INTEL FROM KNOWLEDGE BASE:\n"
    intel_text += "="*50 + "\n"

    for i, doc in enumerate(results["documents"][0]):
        intel_text += f"\n{doc}\n"
        intel_text += "-"*30 + "\n"

    return intel_text

def get_intel_for_alert(collection, alert):
    """
    Gets relevant threat intel for a specific alert
    Searches by process name, domain, technique
    """
    # Build search query from alert
    search_terms = []

    process = alert["process"]["name"]
    command = alert["process"]["command_line"]
    domain = alert["network"]["domain"]
    technique = alert["technique"]
    category = alert["category"]

    search_terms.append(process)
    search_terms.append(command[:100])
    search_terms.append(domain)
    search_terms.append(technique)
    search_terms.append(category)

    query = " ".join(search_terms)

    return search_threat_intel(collection, query)

# ============================================
# TEST THE RAG ENGINE
# ============================================

if __name__ == "__main__":
    print("Setting up RAG engine...")
    collection = setup_rag()

    print("\nTesting search...")
    result = search_threat_intel(
        collection,
        "vssadmin delete shadows ransomware"
    )
    print(result)

    print("\nTesting with alert...")
    test_alert = {
        "process": {
            "name": "vssadmin.exe",
            "command_line": "vssadmin.exe delete shadows /all /quiet"
        },
        "network": {
            "domain": "cdn-update-service.ru"
        },
        "technique": "T1490 - Inhibit System Recovery",
        "category": "Ransomware"
    }
    result = get_intel_for_alert(collection, test_alert)
    print(result)