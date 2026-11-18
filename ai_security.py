import json
import os
import urllib.request


OLLAMA_URL = os.getenv(
    "OLLAMA_URL",
    "http://127.0.0.1:11434/api/generate",
)
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:1b")
OLLAMA_TIMEOUT = float(os.getenv("OLLAMA_TIMEOUT", "30"))
OLLAMA_TEMPERATURE = float(os.getenv("OLLAMA_TEMPERATURE", "0"))


def calculate_risk(events):
    prompt = (
        "You are an AI firewall security classifier. "
        "Analyze the events and return a JSON object with a single integer field "
        "\"risk\" from 0 to 100. Return only the JSON object.\n\n"
        f"Events: {json.dumps(events)}"
    )
    payload = json.dumps(
        {
            "model": OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {"temperature": OLLAMA_TEMPERATURE},
        }
    ).encode("utf-8")

    request = urllib.request.Request(
        OLLAMA_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=OLLAMA_TIMEOUT) as response:
        result = json.loads(response.read().decode("utf-8"))

    model_result = json.loads(result["response"])
    return max(0, min(100, int(model_result["risk"])))
