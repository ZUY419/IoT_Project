from langchain_ollama import OllamaLLM
import paho.mqtt.client as mqtt
import json
import time

# LLM
llm = OllamaLLM(
    model="deepseek-r1:7b",
    base_url="http://ollama:11434"
)

# MQTT
client = mqtt.Client()

client.connect("mqtt_broker", 1883, 60)

# Ask AI
response = llm.invoke(
    "Generate a JSON tool request for nmap scanning 192.168.1.10"
)

print(response)

# Example JSON
payload = {
    "tool": "nmap",
    "target": "192.168.1.10",
    "options": "-sS -T2"
}

# Publish
client.publish(
    "ai/tool_request",
    json.dumps(payload)
)

print("MQTT message sent")
time.sleep(2)
