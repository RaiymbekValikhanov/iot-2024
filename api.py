import os
from typing import Optional
from pydantic import BaseModel
import uvicorn
from fastapi import FastAPI
import pandas as pd
import lightgbm
import sklearn
import joblib
import numpy as np
import requests
import threading
import time
from datetime import datetime, timedelta
from queue import Queue
from collections import defaultdict

app = FastAPI()
log_queue = Queue()
device_status = defaultdict(lambda: {"status": "ok", "history": [], "sent": None})

MODEL_PATH = "lgbm_model.pkl"
try:
    print(f"Start loading model")
    model = joblib.load(MODEL_PATH)
    print(f"Model loaded")
except Exception as e:
    print(f"Error loading model: {e}")
    model = None

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")


class LogSchema(BaseModel):
    duration: Optional[float] = 0.0
    orig_bytes: Optional[float] = 0.0
    resp_bytes: Optional[float] = 0.0
    orig_pkts: Optional[float] = 0.0
    orig_ip_bytes: Optional[float] = 0.0
    resp_pkts: Optional[float] = 0.0
    resp_ip_bytes: Optional[float] = 0.0
    icmp: Optional[bool] = False
    tcp: Optional[bool] = False
    udp: Optional[bool] = False


# Endpoint to register new devices
@app.post("/register-device")
def register_device(device_id: str):
    if device_id in device_status:
        return {"status": "error", "message": "Device already registered."}
    device_status[device_id] = {"status": "ok", "history": [], "sent": None}
    return {"status": "success", "message": f"Device {device_id} registered successfully."}


# Endpoint to receive logs and add them to the queue
@app.post("/send-log")
def receive_log(device_id: str, log: LogSchema):
    """Receives logs from devices and adds them to the queue."""
    log_data = {
        "device_id": device_id,
        "duration": log.duration,
        "orig_bytes": log.orig_bytes,
        "resp_bytes": log.resp_bytes,
        "orig_pkts": log.orig_pkts,
        "orig_ip_bytes": log.orig_ip_bytes,
        "resp_pkts": log.resp_pkts,
        "resp_ip_bytes": log.resp_ip_bytes,
        "icmp": log.icmp,
        "tcp": log.tcp,
        "udp": log.udp,
        "timestamp": time.time()
    }
    log_queue.put(log_data)
    return {"status": "success", "message": "Log received."}


@app.get("/devices")
def get_devices():
    return {device_id: details for device_id, details in device_status.items()}


def send_telegram_alert(message: str):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message
    }
    try:
        response = requests.post(url, json=payload)
        if response.status_code == 200:
            print("Alert sent to Telegram.")
        else:
            print(f"Failed to send alert: {response.text}")
    except Exception as e:
        print(f"Error sending Telegram alert: {e}")


# Endless job to consume logs from the queue and run model
def consume_logs():
    while True:
        if not log_queue.empty():
            log_data = log_queue.get()
            print(f"Processing log: {log_data}")

            numeric_data = np.array([[
                log_data.get("duration", 0.0),
                log_data.get("orig_bytes", 0.0),
                log_data.get("resp_bytes", 0.0),
                log_data.get("orig_pkts", 0.0),
                log_data.get("orig_ip_bytes", 0.0),
                log_data.get("resp_pkts", 0.0),
                log_data.get("resp_ip_bytes", 0.0),
                int(log_data.get("icmp", False)),
                int(log_data.get("tcp", False)),
                int(log_data.get("udp", False))
            ]])

            prediction = model.predict(numeric_data)

            device_id = log_data["device_id"]
            if device_id not in device_status:
                device_status[device_id] = {"status": "ok", "history": [], "sent": None}

            status = "attack" if prediction[0] == 1 else "ok"
            device_status[device_id]["status"] = status
            device_status[device_id]["history"].append({
                "timestamp": log_data["timestamp"],
                "status": status
            })

            if all(x["status"] == "attack" for x in device_status[device_id]["history"][-5:]):
                print(device_status[device_id]["sent"])
                if device_status[device_id]["sent"] is None or time.time() - device_status[device_id]["sent"] >= 1000: 
                    send_telegram_alert(f"⚠️ Attack detected for device {device_id}.")
                    device_status[device_id]["sent"] = time.time()
            else:
                print("OK")
        else:
            time.sleep(1)


# Start the log consumption job in a separate thread
threading.Thread(target=consume_logs, daemon=True).start()

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
