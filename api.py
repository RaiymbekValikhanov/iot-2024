from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional
from queue import Queue
from collections import defaultdict
import threading
import time
import requests
import os
import joblib
import numpy as np

app = FastAPI()
log_queue = Queue()
device_status = defaultdict(lambda: {"status": "ok", "history": [], "sent": None, "metadata": {}})

MODEL_PATH = "lgbm_model_2.pkl"
try:
    print("Start loading model")
    model = joblib.load(MODEL_PATH)
    print("Model loaded")
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


class RegisterDeviceSchema(BaseModel):
    device_id: str
    name: str
    type: str
    location: Optional[str] = None
    ip_address: Optional[str] = None
    admin_contact: Optional[str] = None


@app.post("/register-device")
def register_device(details: RegisterDeviceSchema):
    if details.device_id in device_status:
        return {"status": "error", "message": "Device already registered."}

    device_status[details.device_id] = {
        "status": "ok",
        "history": [],
        "sent": None,
        "metadata": {
            "name": details.name,
            "type": details.type,
            "location": details.location,
            "ip_address": details.ip_address,
            "admin_contact": details.admin_contact,
        },
    }
    return {"status": "success", "message": f"Device {details.device_id} registered successfully."}


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
            print(prediction)

            device_id = log_data["device_id"]
            if device_id not in device_status:
                device_status[device_id] = {"status": "ok", "history": [], "sent": None}

            # status = "ok" if prediction[0] == "Benign" else "attack"
            status = prediction[0]
            device_status[device_id]["status"] = status
            device_status[device_id]["history"].append({
                "timestamp": log_data["timestamp"],
                "status": status
            })

            if all(x["status"] != "Benign" for x in device_status[device_id]["history"][-5:]):
                if device_status[device_id]["sent"] is None or time.time() - device_status[device_id]["sent"] >= 1000:
                    metadata = device_status[device_id]["metadata"]
                    attack_type = device_status[device_id]["history"][-1]["status"]
                    alert_message = (
                        f"\u26A0\uFE0F *Attack Alert* \u26A0\uFE0F\n\n"
                        f"\ud83d\udccd *Device*: `{metadata.get('name', 'Unknown Device')}`\n"
                        f"\ud83d\udd11 *Device ID*: `{device_id}`\n"
                        f"\ud83d\udcbb *Type*: `{metadata.get('type', 'Unknown Type')}`\n"
                        f"\ud83d\udd34 *Status*: `Under Attack`\n"
                        f"\ud83d\udea8 *Attack Type*: `{attack_type}`\n"
                        f"\ud83d\udd39 *Location*: `{metadata.get('location', 'Unknown Location')}`\n"
                        f"\ud83c\udf10 *IP Address*: `{metadata.get('ip_address', 'Unknown IP')}`\n"
                        f"\u23F0 *Detected At*: `{time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(log_data['timestamp']))}`\n\n"
                        f"\ud83d\udee0 *Suggested Action*:\n"
                        f"- Investigate logs.\n"
                        f"- Disconnect from the network.\n"
                        f"- Contact: {metadata.get('admin_contact', 'Unknown Contact')}."
                    )
                    send_telegram_alert(alert_message)
                    device_status[device_id]["sent"] = time.time()
        else:
            time.sleep(1)

threading.Thread(target=consume_logs, daemon=True).start()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)