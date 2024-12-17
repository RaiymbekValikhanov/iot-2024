import requests
import argparse
import pandas as pd
import time
import json
import random
from typing import Optional

CENTRAL_SERVICE_URL = "http://localhost:8000/send-log"

def emulate_logs_from_csv(csv_file: str, device_id: str):
    """
    Reads logs from a CSV file and sends them to the central service.
    Args:
        csv_file (str): Path to the CSV file containing log data.
        device_id (str): Unique identifier for the emulated device.
    """
    try:
        df = pd.read_csv(csv_file)

        for _, row in df.iterrows():
            payload = row.fillna(0).to_dict()
            print(payload)
            try:
                response = requests.post(CENTRAL_SERVICE_URL + f"?device_id={device_id}", json=payload)
                if response.status_code == 200:
                    print(f"Log sent successfully from {device_id}: {payload}")
                else:
                    print(f"Failed to send log. Response: {response.text}")
            except Exception as e:
                print(f"Error sending log: {e}")

            time.sleep(1)

    except FileNotFoundError:
        print(f"CSV file {csv_file} not found.")
    except Exception as e:
        print(f"Error reading or processing CSV file: {e}")


if __name__ == "__main__":
    # CSV_FILE = "logs.csv"
    # DEVICE_ID = "123"

    parser = argparse.ArgumentParser()
    parser.add_argument("log_file", help="File with logs")
    parser.add_argument("device_id", help="Device ID")

    args = parser.parse_args()
    print(args.log_file, args.device_id)

    print(f"Starting log emulation for device: {args.device_id}")
    emulate_logs_from_csv(args.log_file, args.device_id)