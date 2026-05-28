from scapy.all import sniff, IP, TCP, UDP
import joblib
import pandas as pd
from datetime import datetime
import os
import sqlite3
import requests
from collections import defaultdict
import time

from app.firewall_engine.blocker import block_ip, is_blocked

# =====================================
# LOAD TRAINED AI MODEL
# =====================================

model = joblib.load("models/firewall_model.pkl")

# =====================================
# CREATE LOG DIRECTORY
# =====================================

os.makedirs("logs", exist_ok=True)

log_file_path = os.path.join("logs", "firewall_logs.txt")

# =====================================
# STORE LOGGED IPS (ANTI-SPAM)
# =====================================

logged_ips = {}

# =====================================
# ATTACK TRACKER (NEW IDS LAYER)
# =====================================

attack_tracker = defaultdict(lambda: {
    "count": 0,
    "ports": set(),
    "first_seen": time.time()
})

# =====================================
# TELEGRAM CONFIGURATION (UNCHANGED)
# =====================================

BOT_TOKEN = "8904245437:AAHSXUbhImOcvqJsWFvYJxZ57Gay3GQp8ZY"
CHAT_ID = "1258692810"

# =====================================
# GEOIP CACHE
# =====================================

geo_cache = {}

# =====================================
# GEOIP FUNCTION
# =====================================

def get_geoip_info(ip):
    try:
        url = f"http://ip-api.com/json/{ip}"
        response = requests.get(url, timeout=5)
        data = response.json()

        if data["status"] == "success":
            return {
                "country": data.get("country", "Unknown"),
                "city": data.get("city", "Unknown"),
                "isp": data.get("isp", "Unknown")
            }
    except Exception:
        pass

    return {
        "country": "Unknown",
        "city": "Unknown",
        "isp": "Unknown"
    }

# =====================================
# CACHED GEOIP
# =====================================

def get_geoip_cached(ip):

    if ip in geo_cache:
        return geo_cache[ip]

    geo = get_geoip_info(ip)
    geo_cache[ip] = geo

    return geo

# =====================================
# TELEGRAM ALERT
# =====================================

def send_telegram_alert(message):

    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"

    data = {
        "chat_id": CHAT_ID,
        "text": message
    }

    try:
        requests.post(url, data=data, timeout=5)
    except Exception as e:
        print(f"Telegram Error: {e}")

# =====================================
# PROCESS PACKETS
# =====================================

def process_packet(packet):

    if packet.haslayer(IP):

        source_ip = packet[IP].src

        if is_blocked(source_ip):
            return

        protocol = packet[IP].proto
        packet_length = len(packet)

        destination_port = 0

        if packet.haslayer(TCP):
            destination_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            destination_port = packet[UDP].dport

        # =====================================
        # ATTACK TRACKING (NEW)
        # =====================================

        tracker = attack_tracker[source_ip]

        tracker["count"] += 1
        tracker["ports"].add(destination_port)

        if time.time() - tracker["first_seen"] > 60:
            tracker["count"] = 1
            tracker["ports"] = {destination_port}
            tracker["first_seen"] = time.time()

        # =====================================
        # AI INPUT
        # =====================================

        features = pd.DataFrame([{
            "packet_length": packet_length,
            "protocol": protocol,
            "destination_port": destination_port
        }])

        prediction = model.predict(features)[0]

        print("\n===== AI FIREWALL ANALYSIS =====")
        print(f"Source IP: {source_ip}")
        print(f"Packet Length: {packet_length}")
        print(f"Protocol: {protocol}")
        print(f"Destination Port: {destination_port}")

        # =====================================
        # ATTACK TYPE DETECTION (NEW IDS LAYER)
        # =====================================

        attack_type = None

        if len(tracker["ports"]) > 8:
            attack_type = "PORT SCANNING"

        elif tracker["count"] > 50:
            attack_type = "DOS / TRAFFIC FLOOD"

        elif destination_port in [22, 3389, 445] and tracker["count"] > 10:
            attack_type = "BRUTE FORCE ATTEMPT"

        # =====================================
        # SUSPICIOUS TRAFFIC 
        # ML + IDS ENGINE
        # =====================================

        if prediction == 1 or attack_type is not None:

            current_time = datetime.now()
            cooldown = 60

            if (
                source_ip not in logged_ips
                or (current_time - logged_ips[source_ip]).seconds > cooldown
            ):

                logged_ips[source_ip] = current_time

                print("🚨 AI ALERT: Suspicious Traffic Detected!")

                timestamp = current_time.strftime("%Y-%m-%d %H:%M:%S")

                # =====================================
                # GEOIP ENRICHMENT
                # =====================================

                geo = get_geoip_cached(source_ip)

                country = geo["country"]
                city = geo["city"]
                isp = geo["isp"]

                # =====================================
                # THREAT LEVEL (UPDATED)
                # =====================================

                if attack_type == "DOS / TRAFFIC FLOOD":
                    threat_level = "CRITICAL"
                elif attack_type == "PORT SCANNING":
                    threat_level = "HIGH"
                elif attack_type == "BRUTE FORCE ATTEMPT":
                    threat_level = "CRITICAL"
                elif destination_port in [22, 3389, 445]:
                    threat_level = "HIGH"
                else:
                    threat_level = "MEDIUM"

                # =====================================
                # LOG MESSAGE
                # =====================================

                alert_message = (
                    f"{timestamp} | ALERT | "
                    f"Attack Type: {attack_type} | "
                    f"IP: {source_ip} | "
                    f"Port: {destination_port} | "
                    f"Threat: {threat_level} | "
                    f"{country}, {city}, {isp}"
                )

                with open(log_file_path, "a") as log_file:
                    log_file.write(alert_message + "\n")

                # =====================================
                # DATABASE SAVE
                # =====================================

                connection = sqlite3.connect("firewall.db")
                cursor = connection.cursor()

                cursor.execute("""
                    INSERT INTO logs (
                        timestamp,
                        source_ip,
                        destination_port,
                        threat_level,
                        message
                    )
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    timestamp,
                    source_ip,
                    destination_port,
                    threat_level,
                    alert_message
                ))

                connection.commit()
                connection.close()

                # =====================================
                # TELEGRAM ALERT
                # =====================================

                telegram_message = f"""
🚨 AI FIREWALL ALERT 🚨

Threat Level: {threat_level}
Attack Type: {attack_type if attack_type else "Suspicious Activity"}

IP: {source_ip}
Location: {country}, {city}
ISP: {isp}

Port: {destination_port}
Packet Count: {tracker['count']}
Unique Ports: {len(tracker['ports'])}
Time: {timestamp}
"""

                send_telegram_alert(telegram_message)

                # =====================================
                # BLOCK IP
                # =====================================

                block_ip(source_ip)

            else:
                print(f"Ignored duplicate attack from {source_ip}")

        else:
            print("Traffic appears normal.")

# =====================================
# START FIREWALL
# =====================================

print("====================================")
print("AI FIREWALL STARTED SUCCESSFULLY")
print("Monitoring Network Traffic...")
print("====================================")

sniff(prn=process_packet, store=False)