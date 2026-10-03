"""
src/traffic_simulator.py
NGFW - Network Traffic Simulator

Generates realistic network traffic patterns including normal flows,
port scans, DDoS attacks, and data exfiltration attempts.

Author: Allben Rakgoale
"""

import random
import numpy as np
import pandas as pd
from datetime import datetime, timedelta

np.random.seed(42)
random.seed(42)


# Attack types with their signatures
ATTACK_TYPES = ["normal", "port_scan", "ddos", "exfiltration"]

# Common ports
COMMON_PORTS = [80, 443, 22, 53, 443, 8080, 3306, 5432]

# Internal IP ranges
INTERNAL_IPS = [f"192.168.1.{i}" for i in range(10, 100)]
EXTERNAL_IPS = [
    "8.8.8.8", "1.1.1.1", "142.250.185.78",
    "104.16.132.229", "185.220.101.5",
    "45.142.212.61", "89.248.165.74",
]


def generate_normal_flow(timestamp: datetime) -> dict:
    """Generate a single normal network flow."""
    return {
        "timestamp": timestamp,
        "src_ip": random.choice(INTERNAL_IPS),
        "dst_ip": random.choice(EXTERNAL_IPS),
        "src_port": random.randint(49152, 65535),
        "dst_port": random.choice(COMMON_PORTS),
        "protocol": random.choice(["TCP", "UDP", "TCP", "TCP"]),  # Weighted TCP
        "packet_size": int(np.random.normal(800, 200)),
        "duration_ms": int(np.random.normal(500, 150)),
        "packets_sent": int(np.random.normal(15, 5)),
        "bytes_sent": int(np.random.normal(12000, 3000)),
        "flags_syn": random.randint(0, 2),
        "flags_ack": random.randint(2, 5),
        "flags_fin": random.randint(0, 1),
        "payload_entropy": round(np.random.normal(4.5, 0.5), 2),
        "label": "normal",
    }


def generate_port_scan(timestamp: datetime) -> dict:
    """Generate a port scan flow."""
    return {
        "timestamp": timestamp,
        "src_ip": random.choice(EXTERNAL_IPS),
        "dst_ip": random.choice(INTERNAL_IPS),
        "src_port": random.randint(49152, 65535),
        "dst_port": random.randint(1, 65535),  # Random target port
        "protocol": "TCP",
        "packet_size": random.randint(40, 60),  # Tiny SYN packets
        "duration_ms": random.randint(1, 10),  # Very fast
        "packets_sent": 1,  # SYN only
        "bytes_sent": random.randint(40, 60),
        "flags_syn": 1,
        "flags_ack": 0,
        "flags_fin": 0,
        "payload_entropy": 0.0,  # No payload
        "label": "port_scan",
    }


def generate_ddos(timestamp: datetime) -> dict:
    """Generate a DDoS attack flow."""
    return {
        "timestamp": timestamp,
        "src_ip": random.choice(EXTERNAL_IPS),
        "dst_ip": random.choice(INTERNAL_IPS),
        "src_port": random.randint(1, 65535),
        "dst_port": random.choice([80, 443]),
        "protocol": random.choice(["TCP", "UDP"]),
        "packet_size": random.randint(1000, 1500),  # Large packets
        "duration_ms": random.randint(100, 500),
        "packets_sent": random.randint(500, 5000),  # Massive volume
        "bytes_sent": random.randint(500000, 5000000),
        "flags_syn": random.randint(100, 500),  # SYN flood
        "flags_ack": 0,
        "flags_fin": 0,
        "payload_entropy": round(np.random.normal(5.5, 0.8), 2),
        "label": "ddos",
    }


def generate_exfiltration(timestamp: datetime) -> dict:
    """Generate a data exfiltration flow."""
    return {
        "timestamp": timestamp,
        "src_ip": random.choice(INTERNAL_IPS),  # Insider
        "dst_ip": random.choice(EXTERNAL_IPS),  # External C2 server
        "src_port": random.randint(49152, 65535),
        "dst_port": random.choice([443, 8443, 22]),  # Encrypted channels
        "protocol": "TCP",
        "packet_size": random.randint(1400, 1500),
        "duration_ms": random.randint(30000, 300000),  # Long sessions
        "packets_sent": random.randint(1000, 10000),
        "bytes_sent": random.randint(50000000, 500000000),  # 50MB–500MB
        "flags_syn": 1,
        "flags_ack": random.randint(500, 2000),
        "flags_fin": 1,
        "payload_entropy": round(np.random.normal(7.5, 0.3), 2),  # High entropy = encrypted
        "label": "exfiltration",
    }


def generate_traffic(n_flows: int = 1000) -> pd.DataFrame:
    """
    Generate a mixed dataset of normal and malicious network flows.

    Distribution:
        - 75% normal
        - 10% port scan
        - 10% DDoS
        - 5% exfiltration
    """
    now = datetime.now()
    flows = []

    for _ in range(n_flows):
        # Random timestamp within last 24 hours
        timestamp = now - timedelta(seconds=random.randint(0, 86400))

        r = random.random()
        if r < 0.75:
            flows.append(generate_normal_flow(timestamp))
        elif r < 0.85:
            flows.append(generate_port_scan(timestamp))
        elif r < 0.95:
            flows.append(generate_ddos(timestamp))
        else:
            flows.append(generate_exfiltration(timestamp))

    df = pd.DataFrame(flows).sort_values("timestamp").reset_index(drop=True)
    return df


if __name__ == "__main__":
    print("🌐 Generating network traffic dataset...")
    df = generate_traffic(n_flows=2000)
    print(f"✅ Generated {len(df):,} flows")
    print(f"\n📊 Distribution:")
    print(df["label"].value_counts())
