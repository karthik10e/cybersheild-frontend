"""
CyberShield Benchmark Dataset Generator.
Synthesizes high-fidelity network traffic data based on the NSL-KDD / CIC-IDS benchmark standards.
Generates multi-class network flow records (Normal, DoS, Probe, R2L, U2R) with realistic distributions.
"""

import numpy as np
import pandas as pd
import random
import os

SEED = 42
np.random.seed(SEED)
random.seed(SEED)


def generate_nids_dataset(num_samples: int = 12000) -> pd.DataFrame:
    """
    Generates balanced multi-class network connection data.
    Classes:
      - Normal: 45%
      - DoS: 30%
      - Probe: 15%
      - R2L: 7%
      - U2R: 3%
    """
    records = []
    
    n_normal = int(num_samples * 0.45)
    n_dos = int(num_samples * 0.30)
    n_probe = int(num_samples * 0.15)
    n_r2l = int(num_samples * 0.07)
    n_u2r = num_samples - (n_normal + n_dos + n_probe + n_r2l)

    # 1. NORMAL TRAFFIC
    for _ in range(n_normal):
        proto = random.choice(["tcp", "tcp", "tcp", "udp", "icmp"])
        if proto == "tcp":
            service = random.choice(["http", "http", "http", "smtp", "ftp", "ssh", "other"])
            flag = "SF"
            src_bytes = int(np.random.exponential(scale=400) + 50)
            dst_bytes = int(np.random.exponential(scale=2500) + 100)
            logged_in = 1 if service in ["http", "smtp", "ftp"] else 0
        elif proto == "udp":
            service = "dns"
            flag = "SF"
            src_bytes = int(np.random.normal(68, 15))
            dst_bytes = int(np.random.normal(140, 30))
            logged_in = 0
        else: # icmp
            service = "eco_i"
            flag = "SF"
            src_bytes = 84
            dst_bytes = 0
            logged_in = 0

        duration = max(0.0, float(np.random.exponential(scale=0.5)))
        count = int(np.random.randint(1, 15))
        srv_count = int(np.random.randint(1, count + 1))
        
        records.append({
            "duration": round(duration, 2),
            "protocol_type": proto,
            "service": service,
            "flag": flag,
            "src_bytes": max(0, src_bytes),
            "dst_bytes": max(0, dst_bytes),
            "land": 0,
            "wrong_fragment": 0,
            "urgent": 0,
            "hot": 0,
            "num_failed_logins": 0,
            "logged_in": logged_in,
            "num_compromised": 0,
            "root_shell": 0,
            "su_attempted": 0,
            "num_root": 0,
            "num_file_creations": 0,
            "count": count,
            "srv_count": srv_count,
            "serror_rate": 0.0,
            "rerror_rate": 0.0,
            "same_srv_rate": round(random.uniform(0.85, 1.0), 2),
            "diff_srv_rate": round(random.uniform(0.0, 0.15), 2),
            "dst_host_count": int(np.random.randint(1, 50)),
            "dst_host_srv_count": int(np.random.randint(1, 50)),
            "label": "Normal"
        })

    # 2. DoS (Denial of Service - SYN Flood, Smurf, Neptune, Ping of Death)
    for _ in range(n_dos):
        attack_subtype = random.choice(["syn_flood", "smurf", "teardrop", "land"])
        if attack_subtype == "syn_flood":
            proto = "tcp"
            service = random.choice(["http", "private", "other"])
            flag = random.choice(["S0", "S0", "S0", "REJ"])
            src_bytes = 0
            dst_bytes = 0
            land = 0
            wrong_fragment = 0
            serror_rate = round(random.uniform(0.85, 1.0), 2)
            count = int(np.random.randint(100, 512))
            srv_count = int(np.random.randint(80, count))
        elif attack_subtype == "smurf":
            proto = "icmp"
            service = "eco_i"
            flag = "SF"
            src_bytes = 1032
            dst_bytes = 0
            land = 0
            wrong_fragment = 0
            serror_rate = 0.0
            count = int(np.random.randint(200, 512))
            srv_count = count
        elif attack_subtype == "land":
            proto = "tcp"
            service = "http"
            flag = "S0"
            src_bytes = 0
            dst_bytes = 0
            land = 1
            wrong_fragment = 0
            serror_rate = 1.0
            count = 1
            srv_count = 1
        else: # teardrop
            proto = "udp"
            service = "private"
            flag = "SF"
            src_bytes = 28
            dst_bytes = 0
            land = 0
            wrong_fragment = int(np.random.randint(1, 4))
            serror_rate = 0.0
            count = int(np.random.randint(10, 50))
            srv_count = count

        records.append({
            "duration": 0.0,
            "protocol_type": proto,
            "service": service,
            "flag": flag,
            "src_bytes": src_bytes,
            "dst_bytes": dst_bytes,
            "land": land,
            "wrong_fragment": wrong_fragment,
            "urgent": 0,
            "hot": 0,
            "num_failed_logins": 0,
            "logged_in": 0,
            "num_compromised": 0,
            "root_shell": 0,
            "su_attempted": 0,
            "num_root": 0,
            "num_file_creations": 0,
            "count": count,
            "srv_count": srv_count,
            "serror_rate": serror_rate,
            "rerror_rate": 0.0 if flag != "REJ" else round(random.uniform(0.7, 1.0), 2),
            "same_srv_rate": round(random.uniform(0.8, 1.0), 2),
            "diff_srv_rate": round(random.uniform(0.0, 0.2), 2),
            "dst_host_count": 255,
            "dst_host_srv_count": min(255, srv_count),
            "label": "DoS"
        })

    # 3. PROBE (Reconnaissance, Nmap, Portscan, IPSweep)
    for _ in range(n_probe):
        proto = random.choice(["tcp", "udp", "icmp"])
        service = random.choice(["other", "private", "http", "ssh", "dns"])
        flag = random.choice(["REJ", "RSTO", "RSTR", "SH", "SF"])
        count = int(np.random.randint(5, 100))
        srv_count = int(np.random.randint(1, max(2, int(count * 0.2))))
        diff_srv_rate = round(random.uniform(0.6, 1.0), 2)
        same_srv_rate = round(1.0 - diff_srv_rate, 2)

        records.append({
            "duration": round(float(np.random.exponential(scale=0.1)), 2),
            "protocol_type": proto,
            "service": service,
            "flag": flag,
            "src_bytes": int(np.random.choice([0, 20, 44, 60])),
            "dst_bytes": 0,
            "land": 0,
            "wrong_fragment": 0,
            "urgent": 0,
            "hot": 0,
            "num_failed_logins": 0,
            "logged_in": 0,
            "num_compromised": 0,
            "root_shell": 0,
            "su_attempted": 0,
            "num_root": 0,
            "num_file_creations": 0,
            "count": count,
            "srv_count": srv_count,
            "serror_rate": 0.0,
            "rerror_rate": round(random.uniform(0.5, 1.0), 2) if flag in ["REJ", "RSTO"] else 0.0,
            "same_srv_rate": same_srv_rate,
            "diff_srv_rate": diff_srv_rate,
            "dst_host_count": int(np.random.randint(100, 255)),
            "dst_host_srv_count": int(np.random.randint(1, 30)),
            "label": "Probe"
        })

    # 4. R2L (Remote to Local: Brute Force SSH/FTP, Guess Password)
    for _ in range(n_r2l):
        service = random.choice(["ftp", "ssh", "telnet", "http"])
        failed_logins = int(np.random.randint(2, 6))
        hot_indicators = int(np.random.randint(1, 4))
        
        records.append({
            "duration": round(float(np.random.exponential(scale=3.0) + 1.0), 2),
            "protocol_type": "tcp",
            "service": service,
            "flag": random.choice(["SF", "SF", "RSTO"]),
            "src_bytes": int(np.random.randint(100, 600)),
            "dst_bytes": int(np.random.randint(50, 400)),
            "land": 0,
            "wrong_fragment": 0,
            "urgent": 0,
            "hot": hot_indicators,
            "num_failed_logins": failed_logins,
            "logged_in": 0, # Failed unauthorized login
            "num_compromised": 0,
            "root_shell": 0,
            "su_attempted": 0,
            "num_root": 0,
            "num_file_creations": 0,
            "count": int(np.random.randint(1, 10)),
            "srv_count": int(np.random.randint(1, 10)),
            "serror_rate": 0.0,
            "rerror_rate": 0.0,
            "same_srv_rate": 1.0,
            "diff_srv_rate": 0.0,
            "dst_host_count": int(np.random.randint(1, 20)),
            "dst_host_srv_count": int(np.random.randint(1, 20)),
            "label": "R2L"
        })

    # 5. U2R (User to Root: Privilege escalation, buffer overflow, rootkit)
    for _ in range(n_u2r):
        service = random.choice(["telnet", "ssh", "other"])
        root_shell = 1
        su_attempted = int(np.random.choice([1, 2]))
        num_root = int(np.random.randint(1, 8))
        num_compromised = int(np.random.randint(1, 5))
        file_creations = int(np.random.randint(1, 4))
        
        records.append({
            "duration": round(float(np.random.exponential(scale=15.0) + 5.0), 2),
            "protocol_type": "tcp",
            "service": service,
            "flag": "SF",
            "src_bytes": int(np.random.randint(200, 3000)),
            "dst_bytes": int(np.random.randint(1000, 8000)),
            "land": 0,
            "wrong_fragment": 0,
            "urgent": int(np.random.choice([0, 1])),
            "hot": int(np.random.randint(2, 6)),
            "num_failed_logins": 0,
            "logged_in": 1,
            "num_compromised": num_compromised,
            "root_shell": root_shell,
            "su_attempted": su_attempted,
            "num_root": num_root,
            "num_file_creations": file_creations,
            "count": int(np.random.randint(1, 5)),
            "srv_count": int(np.random.randint(1, 5)),
            "serror_rate": 0.0,
            "rerror_rate": 0.0,
            "same_srv_rate": 1.0,
            "diff_srv_rate": 0.0,
            "dst_host_count": int(np.random.randint(1, 10)),
            "dst_host_srv_count": int(np.random.randint(1, 10)),
            "label": "U2R"
        })

    df = pd.DataFrame(records)
    return df.sample(frac=1.0, random_state=SEED).reset_index(drop=True)


if __name__ == "__main__":
    df = generate_nids_dataset()
    print(f"Generated {len(df)} samples.")
    print("Class distribution:\n", df["label"].value_counts())
    
    # Save sample capture for batch scanning demo
    sample_file = os.path.join(os.path.dirname(__file__), "..", "samples", "sample_capture.csv")
    df.head(200).to_csv(sample_file, index=False)
    print(f"Sample capture saved to: {sample_file}")
