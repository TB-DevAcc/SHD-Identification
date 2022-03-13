import datetime
import sys
from multiprocessing.sharedctypes import Value
from pathlib import Path
from tabnanny import verbose

import numpy as np
import pandas as pd
from joblib import load
from scapy.all import rdpcap

from convert_pcap_to_df import convert_pcap_to_df

# supply arguments as:
# python identify_device.py <classifier.joblib> <network_packets_to_classify.pcap>
clf_path = Path(sys.argv[1])
pcap_path = Path(sys.argv[2])

if not clf_path.is_file():
    raise ValueError("Provided classifier path is not a file.")
if not pcap_path.is_file():
    raise ValueError("Provided pcap path is not a file.")

print("Loading classifier from", clf_path.as_posix())
clf = load(clf_path.as_posix())

print("Loading packet from", pcap_path.as_posix())
df = convert_pcap_to_df(pcap_path.as_posix(), verbose=False)

for col in df.select_dtypes(["category"]).columns:
    df[col] = df[col].astype("string")
na_values = {
    # "time": 0,
    "payload": "NoPayload",
    "IP_version": "0",
    "IP_ihl": 0,
    "IP_tos": 0,
    "IP_len": 0,
    "IP_id": 0,
    "IP_flags": 0,
    "IP_frag": 0,
    "IP_ttl": 0,
    "IP_proto": 0,
    "IP_chksum": 0,
    "IP_src": "0",
    "IP_dst": "0",
    "TCP_sport": "0",
    "TCP_dport": "0",
    "TCP_seq": 0,
    "TCP_ack": 0,
    "TCP_dataofs": 0,
    "TCP_reserved": 0,
    "TCP_flags": 0,
    "TCP_window": 0,
    "TCP_chksum": 0,
    "TCP_urgptr": 0,
    "UDP_sport": "0",
    "UDP_dport": "0",
    "UDP_len": 0,
    "UDP_chksum": 0,
    "Raw_load": 0,
    "IP_int_arr_time": datetime.timedelta(seconds=0),
    "IP_Burst_ix": 0,
    "IP_Burst_length": 0,
    "IP_Burst_avg_size": 0,
}

df.fillna(value=na_values, inplace=True)

print("Sample:")
print(df)

training_features = [
    # 'time',
    # 'payload',
    # 'IP_version',
    # 'IP_ihl',
    # 'IP_tos',
    # 'IP_len',
    # 'IP_id',
    # 'IP_flags',
    # 'IP_frag',
    # 'IP_ttl',
    # 'IP_proto',
    # 'IP_chksum',
    # 'IP_src',
    # 'IP_dst',
    # 'TCP_sport',
    # 'TCP_dport',
    # 'TCP_seq',
    # 'TCP_ack',
    # 'TCP_dataofs',
    # 'TCP_reserved',
    # 'TCP_flags',
    # 'TCP_window',
    # 'TCP_chksum',
    # 'TCP_urgptr',
    # 'UDP_sport',
    # 'UDP_dport',
    # 'UDP_len',
    # 'UDP_chksum',
    "Raw_load",
    "IP_int_arr_time",
    # 'IP_Burst_ix',
    "IP_Burst_length",
    "IP_Burst_avg_size",
]

# dimensionality of one hot would be too high for Ports, so we use their integer values
for col in ["TCP_sport", "TCP_dport", "UDP_sport", "UDP_dport"]:
    df[col] = df[col].astype("UInt32")

df["IP_int_arr_time"] = (
    df["IP_int_arr_time"].dt.total_seconds() * 1000
)  # Convert timedelta to milliseconds
df["IP_int_arr_time"] = df["IP_int_arr_time"].astype("Float64")

y_pred = clf.predict(df[training_features])

y_pred = np.mean(y_pred, axis=0)
max_ix = np.argmax(y_pred)
label = ["Argus PT", "HomeBase2", "NoLabel", "Spotlight Cam"][max_ix]
confidence = y_pred[max_ix]

print(f"Identified as {label} with a confidence of {confidence*100}%.")
