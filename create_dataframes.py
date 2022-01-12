import datetime

import numpy as np
import pandas as pd
from scapy.all import IP, TCP, UDP, Raw, rdpcap


def create_df_from_pcap(pcap):
    num_pkts = len(pcap)
    df_dict = {
        **{"time": None},
        **{"payload": None},
        **{"IP_" + field.name: None for field in IP.fields_desc},
        **{"TCP_" + field.name: None for field in TCP.fields_desc},
        **{"UDP_" + field.name: None for field in UDP.fields_desc},
        **{"Raw_" + field.name: None for field in Raw.fields_desc},
    }

    # Set custom dtypes for the data
    layer_dtypes_list = [
        "datetime64[s]",
        "category",
        "category",
        "UInt8",
        "UInt8",
        "UInt16",
        "UInt16",
        "UInt8",
        "UInt16",
        "UInt8",
        "UInt8",
        "UInt16",
        "string",
        "string",
        "object",
        "UInt16",
        "UInt16",
        "UInt32",
        "UInt32",
        "UInt8",
        "UInt8",
        "UInt16",
        "UInt16",
        "UInt16",
        "UInt16",
        "object",
        "UInt16",
        "UInt16",
        "UInt16",
        "UInt16",
        "object",
    ]
    layer_dtypes = dict(zip(df_dict.keys(), layer_dtypes_list))

    # columns that need formatting before setting dtype to avoid conversion errors
    layer_dtypes["time"] = "float64"
    layer_dtypes["payload"] = "string"
    layer_dtypes["IP_version"] = "UInt8"
    layer_dtypes["IP_flags"] = "object"
    layer_dtypes["TCP_flags"] = "object"
    layer_dtypes["IP_options"] = "object"
    layer_dtypes["TCP_options"] = "object"
    layer_dtypes["Raw_load"] = "object"

    df_dict = {k: pd.array(np.full(num_pkts, np.nan), dtype=layer_dtypes[k]) for k in df_dict}

    layer_strings = ["IP", "TCP", "UDP", "Raw"]

    for i, pkt in enumerate(pcap):
        df_dict["time"][i] = float(pkt.time)
        # Loop through payloads until lowest layer, ignoring ethernet frame
        while hasattr(pkt, "payload"):
            pkt = pkt.payload
            layer = type(pkt)

            # Interesting layers for feature set
            if layer.__name__ in layer_strings:
                # Inserting pkt variables in df_dict
                for field in pkt.fields:
                    field_name = layer.__name__ + "_" + field
                    # print(f"df_dict[{field_name}][{i}] = pkt.{field}")
                    exec(f"df_dict[field_name][i] = pkt.{field}")

                # Stop when reaching Raw layer
                if layer == Raw:
                    df_dict["payload"][i] = layer.__name__
                    break

            # Less important layers for feature set saved as 'payload'
            else:
                df_dict["payload"][i] = layer.__name__
                break

    df = pd.DataFrame(df_dict)
    # Time
    df["time"] = pd.to_datetime(df["time"], unit="s")
    # Payload category
    df["payload"] = df["payload"].astype("category")
    # IP Version category
    df["IP_version"] = df["IP_version"].astype("category")
    # IP Addresses category
    df["IP_src"] = df["IP_src"].astype("category")
    df["IP_dst"] = df["IP_dst"].astype("category")
    # TCP ports category
    df["TCP_sport"] = df["TCP_sport"].astype("string").astype("category")
    df["TCP_dport"] = df["TCP_dport"].astype("string").astype("category")
    # UDP ports category
    df["UDP_sport"] = df["UDP_sport"].astype("string").astype("category")
    df["UDP_dport"] = df["UDP_dport"].astype("string").astype("category")
    # Flags
    df["IP_flags"] = df[df["IP_flags"].notnull()]["IP_flags"].apply(int).astype("UInt8")
    # df['TCP_flags'] = df['TCP_flags'].fillna(0)
    df["TCP_flags"] = df[df["TCP_flags"].notnull()]["TCP_flags"].apply(int).astype("UInt8")
    # Options
    df.drop("IP_options", axis=1, inplace=True)
    df.drop("TCP_options", axis=1, inplace=True)
    # Raw payload
    df["Raw_load"] = (
        df["Raw_load"].apply(lambda x: len(x.hex()) // 2).astype("UInt16")
    )  # Payload size in bytes

    # Inter-arrival time
    frames = []
    for addr in set(df["IP_src"].unique()) | set(df["IP_dst"].unique()):
        tmp_df = df[df["IP_dst"] == addr].sort_values("time", ascending=True)
        # Create series and calculate time until the next packet departs
        tmp_df["IP_int_arr_time"] = tmp_df["time"].diff()
        frames.append(tmp_df)
    df = pd.concat(frames, ignore_index=True)

    BURST_TIME_THRESHOLD = datetime.timedelta(
        seconds=0.3
    )  # Only packets sent within this time interval will be considered for the current burst
    BURST_SIZE_THRESHOLD = int(
        df["Raw_load"].mean() * 1.1
    )  # Only packets that have at least this many bytes will be considered for the current burst

    def add_burst_ixs_to_df(df):
        ixs = np.zeros((len(df),))
        burst_ix = 1
        i = 0

        while i < len(df) - 1:
            # Find next package that is big enough to be considered relevant
            j = i + 1
            while j < len(df) - 1 and df.iloc[j]["Raw_load"] < BURST_SIZE_THRESHOLD:
                j += 1

            if df.iloc[j]["time"] - df.iloc[i]["time"] < BURST_TIME_THRESHOLD:
                # Same burst for alle packets within time threshold
                ixs[i : j + 1] = burst_ix
            else:
                ixs[i] = burst_ix
                burst_ix += 1
            # Discard all small payloads outside of time threshold
            for n in range(i + 1, j):
                ixs[n] = burst_ix
                burst_ix += 1

            i = j

        df["IP_Burst_ix"] = ixs
        df["IP_Burst_ix"] = df["IP_Burst_ix"].astype("UInt32")
        return df

    df = add_burst_ixs_to_df(df)

    # add Burst length and size
    df["IP_Burst_length"] = df.groupby(["IP_Burst_ix"])["IP_Burst_ix"].transform("size")
    df["IP_Burst_length"] = (
        df["IP_Burst_length"] - 1
    )  # length 1 should equal a burst with two packets
    df["IP_Burst_avg_size"] = df.groupby(["IP_Burst_ix"])["Raw_load"].transform("mean")
    df["IP_Burst_avg_size"] = df["IP_Burst_avg_size"].round(decimals=2)
    df.loc[df["IP_Burst_length"] == 0, ["IP_Burst_ix", "IP_Burst_length", "IP_Burst_avg_size"]] = 0
    df["IP_Burst_ix"] = df["IP_Burst_ix"].astype("category")
    df["IP_Burst_ix"] = df["IP_Burst_ix"].cat.codes

    return df


devices = [
    ("Ring Spotlight Cam Battery", "data/AmazonRing/ring_merged.pcap", "34:3e:a4:4d:70:b2"),
    ("Reolink Argus PT", "data/Reolink/reo_merged.pcap", "4c:d1:a1:06:86:55"),
    (
        "Telekom Magenta SmartHome HomeBase 2",
        "data/Telekom/telekom_magenta_homebase2.pcap",
        "1c:7f:2c:39:bb:f3",
    ),
]

# Labeled data
for name, path, mac in devices:
    pcap = rdpcap(path)
    # pcap = pcap[50:80] # Working Set

    print(name, path, mac)
    df = create_df_from_pcap(pcap)
    df["label"] = name

    pkl_path = path.split(".")[0] + ".pkl"
    df.to_pickle(path=pkl_path)
    print(df.info())
    print()

# Unlabeled data
for path in ["data/doh_merged_2.pcap"]:
    pcap = rdpcap(path)
    # pcap = pcap[50:180]  # Working Set

    print(path)
    df = create_df_from_pcap(pcap)
    df["label"] = "NoLabel"

    pkl_path = path.split(".")[0] + ".pkl"
    df.to_pickle(path=pkl_path)
    print(df.info())
    print()
