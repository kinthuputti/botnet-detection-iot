"""The seventeen numeric inputs used by /prediction and stored in cleaned_dataset.csv."""

LABEL = "label"              # 0 = Benign, 1 = Malicious (botnet)
ATTACK_TYPE = "attack_type"  # descriptive column present only in raw/sample uploads

# (column, label shown on the form, hint)
FEATURE_INFO = [
    ("duration",         "Flow duration (s)",             "How long the flow lasted"),
    ("protocol",         "Protocol code",                 "0 = ICMP, 1 = TCP, 2 = UDP"),
    ("src_bytes",        "Bytes sent",                    "Bytes sent by the device"),
    ("dst_bytes",        "Bytes received",                "Bytes received by the device"),
    ("src_pkts",         "Packets sent",                  "Packets sent by the device"),
    ("dst_pkts",         "Packets received",              "Packets received by the device"),
    ("mean_pkt_len",     "Mean packet length",            "Average packet size (bytes)"),
    ("std_pkt_len",      "Packet length std-dev",         "Variation in packet size"),
    ("iat_mean",         "Mean inter-arrival time (s)",   "Average gap between packets"),
    ("iat_std",          "Inter-arrival time std-dev",    "Regularity of packet timing"),
    ("syn_count",        "SYN flags",                     "TCP SYN flag count"),
    ("ack_count",        "ACK flags",                     "TCP ACK flag count"),
    ("rst_count",        "RST flags",                     "TCP RST flag count"),
    ("psh_count",        "PSH flags",                     "TCP PSH flag count"),
    ("bytes_per_sec",    "Bytes per second",              "Throughput"),
    ("pkts_per_sec",     "Packets per second",            "Packet rate"),
    ("unique_dst_ports", "Distinct destination ports",    "Ports contacted in the flow"),
]
FEATURES = [f[0] for f in FEATURE_INFO]

# sklearn's LabelEncoder sorts classes alphabetically, so tcp/udp/icmp become:
PROTOCOL_CODES = {"icmp": 0, "tcp": 1, "udp": 2}

# Demo values for the "fill sample" buttons on the prediction form
SAMPLE_BENIGN = dict(duration=12.0, protocol=1, src_bytes=620, dst_bytes=480, src_pkts=9, dst_pkts=8,
                     mean_pkt_len=110, std_pkt_len=35, iat_mean=1.4, iat_std=0.9, syn_count=1,
                     ack_count=8, rst_count=0, psh_count=3, bytes_per_sec=92, pkts_per_sec=1.4,
                     unique_dst_ports=1)
SAMPLE_BOTNET = dict(duration=3.0, protocol=1, src_bytes=48000, dst_bytes=0, src_pkts=900, dst_pkts=2,
                     mean_pkt_len=54, std_pkt_len=4, iat_mean=0.003, iat_std=0.002, syn_count=880,
                     ack_count=4, rst_count=15, psh_count=0, bytes_per_sec=16000, pkts_per_sec=300,
                     unique_dst_ports=2)
