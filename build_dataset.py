"""Builds cleaned_dataset.csv (used by /prediction) and sample_upload.csv (a raw file to try /upload with).

The report evaluates on UNSW-NB15 / Bot-IoT / CICIoT2023-style IoT flow data. Those datasets are large and
separately licensed, so this script generates a synthetic stand-in with the same kind of 17 flow features.
To use real data instead: map your columns to features.FEATURES, add a 0/1 `label`, and save it as
cleaned_dataset.csv.
"""
import numpy as np

from data_processing import clean_dataframe
from dataset_generator import generate_dataset
from features import ATTACK_TYPE, FEATURES, LABEL

PROTO_NAMES = {0: "tcp", 1: "udp", 2: "icmp"}   # generator codes -> raw text, as a real capture would have

if __name__ == "__main__":
    raw = generate_dataset(n=6000, attack_ratio=0.35, seed=42)
    raw["protocol"] = raw["protocol"].round().astype(int).map(PROTO_NAMES)

    # cleaned dataset = raw -> impute + label-encode (protocol becomes icmp=0, tcp=1, udp=2)
    cleaned, info = clean_dataframe(raw.drop(columns=[ATTACK_TYPE]))
    cleaned[LABEL] = cleaned[LABEL].astype(int)
    cleaned[FEATURES + [LABEL]].round(6).to_csv("cleaned_dataset.csv", index=False)
    print("cleaned_dataset.csv", cleaned.shape, "| protocol encoding:", info["encoded"]["protocol"])

    # a small RAW file with gaps, text protocol and a text column, to demonstrate the preprocessing
    sample = generate_dataset(n=200, attack_ratio=0.4, seed=7)
    sample["protocol"] = sample["protocol"].round().astype(int).map(PROTO_NAMES)
    rng = np.random.default_rng(1)
    for col in ["src_bytes", "iat_mean", "rst_count", "protocol"]:
        sample.loc[rng.choice(len(sample), 8, replace=False), col] = np.nan
    sample.round(6).to_csv("sample_upload.csv", index=False)
    print("sample_upload.csv", sample.shape)
