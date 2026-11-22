"""Synthetic IoT flow generator.

Real IoT botnet traffic datasets are large and separately licensed, so this module produces a *synthetic*
stand-in with 17 flow-feature columns so the whole pipeline runs end-to-end. To use real data, map its columns onto ml.features.FEATURES and save it
as data/dataset.csv with a 0/1 `label` column, then run `python train.py`.
"""
import numpy as np
import pandas as pd
from features import FEATURES, LABEL, ATTACK_TYPE


def _lognorm(rng, median, sigma, n):
    return rng.lognormal(np.log(median), sigma, n)


def _benign(rng, n):
    dur = _lognorm(rng, 10, 0.9, n)
    pk = np.maximum(2, _lognorm(rng, 12, 0.8, n)).round()
    mean_len = np.clip(rng.normal(120, 45, n), 40, 900)
    src = pk * mean_len * rng.uniform(0.5, 1.2, n)
    dst = pk * mean_len * rng.uniform(0.3, 1.1, n)
    iat = dur / pk
    return pd.DataFrame({
        "duration": dur, "protocol": rng.choice([0, 1], n, p=[0.75, 0.25]),
        "src_bytes": src, "dst_bytes": dst, "src_pkts": pk,
        "dst_pkts": np.maximum(1, pk * rng.uniform(.5, 1.1, n)).round(),
        "mean_pkt_len": mean_len, "std_pkt_len": np.abs(rng.normal(40, 20, n)),
        "iat_mean": iat, "iat_std": iat * rng.uniform(0.4, 1.3, n),
        "syn_count": rng.choice([0, 1, 2], n, p=[.15, .75, .10]),
        "ack_count": np.maximum(0, pk - rng.integers(0, 3, n)),
        "rst_count": rng.choice([0, 1], n, p=[.95, .05]), "psh_count": rng.integers(0, 6, n),
        "bytes_per_sec": (src + dst) / dur, "pkts_per_sec": pk / dur,
        "unique_dst_ports": rng.choice([1, 2, 3], n, p=[.8, .15, .05]),
        ATTACK_TYPE: "benign",
    })


def _ddos(rng, n):
    dur = _lognorm(rng, 4, 0.8, n)
    pk = _lognorm(rng, 700, 0.7, n).round()
    mean_len = np.clip(rng.normal(70, 25, n), 40, 400)
    return pd.DataFrame({
        "duration": dur, "protocol": rng.choice([0, 1, 2], n, p=[.55, .30, .15]),
        "src_bytes": pk * mean_len, "dst_bytes": pk * mean_len * rng.uniform(0, 0.15, n),
        "src_pkts": pk, "dst_pkts": np.maximum(0, pk * rng.uniform(0, 0.1, n)).round(),
        "mean_pkt_len": mean_len, "std_pkt_len": np.abs(rng.normal(8, 6, n)),
        "iat_mean": dur / pk, "iat_std": dur / pk * rng.uniform(0.2, 0.9, n),
        "syn_count": pk * rng.uniform(0.2, 0.95, n), "ack_count": pk * rng.uniform(0, 0.15, n),
        "rst_count": rng.integers(0, 40, n), "psh_count": rng.integers(0, 3, n),
        "bytes_per_sec": pk * mean_len / dur, "pkts_per_sec": pk / dur,
        "unique_dst_ports": rng.choice([1, 2, 3, 5], n, p=[.5, .3, .15, .05]),
        ATTACK_TYPE: "ddos_flood",
    })


def _scan(rng, n):
    dur = _lognorm(rng, 6, 0.8, n)
    ports = np.maximum(8, _lognorm(rng, 90, 0.7, n)).round()
    pk = ports * rng.uniform(1, 2.2, n)
    return pd.DataFrame({
        "duration": dur, "protocol": rng.choice([0, 1], n, p=[.85, .15]),
        "src_bytes": pk * rng.uniform(40, 70, n), "dst_bytes": pk * rng.uniform(0, 30, n),
        "src_pkts": pk.round(), "dst_pkts": (pk * rng.uniform(.1, .8, n)).round(),
        "mean_pkt_len": rng.normal(55, 10, n).clip(40, 120), "std_pkt_len": np.abs(rng.normal(6, 4, n)),
        "iat_mean": dur / pk, "iat_std": dur / pk * rng.uniform(.3, 1.0, n),
        "syn_count": pk * rng.uniform(.6, 1, n), "ack_count": pk * rng.uniform(0, .2, n),
        "rst_count": pk * rng.uniform(.2, .8, n), "psh_count": rng.integers(0, 2, n),
        "bytes_per_sec": pk * 55 / dur, "pkts_per_sec": pk / dur,
        "unique_dst_ports": ports, ATTACK_TYPE: "port_scan",
    })


def _c2(rng, n):
    """Periodic command-and-control beaconing: small, very regular flows."""
    period = rng.choice([5, 10, 30, 60], n)
    pk = rng.integers(4, 14, n)
    mean_len = rng.normal(95, 12, n).clip(50, 200)
    return pd.DataFrame({
        "duration": period * rng.uniform(.9, 1.1, n), "protocol": rng.choice([0, 1], n, p=[.8, .2]),
        "src_bytes": pk * mean_len * .5, "dst_bytes": pk * mean_len * .5,
        "src_pkts": pk, "dst_pkts": pk, "mean_pkt_len": mean_len,
        "std_pkt_len": np.abs(rng.normal(12, 5, n)),
        "iat_mean": period / pk, "iat_std": period / pk * rng.uniform(0.02, 0.18, n),
        "syn_count": 1, "ack_count": pk, "rst_count": 0, "psh_count": rng.integers(2, 6, n),
        "bytes_per_sec": pk * mean_len / period, "pkts_per_sec": pk / period,
        "unique_dst_ports": 1, ATTACK_TYPE: "c2_beacon",
    })


def _exfil(rng, n):
    dur = _lognorm(rng, 40, 0.7, n)
    pk = _lognorm(rng, 1500, 0.6, n).round()
    mean_len = rng.normal(1100, 150, n).clip(400, 1500)
    return pd.DataFrame({
        "duration": dur, "protocol": 0, "src_bytes": pk * mean_len, "dst_bytes": pk * rng.uniform(0, 12, n),
        "src_pkts": pk, "dst_pkts": (pk * rng.uniform(.3, .6, n)).round(),
        "mean_pkt_len": mean_len, "std_pkt_len": np.abs(rng.normal(120, 40, n)),
        "iat_mean": dur / pk, "iat_std": dur / pk * rng.uniform(.3, .8, n),
        "syn_count": 1, "ack_count": pk * .5, "rst_count": 0, "psh_count": pk * rng.uniform(.2, .6, n),
        "bytes_per_sec": pk * mean_len / dur, "pkts_per_sec": pk / dur,
        "unique_dst_ports": rng.choice([1, 2], n, p=[.9, .1]), ATTACK_TYPE: "data_exfiltration",
    })


def generate_dataset(n=8000, attack_ratio=0.35, seed=42, label_noise=0.01):
    """Return a shuffled DataFrame with FEATURES + label (+ attack_type)."""
    rng = np.random.default_rng(seed)
    n_att = int(n * attack_ratio)
    counts = [int(n_att * s) for s in (0.35, 0.20, 0.25, 0.20)]
    counts[-1] = n_att - sum(counts[:-1])
    parts = [_benign(rng, n - n_att)]
    for gen, c in zip([_ddos, _scan, _c2, _exfil], counts):
        parts.append(gen(rng, c))
    df = pd.concat(parts, ignore_index=True)
    df[LABEL] = (df[ATTACK_TYPE] != "benign").astype(int)
    for col in FEATURES:                       # sensor noise so metrics are realistic
        if col != "protocol":
            df[col] = df[col] * rng.normal(1, 0.04, len(df))
    flip = rng.random(len(df)) < label_noise   # small label noise
    df.loc[flip, LABEL] = 1 - df.loc[flip, LABEL]
    df[FEATURES] = df[FEATURES].clip(lower=0)
    return df.sample(frac=1, random_state=seed).reset_index(drop=True)[FEATURES + [LABEL, ATTACK_TYPE]]
