"""
evaluate.py - measures detection quality against ground_truth.json
Run:  python evaluate.py
"""
import json
from dns_analyzer import analyze, load_queries, split_name


def score(queries, truth, cfg=None):
    res = analyze(queries, cfg)
    malicious = set(truth["dga"]) | set(truth["tunnel_queries"])
    universe = {q["qname"] for q in queries}
    parents = {a["domain"] for a in res["tunnel_alerts"]}
    flagged = {n for n in universe if n in res["flagged"] or split_name(n)[2] in parents}
    tp, fp, fn = len(flagged & malicious), len(flagged - malicious), len(malicious & universe - flagged)
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return res, tp, fp, fn, prec, rec, f1, flagged - malicious


ENTROPY_ONLY = {"digit_ratio": 9, "vowel_ratio_low": -1, "nonvowel_run": 999, "min_random_tests": 1,
                "max_fqdn_len": 999, "max_label_len": 999}

if __name__ == "__main__":
    truth = json.load(open("samples/ground_truth.json"))
    queries, _ = load_queries("samples/mixed.pcap")
    print(f"Ground truth: {len(truth['dga'])} DGA domains + {len(set(truth['tunnel_queries']))} tunnel names\n")

    print("A) Final detector on mixed.pcap")
    print(f"{'setting':34s}{'TP':>5}{'FP':>5}{'FN':>5}{'Prec':>8}{'Recall':>8}{'F1':>7}")
    for label, cfg in [("allowlist ON (default)", {}), ("allowlist OFF", {"use_allowlist": False})]:
        _, tp, fp, fn, p, r, f1, fps = score(queries, truth, cfg)
        print(f"{label:34s}{tp:5d}{fp:5d}{fn:5d}{p:8.2f}{r:8.2f}{f1:7.2f}")
        if fps:
            print("   false positives:", sorted(fps))

    print("\nB) DGA-only detection (tunnel & length checks off): entropy alone vs combined tests")
    dga_set = set(truth["dga"])
    dga_q = [q for q in queries if q["qname"] in dga_set or q["src"] != "192.168.56.151"]
    base = {"tunnel_min_unique": 10 ** 6, "tunnel_min_type_unique": 10 ** 6, "max_fqdn_len": 999, "max_label_len": 999}
    print(f"{'setting':34s}{'DGA found':>10}{'FP':>5}")
    for thr in (2.8, 3.0, 3.3, 3.6, 4.0):
        res = analyze(dga_q, {**ENTROPY_ONLY, **base, "entropy_threshold": thr})
        found = len(set(res["flagged"]) & dga_set)
        fp = len(set(res["flagged"]) - dga_set)
        print(f"{'entropy only, thr=' + str(thr):34s}{found:7d}/60{fp:5d}")
    res = analyze(dga_q, base)
    print(f"{'combined tests (default)':34s}{len(set(res['flagged']) & dga_set):7d}/60{len(set(res['flagged']) - dga_set):5d}")

    print("\nC) Rate-limit sensitivity (window = 60 s)")
    flood, tun = truth["flood_source"], truth["tunnel_source"]
    for limit in (20, 40, 100, 200, 500, 1000):
        res = analyze(queries, {"rate_limit": limit})
        srcs = sorted(a["source"] for a in res["rate_alerts"])
        normal = [s for s in srcs if s not in (flood, tun, "192.168.56.150")]
        print(f"limit={limit:5d}  alerts={len(srcs)}  sources={srcs}  normal-clients-flagged={len(normal)}")

    print("\nD) normal.pcap only (no attacks present)")
    nq, _ = load_queries("samples/normal.pcap")
    for label, cfg in [("allowlist ON", {}), ("allowlist OFF", {"use_allowlist": False})]:
        r = analyze(nq, cfg)
        print(f"{label:15s} flagged domains={len(r['flagged'])}  rate alerts={len(r['rate_alerts'])}"
              f"  tunnel alerts={len(r['tunnel_alerts'])}")
        for n, f in r["flagged"].items():
            print("    ", n, f["reasons"])
