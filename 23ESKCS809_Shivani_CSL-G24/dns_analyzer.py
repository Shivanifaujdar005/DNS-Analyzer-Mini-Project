#!/usr/bin/env python3
"""
DNS Traffic Analyzer & Suspicious Domain Detector   (CSL-G24, Exp 4)

Reads a capture (.pcap / .pcapng from Wireshark or tcpdump), extracts DNS
queries and flags:
    1. LONG_DOMAIN      - very long names / labels
    2. RANDOM_LOOKING   - random-looking (DGA-style) names, using Shannon entropy
                          plus supporting heuristics
    3. HIGH_QUERY_RATE  - one source sending too many queries in a time window
    4. DNS_TUNNELLING   - many long, unique, high-entropy sub-domains under one
                          parent domain, or heavy use of TXT/NULL queries

Usage:  python dns_analyzer.py samples/mixed.pcap --out output
"""
import argparse
import csv
import json
import math
import os
from collections import Counter, defaultdict
from statistics import mean

from pcap_utils import parse_dns_query, read_packets

# ----------------------------------------------------------------------
# Detection thresholds (all in one place so they are easy to explain/tune)
# ----------------------------------------------------------------------
DEFAULT_CFG = {
    "max_fqdn_len": 50,          # whole name longer than this  -> LONG_DOMAIN
    "max_label_len": 30,         # any single label longer than this -> LONG_DOMAIN
    "min_label_for_entropy": 10, # shorter labels are too short to judge randomness
    "entropy_threshold": 3.3,    # test 1: Shannon entropy (bits/char)
    "digit_ratio": 0.20,         # test 2: >=20% digits mixed with letters
    "vowel_ratio_low": 0.15,     # test 3: <=15% vowels
    "nonvowel_run": 5,           # test 4: 5+ consonants/digits in a row
    "min_random_tests": 2,       # label is RANDOM_LOOKING if >=2 tests pass
    "rate_limit": 100,           # more than 100 queries ...
    "rate_window": 60,           # ... within 60 seconds from one source
    "tunnel_min_unique": 20,     # tunnelling needs >=20 unique sub-domains
    "tunnel_avg_len": 20,        # ... with average length >=20 chars, or
    "tunnel_entropy": 3.5,       # ... average entropy >=3.5
    "tunnel_type_share": 0.5,    # ... or >=50% TXT/NULL/CNAME queries
    "tunnel_min_type_unique": 10,
    "use_allowlist": True,
}

# Legitimate services whose host names look random (CDNs, cloud) - avoids false positives
ALLOWLIST = {"cloudfront.net", "amazonaws.com", "akamaiedge.net", "akadns.net",
             "googlevideo.com", "googleusercontent.com", "azureedge.net",
             "fastly.net", "gstatic.com", "ytimg.com"}
TWO_LEVEL_SUFFIXES = {"co.uk", "com.au", "co.in", "ac.in", "org.in", "gov.in",
                      "net.in", "co.jp", "com.br", "edu.in"}
SUSPICIOUS_TYPES = {"TXT", "NULL", "CNAME"}
VOWELS = set("aeiou")


# ----------------------------------------------------------------------
# Helper functions
# ----------------------------------------------------------------------
def shannon_entropy(text):
    """H = -sum(p * log2 p) over the characters of the text (bits per character)."""
    if not text:
        return 0.0
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in Counter(text).values())


def split_name(qname):
    """'a.b.example.co.in' -> (['a','b'], 'example', 'example.co.in')"""
    labels = qname.split(".")
    suffix_len = 2 if ".".join(labels[-2:]) in TWO_LEVEL_SUFFIXES else 1
    if len(labels) <= suffix_len:
        return [], labels[0], qname
    sld = labels[-suffix_len - 1]
    parent = ".".join(labels[-suffix_len - 1:])
    return labels[:-suffix_len - 1], sld, parent


def randomness_tests(label, cfg):
    """Return the list of randomness tests that this label fails (looks random)."""
    passed = []
    if shannon_entropy(label) >= cfg["entropy_threshold"]:
        passed.append("entropy")
    digits = sum(ch.isdigit() for ch in label)
    letters = sum(ch.isalpha() for ch in label)
    if letters and digits / len(label) >= cfg["digit_ratio"]:
        passed.append("digits")
    vowels = sum(ch in VOWELS for ch in label)
    if letters and vowels / len(label) <= cfg["vowel_ratio_low"]:
        passed.append("few_vowels")
    run = best = 0
    for ch in label:
        run = 0 if (ch in VOWELS or ch == "-") else run + 1
        best = max(best, run)
    if best >= cfg["nonvowel_run"]:
        passed.append("consonant_run")
    return passed


def check_domain(qname, cfg):
    """Per-domain checks 1 and 2. Returns (reasons, entropy_of_longest_label)."""
    subs, sld, parent = split_name(qname)
    longest = max(subs + [sld], key=len)
    ent = shannon_entropy(longest)
    if cfg["use_allowlist"] and parent in ALLOWLIST:
        return [], ent
    reasons = []
    if len(qname) > cfg["max_fqdn_len"] or len(longest) > cfg["max_label_len"]:
        reasons.append("LONG_DOMAIN")
    if len(longest) >= cfg["min_label_for_entropy"]:
        if len(randomness_tests(longest, cfg)) >= cfg["min_random_tests"]:
            reasons.append("RANDOM_LOOKING")
    return reasons, ent


# ----------------------------------------------------------------------
# Loading + analysis
# ----------------------------------------------------------------------
def load_queries(path):
    queries, total = [], 0
    for ts, linktype, data in read_packets(path):
        total += 1
        q = parse_dns_query(linktype, data)
        if q:
            q["ts"] = ts
            queries.append(q)
    queries.sort(key=lambda q: q["ts"])
    return queries, total


def rate_alerts(queries, cfg):
    """Check 3: sliding window - most queries from one source inside rate_window seconds."""
    by_src = defaultdict(list)
    for q in queries:
        by_src[q["src"]].append(q["ts"])
    alerts = []
    for src, times in by_src.items():
        left = peak = 0
        peak_start = times[0]
        for right, t in enumerate(times):
            while t - times[left] > cfg["rate_window"]:
                left += 1
            if right - left + 1 > peak:
                peak, peak_start = right - left + 1, times[left]
        if peak > cfg["rate_limit"]:
            alerts.append({"source": src, "peak_queries": peak, "window_s": cfg["rate_window"],
                           "per_minute": round(peak * 60 / cfg["rate_window"]),
                           "window_start": peak_start})
    return sorted(alerts, key=lambda a: -a["peak_queries"])


def tunnel_alerts(queries, cfg):
    """Check 4: group by parent domain and look at the sub-domain statistics."""
    groups = defaultdict(list)
    for q in queries:
        subs, _sld, parent = split_name(q["qname"])
        if cfg["use_allowlist"] and parent in ALLOWLIST:
            continue
        if subs:
            groups[parent].append((".".join(subs), q))
    alerts = []
    for parent, items in groups.items():
        unique = {s for s, _ in items}
        n = len(unique)
        avg_len = mean(len(s) for s in unique)
        avg_ent = mean(shannon_entropy(max(s.split("."), key=len)) for s in unique)
        share = sum(q["qtype"] in SUSPICIOUS_TYPES for _, q in items) / len(items)
        why = []
        if n >= cfg["tunnel_min_unique"] and avg_len >= cfg["tunnel_avg_len"]:
            why.append("many long unique sub-domains")
        if n >= cfg["tunnel_min_unique"] and avg_ent >= cfg["tunnel_entropy"]:
            why.append("high-entropy sub-domains")
        if n >= cfg["tunnel_min_type_unique"] and share >= cfg["tunnel_type_share"]:
            why.append("mostly TXT/NULL queries")
        if why:
            alerts.append({"domain": parent, "queries": len(items), "unique_subdomains": n,
                           "avg_subdomain_len": round(avg_len, 1), "avg_entropy": round(avg_ent, 2),
                           "txt_null_share": round(share, 2),
                           "sources": sorted({q["src"] for _, q in items}), "reasons": why})
    return sorted(alerts, key=lambda a: -a["unique_subdomains"])


def analyze(queries, cfg=None):
    cfg = {**DEFAULT_CFG, **(cfg or {})}
    domains = {}                                    # qname -> info (only flagged ones go in "flagged")
    for q in queries:
        d = domains.setdefault(q["qname"], {"count": 0, "sources": set(), "types": Counter()})
        d["count"] += 1
        d["sources"].add(q["src"])
        d["types"][q["qtype"]] += 1
    flagged = {}
    for name, info in domains.items():
        reasons, ent = check_domain(name, cfg)
        info["entropy"] = ent
        if reasons:
            flagged[name] = {"reasons": reasons, "entropy": round(ent, 2), "count": info["count"],
                             "sources": sorted(info["sources"])}
    return {"cfg": cfg, "domains": domains, "flagged": flagged,
            "rate_alerts": rate_alerts(queries, cfg), "tunnel_alerts": tunnel_alerts(queries, cfg)}


# ----------------------------------------------------------------------
# Output: text report, files and graphs
# ----------------------------------------------------------------------
def print_report(path, queries, total, res):
    span = queries[-1]["ts"] - queries[0]["ts"] if queries else 0
    parents = Counter(split_name(q["qname"])[2] for q in queries)
    print("=" * 66)
    print(" DNS TRAFFIC ANALYSIS REPORT")
    print("=" * 66)
    print(f" File            : {path}")
    print(f" Packets read    : {total}")
    print(f" DNS queries     : {len(queries)}")
    print(f" Unique sources  : {len({q['src'] for q in queries})}")
    print(f" Unique domains  : {len(res['domains'])}")
    print(f" Capture length  : {span:.0f} seconds")
    print("\n--- Top 10 queried domains ---")
    for dom, n in parents.most_common(10):
        print(f" {n:5d}  {dom}")
    print("\n--- Query types ---")
    for t, n in Counter(q["qtype"] for q in queries).most_common():
        print(f" {t:6s} {n}")
    print(f"\n--- [1] Suspicious domains (long / random-looking): {len(res['flagged'])} ---")
    for name, f in sorted(res["flagged"].items(), key=lambda x: -x[1]["entropy"])[:15]:
        print(f" {','.join(f['reasons']):24s} H={f['entropy']:.2f}  {name[:70]}")
    if len(res["flagged"]) > 15:
        print(f" ... and {len(res['flagged']) - 15} more (see flagged_domains.csv)")
    print(f"\n--- [2] High query rate sources: {len(res['rate_alerts'])} ---")
    for a in res["rate_alerts"]:
        print(f" {a['source']:16s} {a['peak_queries']} queries in {a['window_s']}s (~{a['per_minute']}/min)")
    print(f"\n--- [3] DNS tunnelling suspects: {len(res['tunnel_alerts'])} ---")
    for a in res["tunnel_alerts"]:
        print(f" {a['domain']}: {a['queries']} queries, {a['unique_subdomains']} unique sub-domains, "
              f"avg len {a['avg_subdomain_len']}, avg H {a['avg_entropy']}, TXT/NULL {a['txt_null_share']:.0%}")
        print(f"   from {', '.join(a['sources'])}  ->  {'; '.join(a['reasons'])}")
    print("=" * 66)


def save_files(outdir, res):
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "flagged_domains.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["domain", "reasons", "entropy", "count", "sources"])
        for name, x in sorted(res["flagged"].items()):
            w.writerow([name, "|".join(x["reasons"]), x["entropy"], x["count"], "|".join(x["sources"])])
    with open(os.path.join(outdir, "alerts.json"), "w") as f:
        json.dump({"rate_alerts": res["rate_alerts"], "tunnel_alerts": res["tunnel_alerts"]}, f, indent=2)


def make_plots(outdir, queries, res):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    t0 = queries[0]["ts"]
    # Fig 1: query rate over time per source (10-second bins)
    by_src = defaultdict(Counter)
    for q in queries:
        by_src[q["src"]][int((q["ts"] - t0) // 10)] += 1
    nbins = int((queries[-1]["ts"] - t0) // 10) + 1
    plt.figure(figsize=(8, 4))
    for src, c in sorted(by_src.items()):
        plt.plot([i * 10 for i in range(nbins)], [c.get(i, 0) for i in range(nbins)], label=src, lw=1.3)
    plt.axhline(res["cfg"]["rate_limit"] * 10 / res["cfg"]["rate_window"], color="red", ls="--", lw=1,
                label="rate limit (100 per 60 s = 17 per 10 s)")
    plt.xlabel("Time since start of capture (s)"); plt.ylabel("Queries per 10 s")
    plt.title("DNS query rate per source"); plt.legend(fontsize=7); plt.tight_layout()
    plt.savefig(os.path.join(outdir, "fig_query_rate.png"), dpi=150); plt.close()
    # Fig 2: entropy histogram - flagged vs not flagged
    ok = [d["entropy"] for n, d in res["domains"].items() if n not in res["flagged"]]
    bad = [d["entropy"] for n, d in res["domains"].items() if n in res["flagged"]]
    plt.figure(figsize=(8, 4))
    plt.hist([ok, bad], bins=20, label=["not flagged", "flagged"], color=["#4a7ebb", "#c0392b"], stacked=True)
    plt.axvline(res["cfg"]["entropy_threshold"], color="black", ls="--", lw=1, label="entropy threshold")
    plt.xlabel("Shannon entropy of longest label (bits/char)"); plt.ylabel("Number of unique domains")
    plt.title("Entropy distribution of queried domains"); plt.legend(); plt.tight_layout()
    plt.savefig(os.path.join(outdir, "fig_entropy_hist.png"), dpi=150); plt.close()
    # Fig 3: top 10 domains
    top = Counter(split_name(q["qname"])[2] for q in queries).most_common(10)[::-1]
    plt.figure(figsize=(8, 4))
    plt.barh([d for d, _ in top], [n for _, n in top], color="#4a7ebb")
    plt.xlabel("Number of queries"); plt.title("Top 10 queried domains"); plt.tight_layout()
    plt.savefig(os.path.join(outdir, "fig_top_domains.png"), dpi=150); plt.close()
    # Fig 4: alerts by type
    counts = Counter(r for f in res["flagged"].values() for r in f["reasons"])
    counts["HIGH_QUERY_RATE"] = len(res["rate_alerts"])
    counts["DNS_TUNNELLING"] = len(res["tunnel_alerts"])
    plt.figure(figsize=(8, 4))
    plt.bar(list(counts), list(counts.values()), color="#c0392b")
    plt.ylabel("Number of alerts"); plt.title("Alerts raised by detection type"); plt.tight_layout()
    plt.savefig(os.path.join(outdir, "fig_alerts.png"), dpi=150); plt.close()


def main():
    ap = argparse.ArgumentParser(description="DNS Traffic Analyzer & Suspicious Domain Detector")
    ap.add_argument("pcap", help="capture file (.pcap / .pcapng)")
    ap.add_argument("--out", default="output", help="folder for csv/json/png results")
    ap.add_argument("--rate-limit", type=int, default=DEFAULT_CFG["rate_limit"])
    ap.add_argument("--window", type=int, default=DEFAULT_CFG["rate_window"])
    ap.add_argument("--no-allowlist", action="store_true", help="disable CDN allowlist")
    ap.add_argument("--no-plots", action="store_true")
    a = ap.parse_args()
    cfg = {"rate_limit": a.rate_limit, "rate_window": a.window, "use_allowlist": not a.no_allowlist}
    queries, total = load_queries(a.pcap)
    if not queries:
        print("No DNS queries found in this capture.")
        return
    res = analyze(queries, cfg)
    print_report(a.pcap, queries, total, res)
    save_files(a.out, res)
    if not a.no_plots:
        try:
            make_plots(a.out, queries, res)
        except ImportError:
            print("(matplotlib not installed - graphs skipped)")
    print(f"Results saved in: {a.out}/")


if __name__ == "__main__":
    main()
