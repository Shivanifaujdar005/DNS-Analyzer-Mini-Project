"""
generate_traffic.py
Creates SAFE test capture files for the lab. It never sends anything on any
network - it only WRITES .pcap files to disk. The "malicious" domains use the
reserved TLD ".test" (RFC 2606) or random names that are never resolved.

Output (in ./samples):
    normal.pcap      - ordinary browsing from 3 lab clients
    suspicious.pcap  - DGA-like domains, DNS tunnelling, query flood
    mixed.pcap       - both together (used for evaluation)
    ground_truth.json- which names/sources are malicious (for precision/recall)
"""
import base64
import json
import random
import string
from pcap_utils import QTYPE_NUM, build_dns_query, build_frame, write_pcap

RESOLVER = "192.168.56.1"
START = 1794700800 + 36000          # 15 Nov 2026, 10:00 UTC
rng = random.Random(2026)           # fixed seed -> same files every time
txid = [0]

BENIGN = [
    "www.google.com", "google.com", "www.youtube.com", "i.ytimg.com", "fonts.gstatic.com",
    "mail.google.com", "accounts.google.com", "www.facebook.com", "www.instagram.com",
    "github.com", "api.github.com", "stackoverflow.com", "en.wikipedia.org",
    "www.wikipedia.org", "skit.ac.in", "www.rtu.ac.in", "pypi.org", "files.pythonhosted.org",
    "outlook.office365.com", "login.microsoftonline.com", "teams.microsoft.com",
    "www.bing.com", "ocsp.digicert.com", "clients4.google.com", "play.google.com",
    "www.amazon.in", "www.flipkart.com", "www.linkedin.com", "web.whatsapp.com",
    "update.googleapis.com", "www.nptel.ac.in", "classroom.google.com",
    "docs.python.org", "www.w3schools.com", "cdn.jsdelivr.net", "www.zoho.com",
    # legitimate names that LOOK random (CDNs) - good test for false positives
    "d3e54v103j8qbb.cloudfront.net", "d2z9xk4f7ab1cq.cloudfront.net",
    "ec2-54-12-34-56.compute-1.amazonaws.com", "a1234.dscg.akamaiedge.net",
    "dualstack.elb-prod-1234567890.us-east-1.elb.amazonaws.com",
    "r3---sn-ab5l6n7y.googlevideo.com",
]


def add(records, ts, src, name, qtype):
    records.append((ts, src, name, qtype))


def normal_traffic(records, n_pages=60, duration=600):
    clients = ["192.168.56.101", "192.168.56.102", "192.168.56.103"]
    weights = [1 / (i + 1) ** 0.6 for i in range(len(BENIGN))]     # popular sites more often
    for _ in range(n_pages):                                         # one "page load" = burst of queries
        t0 = START + rng.uniform(0, duration)
        client = rng.choice(clients)
        for _ in range(rng.randint(3, 9)):
            name = rng.choices(BENIGN, weights)[0]
            qt = rng.choices(["A", "AAAA", "HTTPS"], [0.5, 0.42, 0.08])[0]
            add(records, t0 + rng.uniform(0, 3), client, name, qt)


def dga_traffic(records, truth, n=60):
    src = "192.168.56.150"
    tlds = [".com", ".net", ".biz", ".ru", ".info", ".top"]
    for i in range(n):
        length = rng.randint(12, 18)
        alphabet = string.ascii_lowercase + (string.digits if i % 2 == 0 else "")
        name = "".join(rng.choice(alphabet) for _ in range(length)) + rng.choice(tlds)
        truth["dga"].append(name)
        add(records, START + 100 + i * 2 + rng.random(), src, name, "A")


def tunnel_traffic(records, truth, n=150):
    src = "192.168.56.151"
    for i in range(n):
        chunk = rng.randbytes(30)                                    # pretend "stolen file" bytes
        label = base64.b32encode(chunk).decode().lower()             # 48 chars of base32
        name = f"{label}.c2.tunnel-lab.test"
        truth["tunnel_queries"].append(name)
        add(records, START + 200 + i * 0.2, src, name, "TXT" if rng.random() < 0.7 else "NULL")
    truth["tunnel_source"] = src
    truth["tunnel_parent"] = "tunnel-lab.test"


def flood_traffic(records, truth, n=900):
    src = "192.168.56.152"
    for i in range(n):
        add(records, START + 350 + i * (30 / n), src, rng.choice(BENIGN[:10]), "A")
    truth["flood_source"] = src


def to_packets(records):
    pkts = []
    for ts, src, name, qt in records:
        txid[0] = (txid[0] + 1) % 65536
        payload = build_dns_query(name, QTYPE_NUM[qt], txid[0])
        pkts.append((ts, build_frame(src, RESOLVER, 40000 + txid[0] % 20000, payload, txid[0])))
    return pkts


if __name__ == "__main__":
    truth = {"dga": [], "tunnel_queries": []}
    normal, bad = [], []
    normal_traffic(normal)
    dga_traffic(bad, truth)
    tunnel_traffic(bad, truth)
    flood_traffic(bad, truth)
    write_pcap("samples/normal.pcap", to_packets(normal))
    write_pcap("samples/suspicious.pcap", to_packets(bad))
    write_pcap("samples/mixed.pcap", to_packets(normal + bad))
    json.dump(truth, open("samples/ground_truth.json", "w"), indent=2)
    print("normal queries    :", len(normal))
    print("suspicious queries:", len(bad))
    print("files written to ./samples")
