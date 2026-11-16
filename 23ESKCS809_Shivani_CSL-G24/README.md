# DNS Traffic Analyzer & Suspicious Domain Detector
Cyber Security Lab (7CS4-22) - Mini Project CSL-G24 | Shivani, 23ESKCS809 | Linked to Exp 4 (Wireshark / tcpdump, TCP & UDP)

Requirements: Python 3.8+ (standard library only). `matplotlib` is optional (for graphs).

## Run
    python generate_traffic.py                         # makes samples/*.pcap (writes files only, sends nothing)
    python dns_analyzer.py samples/mixed.pcap --out output/mixed
    python dns_analyzer.py real.pcap                   # your own Wireshark / tcpdump capture (.pcap or .pcapng)
    python evaluate.py                                 # precision / recall experiments
    python -m unittest test_analyzer -v                # 14 unit tests

Useful options: `--rate-limit 100  --window 60  --no-allowlist  --no-plots`

## Ethics
Only own PC / VM. The generator never uses a network. Tunnel test domain uses the reserved TLD `.test` (RFC 2606).
