"""
pcap_utils.py
Minimal helpers to READ capture files (.pcap / .pcapng) and to BUILD DNS packets.
Written with only the Python standard library (struct, socket) so that no
external package (scapy etc.) is needed.
"""
import socket
import struct

QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 10: "NULL", 12: "PTR",
          15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS"}
QTYPE_NUM = {v: k for k, v in QTYPES.items()}


# ----------------------------------------------------------------------
# 1. READING CAPTURE FILES
# ----------------------------------------------------------------------
def read_packets(path):
    """Yield (timestamp_in_seconds, linktype, raw_bytes) for every packet."""
    with open(path, "rb") as f:
        raw = f.read()
    if raw[:4] == b"\x0a\x0d\x0d\x0a":          # pcapng (Wireshark default)
        yield from _read_pcapng(raw)
    else:                                         # classic pcap (tcpdump)
        yield from _read_pcap(raw)


def _read_pcap(raw):
    # magic number tells us byte order and timestamp precision
    table = {b"\xd4\xc3\xb2\xa1": ("<", 1e6), b"\xa1\xb2\xc3\xd4": (">", 1e6),
             b"\x4d\x3c\xb2\xa1": ("<", 1e9), b"\xa1\xb2\x3c\x4d": (">", 1e9)}
    if raw[:4] not in table:
        raise ValueError("Not a pcap / pcapng file")
    end, div = table[raw[:4]]
    linktype = struct.unpack(end + "I", raw[20:24])[0]   # 1 = Ethernet
    pos = 24                                              # global header = 24 bytes
    while pos + 16 <= len(raw):                           # per-packet header = 16 bytes
        sec, frac, incl, _orig = struct.unpack(end + "IIII", raw[pos:pos + 16])
        pos += 16
        yield sec + frac / div, linktype, raw[pos:pos + incl]
        pos += incl


def _read_pcapng(raw):
    end, ifaces, pos = "<", [], 0                         # ifaces = [(linktype, divisor)]
    while pos + 12 <= len(raw):
        if raw[pos:pos + 4] == b"\x0a\x0d\x0d\x0a":       # Section Header Block
            end = "<" if raw[pos + 8:pos + 12] == b"\x4d\x3c\x2b\x1a" else ">"
            ifaces = []
        btype, blen = struct.unpack(end + "II", raw[pos:pos + 8])
        if blen < 12:
            break
        body = raw[pos + 8:pos + blen - 4]
        if btype == 1:                                    # Interface Description Block
            linktype = struct.unpack(end + "H", body[0:2])[0]
            div, opts, o = 1e6, body[8:], 0
            while o + 4 <= len(opts):
                code, olen = struct.unpack(end + "HH", opts[o:o + 4])
                if code == 0:
                    break
                if code == 9 and olen >= 1:               # if_tsresol option
                    v = opts[o + 4]
                    div = 2.0 ** (v & 0x7F) if v & 0x80 else 10.0 ** v
                o += 4 + ((olen + 3) // 4) * 4
            ifaces.append((linktype, div))
        elif btype == 6:                                  # Enhanced Packet Block
            iid, th, tl, caplen, _ = struct.unpack(end + "IIIII", body[:20])
            lt, div = ifaces[iid]
            yield ((th << 32) | tl) / div, lt, body[20:20 + caplen]
        pos += blen


# ----------------------------------------------------------------------
# 2. PARSING ONE PACKET  (Ethernet -> IP -> UDP -> DNS)
# ----------------------------------------------------------------------
def parse_dns_query(linktype, data):
    """Return dict(src, dst, qname, qtype) if packet is a DNS query to UDP/53, else None."""
    try:
        return _parse(linktype, data)
    except (struct.error, IndexError):
        return None


def _parse(linktype, data):
    off = 0
    if linktype == 1:                                     # Ethernet II
        etype, off = struct.unpack("!H", data[12:14])[0], 14
        if etype == 0x8100:                               # VLAN tag
            etype, off = struct.unpack("!H", data[16:18])[0], 18
    elif linktype == 113:                                 # Linux "any" interface (tcpdump -i any)
        etype, off = struct.unpack("!H", data[14:16])[0], 16
    elif linktype == 0:                                   # loopback
        off = 4
        etype = 0x0800 if data[4] >> 4 == 4 else 0x86DD
    elif linktype == 101:                                 # raw IP
        etype = 0x0800 if data[0] >> 4 == 4 else 0x86DD
    else:
        return None

    if etype == 0x0800:                                   # IPv4
        ihl = (data[off] & 0x0F) * 4
        if data[off + 9] != 17:                           # protocol 17 = UDP
            return None
        src = socket.inet_ntoa(data[off + 12:off + 16])
        dst = socket.inet_ntoa(data[off + 16:off + 20])
        off += ihl
    elif etype == 0x86DD:                                 # IPv6
        if data[off + 6] != 17:
            return None
        src = socket.inet_ntop(socket.AF_INET6, data[off + 8:off + 24])
        dst = socket.inet_ntop(socket.AF_INET6, data[off + 24:off + 40])
        off += 40
    else:
        return None

    _sport, dport = struct.unpack("!HH", data[off:off + 4])
    if dport != 53:                                       # we only want queries going TO a DNS server
        return None
    off += 8                                              # UDP header is 8 bytes

    _txid, flags, qdcount = struct.unpack("!HHH", data[off:off + 6])
    if flags & 0x8000 or qdcount < 1:                     # QR bit = 1 means response
        return None
    off += 12                                             # DNS header is 12 bytes

    labels = []
    while True:                                           # QNAME = length-prefixed labels
        n = data[off]
        off += 1
        if n == 0:
            break
        if n & 0xC0:                                      # compression pointer, not expected in queries
            return None
        labels.append(data[off:off + n].decode("ascii", "ignore").lower())
        off += n
    qtype = struct.unpack("!H", data[off:off + 2])[0]
    return {"src": src, "dst": dst, "qname": ".".join(labels),
            "qtype": QTYPES.get(qtype, str(qtype))}


# ----------------------------------------------------------------------
# 3. BUILDING PACKETS (used only by generate_traffic.py to make test files)
# ----------------------------------------------------------------------
def build_dns_query(name, qtype, txid):
    qname = b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\x00"
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)   # RD flag set, 1 question
    return header + qname + struct.pack("!HH", qtype, 1)          # class IN


def _checksum(header):
    s = sum(struct.unpack("!%dH" % (len(header) // 2), header))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def build_frame(src_ip, dst_ip, sport, dns_payload, ip_id=0):
    udp = struct.pack("!HHHH", sport, 53, 8 + len(dns_payload), 0) + dns_payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), ip_id, 0, 64, 17, 0,
                     socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    ip = ip[:10] + struct.pack("!H", _checksum(ip)) + ip[12:]
    eth = bytes.fromhex("020000000001") + bytes.fromhex("020000000002") + b"\x08\x00"
    return eth + ip + udp


def write_pcap(path, packets):
    """packets = list of (timestamp, frame_bytes). Writes a classic pcap file."""
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, frame in sorted(packets, key=lambda p: p[0]):
            sec = int(ts)
            usec = int((ts - sec) * 1e6)
            f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            f.write(frame)
