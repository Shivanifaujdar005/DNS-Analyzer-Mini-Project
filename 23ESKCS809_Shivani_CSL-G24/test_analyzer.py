"""Unit tests - run with:  python -m unittest test_analyzer -v"""
import os
import tempfile
import unittest

from dns_analyzer import (DEFAULT_CFG, analyze, check_domain, load_queries,
                          rate_alerts, shannon_entropy, split_name, tunnel_alerts)
from pcap_utils import QTYPE_NUM, build_dns_query, build_frame, write_pcap


def make_pcap(records):
    """records = [(ts, src, name, qtype)] -> temp pcap path"""
    pk = [(ts, build_frame(src, "192.168.56.1", 5555, build_dns_query(n, QTYPE_NUM[t], 1))) for ts, src, n, t in records]
    path = os.path.join(tempfile.mkdtemp(), "t.pcap")
    write_pcap(path, pk)
    return path


class TestEntropy(unittest.TestCase):
    def test_zero_for_same_char(self):
        self.assertEqual(shannon_entropy("aaaa"), 0.0)

    def test_one_bit_for_two_chars(self):
        self.assertAlmostEqual(shannon_entropy("abab"), 1.0)

    def test_random_higher_than_word(self):
        self.assertGreater(shannon_entropy("xk3j9qz8vb2mw7"), shannon_entropy("googlegoogle"))


class TestSplit(unittest.TestCase):
    def test_simple(self):
        self.assertEqual(split_name("www.google.com"), (["www"], "google", "google.com"))

    def test_two_level_suffix(self):
        self.assertEqual(split_name("mail.skit.ac.in"), (["mail"], "skit", "skit.ac.in"))


class TestDomainChecks(unittest.TestCase):
    def test_normal_domains_not_flagged(self):
        for d in ("www.google.com", "github.com", "stackoverflow.com", "files.pythonhosted.org"):
            self.assertEqual(check_domain(d, DEFAULT_CFG)[0], [], d)

    def test_random_domain_flagged(self):
        self.assertIn("RANDOM_LOOKING", check_domain("xk3j9qz8vb2mw7.com", DEFAULT_CFG)[0])

    def test_long_domain_flagged(self):
        self.assertIn("LONG_DOMAIN", check_domain("a" * 40 + ".example.com", DEFAULT_CFG)[0])

    def test_cdn_allowlisted(self):
        self.assertEqual(check_domain("d3e54v103j8qbb.cloudfront.net", DEFAULT_CFG)[0], [])


class TestRate(unittest.TestCase):
    def test_flood_detected_and_normal_ignored(self):
        recs = [(1000 + i * 0.1, "10.0.0.9", "www.google.com", "A") for i in range(150)]
        recs += [(1000 + i * 5, "10.0.0.2", "github.com", "A") for i in range(10)]
        q, _ = load_queries(make_pcap(recs))
        alerts = rate_alerts(q, DEFAULT_CFG)
        self.assertEqual([a["source"] for a in alerts], ["10.0.0.9"])


class TestTunnel(unittest.TestCase):
    def test_tunnel_detected(self):
        recs = [(1000 + i, "10.0.0.5", f"{'abcdefghij1234567890'[i % 20]}{i:030d}xyz.t.evil-lab.test", "TXT") for i in range(30)]
        q, _ = load_queries(make_pcap(recs))
        self.assertEqual([a["domain"] for a in tunnel_alerts(q, DEFAULT_CFG)], ["evil-lab.test"])

    def test_normal_subdomains_not_flagged(self):
        recs = [(1000 + i, "10.0.0.5", f"{s}.google.com", "A") for i, s in enumerate(["www", "mail", "docs", "maps"])]
        q, _ = load_queries(make_pcap(recs))
        self.assertEqual(tunnel_alerts(q, DEFAULT_CFG), [])


class TestParser(unittest.TestCase):
    def test_roundtrip(self):
        q, total = load_queries(make_pcap([(1.5, "10.1.2.3", "Test.Example.com", "AAAA")]))
        self.assertEqual(total, 1)
        self.assertEqual((q[0]["src"], q[0]["qname"], q[0]["qtype"]), ("10.1.2.3", "test.example.com", "AAAA"))


class TestPcapng(unittest.TestCase):
    def test_pcapng_reader(self):
        import struct
        frame = build_frame("10.9.9.9", "192.168.56.1", 4444, build_dns_query("hello.example.org", 1, 7))
        def block(btype, body):
            body += b"\x00" * (-len(body) % 4)
            return struct.pack("<II", btype, len(body) + 12) + body + struct.pack("<I", len(body) + 12)
        shb = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
        idb = block(1, struct.pack("<HHI", 1, 0, 65535))
        epb = block(6, struct.pack("<IIIII", 0, 0, 2_000_000, len(frame), len(frame)) + frame)
        path = os.path.join(tempfile.mkdtemp(), "t.pcapng")
        open(path, "wb").write(shb + idb + epb)
        q, total = load_queries(path)
        self.assertEqual((total, q[0]["qname"], q[0]["src"]), (1, "hello.example.org", "10.9.9.9"))
        self.assertAlmostEqual(q[0]["ts"], 2.0)


if __name__ == "__main__":
    unittest.main()
