import unittest

from ipscan.targets import (TargetError, check_pair_budget, iter_pairs,
                            parse_ports, parse_targets)


class PortParsing(unittest.TestCase):
    def test_list_and_range(self):
        self.assertEqual(parse_ports("22,80,443"), [22, 80, 443])
        self.assertEqual(parse_ports("80-83"), [80, 81, 82, 83])
        self.assertEqual(parse_ports("443,80-82,443"), [80, 81, 82, 443])

    def test_named_sets(self):
        self.assertIn(22, parse_ports("top100"))
        self.assertEqual(len(parse_ports("all")), 65535)
        self.assertEqual(len(parse_ports("-")), 65535)

    def test_open_ended_range(self):
        # nmap ile ayni davranis: "65530-" -> 65530..65535, "-3" -> 1..3
        self.assertEqual(parse_ports("65530-")[0], 65530)
        self.assertEqual(parse_ports("65530-")[-1], 65535)
        self.assertEqual(parse_ports("-3"), [1, 2, 3])

    def test_reversed_range(self):
        self.assertEqual(parse_ports("90-88"), [88, 89, 90])

    def test_rejects_invalid(self):
        for bad in ["0", "65536", "abc", "22;rm -rf /", "80-99999", ""]:
            with self.assertRaises(TargetError, msg=bad):
                parse_ports(bad)

    def test_ignores_comments(self):
        self.assertEqual(parse_ports("22 # ssh\n80"), [22, 80])


class TargetParsing(unittest.TestCase):
    def test_single_ip(self):
        self.assertEqual(parse_targets("10.0.0.1").hosts, ["10.0.0.1"])

    def test_ipv6(self):
        self.assertEqual(parse_targets("::1").hosts, ["::1"])

    def test_cidr_excludes_network_and_broadcast(self):
        hosts = parse_targets("192.168.1.0/30").hosts
        self.assertEqual(hosts, ["192.168.1.1", "192.168.1.2"])

    def test_cidr_slash_32(self):
        self.assertEqual(parse_targets("192.168.1.7/32").hosts, ["192.168.1.7"])

    def test_short_range(self):
        self.assertEqual(parse_targets("10.0.0.5-8").hosts,
                         ["10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8"])

    def test_full_range(self):
        self.assertEqual(parse_targets("10.0.0.254-10.0.1.1").hosts,
                         ["10.0.0.254", "10.0.0.255", "10.0.1.0", "10.0.1.1"])

    def test_dedup_and_order(self):
        self.assertEqual(parse_targets("10.0.0.2, 10.0.0.1, 10.0.0.2").hosts,
                         ["10.0.0.2", "10.0.0.1"])

    def test_multiline_and_comments(self):
        text = "10.0.0.1  # gateway\n10.0.0.2\n\n# yorum\n10.0.0.3"
        self.assertEqual(len(parse_targets(text).hosts), 3)

    def test_hostname_requires_resolve_flag(self):
        with self.assertRaises(TargetError):
            parse_targets("example.com")

    def test_rejects_garbage(self):
        for bad in ["999.1.1.1", "10.0.0.1/33", "; ls", "10.0.0.1-abc", ""]:
            with self.assertRaises(TargetError, msg=bad):
                parse_targets(bad)

    def test_max_targets_enforced(self):
        with self.assertRaises(TargetError):
            parse_targets("10.0.0.0/16", max_targets=100)

    def test_pair_budget(self):
        self.assertEqual(check_pair_budget(10, 10), 100)
        with self.assertRaises(TargetError):
            check_pair_budget(1000, 65535, max_pairs=1000)

    def test_iter_pairs_is_port_major(self):
        pairs = list(iter_pairs(["a", "b"], [1, 2]))
        self.assertEqual(pairs, [("a", 1), ("b", 1), ("a", 2), ("b", 2)])


if __name__ == "__main__":
    unittest.main()
