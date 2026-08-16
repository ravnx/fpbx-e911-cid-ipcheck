#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Regression tests for run_e911_audit.py.

Run with: python3 -m unittest discover -v

These cover the parsing/sorting logic against captured Asterisk CLI output,
so no live Asterisk is required.
"""

import unittest

import run_e911_audit as audit


# Realistic `sip show peers` output, including the column padding, an
# offline peer, an unmonitored peer, a whitespace-only line and the
# trailing summary line.
SIP_OUTPUT = (
    "Name/username             Host                                    Dyn Forcerport Comedia    ACL Port     Status      Description\n"
    "122/122                   127.12.17.90                             D  Yes        Yes         A  11889    OK (34 ms)                    \n"
    "124/124                   219.33.50.50                             D  Yes        Yes         A  13479    OK (31 ms)                    \n"
    "130/130                   10.0.0.55                                D  Yes        Yes         A  5060     UNREACHABLE                   \n"
    "131/131                   10.0.0.56                                D  Yes        Yes         A  5060     Lagged (12 ms)                \n"
    "132                       (Unspecified)                            D  Yes        Yes         A  0        Unmonitored                   \n"
    "                                                                                                                                       \n"
    "5\n"
    "5 sip peers [Monitored: 2 online, 1 offline Unmonitored: 1 online, 0 offline]\n"
)

# Realistic `pjsip show contacts` output. Note ext 120 registers its
# contact with the device MAC rather than the extension number, and 130
# is Unavail.
PJSIP_OUTPUT = (
    "  Contact:  <Aor/ContactUri>                                        <Hash....> <Status> <RTT(ms)..>\n"
    "==========================================================================================\n"
    "  Contact:  115/sip:115@127.153.63.153:5887;x-ast-orig-host= 47e23d99a7 Avail        62.119\n"
    "  Contact:  120/sip:mac001565abcdef@234.151.131.15:5555;x-ast-o 000b045248 Avail       143.726\n"
    "  Contact:  130/sip:130@10.0.0.55:5060                        0011223344 Unavail        nan\n"
    "   \n"
)

DATABASE_OUTPUT = (
    "/DEVICE/814/emergency_cid                         : 713652565\n"
    "/DEVICE/815/emergency_cid                         : <7135551212>\n"
    "/DEVICE/816/emergency_cid                         : +17135551212\n"
    "/DEVICE/817/emergency_cid                         :\n"
    "/DEVICE/818/dial                                  : PJSIP/818\n"
    "   \n"
)


class TestCliFailureDetection(unittest.TestCase):
    """Finding 1: a failed Asterisk call must not look like an empty result."""

    def test_unable_to_connect_is_failure(self):
        out = "Unable to connect to remote asterisk (does /var/run/asterisk/asterisk.ctl exist?)\n"
        self.assertTrue(audit.is_cli_failure(0, out))

    def test_no_such_command_is_failure(self):
        out = "No such command 'sip show peers' (type 'core show help sip show' for other possible commands)\n"
        self.assertTrue(audit.is_cli_failure(0, out))

    def test_nonzero_returncode_is_failure(self):
        self.assertTrue(audit.is_cli_failure(1, "anything at all\n"))

    def test_empty_output_is_failure(self):
        self.assertTrue(audit.is_cli_failure(0, "   \n"))

    def test_normal_output_is_not_failure(self):
        self.assertFalse(audit.is_cli_failure(0, SIP_OUTPUT))


class TestParseSipPeers(unittest.TestCase):

    def test_extracts_online_peers(self):
        pairs = audit.parse_sip_peers(SIP_OUTPUT)
        self.assertIn(("122", "127.12.17.90"), pairs)
        self.assertIn(("124", "219.33.50.50"), pairs)

    def test_skips_unreachable_peer(self):
        """Finding 2: an unplugged phone still lists its last-known host."""
        exts = [ext for ext, _ip in audit.parse_sip_peers(SIP_OUTPUT)]
        self.assertNotIn("130", exts)

    def test_skips_unmonitored_peer(self):
        exts = [ext for ext, _ip in audit.parse_sip_peers(SIP_OUTPUT)]
        self.assertNotIn("132", exts)

    def test_whitespace_only_line_does_not_raise(self):
        """Finding 4: `len(line) > 0` passes for a line of spaces."""
        self.assertEqual(audit.parse_sip_peers("      \n"), [])

    def test_single_numeric_token_line_does_not_raise(self):
        """Finding 4: parts[1] indexed without a length check."""
        self.assertEqual(audit.parse_sip_peers("5\n"), [])


class TestParsePjsipContacts(unittest.TestCase):

    def test_extracts_available_contact(self):
        pairs = audit.parse_pjsip_contacts(PJSIP_OUTPUT)
        self.assertIn(("115", "127.153.63.153"), pairs)

    def test_uses_aor_not_contact_user(self):
        """Finding 6: Yealinks register the contact under the device MAC."""
        pairs = audit.parse_pjsip_contacts(PJSIP_OUTPUT)
        self.assertIn(("120", "234.151.131.15"), pairs)

    def test_skips_unavailable_contact(self):
        """Finding 2: `Unavail` must not be grouped into a location."""
        exts = [ext for ext, _ip in audit.parse_pjsip_contacts(PJSIP_OUTPUT)]
        self.assertNotIn("130", exts)

    def test_whitespace_only_line_does_not_raise(self):
        self.assertEqual(audit.parse_pjsip_contacts("   \n"), [])


class TestParseEmergencyCids(unittest.TestCase):

    def test_plain_digits(self):
        self.assertEqual(audit.parse_emergency_cids(DATABASE_OUTPUT)["814"], "713652565")

    def test_angle_bracketed_value(self):
        """Finding 3: <7135551212> silently read as a missing CID."""
        self.assertEqual(audit.parse_emergency_cids(DATABASE_OUTPUT)["815"], "7135551212")

    def test_e164_value(self):
        self.assertEqual(audit.parse_emergency_cids(DATABASE_OUTPUT)["816"], "17135551212")

    def test_genuinely_empty_value_is_absent(self):
        self.assertNotIn("817", audit.parse_emergency_cids(DATABASE_OUTPUT))

    def test_ignores_other_device_keys(self):
        self.assertNotIn("818", audit.parse_emergency_cids(DATABASE_OUTPUT))


class TestSorting(unittest.TestCase):

    def test_ips_sort_numerically(self):
        """Finding 5: string sort scatters a subnet."""
        ips = ["192.168.1.10", "10.0.0.2", "192.168.1.2", "2.2.2.2"]
        self.assertEqual(
            audit.sort_ips(ips),
            ["2.2.2.2", "10.0.0.2", "192.168.1.2", "192.168.1.10"],
        )

    def test_extensions_sort_numerically(self):
        self.assertEqual(
            audit.sort_extensions(["1000", "200", "9", "815"]),
            ["9", "200", "815", "1000"],
        )


class TestIpValidation(unittest.TestCase):
    """Sorting by numeric value requires the collector to reject junk."""

    def test_rejects_out_of_range_octet(self):
        self.assertFalse(audit.is_valid_ip("999.1.1.1"))

    def test_accepts_normal_address(self):
        self.assertTrue(audit.is_valid_ip("10.0.0.55"))


if __name__ == "__main__":
    unittest.main()
