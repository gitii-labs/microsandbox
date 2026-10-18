import unittest

from microsandbox import Network, Sandbox


class HostAliasIPv4PortsTests(unittest.TestCase):
    def test_wire_field_is_optional_and_preserves_ports(self):
        self.assertNotIn("host_alias_ipv4_ports", Network()._to_dict())
        self.assertEqual(
            Network(host_alias_ipv4_ports=(12345,))._to_dict()["host_alias_ipv4_ports"],
            [12345],
        )

    def test_restore_rejects_invalid_ports(self):
        for port in (0, -1, 65536):
            with self.subTest(port=port), self.assertRaises((ValueError, OverflowError)):
                Sandbox.restore_with_progress(
                    "saved", name="invalid-host-alias", host_alias_ipv4_ports=(port,)
                )
