# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest
from unittest.mock import PropertyMock, patch

from ops import testing
from test_charms.test_provider_charm.src.charm import WhateverCharm  # type: ignore[import]

TEST_CHARM_PATH = "test_charms.test_provider_charm.src.charm.WhateverCharm"


class TestN4Provides(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = testing.Harness(WhateverCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()
        self.relation_name = "fiveg_n4"

    @patch(f"{TEST_CHARM_PATH}.TEST_UPF_HOSTNAME", new_callable=PropertyMock)
    @patch(f"{TEST_CHARM_PATH}.TEST_UPF_PORT", new_callable=PropertyMock)
    def test_given_fiveg_n4_relation_when_relation_created_then_upf_hostname_and_upf_port_is_published_in_the_relation_data(
        self, patched_test_upf_port, patched_test_upf_hostname
    ):
        self.harness.set_leader(is_leader=True)
        test_upf_hostname = "upf.edge-cloud.test.com"
        test_upf_port = 1234
        patched_test_upf_hostname.return_value = test_upf_hostname
        patched_test_upf_port.return_value = test_upf_port
        relation_id = self.harness.add_relation(
            relation_name=self.relation_name, remote_app="whatever-app"
        )
        self.harness.add_relation_unit(relation_id, "whatever-app/0")

        relation_data = self.harness.get_relation_data(
            relation_id=relation_id, app_or_unit=self.harness.charm.app
        )
        self.assertEqual(test_upf_hostname, relation_data["upf_hostname"])
        self.assertEqual(str(test_upf_port), relation_data["upf_port"])

    @patch(f"{TEST_CHARM_PATH}.TEST_UPF_HOSTNAME", new_callable=PropertyMock)
    @patch(f"{TEST_CHARM_PATH}.TEST_UPF_PORT", new_callable=PropertyMock)
    def test_given_invalid_upf_hostname_when_relation_created_then_value_error_is_raised(
        self, patched_test_upf_port, patched_test_upf_hostname
    ):
        self.harness.set_leader(is_leader=True)
        test_invalid_upf_hostname = None
        test_upf_port = 1234
        patched_test_upf_hostname.return_value = test_invalid_upf_hostname
        patched_test_upf_port.return_value = test_upf_port

        with self.assertRaises(ValueError):
            relation_id = self.harness.add_relation(
                relation_name=self.relation_name, remote_app="whatever-app"
            )
            self.harness.add_relation_unit(relation_id, "whatever-app/0")

    @patch(f"{TEST_CHARM_PATH}.TEST_UPF_HOSTNAME", new_callable=PropertyMock)
    @patch(f"{TEST_CHARM_PATH}.TEST_UPF_PORT", new_callable=PropertyMock)
    def test_given_invalid_upf_port_when_relation_created_then_value_error_is_raised(
        self, patched_test_upf_port, patched_test_upf_hostname
    ):
        self.harness.set_leader(is_leader=True)
        test_upf_hostname = "upf.edge-cloud.test.com"
        test_invalid_upf_port = "not_an_int"
        patched_test_upf_hostname.return_value = test_upf_hostname
        patched_test_upf_port.return_value = test_invalid_upf_port

        with self.assertRaises(ValueError):
            relation_id = self.harness.add_relation(
                relation_name=self.relation_name, remote_app="whatever-app"
            )
            self.harness.add_relation_unit(relation_id, "whatever-app/0")
