# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest
from unittest.mock import PropertyMock, patch

from ops import testing
from test_charms.test_provider_charm.src.charm import WhateverCharm  # type: ignore[import]

TEST_CHARM_PATH = "test_charms.test_provider_charm.src.charm.WhateverCharm"


class TestN3Provides(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = testing.Harness(WhateverCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()
        self.relation_name = "fiveg_n3"

    @patch(f"{TEST_CHARM_PATH}.TEST_UPF_IP_ADDRESS", new_callable=PropertyMock)
    def test_given_fiveg_n3_relation_when_relation_created_then_upf_ip_address_is_published_in_the_relation_data(
        self, patched_test_upf_ip
    ):
        self.harness.set_leader(is_leader=True)
        test_upf_ip = "1.2.3.4"
        patched_test_upf_ip.return_value = test_upf_ip
        relation_id = self.harness.add_relation(
            relation_name=self.relation_name, remote_app="whatever-app"
        )
        self.harness.add_relation_unit(relation_id, "whatever-app/0")

        relation_data = self.harness.get_relation_data(
            relation_id=relation_id, app_or_unit=self.harness.charm.app
        )
        self.assertEqual(test_upf_ip, relation_data["upf_ip_address"])

    @patch(f"{TEST_CHARM_PATH}.TEST_UPF_IP_ADDRESS", new_callable=PropertyMock)
    def test_given_invalid_upf_ip_address_when_relation_created_then_value_error_is_raised(
        self, patched_test_upf_ip
    ):
        self.harness.set_leader(is_leader=True)
        invalid_upf_ip = "777.888.9999.0"
        patched_test_upf_ip.return_value = invalid_upf_ip

        with self.assertRaises(ValueError):
            relation_id = self.harness.add_relation(
                relation_name=self.relation_name, remote_app="whatever-app"
            )
            self.harness.add_relation_unit(relation_id, "whatever-app/0")
