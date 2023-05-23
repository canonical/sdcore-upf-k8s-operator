# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest

from ops import testing
from ops.model import ActiveStatus
from test_charms.test_fiveg_n3_requirer.src.charm import WhateverCharm  # type: ignore[import]


class TestN3Requires(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = testing.Harness(WhateverCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()
        self.relation_name = "fiveg_n3"

    def test_given_fiveg_n3_requirer_charm_when_fiveg_n3_available_then_charm_goes_to_active_status_and_the_message_contains_valid_upf_ip_address(  # noqa: E501
        self,
    ):
        test_upf_ip = "1.2.3.4"
        relation_id = self.harness.add_relation(
            relation_name=self.relation_name, remote_app="whatever-app"
        )
        self.harness.add_relation_unit(relation_id, "whatever-app/0")
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit="whatever-app/0",
            key_values={"upf_ip_address": test_upf_ip},
        )

        self.assertEqual(self.harness.model.unit.status, ActiveStatus(test_upf_ip))
