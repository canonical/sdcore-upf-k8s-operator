# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest
from unittest.mock import call, patch

from ops import testing
from test_charms.test_requirer_charm.src.charm import WhateverCharm  # type: ignore[import]


class TestN3Requires(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = testing.Harness(WhateverCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()
        self.relation_name = "fiveg_n4"

    @patch("charms.sdcore_upf.v0.fiveg_n4.N4RequirerCharmEvents.fiveg_n4_available")
    def test_given_relation_with_n4_profider_when_fiveg_n4_available_event_then_n4_information_is_provided(  # noqa: E501
        self, patched_fiveg_n4_available_event
    ):
        test_upf_hostname = "upf.edge-cloud.test.com"
        test_upf_port = 1234
        relation_id = self.harness.add_relation(
            relation_name=self.relation_name, remote_app="whatever-app"
        )
        self.harness.add_relation_unit(relation_id, "whatever-app/0")

        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit="whatever-app/0",
            key_values={"upf_hostname": test_upf_hostname, "upf_port": str(test_upf_port)},
        )

        calls = [
            call.emit(upf_hostname=test_upf_hostname, upf_port=str(test_upf_port)),
        ]
        patched_fiveg_n4_available_event.assert_has_calls(calls)
