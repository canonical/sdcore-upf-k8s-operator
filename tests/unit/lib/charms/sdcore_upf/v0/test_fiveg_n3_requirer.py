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
        self.relation_name = "fiveg_n3"

    @patch("charms.sdcore_upf_k8s.v0.fiveg_n3.N3RequirerCharmEvents.fiveg_n3_available")
    def test_given_relation_with_n3_provider_when_fiveg_n3_available_event_then_n3_information_is_provided(
        self, patched_fiveg_n3_available_event
    ):
        test_upf_ip = "1.2.3.4"
        relation_id = self.harness.add_relation(
            relation_name=self.relation_name, remote_app="whatever-app"
        )
        self.harness.add_relation_unit(relation_id, "whatever-app/0")

        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit="whatever-app",
            key_values={"upf_ip_address": test_upf_ip},
        )

        calls = [
            call.emit(upf_ip_address=test_upf_ip),
        ]
        patched_fiveg_n3_available_event.assert_has_calls(calls)
