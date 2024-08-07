# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

from unittest.mock import call, patch

import pytest
from ops import BoundEvent, testing

from tests.unit.lib.charms.sdcore_upf.v0.test_charms.test_requirer_charm.src.charm import (
    WhateverCharm,
)


class TestN4Requires:
    patch_n4_available = patch(
        "charms.sdcore_upf_k8s.v0.fiveg_n4.N4RequirerCharmEvents.fiveg_n4_available"
    )

    @pytest.fixture()
    def setUp(self) -> None:
        self.mock_n4_available = TestN4Requires.patch_n4_available.start()
        self.mock_n4_available.__class__ = BoundEvent

    @staticmethod
    def tearDown() -> None:
        patch.stopall()

    @pytest.fixture(autouse=True)
    def setup_harness(self, setUp, request):
        self.harness = testing.Harness(WhateverCharm)
        self.harness.set_model_name(name="whatever")
        self.harness.begin()
        yield self.harness
        self.harness.cleanup()
        request.addfinalizer(self.tearDown)

    def test_given_relation_with_n4_provider_when_fiveg_n4_available_event_then_n4_information_is_provided(  # noqa: E501
        self,
    ):
        test_upf_hostname = "upf.edge-cloud.test.com"
        test_upf_port = 1234
        relation_id = self.harness.add_relation(
            relation_name="fiveg_n4", remote_app="whatever-app"
        )
        self.harness.add_relation_unit(relation_id, "whatever-app/0")
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit="whatever-app",
            key_values={"upf_hostname": test_upf_hostname, "upf_port": str(test_upf_port)},
        )

        calls = [
            call.emit(upf_hostname=test_upf_hostname, upf_port=str(test_upf_port)),
        ]
        self.mock_n4_available.assert_has_calls(calls)
