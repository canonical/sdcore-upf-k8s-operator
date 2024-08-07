# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

from unittest.mock import PropertyMock, patch

import pytest
from ops import testing

from tests.unit.lib.charms.sdcore_upf.v0.test_charms.test_provider_charm.src.charm import (
    WhateverCharm,
)

RELATION_NAME = "fiveg_n3"
REMOVE_APP = "whatever-app"
TEST_CHARM_PATH = (
    "tests.unit.lib.charms.sdcore_upf.v0.test_charms.test_provider_charm.src.charm.WhateverCharm"
)


class TestN3Provides:
    patcher_upf_ip_address = patch(
        f"{TEST_CHARM_PATH}.TEST_UPF_IP_ADDRESS", new_callable=PropertyMock
    )

    @pytest.fixture()
    def setUp(self) -> None:
        self.mock_upf_ip_address = TestN3Provides.patcher_upf_ip_address.start()

    @staticmethod
    def tearDown() -> None:
        patch.stopall()

    @pytest.fixture(autouse=True)
    def setup_harness(self, setUp, request):
        self.harness = testing.Harness(WhateverCharm)
        self.harness.set_model_name(name="whatever")
        self.harness.set_leader(is_leader=True)
        self.harness.begin()
        yield self.harness
        self.harness.cleanup()
        request.addfinalizer(self.tearDown)

    def test_given_fiveg_n3_relation_when_relation_created_then_upf_ip_address_is_published_in_the_relation_data(  # noqa: E501
        self,
    ):
        test_upf_ip = "1.2.3.4"
        self.mock_upf_ip_address.return_value = test_upf_ip
        relation_id = self.harness.add_relation(relation_name=RELATION_NAME, remote_app=REMOVE_APP)
        self.harness.add_relation_unit(relation_id, f"{REMOVE_APP}/0")

        relation_data = self.harness.get_relation_data(
            relation_id=relation_id, app_or_unit=self.harness.charm.app
        )
        assert test_upf_ip == relation_data["upf_ip_address"]

    def test_given_invalid_upf_ip_address_when_relation_created_then_value_error_is_raised(
        self,
    ):
        invalid_upf_ip = "777.888.9999.0"
        self.mock_upf_ip_address.return_value = invalid_upf_ip

        with pytest.raises(ValueError):
            relation_id = self.harness.add_relation(
                relation_name=RELATION_NAME, remote_app=REMOVE_APP
            )
            self.harness.add_relation_unit(relation_id, f"{REMOVE_APP}/0")
