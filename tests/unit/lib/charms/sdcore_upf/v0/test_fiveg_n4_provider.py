# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import pytest
from unittest.mock import PropertyMock, patch

from ops import testing
from test_charms.test_provider_charm.src.charm import WhateverCharm  # type: ignore[import]

TEST_CHARM_PATH = "test_charms.test_provider_charm.src.charm.WhateverCharm"
VALID_HOSTNAME = "upf.edge-cloud.test.com"
VALID_PORT = 1234

class TestN4Provides:
    
    patcher_upf_hostname = patch(f"{TEST_CHARM_PATH}.TEST_UPF_HOSTNAME", new_callable=PropertyMock)
    patcher_upf_port = patch(f"{TEST_CHARM_PATH}.TEST_UPF_PORT", new_callable=PropertyMock)
    
    @pytest.fixture()
    def setUp(self) -> None:
        self.mock_upf_hostname = TestN4Provides.patcher_upf_hostname.start()
        self.mock_upf_port = TestN4Provides.patcher_upf_port.start()
        self.mock_upf_hostname.return_value = VALID_HOSTNAME
        self.mock_upf_port.return_value = VALID_PORT
    
    @staticmethod
    def tearDown() -> None:
        patch.stopall()
        
    @pytest.fixture(autouse=True)
    def harness(self, setUp, request):
        self.harness = testing.Harness(WhateverCharm)
        self.harness.set_model_name(name="whatever")
        self.harness.set_leader(is_leader=True)
        self.harness.begin()
        yield self.harness
        self.harness.cleanup()
        request.addfinalizer(self.tearDown)
        
    def add_fiveg_n4_relation(self) -> int:
        relation_id = self.harness.add_relation(
            relation_name="fiveg_n4", remote_app="whatever-app"
        )
        self.harness.add_relation_unit(relation_id, "whatever-app/0")
        return relation_id

    def test_given_fiveg_n4_relation_when_relation_created_then_upf_hostname_and_upf_port_is_published_in_the_relation_data(  # noqa: E501
        self,
    ):
        relation_id = self.add_fiveg_n4_relation()
        relation_data = self.harness.get_relation_data(
            relation_id=relation_id, app_or_unit=self.harness.charm.app
        )
        assert VALID_HOSTNAME == relation_data["upf_hostname"]
        assert str(VALID_PORT) == relation_data["upf_port"]

    def test_given_invalid_upf_hostname_when_relation_created_then_value_error_is_raised(
        self,
    ):
        test_invalid_upf_hostname = None
        self.mock_upf_hostname.return_value = test_invalid_upf_hostname
        with pytest.raises(ValueError):
            self.add_fiveg_n4_relation()

    def test_given_invalid_upf_port_when_relation_created_then_value_error_is_raised(
        self,
    ):
        test_invalid_upf_port = "not_an_int"
        self.mock_upf_port.return_value = test_invalid_upf_port
        with pytest.raises(ValueError):
            self.add_fiveg_n4_relation()
