# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from unittest.mock import patch

import pytest
from ops import testing

from charm import UPFOperatorCharm
from dpdk import DPDK
from k8s_service import K8sService


class UPFUnitTestFixtures:
    patcher_k8s_client = patch("lightkube.core.client.GenericSyncClient")
    patcher_client_list = patch("lightkube.core.client.Client.list")
    patcher_k8sclient_list = patch("k8s_client.K8sClient.list")
    patcher_k8s_service = patch("charm.K8sService", autospec=K8sService)
    patcher_huge_pages_is_patched = patch(
        "charm.KubernetesHugePagesPatchCharmLib.is_patched",
    )
    patcher_multus_is_available = patch("charm.KubernetesMultusCharmLib.multus_is_available")
    patcher_multus_is_ready = patch("charm.KubernetesMultusCharmLib.is_ready")
    patcher_check_output = patch("charm.check_output")
    patcher_dpdk = patch("charm.DPDK", autospec=DPDK)
    patcher_n3_provides_publish_upf_information = patch("charm.N3Provides.publish_upf_information")
    patcher_n4_provides_publish_upf_information = patch(
        "charm.N4Provides.publish_upf_n4_information"
    )

    @pytest.fixture(autouse=True)
    def setup(self, request):
        self.mock_k8s_client = UPFUnitTestFixtures.patcher_k8s_client.start().return_value
        self.mock_client_list = UPFUnitTestFixtures.patcher_client_list.start()
        self.mock_k8sclient_list = UPFUnitTestFixtures.patcher_k8sclient_list.start()
        self.mock_k8s_service = UPFUnitTestFixtures.patcher_k8s_service.start().return_value
        self.mock_huge_pages_is_patched = UPFUnitTestFixtures.patcher_huge_pages_is_patched.start()
        self.mock_multus_is_available = UPFUnitTestFixtures.patcher_multus_is_available.start()
        self.mock_multus_is_ready = UPFUnitTestFixtures.patcher_multus_is_ready.start()
        self.mock_check_output = UPFUnitTestFixtures.patcher_check_output.start()
        self.mock_dpdk = UPFUnitTestFixtures.patcher_dpdk.start().return_value
        self.mock_n3_provides_publish_upf_information = (
            UPFUnitTestFixtures.patcher_n3_provides_publish_upf_information.start()
        )
        self.mock_n4_provides_publish_upf_information = (
            UPFUnitTestFixtures.patcher_n4_provides_publish_upf_information.start()
        )
        yield
        request.addfinalizer(self.teardown)

    @staticmethod
    def teardown() -> None:
        patch.stopall()

    @pytest.fixture(autouse=True)
    def context(self):
        self.ctx = testing.Context(
            charm_type=UPFOperatorCharm,
        )
