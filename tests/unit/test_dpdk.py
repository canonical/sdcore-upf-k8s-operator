# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

from unittest.mock import MagicMock, Mock, patch

import pytest
from lightkube.core.exceptions import ApiError
from lightkube.models.apps_v1 import StatefulSetSpec
from lightkube.models.core_v1 import (
    Container,
    PodSpec,
    PodTemplateSpec,
    ResourceRequirements,
    SecurityContext,
)
from lightkube.models.meta_v1 import LabelSelector, ObjectMeta
from lightkube.resources.apps_v1 import StatefulSet

from dpdk import DPDK, DPDKError

TEST_CONTAINER_NAME = "bullseye"
TEST_RESOURCE_REQUESTS = {"test_request": 1234}
TEST_RESOURCE_LIMITS = {"test_limit": 4321}
TEST_RESOURCE_REQUIREMENTS = {
    "requests": TEST_RESOURCE_REQUESTS,
    "limits": TEST_RESOURCE_LIMITS,
}


class TestDPDKStatefulSetUpdater:
    patcher_lightkube_client = patch("lightkube.core.client.GenericSyncClient", new=Mock)
    patcher_lightkube_client_get = patch("lightkube.core.client.Client.get")
    patcher_k8sclient_get = patch("k8s_client.K8sClient.get")
    patcher_k8sclient_replace = patch("k8s_client.K8sClient.replace")

    @pytest.fixture(autouse=True)
    def setUp(self, request) -> None:
        TestDPDKStatefulSetUpdater.patcher_lightkube_client.start()
        self.mock_lightkube_client_get = (
            TestDPDKStatefulSetUpdater.patcher_lightkube_client_get.start()
        )
        self.mock_k8sclient_get = (
            TestDPDKStatefulSetUpdater.patcher_k8sclient_get.start()
        )
        self.mock_k8sclient_replace = (
            TestDPDKStatefulSetUpdater.patcher_k8sclient_replace.start()
        )
        self.dpdk_statefulset_updater = DPDK(
            statefulset_name="doesntmatter",
            namespace="whatever",
            dpdk_access_interface_resource_name="who",
            dpdk_core_interface_resource_name="cares",
        )
        request.addfinalizer(self.tearDown)

    @staticmethod
    def tearDown() -> None:
        patch.stopall()

    def test_given_lightkube_client_returns_api_error_on_get_when_container_configured_for_dpdk_called_then_dpdk_statefulset_updater_error_is_raised(  # noqa: E501
        self,
    ):
        self.mock_lightkube_client_get.side_effect = ApiError(response=MagicMock())

        with pytest.raises(DPDKError):
            self.dpdk_statefulset_updater.is_configured("justatest")

    def test_given_container_not_is_statefulset_when_container_configured_for_dpdk_called_then_dpdk_statefulset_updater_error_is_raised(  # noqa: E501
        self,
    ):
        test_statefulset = StatefulSet(
            spec=StatefulSetSpec(
                selector=LabelSelector(),
                serviceName="whatever",
                template=PodTemplateSpec(spec=PodSpec(containers=[])),
            )
        )
        self.mock_k8sclient_get.return_value = test_statefulset

        with pytest.raises(DPDKError):
            self.dpdk_statefulset_updater.is_configured("justatest")

    def test_given_container_is_not_privileged_when_container_configured_for_dpdk_called_then_false_is_returned(  # noqa: E501
        self,
    ):
        test_statefulset = StatefulSet(
            spec=StatefulSetSpec(
                selector=LabelSelector(),
                serviceName="whatever",
                template=PodTemplateSpec(
                    spec=PodSpec(
                        containers=[
                            Container(
                                name=TEST_CONTAINER_NAME,
                                securityContext=SecurityContext(privileged=False),
                            )
                        ]
                    )
                ),
            )
        )
        self.mock_k8sclient_get.return_value = test_statefulset

        assert self.dpdk_statefulset_updater.is_configured(TEST_CONTAINER_NAME) is False

    def test_given_resource_requirements_not_applied_to_the_container_when_container_configured_for_dpdk_called_then_false_is_returned(  # noqa: E501
        self,
    ):
        test_statefulset = StatefulSet(
            spec=StatefulSetSpec(
                selector=LabelSelector(),
                serviceName="whatever",
                template=PodTemplateSpec(
                    spec=PodSpec(
                        containers=[
                            Container(
                                name=TEST_CONTAINER_NAME,
                                resources=ResourceRequirements(limits={}, requests={}),
                                securityContext=SecurityContext(privileged=True),
                            )
                        ]
                    )
                ),
            )
        )
        self.mock_k8sclient_get.return_value = test_statefulset

        assert self.dpdk_statefulset_updater.is_configured(TEST_CONTAINER_NAME) is False

    def test_given_resource_requests_applied_but_limits_not_applied_to_the_container_when_container_configured_for_dpdk_called_then_false_is_returned(  # noqa: E501
        self,
    ):
        self.dpdk_statefulset_updater.dpdk_resource_requirements = TEST_RESOURCE_REQUIREMENTS
        test_statefulset = StatefulSet(
            spec=StatefulSetSpec(
                selector=LabelSelector(),
                serviceName="whatever",
                template=PodTemplateSpec(
                    spec=PodSpec(
                        containers=[
                            Container(
                                name=TEST_CONTAINER_NAME,
                                resources=ResourceRequirements(
                                    limits={},
                                    requests=TEST_RESOURCE_REQUESTS,
                                ),
                                securityContext=SecurityContext(privileged=True),
                            )
                        ]
                    )
                ),
            )
        )
        self.mock_k8sclient_get.return_value = test_statefulset

        assert self.dpdk_statefulset_updater.is_configured(TEST_CONTAINER_NAME) is False

    def test_given_resource_limits_applied_but_requests_not_applied_to_the_container_when_container_configured_for_dpdk_called_then_false_is_returned(  # noqa: E501
        self,
    ):
        self.dpdk_statefulset_updater.dpdk_resource_requirements = TEST_RESOURCE_REQUIREMENTS
        test_statefulset = StatefulSet(
            spec=StatefulSetSpec(
                selector=LabelSelector(),
                serviceName="whatever",
                template=PodTemplateSpec(
                    spec=PodSpec(
                        containers=[
                            Container(
                                name=TEST_CONTAINER_NAME,
                                resources=ResourceRequirements(
                                    limits=TEST_RESOURCE_LIMITS,
                                    requests={},
                                ),
                                securityContext=SecurityContext(privileged=True),
                            )
                        ]
                    )
                ),
            )
        )
        self.mock_k8sclient_get.return_value = test_statefulset

        assert self.dpdk_statefulset_updater.is_configured(TEST_CONTAINER_NAME) is False

    def test_given_container_is_privileged_and_has_resource_requirements_applied_when_container_configured_for_dpdk_called_then_true_is_returned(  # noqa: E501
        self,
    ):
        self.dpdk_statefulset_updater.dpdk_resource_requirements = TEST_RESOURCE_REQUIREMENTS
        test_statefulset = StatefulSet(
            spec=StatefulSetSpec(
                selector=LabelSelector(),
                serviceName="whatever",
                template=PodTemplateSpec(
                    spec=PodSpec(
                        containers=[
                            Container(
                                name=TEST_CONTAINER_NAME,
                                resources=ResourceRequirements(
                                    limits=TEST_RESOURCE_LIMITS,
                                    requests=TEST_RESOURCE_REQUESTS,
                                ),
                                securityContext=SecurityContext(privileged=True),
                            )
                        ]
                    )
                ),
            )
        )
        self.mock_k8sclient_get.return_value = test_statefulset

        assert self.dpdk_statefulset_updater.is_configured(TEST_CONTAINER_NAME) is True

    def test_given_container_exists_and_requires_configuration_when_configure_container_for_dpdk_then_container_is_configured(  # noqa: E501
        self,
    ):
        self.dpdk_statefulset_updater.dpdk_resource_requirements = TEST_RESOURCE_REQUIREMENTS
        test_statefulset = StatefulSet(
            metadata=ObjectMeta(name="whatever"),
            spec=StatefulSetSpec(
                selector=LabelSelector(),
                serviceName="whatever",
                template=PodTemplateSpec(
                    spec=PodSpec(
                        containers=[
                            Container(
                                name=TEST_CONTAINER_NAME,
                                resources=ResourceRequirements(limits={}, requests={}),
                                securityContext=SecurityContext(privileged=False),
                            )
                        ]
                    )
                ),
            ),
        )
        self.mock_k8sclient_get.return_value = test_statefulset
        expected_updated_container_spec = Container(
            name=TEST_CONTAINER_NAME,
            resources=ResourceRequirements(
                limits=TEST_RESOURCE_LIMITS,
                requests=TEST_RESOURCE_REQUESTS,
            ),
            securityContext=SecurityContext(privileged=True),
        )

        self.dpdk_statefulset_updater.configure(TEST_CONTAINER_NAME)

        assert test_statefulset.spec
        assert test_statefulset.spec.template.spec
        assert test_statefulset.spec.template.spec.containers[0] == expected_updated_container_spec

    def test_given_client_when_configure_container_for_dpdk_then_statefulset_is_replaced(  # noqa: E501
        self,
    ):
        self.dpdk_statefulset_updater.dpdk_resource_requirements = TEST_RESOURCE_REQUIREMENTS
        test_statefulset = StatefulSet(
            metadata=ObjectMeta(name="whatever"),
            spec=StatefulSetSpec(
                selector=LabelSelector(),
                serviceName="whatever",
                template=PodTemplateSpec(
                    spec=PodSpec(
                        containers=[
                            Container(
                                name=TEST_CONTAINER_NAME,
                                resources=ResourceRequirements(
                                    limits=TEST_RESOURCE_LIMITS,
                                    requests=TEST_RESOURCE_REQUESTS,
                                ),
                                securityContext=SecurityContext(privileged=True),
                            )
                        ]
                    )
                ),
            ),
        )
        self.mock_k8sclient_get.return_value = test_statefulset

        self.dpdk_statefulset_updater.configure(TEST_CONTAINER_NAME)

        self.mock_k8sclient_replace.assert_called_once_with(obj=test_statefulset)

    def test_given_lightkube_client_returns_api_error_on_replace_when_configure_container_for_dpdk_then_dpdk_statefulset_updater_error_is_raised(  # noqa: E501
        self,
    ):
        self.dpdk_statefulset_updater.dpdk_resource_requirements = TEST_RESOURCE_REQUIREMENTS
        test_statefulset = StatefulSet(
            metadata=ObjectMeta(name="whatever"),
            spec=StatefulSetSpec(
                selector=LabelSelector(),
                serviceName="whatever",
                template=PodTemplateSpec(
                    spec=PodSpec(
                        containers=[
                            Container(
                                name=TEST_CONTAINER_NAME,
                                resources=ResourceRequirements(
                                    limits=TEST_RESOURCE_LIMITS,
                                    requests=TEST_RESOURCE_REQUESTS,
                                ),
                                securityContext=SecurityContext(privileged=True),
                            )
                        ]
                    )
                ),
            ),
        )
        self.mock_lightkube_client_get.return_value = test_statefulset
        self.mock_k8sclient_replace.side_effect = ApiError(response=MagicMock())

        with pytest.raises(DPDKError):
            self.dpdk_statefulset_updater.configure(TEST_CONTAINER_NAME)

    def test_given_lightkube_client_returns_no_stateful_set_on_get_when_configure_container_for_dpdk_then_runtime_error_is_raised(  # noqa: E501
        self,
    ):
        self.mock_k8sclient_get.return_value = None

        with pytest.raises(RuntimeError):
            self.dpdk_statefulset_updater.configure(TEST_CONTAINER_NAME)

    def test_given_lightkube_client_returns_no_stateful_set_when_configured_container_for_dpdk_then_runtime_error_is_raised(  # noqa: E501
        self,
    ):
        self.dpdk_statefulset_updater.dpdk_resource_requirements = TEST_RESOURCE_REQUIREMENTS
        self.mock_k8sclient_get.return_value = None

        with pytest.raises(RuntimeError):
            self.dpdk_statefulset_updater.is_configured(TEST_CONTAINER_NAME)
