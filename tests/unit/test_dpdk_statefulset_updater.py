# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest
from unittest.mock import MagicMock, Mock, patch

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

from dpdk_statefulset_updater import DPDKStatefulSetUpdater, DPDKStatefulSetUpdaterError

TEST_CONTAINER_NAME = "bullseye"
TEST_RESOURCE_REQUESTS = {"test_request": 1234}
TEST_RESOURCE_LIMITS = {"test_limit": 4321}
TEST_RESOURCE_REQUIREMENTS = {
    "requests": TEST_RESOURCE_REQUESTS,
    "limits": TEST_RESOURCE_LIMITS,
}


class TestDPDKStatefulSetUpdater(unittest.TestCase):
    @patch("lightkube.core.client.GenericSyncClient", new=Mock)
    def setUp(self) -> None:
        self.dpdk_statefulset_updater = DPDKStatefulSetUpdater(
            statefulset_name="doesntmatter",
            namespace="whatever",
            dpdk_access_interface_resource_name="who",
            dpdk_core_interface_resource_name="cares",
        )

    @patch("lightkube.core.client.Client.get")
    def test_given_lightkube_client_returns_api_error_on_get_when_container_configured_for_dpdk_called_then_dpdk_statefulset_updater_error_is_raised(  # noqa: E501
        self, patched_lightkube_client_get
    ):
        patched_lightkube_client_get.side_effect = ApiError(response=MagicMock())

        with self.assertRaises(DPDKStatefulSetUpdaterError):
            self.dpdk_statefulset_updater.container_configured_for_dpdk("justatest")

    @patch("lightkube.core.client.Client.get")
    def test_given_container_not_is_statefulset_when_container_configured_for_dpdk_called_then_dpdk_statefulset_updater_error_is_raised(  # noqa: E501
        self, patched_lightkube_client_get
    ):
        test_statefulset = StatefulSet(
            spec=StatefulSetSpec(
                selector=LabelSelector(),
                serviceName="whatever",
                template=PodTemplateSpec(spec=PodSpec(containers=[])),
            )
        )
        patched_lightkube_client_get.return_value = test_statefulset

        with self.assertRaises(DPDKStatefulSetUpdaterError):
            self.dpdk_statefulset_updater.container_configured_for_dpdk("justatest")

    @patch("lightkube.core.client.Client.get")
    def test_given_container_is_not_privileged_when_container_configured_for_dpdk_called_then_false_is_returned(  # noqa: E501
        self, patched_lightkube_client_get
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
        patched_lightkube_client_get.return_value = test_statefulset

        self.assertFalse(
            self.dpdk_statefulset_updater.container_configured_for_dpdk(TEST_CONTAINER_NAME)
        )

    @patch("lightkube.core.client.Client.get")
    def test_given_resource_requirements_not_applied_to_the_container_when_container_configured_for_dpdk_called_then_false_is_returned(  # noqa: E501
        self, patched_lightkube_client_get
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
        patched_lightkube_client_get.return_value = test_statefulset

        self.assertFalse(
            self.dpdk_statefulset_updater.container_configured_for_dpdk(TEST_CONTAINER_NAME)
        )

    @patch("lightkube.core.client.Client.get")
    def test_given_resource_requests_applied_but_limits_not_applied_to_the_container_when_container_configured_for_dpdk_called_then_false_is_returned(  # noqa: E501
        self, patched_lightkube_client_get
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
        patched_lightkube_client_get.return_value = test_statefulset

        self.assertFalse(
            self.dpdk_statefulset_updater.container_configured_for_dpdk(TEST_CONTAINER_NAME)
        )

    @patch("lightkube.core.client.Client.get")
    def test_given_resource_limits_applied_but_requests_not_applied_to_the_container_when_container_configured_for_dpdk_called_then_false_is_returned(  # noqa: E501
        self, patched_lightkube_client_get
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
        patched_lightkube_client_get.return_value = test_statefulset

        self.assertFalse(
            self.dpdk_statefulset_updater.container_configured_for_dpdk(TEST_CONTAINER_NAME)
        )

    @patch("lightkube.core.client.Client.get")
    def test_given_container_is_privileged_and_has_resource_requirements_applied_when_container_configured_for_dpdk_called_then_true_is_returned(  # noqa: E501
        self, patched_lightkube_client_get
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
        patched_lightkube_client_get.return_value = test_statefulset

        self.assertTrue(
            self.dpdk_statefulset_updater.container_configured_for_dpdk(TEST_CONTAINER_NAME)
        )

    @patch("lightkube.core.client.Client.get")
    def test_given_container_exists_and_requires_configuration_when_configure_container_for_dpdk_then_container_is_configured(  # noqa: E501
        self, patched_lightkube_client_get
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
            )
        )
        patched_lightkube_client_get.return_value = test_statefulset
        expected_updated_container_spec = Container(
            name=TEST_CONTAINER_NAME,
            resources=ResourceRequirements(
                limits=TEST_RESOURCE_LIMITS,
                requests=TEST_RESOURCE_REQUESTS,
            ),
            securityContext=SecurityContext(privileged=True),
        )

        self.dpdk_statefulset_updater.configure_container_for_dpdk(TEST_CONTAINER_NAME)

        self.assertEqual(
            test_statefulset.spec.template.spec.containers[0],
            expected_updated_container_spec,
        )

    @patch("lightkube.core.client.Client.get")
    @patch("lightkube.core.client.Client.replace")
    def test_given_client_when_configure_container_for_dpdk_then_statefulset_is_replaced(  # noqa: E501
        self, patched_lightkube_client_replace, patched_lightkube_client_get
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
            )
        )
        patched_lightkube_client_get.return_value = test_statefulset

        self.dpdk_statefulset_updater.configure_container_for_dpdk(TEST_CONTAINER_NAME)

        patched_lightkube_client_replace.assert_called_once_with(obj=test_statefulset)

    @patch("lightkube.core.client.Client.get")
    @patch("lightkube.core.client.Client.replace")
    def test_given_lightkube_client_returns_api_error_on_replace_when_configure_container_for_dpdk_then_dpdk_statefulset_updater_error_is_raised(  # noqa: E501
        self, patched_lightkube_client_replace, patched_lightkube_client_get
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
        patched_lightkube_client_get.return_value = test_statefulset
        patched_lightkube_client_replace.side_effect = ApiError(response=MagicMock())

        with self.assertRaises(DPDKStatefulSetUpdaterError):
            self.dpdk_statefulset_updater.configure_container_for_dpdk(TEST_CONTAINER_NAME)
