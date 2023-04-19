# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.
import copy
import json
import unittest
from unittest.mock import call, patch

import httpx
import pytest
from lightkube.core.exceptions import ApiError
from lightkube.generic_resource import create_namespaced_resource
from lightkube.models.apps_v1 import StatefulSet, StatefulSetSpec
from lightkube.models.core_v1 import (
    Capabilities,
    Container,
    PodSpec,
    PodTemplateSpec,
    SecurityContext,
)
from lightkube.models.meta_v1 import ObjectMeta
from lightkube.resources.apps_v1 import StatefulSet as StatefulSetResource
from lightkube.types import PatchType

from kubernetes_utils import Kubernetes


class TestKubernetes(unittest.TestCase):
    @patch("lightkube.core.client.Client.get")
    def test_given_get_returns_something_when_network_attachment_definition_created_then_return_true(  # noqa: E501
        self, patch_get
    ):
        kubernetes = Kubernetes(namespace="whatever namespace")
        patch_get.return_value = "anything"

        created = kubernetes.network_attachment_definition_created(name="whatever nad")

        assert created

    @patch("lightkube.core.client.Client.get")
    def test_given_not_found_api_error_when_network_attachment_definition_created_then_return_false(  # noqa: E501
        self, patch_get
    ):
        kubernetes = Kubernetes(namespace="whatever namespace")
        patch_get.side_effect = ApiError(
            request=httpx.Request(method="", url=""),
            response=httpx.Response(status_code=400, json={"reason": "NotFound"}),
        )

        created = kubernetes.network_attachment_definition_created(name="whatever nad")

        assert not created

    @patch("lightkube.core.client.Client.get")
    def test_given_404_httpstatuserror_when_network_attachment_definition_created_then_same_error_is_raised(  # noqa: E501
        self, patch_get
    ):
        patch_get.side_effect = httpx.HTTPStatusError(
            request=httpx.Request(method="whatever method", url="http://whatever"),
            response=httpx.Response(status_code=404),
            message="whatever",
        )
        kubernetes = Kubernetes(namespace="whatever namespace")

        with pytest.raises(httpx.HTTPStatusError):
            kubernetes.network_attachment_definition_created("whatever nad")

    @patch("lightkube.core.client.Client.get")
    def test_given_unexpected_error_when_network_attachment_definition_created_then_same_error_is_raised(  # noqa: E501
        self, patch_get
    ):
        patch_get.side_effect = TimeoutError
        kubernetes = Kubernetes(namespace="whatever namespace")

        with pytest.raises(TimeoutError):
            kubernetes.network_attachment_definition_created("whatever nad")

    @patch("lightkube.core.client.Client.get")
    def test_given_bad_reason_in_api_error_when_network_attachment_definition_created_then_same_error_is_raised(  # noqa: E501
        self, patch_get
    ):
        patch_get.side_effect = ApiError(
            request=httpx.Request(method="", url=""),
            response=httpx.Response(status_code=400, json={"reason": "Bad reason"}),
        )
        kubernetes = Kubernetes(namespace="whatever namespace")

        with pytest.raises(ApiError):
            kubernetes.network_attachment_definition_created("whatever nad")

    @patch("lightkube.core.client.Client.create")
    @patch("kubernetes_utils.Kubernetes.network_attachment_definition_created")
    def test_given_network_attachment_definitions_not_created_when_create_network_attachement_definition_then_created(  # noqa: E501
        self, patch_created, patch_create
    ):
        patch_created.return_value = False

        namespace = "whatever namespace"
        kubernetes = Kubernetes(namespace=namespace)

        kubernetes.create_network_attachment_definitions()

        patch_create.assert_has_calls(
            calls=[
                call(
                    obj={
                        "metadata": ObjectMeta(name="access-net"),
                        "spec": {
                            "config": json.dumps(
                                {
                                    "cniVersion": "0.3.1",
                                    "type": "macvlan",
                                    "ipam": {"type": "static"},
                                    "capabilities": {"mac": True},
                                }
                            )
                        },
                    },
                    namespace=namespace,
                ),
                call(
                    obj={
                        "metadata": ObjectMeta(name="core-net"),
                        "spec": {
                            "config": json.dumps(
                                {
                                    "cniVersion": "0.3.1",
                                    "type": "macvlan",
                                    "ipam": {"type": "static"},
                                    "capabilities": {"mac": True},
                                }
                            )
                        },
                    },
                    namespace=namespace,
                ),
            ]
        )

    @patch("lightkube.core.client.Client.create")
    @patch("kubernetes_utils.Kubernetes.network_attachment_definition_created")
    def test_given_network_attachment_definitions_created_when_create_network_attachement_definition_then_created(  # noqa: E501
        self, patch_created, patch_create
    ):
        patch_created.return_value = True
        namespace = "whatever namespace"
        kubernetes = Kubernetes(namespace=namespace)

        kubernetes.create_network_attachment_definitions()

        patch_create.assert_not_called()

    @patch("lightkube.core.client.Client.delete")
    @patch("kubernetes_utils.Kubernetes.network_attachment_definition_created")
    def test_given_network_attachment_definitions_created_when_delete_network_attachment_definitions_then_network_attachment_definitions_are_deleted(  # noqa: E501
        self, patch_created, patch_delete
    ):
        patch_created.return_value = True
        namespace = "whatever namespace"
        kubernetes = Kubernetes(namespace=namespace)
        network_attachment_definition = create_namespaced_resource(
            group="k8s.cni.cncf.io",
            version="v1",
            kind="NetworkAttachmentDefinition",
            plural="network-attachment-definitions",
        )

        kubernetes.delete_network_attachment_definitions()

        patch_delete.assert_has_calls(
            calls=[
                call(res=network_attachment_definition, name="access-net", namespace=namespace),
                call(res=network_attachment_definition, name="core-net", namespace=namespace),
            ]
        )

    @patch("lightkube.core.client.Client.delete")
    @patch("kubernetes_utils.Kubernetes.network_attachment_definition_created")
    def test_given_network_attachment_definitions_not_created_when_delete_network_attachment_definitions_then_network_attachment_definitions_are_not_deleted(  # noqa: E501
        self, patch_created, patch_delete
    ):
        patch_created.return_value = False
        kubernetes = Kubernetes(namespace="whatever namespace")

        kubernetes.delete_network_attachment_definitions()

        patch_delete.assert_not_called()

    @patch("lightkube.core.client.Client.patch")
    @patch("lightkube.core.client.Client.get")
    @patch("kubernetes_utils.Kubernetes.statefulset_is_patched")
    def test_given_statefulset_not_patched_when_patch_statefulset_then_statefulset_is_patched(
        self, patch_is_patched, patch_get, patch_patch
    ):
        initial_statefulset = StatefulSet(
            spec=StatefulSetSpec(
                selector="",
                serviceName="",
                template=PodTemplateSpec(
                    metadata=ObjectMeta(annotations={}),
                    spec=PodSpec(
                        containers=[
                            Container(name="0"),
                            Container(name="1"),
                            Container(name="2", securityContext=SecurityContext()),
                        ]
                    ),
                ),
            )
        )
        patch_is_patched.return_value = False
        patch_get.return_value = initial_statefulset
        statefulset_name = "my statefulset"
        namespace = "my namespace"
        kubernetes = Kubernetes(namespace=namespace)

        kubernetes.patch_statefulset(statefulset_name=statefulset_name)

        final_statefulset = copy.deepcopy(initial_statefulset)
        final_statefulset.spec.template.metadata.annotations[
            "k8s.v1.cni.cncf.io/networks"
        ] = json.dumps(
            [
                {
                    "name": "access-net",
                    "interface": "access",
                    "ips": ["192.168.252.3/24"],
                },
                {
                    "name": "core-net",
                    "interface": "core",
                    "ips": ["192.168.250.3/24"],
                },
            ]
        )
        final_statefulset.spec.template.spec.containers[2].securityContext.privileged = True
        final_statefulset.spec.template.spec.containers[
            2
        ].securityContext.capabilities = Capabilities(
            add=[
                "NET_ADMIN",
            ]
        )

        patch_patch.assert_called_with(
            res=StatefulSetResource,
            name=statefulset_name,
            obj=final_statefulset,
            patch_type=PatchType.MERGE,
            namespace=namespace,
        )

    @patch("lightkube.core.client.Client.patch")
    @patch("kubernetes_utils.Kubernetes.statefulset_is_patched")
    def test_given_statefulset_is_patched_when_patch_statefulset_then_statefulset_is_not_patched(
        self, patch_is_patched, patch_patch
    ):
        patch_is_patched.return_value = True
        kubernetes = Kubernetes(namespace="my namespace")

        kubernetes.patch_statefulset(statefulset_name="my statefulset")

        patch_patch.assert_not_called()

    @patch("lightkube.core.client.Client.get")
    def test_given_annotations_and_security_context_when_statefulset_is_patched_then_return_true(
        self, patch_get
    ):
        kubernetes = Kubernetes(namespace="my namespace")
        patch_get.return_value = StatefulSet(
            spec=StatefulSetSpec(
                selector="",
                serviceName="",
                template=PodTemplateSpec(
                    metadata=ObjectMeta(
                        annotations={
                            "k8s.v1.cni.cncf.io/networks": json.dumps(
                                [
                                    {
                                        "name": "access-net",
                                        "interface": "access",
                                        "ips": ["192.168.252.3/24"],
                                    },
                                    {
                                        "name": "core-net",
                                        "interface": "core",
                                        "ips": ["192.168.250.3/24"],
                                    },
                                ]
                            )
                        }
                    ),
                    spec=PodSpec(
                        containers=[
                            Container(name="0"),
                            Container(name="1"),
                            Container(name="2", securityContext=SecurityContext(privileged=True)),
                        ]
                    ),
                ),
            )
        )

        is_patched = kubernetes.statefulset_is_patched(statefulset_name="my-statefulset")

        assert is_patched

    @patch("lightkube.core.client.Client.get")
    def test_given_no_annotations_when_statefulset_is_patched_then_return_false(self, patch_get):
        kubernetes = Kubernetes(namespace="my namespace")
        patch_get.return_value = StatefulSet(
            spec=StatefulSetSpec(
                selector="",
                serviceName="",
                template=PodTemplateSpec(
                    metadata=ObjectMeta(annotations={}),
                    spec=PodSpec(
                        containers=[
                            Container(name="0"),
                            Container(name="1"),
                            Container(name="2", securityContext=SecurityContext(privileged=True)),
                        ]
                    ),
                ),
            )
        )

        is_patched = kubernetes.statefulset_is_patched(statefulset_name="my-statefulset")

        assert not is_patched

    @patch("lightkube.core.client.Client.get")
    def test_given_no_security_context_when_statefulset_is_patched_then_return_false(
        self, patch_get
    ):
        kubernetes = Kubernetes(namespace="my namespace")
        patch_get.return_value = StatefulSet(
            spec=StatefulSetSpec(
                selector="",
                serviceName="",
                template=PodTemplateSpec(
                    metadata=ObjectMeta(
                        annotations={
                            "k8s.v1.cni.cncf.io/networks": json.dumps(
                                [
                                    {
                                        "name": "access-net",
                                        "interface": "access",
                                        "ips": ["192.168.252.3/24"],
                                    },
                                    {
                                        "name": "core-net",
                                        "interface": "core",
                                        "ips": ["192.168.250.3/24"],
                                    },
                                ]
                            )
                        }
                    ),
                    spec=PodSpec(
                        containers=[
                            Container(name="0"),
                            Container(name="1"),
                            Container(name="2", securityContext=SecurityContext()),
                        ]
                    ),
                ),
            )
        )

        is_patched = kubernetes.statefulset_is_patched(statefulset_name="my-statefulset")

        assert not is_patched
