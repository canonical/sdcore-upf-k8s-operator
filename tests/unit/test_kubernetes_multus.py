# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import unittest
from unittest.mock import Mock, call, patch

import httpx
import pytest
from lightkube.core.exceptions import ApiError
from lightkube.models.apps_v1 import StatefulSet, StatefulSetSpec
from lightkube.models.core_v1 import PodTemplateSpec
from lightkube.models.meta_v1 import LabelSelector, ObjectMeta
from lightkube.resources.apps_v1 import StatefulSet as StatefulSetResource
from lightkube.types import PatchType
from ops.charm import CharmBase
from ops.testing import Harness

from kubernetes_multus import (
    KubernetesMultus,
    KubernetesMultusCharmLib,
    KubernetesMultusError,
    NetworkAnnotation,
    NetworkAttachmentDefinition,
    NetworkAttachmentDefinitionResource,
)


class TestKubernetesMultus(unittest.TestCase):
    @patch("lightkube.core.client.Client.get")
    def test_given_k8s_get_doesnt_throw_error_when_nad_is_created_then_return_true(
        self, patch_get
    ):
        namespace = "whatever ns"
        patch_get.return_value = Mock()
        kubernetes_multus = KubernetesMultus(namespace=namespace)

        is_created = kubernetes_multus.network_attachment_definition_is_created(
            name="whatever name"
        )

        assert is_created

    @patch("lightkube.core.client.Client.get")
    def test_given_k8s_get_throws_notfound_api_error_when_nad_is_created_then_return_false(
        self, patch_get
    ):
        patch_get.side_effect = ApiError(
            request=httpx.Request(method="GET", url="http://whatever.com"),
            response=httpx.Response(status_code=400, json={"reason": "NotFound"}),
        )
        kubernetes_multus = KubernetesMultus(namespace="whatever ns")

        is_created = kubernetes_multus.network_attachment_definition_is_created(
            name="whatever name"
        )

        assert not is_created

    @patch("lightkube.core.client.Client.get")
    def test_given_k8s_get_throws_other_api_error_when_nad_is_created_then_custom_exception_is_thrown(  # noqa: E501
        self, patch_get
    ):
        nad_name = "whatever name"
        patch_get.side_effect = ApiError(
            request=httpx.Request(method="GET", url="http://whatever.com"),
            response=httpx.Response(status_code=400, json={"reason": "whatever reason"}),
        )
        kubernetes_multus = KubernetesMultus(namespace="whatever ns")

        with pytest.raises(KubernetesMultusError) as e:
            kubernetes_multus.network_attachment_definition_is_created(name=nad_name)
        self.assertEqual(
            e.value.message,
            f"Unexpected outcome when retrieving network attachment definition {nad_name}",
        )

    @patch("lightkube.core.client.Client.get")
    def test_given_k8s_get_throws_404_httpx_error_when_nad_is_created_then_exception_is_thrown(
        self, patch_get
    ):
        patch_get.side_effect = httpx.HTTPStatusError(
            message="error message",
            request=httpx.Request(method="GET", url="http://whatever.com"),
            response=httpx.Response(
                status_code=404,
            ),
        )
        kubernetes_multus = KubernetesMultus(namespace="whatever ns")

        with pytest.raises(KubernetesMultusError) as e:
            kubernetes_multus.network_attachment_definition_is_created(name="whatever name")
        self.assertEqual(
            e.value.message,
            "NetworkAttachmentDefinitionResource resource not found. "
            "You may need to install Multus CNI.",
        )

    @patch("lightkube.core.client.Client.get")
    def test_given_k8s_get_throws_other_httpx_error_when_nad_is_created_then_exception_is_thrown(
        self, patch_get
    ):
        nad_name = "whatever name"
        patch_get.side_effect = httpx.HTTPStatusError(
            message="error message",
            request=httpx.Request(method="GET", url="http://whatever.com"),
            response=httpx.Response(
                status_code=405,
            ),
        )
        kubernetes_multus = KubernetesMultus(namespace="whatever ns")

        with pytest.raises(KubernetesMultusError) as e:
            kubernetes_multus.network_attachment_definition_is_created(name=nad_name)
        self.assertEqual(
            e.value.message,
            f"Unexpected outcome when retrieving network attachment definition {nad_name}",
        )

    @patch("lightkube.core.client.Client.create")
    def test_given_nad_when_create_nad_then_k8s_create_is_called(self, patch_create):
        nad_name = "whatever name"
        nad_spec = {"a": "b"}
        namespace = "whatever ns"
        kubernetes_multus = KubernetesMultus(namespace=namespace)
        network_attachment_definition = NetworkAttachmentDefinition(name=nad_name, spec=nad_spec)

        kubernetes_multus.create_network_attachment_definition(
            network_attachment_definition=network_attachment_definition
        )

        patch_create.assert_called_with(
            obj={"metadata": ObjectMeta(name=nad_name), "spec": nad_spec}, namespace=namespace
        )

    @patch("lightkube.core.client.Client.patch")
    def test_given_no_annotation_when_patch_statefulset_then_statefulset_is_not_patched(
        self, patch_patch
    ):
        kubernetes_multus = KubernetesMultus(namespace="whatever ns")

        kubernetes_multus.patch_statefulset(
            name="whatever statefulset name", network_annotations=[]
        )

        patch_patch.assert_not_called()

    @patch("lightkube.core.client.Client.patch")
    @patch("lightkube.core.client.Client.get")
    def test_given_statefulset_doesnt_have_network_annotations_when_patch_statefulset_then_statefulset_is_patched(  # noqa: E501
        self, patch_get, patch_patch
    ):
        namespace = "whatever ns"
        statefulset_name = "whatever statefulset name"
        network_annotations = [
            NetworkAnnotation(interface="whatever interface 1", name="whatever name 1"),
            NetworkAnnotation(interface="whatever interface 2", name="whatever name 2"),
        ]
        kubernetes_multus = KubernetesMultus(namespace=namespace)
        initial_statefulset = StatefulSet(
            spec=StatefulSetSpec(
                selector=LabelSelector(),
                serviceName="",
                template=PodTemplateSpec(
                    metadata=ObjectMeta(
                        annotations={},
                    ),
                ),
            )
        )
        patch_get.return_value = initial_statefulset

        kubernetes_multus.patch_statefulset(
            name=statefulset_name, network_annotations=network_annotations
        )

        args, kwargs = patch_patch.call_args
        self.assertEqual(kwargs["res"], StatefulSetResource)
        self.assertEqual(kwargs["name"], statefulset_name)
        self.assertEqual(
            kwargs["obj"].spec.template.metadata.annotations["k8s.v1.cni.cncf.io/networks"],
            json.dumps([network_annotation.dict() for network_annotation in network_annotations]),
        )
        self.assertEqual(kwargs["patch_type"], PatchType.MERGE)
        self.assertEqual(kwargs["namespace"], namespace)

    @patch("lightkube.core.client.Client.get")
    def test_given_no_annotations_when_statefulset_is_patched_then_returns_false(self, patch_get):
        namespace = "whatever ns"
        statefulset_name = "whatever name"
        kubernetes_multus = KubernetesMultus(namespace=namespace)
        network_annotations = [
            NetworkAnnotation(interface="whatever interface 1", name="whatever name 1"),
            NetworkAnnotation(interface="whatever interface 2", name="whatever name 2"),
        ]
        patch_get.return_value = StatefulSet(
            spec=StatefulSetSpec(
                selector=LabelSelector(),
                serviceName="",
                template=PodTemplateSpec(
                    metadata=ObjectMeta(
                        annotations={},
                    ),
                ),
            )
        )

        is_patched = kubernetes_multus.statefulset_is_patched(
            name=statefulset_name, network_annotations=network_annotations
        )

        assert not is_patched

    @patch("lightkube.core.client.Client.get")
    def test_given_annotations_are_different_when_statefulset_is_patched_then_returns_false(
        self, patch_get
    ):
        namespace = "whatever ns"
        statefulset_name = "whatever name"
        kubernetes_multus = KubernetesMultus(namespace=namespace)
        network_annotations_in_statefulset = [
            NetworkAnnotation(interface="whatever interface 1", name="whatever name 1"),
            NetworkAnnotation(interface="whatever interface 2", name="whatever name 2"),
        ]
        network_annotations = [
            NetworkAnnotation(interface="whatever new interface 1", name="whatever new name 1"),
            NetworkAnnotation(interface="whatever new interface 2", name="whatever new name 2"),
        ]
        patch_get.return_value = StatefulSet(
            spec=StatefulSetSpec(
                selector=LabelSelector(),
                serviceName="",
                template=PodTemplateSpec(
                    metadata=ObjectMeta(
                        annotations={
                            "k8s.v1.cni.cncf.io/networks": json.dumps(
                                [
                                    network_annotation.dict()
                                    for network_annotation in network_annotations_in_statefulset
                                ]
                            )
                        },
                    ),
                ),
            )
        )

        is_patched = kubernetes_multus.statefulset_is_patched(
            name=statefulset_name, network_annotations=network_annotations
        )

        assert not is_patched

    @patch("lightkube.core.client.Client.get")
    def test_given_annotations_are_already_present_when_statefulset_is_patched_then_returns_true(
        self, patch_get
    ):
        namespace = "whatever ns"
        statefulset_name = "whatever name"
        kubernetes_multus = KubernetesMultus(namespace=namespace)
        network_annotations = [
            NetworkAnnotation(interface="whatever interface 1", name="whatever name 1"),
            NetworkAnnotation(interface="whatever interface 2", name="whatever name 2"),
        ]
        patch_get.return_value = StatefulSet(
            spec=StatefulSetSpec(
                selector=LabelSelector(),
                serviceName="",
                template=PodTemplateSpec(
                    metadata=ObjectMeta(
                        annotations={
                            "k8s.v1.cni.cncf.io/networks": json.dumps(
                                [
                                    network_annotation.dict()
                                    for network_annotation in network_annotations
                                ]
                            )
                        },
                    ),
                ),
            )
        )

        is_patched = kubernetes_multus.statefulset_is_patched(
            name=statefulset_name, network_annotations=network_annotations
        )

        assert is_patched

    @patch("lightkube.core.client.Client.delete")
    def test_given_when_delete_nad_then_k8s_delete_is_called(self, patch_delete):
        namespace = "whatever ns"
        nad_name = "whatever name"
        kubernetes_multus = KubernetesMultus(namespace=namespace)

        kubernetes_multus.delete_network_attachment_definition(name=nad_name)

        patch_delete.assert_called_with(
            res=NetworkAttachmentDefinitionResource, name=nad_name, namespace=namespace
        )


class _TestCharmNoNAD(CharmBase):
    def __init__(self, *args):
        super().__init__(*args)
        self.kubernetes_multus = KubernetesMultusCharmLib(
            charm=self,
            network_attachment_definitions=[],
            network_annotations=[],
        )


class _TestCharmMultipleNAD(CharmBase):
    def __init__(self, *args):
        super().__init__(*args)
        self.nad_1_name = "nad-1"
        self.nad_1_spec = {
            "config": {
                "cniVersion": "1.2.3",
                "type": "macvlan",
                "ipam": {"type": "static"},
                "capabilities": {"mac": True},
            }
        }
        self.nad_2_name = "nad-2"
        self.nad_2_spec = {
            "config": {
                "cniVersion": "4.5.6",
                "type": "pizza",
                "ipam": {"type": "whatever"},
                "capabilities": {"mac": True},
            }
        }
        self.annotation_1_name = "eth0"
        self.annotation_2_name = "eth1"
        nad_1 = NetworkAttachmentDefinition(name=self.nad_1_name, spec=self.nad_1_spec)
        nad_2 = NetworkAttachmentDefinition(name=self.nad_2_name, spec=self.nad_2_spec)
        self.network_attachment_definitions = [nad_1, nad_2]
        self.kubernetes_multus = KubernetesMultusCharmLib(
            charm=self,
            network_attachment_definitions=self.network_attachment_definitions,
            network_annotations=[
                NetworkAnnotation(interface=self.nad_1_name, name=self.annotation_1_name),
                NetworkAnnotation(interface=self.nad_2_name, name=self.annotation_2_name),
            ],
        )


class TestKubernetesMultusCharmLib(unittest.TestCase):
    @patch("kubernetes_multus.KubernetesMultus.patch_statefulset", new=Mock)
    @patch("kubernetes_multus.KubernetesMultus.statefulset_is_patched", new=Mock)
    @patch("kubernetes_multus.KubernetesMultus.create_network_attachment_definition")
    def test_given_no_nad_when_install_then_create_is_not_called(self, patch_create_nad):
        harness = Harness(_TestCharmNoNAD)
        self.addCleanup(harness.cleanup)
        harness.begin()

        harness.charm.on.install.emit()

        patch_create_nad.assert_not_called()

    @patch("kubernetes_multus.KubernetesMultus.patch_statefulset", new=Mock)
    @patch("kubernetes_multus.KubernetesMultus.statefulset_is_patched", new=Mock)
    @patch("kubernetes_multus.KubernetesMultus.create_network_attachment_definition")
    @patch("kubernetes_multus.KubernetesMultus.network_attachment_definition_is_created")
    def test_given_multiple_nads_already_exist_when_install_then_create_is_not_called(
        self, patch_is_nad_created, patch_create_nad
    ):
        harness = Harness(_TestCharmMultipleNAD)
        self.addCleanup(harness.cleanup)
        harness.begin()
        patch_is_nad_created.return_value = True

        harness.charm.on.install.emit()

        patch_create_nad.assert_not_called()

    @patch("kubernetes_multus.KubernetesMultus.patch_statefulset", new=Mock)
    @patch("kubernetes_multus.KubernetesMultus.statefulset_is_patched", new=Mock)
    @patch("kubernetes_multus.KubernetesMultus.create_network_attachment_definition")
    @patch("kubernetes_multus.KubernetesMultus.network_attachment_definition_is_created")
    def test_given_nads_not_created_when_install_then_create_is_called(
        self,
        patch_is_nad_created,
        patch_create_nad,
    ):
        harness = Harness(_TestCharmMultipleNAD)
        self.addCleanup(harness.cleanup)
        harness.begin()
        patch_is_nad_created.return_value = False

        harness.charm.on.install.emit()

        patch_create_nad.assert_has_calls(
            calls=[
                call(
                    network_attachment_definition=NetworkAttachmentDefinition(
                        name=harness.charm.nad_1_name, spec=harness.charm.nad_1_spec
                    )
                ),
                call(
                    network_attachment_definition=NetworkAttachmentDefinition(
                        name=harness.charm.nad_2_name, spec=harness.charm.nad_2_spec
                    )
                ),
            ]
        )

    @patch("kubernetes_multus.KubernetesMultus.patch_statefulset")
    @patch("kubernetes_multus.KubernetesMultus.statefulset_is_patched")
    @patch("kubernetes_multus.KubernetesMultus.create_network_attachment_definition", new=Mock)
    @patch("kubernetes_multus.KubernetesMultus.network_attachment_definition_is_created", new=Mock)
    def test_given_nads_not_created_when_install_then_patch_statefulset_create_is_called(
        self, patch_is_statefulset_patched, patch_patch_statefulset
    ):
        harness = Harness(_TestCharmMultipleNAD)
        self.addCleanup(harness.cleanup)
        harness.begin()
        patch_is_statefulset_patched.return_value = False

        harness.charm.on.install.emit()

        patch_patch_statefulset.assert_called_with(
            name=harness.charm.app.name,
            network_annotations=[
                NetworkAnnotation(
                    name=harness.charm.annotation_1_name, interface=harness.charm.nad_1_name
                ),
                NetworkAnnotation(
                    name=harness.charm.annotation_2_name, interface=harness.charm.nad_2_name
                ),
            ],
        )

    @patch("kubernetes_multus.KubernetesMultus.delete_network_attachment_definition")
    @patch("kubernetes_multus.KubernetesMultus.network_attachment_definition_is_created")
    def test_given_nad_is_created_when_remove_then_network_attachment_definitions_are_deleted(
        self, patch_is_nad_created, patch_delete_network_attachment_definition
    ):
        harness = Harness(_TestCharmMultipleNAD)
        self.addCleanup(harness.cleanup)
        harness.begin()
        patch_is_nad_created.return_value = True

        harness.charm.on.remove.emit()

        patch_delete_network_attachment_definition.assert_has_calls(
            calls=[
                call(name=harness.charm.nad_1_name),
                call(name=harness.charm.nad_2_name),
            ]
        )

    @patch("kubernetes_multus.KubernetesMultus.delete_network_attachment_definition")
    @patch("kubernetes_multus.KubernetesMultus.network_attachment_definition_is_created")
    def test_given_nad_is_not_created_when_remove_then_network_attachment_definitions_are_not_deleted(  # noqa: E501
        self, patch_is_nad_created, patch_delete_network_attachment_definition
    ):
        harness = Harness(_TestCharmMultipleNAD)
        self.addCleanup(harness.cleanup)
        harness.begin()
        patch_is_nad_created.return_value = False

        harness.charm.on.remove.emit()

        patch_delete_network_attachment_definition.assert_not_called()

    @patch("kubernetes_multus.KubernetesMultus.delete_network_attachment_definition")
    @patch("kubernetes_multus.KubernetesMultus.network_attachment_definition_is_created", new=Mock)
    def test_given_no_nad_when_remove_then_network_attachment_definitions_are_not_deleted(
        self, patch_delete_network_attachment_definition
    ):
        harness = Harness(_TestCharmNoNAD)
        self.addCleanup(harness.cleanup)
        harness.begin()

        harness.charm.on.remove.emit()

        patch_delete_network_attachment_definition.assert_not_called()
