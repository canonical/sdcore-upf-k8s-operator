# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.


import json
import unittest
from unittest.mock import call, patch

import httpx
import pytest
from lightkube.core.exceptions import ApiError
from lightkube.models.meta_v1 import ObjectMeta

from kubernetes_utils import Kubernetes


class TestKubernetes(unittest.TestCase):
    @patch("lightkube.core.client.Client.create")
    @patch("lightkube.core.client.Client.get")
    def test_given_network_attachment_definitions_not_found_when_create_network_attachement_definition_then_created(  # noqa: E501
        self, patch_get, patch_create
    ):
        patch_get.side_effect = ApiError(
            request=httpx.Request(method="", url=""),
            response=httpx.Response(status_code=400, json={"reason": "NotFound"}),
        )
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

    @patch("lightkube.core.client.Client.get")
    def test_given_httpstatuserror_when_create_network_attachement_definition_then_same_error_is_raised(  # noqa: E501
        self, patch_get
    ):
        patch_get.side_effect = httpx.HTTPStatusError(
            request=httpx.Request(method="whatever method", url="http://whatever"),
            response=httpx.Response(status_code=404),
            message="whatever",
        )
        namespace = "whatever namespace"
        kubernetes = Kubernetes(namespace=namespace)

        with pytest.raises(httpx.HTTPStatusError):
            kubernetes.create_network_attachment_definitions()

    @patch("lightkube.core.client.Client.create")
    @patch("lightkube.core.client.Client.get")
    def test_given_network_attachment_definitions_found_when_create_network_attachement_definition_then_not_created(  # noqa: E501
        self, patch_get, patch_create
    ):
        patch_get.return_value = "whatever"
        namespace = "whatever namespace"
        kubernetes = Kubernetes(namespace=namespace)

        kubernetes.create_network_attachment_definitions()

        patch_create.assert_not_called()
