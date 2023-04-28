# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charm Library used to leverage the Multus Kubernetes CNI in charms.

- On charm installation, it will:
  - Create the requested network attachment definitions
  - Patch the statefultset with the necessary annotations for the container to have interfaces
    that use those new network attachments.
- On charm removal, it will:
  - Delete the created network attachment definitions

## Usage

```python

from kubernetes_multus import (
    KubernetesMultusCharmLib,
    NetworkAttachmentDefinition,
    NetworkAnnotation
)

class YourCharm(CharmBase):

    def __init__(self, *args):
        super().__init__(*args)
        self._kubernetes_multus = KubernetesMultusCharmLib(
            charm=self,
            network_attachment_definitions=[
                NetworkAttachmentDefinition(name="access-net"),
                NetworkAttachmentDefinition(name="core-net"),
            ],
            network_annotations=[
                NetworkAnnotation(name="access-net", interface="eth0"),
                NetworkAnnotation(name="core-net", interface="eth1"),
            ]
        )
```
"""

import json
import logging
from dataclasses import asdict, dataclass, field
from typing import List, Optional, Union

import httpx
from lightkube import Client
from lightkube.core.exceptions import ApiError
from lightkube.generic_resource import create_namespaced_resource
from lightkube.models.meta_v1 import ObjectMeta
from lightkube.resources.apps_v1 import StatefulSet
from lightkube.types import PatchType
from ops.charm import CharmBase, InstallEvent, RemoveEvent, UpgradeCharmEvent
from ops.framework import Object

logger = logging.getLogger(__name__)

NetworkAttachmentDefinitionResource = create_namespaced_resource(
    group="k8s.cni.cncf.io",
    version="v1",
    kind="NetworkAttachmentDefinitionResource",
    plural="network-attachment-definitions",
)


@dataclass
class NetworkAttachmentDefinition:
    """NetworkAttachmentDefinition."""

    name: str
    spec: dict = field(
        default_factory=lambda: {
            "config": {
                "cniVersion": "0.3.1",
                "type": "macvlan",
                "ipam": {"type": "static"},
                "capabilities": {"mac": True},
            }
        }
    )

    dict = asdict


@dataclass
class NetworkAnnotation:
    """NetworkAnnotation."""

    name: str
    interface: str
    ips: Optional[List] = None

    dict = asdict


class KubernetesMultusError(Exception):
    """KubernetesMultusError."""

    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)


class KubernetesMultus:
    """Class containing all the Kubernetes Multus specific calls."""

    def __init__(self, namespace: str):
        self.client = Client()
        self.namespace = namespace

    def network_attachment_definition_is_created(self, name: str) -> bool:
        """Returns whether a NetworkAttachmentDefinitionResource is created.

        Args:
            name: NetworkAttachmentDefinition name

        Returns:
            bool: Whether the NetworkAttachmentDefinitionResource is created
        """
        try:
            self.client.get(
                res=NetworkAttachmentDefinitionResource,
                name=name,
                namespace=self.namespace,
            )
            logger.info(f"NetworkAttachmentDefinitionResource {name} already created")
            return True
        except ApiError as e:
            if e.status.reason == "NotFound":
                logger.info(f"NetworkAttachmentDefinitionResource {name} not yet created")
                return False
            else:
                raise KubernetesMultusError(
                    f"Unexpected outcome when retrieving network attachment definition {name}"
                )
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                raise KubernetesMultusError(
                    "NetworkAttachmentDefinitionResource resource not found. "
                    "You may need to install Multus CNI."
                )
            else:
                raise KubernetesMultusError(
                    f"Unexpected outcome when retrieving network attachment definition {name}"
                )

    def create_network_attachment_definition(
        self, network_attachment_definition: NetworkAttachmentDefinition
    ) -> None:
        """Creates a NetworkAttachmentDefinitionResource.

        Args:
            network_attachment_definition: NetworkAttachmentDefinition object
        """
        network_attachment_definition_obj = NetworkAttachmentDefinitionResource(
            metadata=ObjectMeta(name=network_attachment_definition.name),
            spec=network_attachment_definition.spec,
        )
        self.client.create(obj=network_attachment_definition_obj, namespace=self.namespace)  # type: ignore[call-overload]  # noqa: E501
        logger.info(
            f"NetworkAttachmentDefinitionResource {network_attachment_definition.name} created"
        )

    def delete_network_attachment_definition(self, name: str) -> None:
        """Deletes network attachment definition based on name.

        Args:
            name: NetworkAttachmentDefinition name
        """
        self.client.delete(
            res=NetworkAttachmentDefinitionResource, name=name, namespace=self.namespace
        )
        logger.info(f"NetworkAttachmentDefinition {name} deleted")

    def patch_statefulset(self, name: str, network_annotations: List[NetworkAnnotation]) -> None:
        """Patches a statefulset with multus annotation.

        Args:
            name: Statefulset name
            network_annotations: List of network annotations
        """
        if not network_annotations:
            logger.info("No network annotations were provided")
            return
        statefulset = self.client.get(res=StatefulSet, name=name, namespace=self.namespace)
        statefulset.spec.template.metadata.annotations["k8s.v1.cni.cncf.io/networks"] = json.dumps(  # type: ignore[attr-defined]  # noqa: E501
            [network_annotation.dict() for network_annotation in network_annotations]
        )

        # statefulset.spec.template.spec.containers[2].securityContext.privileged = True
        # statefulset.spec.template.spec.containers[2].securityContext.capabilities = Capabilities(
        #     add=[
        #         "NET_ADMIN",
        #     ]
        # )

        self.client.patch(
            res=StatefulSet,
            name=name,
            obj=statefulset,
            patch_type=PatchType.MERGE,
            namespace=self.namespace,
        )
        logger.info(f"Multus annotation added to {name} Statefulset")

    def statefulset_is_patched(
        self, name: str, network_annotations: List[NetworkAnnotation]
    ) -> bool:
        """Returns whether the statefulset has the expected multus annotation.

        Args:
            name: Statefulset name.
            network_annotations: List of network annotations

        Returns:
            bool: Whether the statefulset has the expected multus annotation.
        """
        statefulset = self.client.get(res=StatefulSet, name=name, namespace=self.namespace)
        if "k8s.v1.cni.cncf.io/networks" not in statefulset.spec.template.metadata.annotations:  # type: ignore[attr-defined]  # noqa: E501
            logger.info("Multus annotation not yet added to statefulset")
            return False
        if json.loads(
            statefulset.spec.template.metadata.annotations["k8s.v1.cni.cncf.io/networks"]  # type: ignore[attr-defined]  # noqa: E501
        ) != [network_annotation.dict() for network_annotation in network_annotations]:
            logger.info("Existing annotation are not identical to the expected ones")
            return False
        logger.info("Multus annotation already added to statefulset")
        return True


class KubernetesMultusCharmLib(Object):
    """Class to be instantiated by charms requiring Multus networking."""

    def __init__(
        self,
        charm: CharmBase,
        network_attachment_definitions: List[NetworkAttachmentDefinition],
        network_annotations: List[NetworkAnnotation],
    ):
        super().__init__(charm, "kubernetes-multus")
        self.network_attachment_definitions = network_attachment_definitions
        self.network_annotations = network_annotations
        self.framework.observe(charm.on.install, self._patch)
        self.framework.observe(charm.on.upgrade_charm, self._patch)
        self.framework.observe(charm.on.remove, self._on_remove)

    def _patch(self, event: Union[InstallEvent, UpgradeCharmEvent]) -> None:
        kubernetes_multus = KubernetesMultus(namespace=self.model.name)
        for network_attachment_definition in self.network_attachment_definitions:
            if not kubernetes_multus.network_attachment_definition_is_created(
                name=network_attachment_definition.name
            ):
                kubernetes_multus.create_network_attachment_definition(
                    network_attachment_definition=network_attachment_definition
                )
        if not kubernetes_multus.statefulset_is_patched(
            name=self.model.app.name, network_annotations=self.network_annotations
        ):
            kubernetes_multus.patch_statefulset(
                name=self.model.app.name, network_annotations=self.network_annotations
            )

    def _on_remove(self, event: RemoveEvent) -> None:
        """Deletes network attachment definitions.

        Args:
            event: RemoveEvent
        """
        kubernetes_multus = KubernetesMultus(namespace=self.model.name)
        for network_attachment_definition in self.network_attachment_definitions:
            if kubernetes_multus.network_attachment_definition_is_created(
                name=network_attachment_definition.name
            ):
                kubernetes_multus.delete_network_attachment_definition(
                    name=network_attachment_definition.name
                )
