#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Module used to update Kubernetes Statefulset to support DPDK."""

import logging
from typing import Iterable, Optional

from lightkube import Client
from lightkube.core.exceptions import ApiError
from lightkube.models.core_v1 import Container
from lightkube.resources.apps_v1 import StatefulSet

logger = logging.getLogger(__name__)


class DPDKError(Exception):
    """DPDKError."""

    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)


class DPDK:
    """Class used to update Kubernetes Statefulset to support DPDK."""

    def __init__(
        self,
        statefulset_name: str,
        namespace: str,
        dpdk_access_interface_resource_name: str,
        dpdk_core_interface_resource_name: str,
    ):
        self.k8s_client = Client()
        self.statefulset_name = statefulset_name
        self.namespace = namespace
        self.dpdk_resource_requirements = {
            "requests": {
                dpdk_access_interface_resource_name: "1",
                dpdk_core_interface_resource_name: "1",
            },
            "limits": {
                dpdk_access_interface_resource_name: "1",
                dpdk_core_interface_resource_name: "1",
            },
        }

    def is_configured(self, container_name: str) -> bool:
        """Check whether the container config required for DPDK has been applied or not.

        Args:
            container_name (str): Name of the container to update

        Returns:
            bool: True if container config required for DPDK is applied, otherwise False
        """
        statefulset = self._get_statefulset(self.statefulset_name, self.namespace)
        if not statefulset:
            raise RuntimeError("StatefulSet not found!")
        container = self._get_container(
            container_name=container_name,
            containers=statefulset.spec.template.spec.containers,  # type: ignore[union-attr]
        )
        if not container:
            raise RuntimeError("Container not found!")
        if not container.securityContext.privileged:  # type: ignore[union-attr]
            return False
        if not self._resource_requirements_applied(container, self.dpdk_resource_requirements):
            return False
        return True

    def configure(self, container_name: str) -> None:
        """Apply config required by DPDK to a given container.

        Args:
            container_name (str): Name of the container to update
        """
        statefulset = self._get_statefulset(self.statefulset_name, self.namespace)
        if not statefulset:
            raise RuntimeError("StatefulSet not found!")
        container = self._get_container(
            container_name=container_name,
            containers=statefulset.spec.template.spec.containers,  # type: ignore[union-attr]
        )
        if not container:
            raise RuntimeError("Container not found!")
        container.securityContext.privileged = True  # type: ignore[union-attr]
        self._apply_resource_requirements(
            container=container,
            resource_requirements=self.dpdk_resource_requirements,
        )

        self._replace_statefulset(statefulset=statefulset)
        logger.info("Container %s configured for DPDK", container_name)

    def _get_statefulset(self, statefulset_name: str, namespace: str) -> Optional[StatefulSet]:
        """Return StatefulSet object with given name from given namespace.

        Args:
            statefulset_name (str): Name of the StatefulSet to get
            namespace (str): Namespace to get StatefulSet from

        Returns:
            StatefulSet: StatefulSet object
        """
        try:
            return self.k8s_client.get(res=StatefulSet, name=statefulset_name, namespace=namespace)  # type: ignore[return-value]  # noqa: E501
        except ApiError as e:
            raise DPDKError(f"Could not get statefulset `{statefulset_name}`: {e.status.message}")

    @staticmethod
    def _get_container(
        containers: Iterable[Container], container_name: str
    ) -> Optional[Container]:
        """Return Container object with given name.

        Args:
            containers (Iterable[Container]): Containers to search among
            container_name (str): Name of the Container to get

        Returns:
            Container: Container object
        """
        try:
            return next(iter(filter(lambda ctr: ctr.name == container_name, containers)))
        except StopIteration:
            raise DPDKError(f"Container `{container_name}` not found")

    @staticmethod
    def _apply_resource_requirements(container: Container, resource_requirements: dict) -> None:
        """Apply given resource requests and limits to a given container.

        Args:
            container (Container): Container to update
            resource_requirements (dict): Dictionary of `requests` and `limits`
        """
        for request, value in resource_requirements["requests"].items():
            container.resources.requests.update({request: int(value)})  # type: ignore[union-attr]
        for limit, value in resource_requirements["limits"].items():
            container.resources.limits.update({limit: int(value)})  # type: ignore[union-attr]
        logger.info(
            "Applied ResourceRequirements to the %s container: %s",
            container,
            resource_requirements,
        )

    @staticmethod
    def _resource_requirements_applied(container: Container, resource_requirements: dict) -> bool:
        """Check whether the container ResourceRequirements have been applied or not.

        Args:
            container (Container): Container to check
            resource_requirements (dict): Dictionary of `requests` and `limits`

        Returns:
            bool: True if container ResourceRequirements have been applied, otherwise False
        """
        for request, value in resource_requirements["requests"].items():
            if not container.resources.requests.get(request) == value:  # type: ignore[union-attr]
                return False
        for limit, value in resource_requirements["limits"].items():
            if not container.resources.limits.get(limit) == value:  # type: ignore[union-attr]
                return False
        return True

    def _replace_statefulset(self, statefulset: StatefulSet) -> None:
        """Replace StatefulSet.

        Args:
            statefulset (StatefulSet): StatefulSet object to replace
        """
        try:
            self.k8s_client.replace(obj=statefulset)
            logger.info("Statefulset %s replaced", statefulset.metadata.name)  # type: ignore[union-attr]  # noqa: E501
        except ApiError as e:
            raise DPDKError(
                f"Could not replace statefulset `{statefulset.metadata.name}`: {e.status.message}"  # type: ignore[union-attr]  # noqa: E501, W505
            )
