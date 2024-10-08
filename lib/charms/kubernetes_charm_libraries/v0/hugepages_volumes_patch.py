# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charm library used to manage HugePages volumes in Kubernetes charms.

- Using the `configure` endpoint, it will:
  - Replace the volumes in the StatefulSet with the new requested ones
  - Replace the volume mounts in the container in the Pod with the new requested ones.
  - Replace the resource requirements in the container in the Pod with the new requested ones.

## Usage

```python

from charms.kubernetes_charm_libraries.v0.kubernetes_hugepages_volumes_patch import (
    KubernetesHugePagesPatchCharmLib,
    HugePagesVolume,
)


class YourCharm(CharmBase):

    def __init__(self, *args):
        super().__init__(*args)
        self._kubernetes_volumes_patch = KubernetesHugePagesPatchCharmLib(
            statefulset_name=self.model.app.name,
            container_name=self._bessd_container_name,
            pod_name=self._pod_name,
            hugepages_volumes=self._volumes_request_from_config(),
        )
        self.framework.observe(self.on.config_changed, self.on_config_changed)

    def _volumes_request_from_config(self) -> list[HugePagesVolume]:
        return [
            HugePagesVolume(
                mount_path="/dev/hugepages",
                size="1Gi",
                limit="4Gi",
            )
        ]

    def on_config_changed(self, event: ConfigChangedEvent):
        self._kubernetes_volumes_patch.configure()
```
"""

import logging
from dataclasses import dataclass
from typing import Iterable, List

from lightkube.core.client import Client
from lightkube.core.exceptions import ApiError
from lightkube.models.apps_v1 import StatefulSetSpec
from lightkube.models.core_v1 import (
    Container,
    EmptyDirVolumeSource,
    ResourceRequirements,
    Volume,
    VolumeMount,
)
from lightkube.resources.apps_v1 import StatefulSet
from lightkube.resources.core_v1 import Pod

# The unique Charmhub library identifier, never change it
LIBID = "b4cf8e58c9f64b73b22083d3e8d0de8e"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 6

logger = logging.getLogger(__name__)


@dataclass
class HugePagesVolume:
    """HugePagesVolume."""

    mount_path: str
    size: str = "1Gi"
    limit: str = "2Gi"


class KubernetesHugePagesVolumesPatchError(Exception):
    """KubernetesHugePagesVolumesPatchError."""

    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)


class KubernetesClient:
    """Class containing all the Kubernetes specific calls."""

    def __init__(self, namespace: str):
        self.client = Client()
        self.namespace = namespace

    @classmethod
    def _get_container(
        cls, container_name: str, containers: Iterable[Container]
    ) -> Container:
        """Find the container from the container list, assuming list is unique by name.

        Args:
            containers: Iterable of containers
            container_name: Container name

        Raises:
            KubernetesHugePagesVolumesPatchError: If the user-provided container name does
            not exist in the list.

        Returns:
            Container: An instance of :class:`Container` whose name matches the given name.
        """
        try:
            return next(
                iter(filter(lambda ctr: ctr.name == container_name, containers))
            )
        except StopIteration:
            raise KubernetesHugePagesVolumesPatchError(
                f"Container `{container_name}` not found"
            )

    def pod_is_patched(
        self,
        pod_name: str,
        requested_volumemounts: Iterable[VolumeMount],
        requested_resources: ResourceRequirements,
        container_name: str,
    ) -> bool:
        """Return whether pod contains the given volumes mounts and resources.

        Args:
            pod_name: Pod name
            requested_volumemounts: Iterable of volume mounts
            requested_resources: requested resources
            container_name: Container name

        Raises:
            KubernetesHugePagesVolumesPatchError: If the user-provided pod name does
            not exist.

        Returns:
            bool: Whether pod contains the given volumes mounts and resources.
        """
        try:
            pod = self.client.get(Pod, name=pod_name, namespace=self.namespace)
        except ApiError as e:
            if e.status.reason == "Unauthorized":
                logger.debug("kube-apiserver not ready yet")
            else:
                raise KubernetesHugePagesVolumesPatchError(
                    f"Pod `{pod_name}` not found"
                )
            return False
        pod_has_volumemounts = self._pod_contains_requested_volumemounts(
            requested_volumemounts=requested_volumemounts,
            containers=pod.spec.containers,  # type: ignore[union-attr]
            container_name=container_name,
        )
        pod_has_resources = self._pod_resources_are_set(
            containers=pod.spec.containers,  # type: ignore[union-attr]
            container_name=container_name,
            requested_resources=requested_resources,
        )
        return pod_has_volumemounts and pod_has_resources

    def statefulset_is_patched(
        self,
        statefulset_name: str,
        requested_volumes: Iterable[Volume],
    ) -> bool:
        """Return whether the statefulset contains the given volumes.

        Args:
            statefulset_name: Statefulset name
            requested_volumes: Iterable of volumes

        Raises:
            KubernetesHugePagesVolumesPatchError: If the user-provided statefulset name does
            not exist.

        Returns:
            bool: Whether the statefulset contains the given volumes.
        """
        try:
            statefulset = self.client.get(
                res=StatefulSet, name=statefulset_name, namespace=self.namespace
            )
        except ApiError as e:
            if e.status.reason == "Unauthorized":
                logger.debug("kube-apiserver not ready yet")
            else:
                raise KubernetesHugePagesVolumesPatchError(
                    f"Could not get statefulset `{statefulset_name}`"
                )
            return False
        if not statefulset.spec:
            return False
        return self._statefulset_contains_requested_volumes(
            statefulset_spec=statefulset.spec,
            requested_volumes=requested_volumes,
        )

    @staticmethod
    def _statefulset_contains_requested_volumes(
        statefulset_spec: StatefulSetSpec,
        requested_volumes: Iterable[Volume],
    ) -> bool:
        """Return whether the StatefulSet contains the given volumes.

        Args:
            statefulset_spec: StatefulSet spec
            requested_volumes: Iterable of volumes

        Returns:
            bool: Whether the StatefulSet contains the given volumes.
        """
        if not statefulset_spec.template.spec.volumes:  # type: ignore[reportOptionalMemberAccess]
            return False
        return all(
            requested_volume in statefulset_spec.template.spec.volumes  # type: ignore[reportOptionalMemberAccess]
            for requested_volume in requested_volumes
        )

    def _pod_contains_requested_volumemounts(
        self,
        containers: Iterable[Container],
        container_name: str,
        requested_volumemounts: Iterable[VolumeMount],
    ) -> bool:
        """Return whether container spec contains the given volumemounts.

        Args:
            containers: Iterable of Containers
            container_name: Container name
            requested_volumemounts: Iterable of volume mounts that the container shall contain

        Returns:
            bool: Whether container spec contains the given volumemounts.
        """
        container = self._get_container(
            container_name=container_name, containers=containers
        )
        return all(
            requested_volumemount in container.volumeMounts  # type: ignore[reportOperatorIssue]
            for requested_volumemount in requested_volumemounts
        )

    def _pod_resources_are_set(
        self,
        containers: Iterable[Container],
        container_name: str,
        requested_resources: ResourceRequirements,
    ) -> bool:
        """Return whether container spec contains the expected resources requests and limits.

        Args:
            containers: Iterable of Containers
            container_name: Container name
            requested_resources: resource requirements

        Returns:
            bool: whether container spec contains the expected resources requests and limits.
        """
        container = self._get_container(
            container_name=container_name, containers=containers
        )
        if requested_resources.limits:
            for limit, value in requested_resources.limits.items():
                if not container.resources.limits:  # type: ignore[reportOptionalMemberAccess]
                    return False
                if container.resources.limits.get(limit) != value:  # type: ignore[reportOptionalMemberAccess]
                    return False
        if requested_resources.requests:
            for request, value in requested_resources.requests.items():
                if not container.resources.requests:  # type: ignore[reportOptionalMemberAccess]
                    return False
                if container.resources.requests.get(request) != value:  # type: ignore[reportOptionalMemberAccess]
                    return False
        return True

    def replace_statefulset(
        self,
        statefulset_name: str,
        requested_volumes: Iterable[Volume],
        requested_volumemounts: Iterable[VolumeMount],
        requested_resources: ResourceRequirements,
        container_name: str,
    ) -> None:
        """Update a StatefulSet and a container in its spec.

        Raises:
            KubernetesHugePagesVolumesPatchError: If the user-provided statefulset name does
            not exist, or replacing statefulset failed.

        Args:
            statefulset_name: Statefulset name
            requested_volumes: Iterable of new volumes to be set in the StatefulSet
            requested_volumemounts: Iterable of new volume mounts to be set in the given container
            requested_resources: new resource requirements to be set in the given container
            container_name: Container name
        """
        try:
            statefulset = self.client.get(
                res=StatefulSet, name=statefulset_name, namespace=self.namespace
            )
        except ApiError:
            raise KubernetesHugePagesVolumesPatchError(
                f"Could not get statefulset `{statefulset_name}`"
            )
        containers: Iterable[Container] = statefulset.spec.template.spec.containers  # type: ignore[reportOptionalMemberAccess]
        container = self._get_container(
            container_name=container_name, containers=containers
        )
        container.volumeMounts = requested_volumemounts  # type: ignore[reportAttributeAccessIssue]
        container.resources = requested_resources
        statefulset.spec.template.spec.volumes = requested_volumes  # type: ignore[reportOptionalMemberAccess]
        try:
            self.client.replace(obj=statefulset)
        except ApiError:
            raise KubernetesHugePagesVolumesPatchError(
                f"Could not replace statefulset `{statefulset_name}`"
            )
        logger.info("Replaced `%s` statefulset", statefulset_name)

    def list_volumes(self, statefulset_name: str) -> list[Volume]:
        """List current volumes in the given StatefulSet.

        Args:
            statefulset_name: Statefulset name

        Raises:
            KubernetesHugePagesVolumesPatchError: If the user-provided statefulset name does
            not exist.

        Returns:
            list[Volume]: List of current volumes in the given StatefulSet
        """
        try:
            statefulset = self.client.get(
                res=StatefulSet, name=statefulset_name, namespace=self.namespace
            )
        except ApiError:
            raise KubernetesHugePagesVolumesPatchError(
                f"Could not get statefulset `{statefulset_name}`"
            )
        return statefulset.spec.template.spec.volumes  # type: ignore[reportOptionalMemberAccess]

    def list_volumemounts(
        self, statefulset_name: str, container_name: str
    ) -> list[VolumeMount]:
        """List current volume mounts in the given container.

        Args:
            statefulset_name: Statefulset name
            container_name: Container name

        Raises:
            KubernetesHugePagesVolumesPatchError: If the user-provided statefulset name does
            not exist.

        Returns:
            list[VolumeMount]: List of current volume mounts in the given container
        """
        try:
            statefulset = self.client.get(
                res=StatefulSet, name=statefulset_name, namespace=self.namespace
            )
        except ApiError:
            raise KubernetesHugePagesVolumesPatchError(
                f"Could not get statefulset `{statefulset_name}`"
            )
        containers: Iterable[Container] = statefulset.spec.template.spec.containers  # type: ignore[reportOptionalMemberAccess]
        container = self._get_container(
            container_name=container_name, containers=containers
        )
        return container.volumeMounts if container.volumeMounts else []

    def list_container_resources(
        self, statefulset_name: str, container_name: str
    ) -> ResourceRequirements:
        """Return resource requirements in the given container.

        Args:
            statefulset_name: Statefulset name
            container_name: Container name

        Raises:
            KubernetesHugePagesVolumesPatchError: If the user-provided statefulset name does
            not exist.

        Returns:
            ResourceRequirements: resource requirements in the given container
        """
        try:
            statefulset = self.client.get(
                res=StatefulSet, name=statefulset_name, namespace=self.namespace
            )
        except ApiError:
            raise KubernetesHugePagesVolumesPatchError(
                f"Could not get statefulset `{statefulset_name}`"
            )
        containers: Iterable[Container] = statefulset.spec.template.spec.containers  # type: ignore[union-attr]
        container = self._get_container(
            container_name=container_name, containers=containers
        )
        return container.resources  # type: ignore[return-value]


class KubernetesHugePagesPatchCharmLib:
    """Class to be instantiated by charms requiring changes in HugePages volumes."""

    def __init__(
        self,
        hugepages_volumes: List[HugePagesVolume],
        namespace: str,
        statefulset_name: str,
        container_name: str,
        pod_name: str,
    ):
        """Construct the KubernetesHugePagesPatchCharmLib.

        Args:
            hugepages_volumes: list of `HugePagesVolume` to be created.
            namespace: Namespace where the StatefulSet is located
            statefulset_name: Statefulset name
            container_name: Container name
            pod_name: Pod name
        """
        self.statefulset_name = statefulset_name
        self.namespace = namespace
        self.kubernetes = KubernetesClient(namespace=self.namespace)
        self.hugepages_volumes = hugepages_volumes
        self.container_name = container_name
        self.pod_name = pod_name

    def configure(self):
        """Configure HugePages in the StatefulSet and container."""
        if not self.is_patched():
            self.kubernetes.replace_statefulset(
                statefulset_name=self.statefulset_name,
                container_name=self.container_name,
                requested_volumes=self._generate_volumes_to_be_replaced(),
                requested_volumemounts=self._generate_volumemounts_to_be_replaced(),
                requested_resources=self._generate_resource_requirements_to_be_replaced(),
            )

    def _pod_is_patched(
        self,
        requested_volumemounts: Iterable[VolumeMount],
        requested_resources: ResourceRequirements,
    ) -> bool:
        """Return whether pod contains given volume mounts and resource limits.

        If no HugePages volumeMount is requested, it returns whether other HugePages
        volumeMounts are present in the pod.

        Args:
            requested_volumemounts: Iterable of volume mounts to be set in the pod.
            requested_resources: resource requirements to be set in the pod.

        Returns:
            bool: Whether pod contains given volume mounts and resource limits.
        """
        if not requested_volumemounts:
            return not any(
                self._volumemount_is_hugepages(x)
                for x in self.kubernetes.list_volumemounts(
                    statefulset_name=self.statefulset_name,
                    container_name=self.container_name,
                )
            )
        return self.kubernetes.pod_is_patched(
            pod_name=self.pod_name,
            requested_volumemounts=requested_volumemounts,
            requested_resources=requested_resources,
            container_name=self.container_name,
        )

    def _statefulset_is_patched(self, requested_volumes: Iterable[Volume]) -> bool:
        """Return whether statefulset contains requested volumes.

        If no HugePages volume is requested, it returns whether other HugePages
        volumes are present in the statefulset.

        Args:
            requested_volumes: Iterable of volumes to be set in the statefulset

        Returns:
            bool: Whether statefulset contains requested volumes.
        """
        if not requested_volumes:
            return not any(
                self._volume_is_hugepages(volume)
                for volume in self.kubernetes.list_volumes(
                    statefulset_name=self.statefulset_name
                )
            )
        return self.kubernetes.statefulset_is_patched(
            statefulset_name=self.statefulset_name,
            requested_volumes=requested_volumes,
        )

    def is_patched(self) -> bool:
        """Return whether statefulset and pod are patched.

        Validates that the statefulset contains the appropriate volumes
        and that the pod also contains the appropriate volume mounts and
        resource requirements.

        Returns:
            bool: Whether statefulset and pod are patched.
        """
        volumes = self._generate_volumes_from_requested_hugepage()
        statefulset_is_patched = self._statefulset_is_patched(volumes)
        volumemounts = self._generate_volumemounts_from_requested_hugepage()
        resource_requirements = (
            self._generate_resource_requirements_from_requested_hugepage()
        )
        pod_is_patched = self._pod_is_patched(
            requested_volumemounts=volumemounts,
            requested_resources=resource_requirements,
        )
        return statefulset_is_patched and pod_is_patched

    def _generate_volumes_from_requested_hugepage(self) -> list[Volume]:
        """Generate the list of required HugePages volumes.

        Returns:
            list[Volume]: list of volumes to be set in the StatefulSet.
        """
        return [
            Volume(
                name=f"hugepages-{requested_hugepages.size.lower()}",
                emptyDir=EmptyDirVolumeSource(
                    medium=f"HugePages-{requested_hugepages.size}"
                ),
            )
            for requested_hugepages in self.hugepages_volumes
        ]

    def _generate_volumemounts_from_requested_hugepage(self) -> list[VolumeMount]:
        """Generate the list of required HugePages volume mounts.

        Returns:
            list[VolumeMount]: list of volume mounts to be set in the container.
        """
        return [
            VolumeMount(
                name=f"hugepages-{requested_hugepages.size.lower()}",
                mountPath=requested_hugepages.mount_path,
            )
            for requested_hugepages in self.hugepages_volumes
        ]

    def _generate_resource_requirements_from_requested_hugepage(
        self,
    ) -> ResourceRequirements:
        """Generate the required resource requirements for HugePages.

        Returns:
            ResourceRequirements: required resource requirements to be set in the container.
        """
        limits = {}
        requests = {}
        for hugepage in self.hugepages_volumes:
            limits.update({f"hugepages-{hugepage.size}": hugepage.limit})
            limits.update({"cpu": "2"})
            requests.update({f"hugepages-{hugepage.size}": hugepage.limit})
            requests.update({"cpu": "2"})
        return ResourceRequirements(
            limits=limits,
            requests=requests,
        )

    @staticmethod
    def _volumemount_is_hugepages(volume_mount: VolumeMount) -> bool:
        """Return whether the specified volumeMount is HugePages."""
        return volume_mount.name.startswith("hugepages")

    @staticmethod
    def _volume_is_hugepages(volume: Volume) -> bool:
        """Return whether the specified volume is HugePages."""
        return volume.name.startswith("hugepages")

    @staticmethod
    def _limit_or_request_is_hugepages(key: str) -> bool:
        """Return whether the specified limit or request regards HugePages."""
        return key.startswith("hugepages")

    def _generate_volumes_to_be_replaced(self) -> list[Volume]:
        """Generate the list of new volumes to be replaced in the StatefulSet.

        1. Generates the list of new HugePages volumes to be added
        2. Goes through the list of current volumes for the specified StatefulSet
        - If a current volume is HugePages, discard it.
        - Else keep it.

        Returns:
            list[Volume]: list of new volumes to be replaced in the StatefulSet.
        """
        new_volumes = self._generate_volumes_from_requested_hugepage()
        current_volumes = self.kubernetes.list_volumes(
            statefulset_name=self.statefulset_name,
        )
        for current_volume in current_volumes:
            if not self._volume_is_hugepages(current_volume):
                new_volumes.append(current_volume)
        if not new_volumes:
            logger.warning(
                "StatefulSet `%s` will have no volumes", self.statefulset_name
            )
        return new_volumes

    def _generate_volumemounts_to_be_replaced(self) -> list[VolumeMount]:
        """Generate the list of new volume mounts to be replaced in the container.

        1. Generates the list of new HugePages volume mounts to be added
        2. Goes through the list of current volume mounts for the specified container
        - If a current volume mount is HugePages, discard it.
        - Else keep it.

        Returns:
            list[VolumeMount]: list of new volume mounts to be replaced in the container.
        """
        new_volumemounts = self._generate_volumemounts_from_requested_hugepage()
        current_volumemounts = self.kubernetes.list_volumemounts(
            statefulset_name=self.statefulset_name, container_name=self.container_name
        )
        for current_volumemount in current_volumemounts:
            if not self._volumemount_is_hugepages(current_volumemount):
                new_volumemounts.append(current_volumemount)
        if not new_volumemounts:
            logger.warning(
                "Container `%s` will have no volumeMounts", self.container_name
            )
        return new_volumemounts

    def _remove_hugepages_from_resource_requirements(
        self, resource_attribute: dict
    ) -> dict:
        """Remove HugePages-related keys from the given dictionary.

        Args:
            resource_attribute: dictionary of resource requirements attribute (limits or requests)

        Returns:
            dict: the input dictionary without HugePages-related keys.
        """
        return {
            key: value
            for key, value in resource_attribute.items()
            if not self._limit_or_request_is_hugepages(key)
        }

    def _generate_resource_requirements_to_be_replaced(self) -> ResourceRequirements:
        """Generate the new resource requirements to be replaced in the container.

        1. Generates the new HugePages resource requirements (limits and requests) to be added
        2. Goes through the current resource requirements for the specified container
        - If a current limit (or request) is HugePages, discard it.
        - Else keep it.
        3. Merge old resource requirements (without HugePages) and new HugePages requirements.

        Returns:
            ResourceRequirements: new resource requirements to be replaced in the container.
        """
        additional_resources = (
            self._generate_resource_requirements_from_requested_hugepage()
        )
        current_resources = self.kubernetes.list_container_resources(
            statefulset_name=self.statefulset_name, container_name=self.container_name
        )

        new_limits = (
            self._remove_hugepages_from_resource_requirements(current_resources.limits)
            if current_resources.limits
            else {}
        )
        new_requests = (
            self._remove_hugepages_from_resource_requirements(
                current_resources.requests
            )
            if current_resources.requests
            else {}
        )
        new_limits = dict(new_limits.items() | additional_resources.limits.items())  # type: ignore[reportOptionalMemberAccess]
        new_requests = dict(
            new_requests.items() | additional_resources.requests.items()  # type: ignore[reportOptionalMemberAccess]
        )
        new_resources = ResourceRequirements(
            limits=new_limits, requests=new_requests, claims=current_resources.claims
        )
        return new_resources
