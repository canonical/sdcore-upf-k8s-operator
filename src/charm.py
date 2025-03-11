#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charmed operator for the SD-Core UPF service for K8s."""

import json
import logging
import time
from pathlib import PurePath
from subprocess import check_output
from typing import Any, Dict, List, Optional, Tuple, Union

from charms.kubernetes_charm_libraries.v0.hugepages_volumes_patch import (
    HugePagesVolume,
    KubernetesHugePagesPatchCharmLib,
)
from charms.kubernetes_charm_libraries.v0.multus import (
    KubernetesMultusCharmLib,
    NetworkAnnotation,
    NetworkAttachmentDefinition,
)
from charms.loki_k8s.v1.loki_push_api import LogForwarder
from charms.prometheus_k8s.v0.prometheus_scrape import (
    MetricsEndpointProvider,
)
from charms.sdcore_upf_k8s.v0.fiveg_n3 import N3Provides
from charms.sdcore_upf_k8s.v0.fiveg_n4 import N4Provides
from jinja2 import Environment, FileSystemLoader
from lightkube.models.meta_v1 import ObjectMeta
from lightkube.resources.core_v1 import Node, Pod
from ops import (
    ActiveStatus,
    BlockedStatus,
    Container,
    ModelError,
    RemoveEvent,
    WaitingStatus,
    main,
)
from ops.charm import CharmBase, CollectStatusEvent
from ops.framework import EventBase
from ops.pebble import ChangeError, ConnectionError, ExecError, Layer, PathError

from charm_config import CharmConfig, CharmConfigInvalidError, CNIType, UpfMode
from dpdk import DPDK
from k8s_client import K8sClient
from k8s_service import K8sService, K8sServiceError

logger = logging.getLogger(__name__)

BESSD_CONTAINER_CONFIG_PATH = "/etc/bess/conf"
PFCP_AGENT_CONTAINER_CONFIG_PATH = "/tmp/conf"
POD_SHARE_PATH = "/pod-share"
ACCESS_NETWORK_ATTACHMENT_DEFINITION_NAME = "access-net"
CORE_NETWORK_ATTACHMENT_DEFINITION_NAME = "core-net"
ACCESS_INTERFACE_NAME = "access"
CORE_INTERFACE_NAME = "core"
ACCESS_INTERFACE_BRIDGE_NAME = "access-br"
CORE_INTERFACE_BRIDGE_NAME = "core-br"
DPDK_ACCESS_INTERFACE_RESOURCE_NAME = "intel.com/intel_sriov_vfio_access"
DPDK_CORE_INTERFACE_RESOURCE_NAME = "intel.com/intel_sriov_vfio_core"
CONFIG_FILE_NAME = "upf.json"
BESSD_PORT = 10514
PROMETHEUS_PORT = 8080
PFCP_PORT = 8805
REQUIRED_CPU_EXTENSIONS = ["avx2", "rdrand"]
REQUIRED_CPU_EXTENSIONS_HUGEPAGES = ["pdpe1gb"]
LOGGING_RELATION_NAME = "logging"
WORKLOAD_VERSION_FILE_NAME = "/etc/workload-version"


class UPFOperatorCharm(CharmBase):
    """Main class to describe juju event handling for the 5G UPF operator for K8s."""

    def __init__(self, *args):
        super().__init__(*args)
        self.framework.observe(self.on.collect_unit_status, self._on_collect_unit_status)
        if not self.unit.is_leader():
            return
        self._bessd_container_name = self._bessd_service_name = "bessd"
        self._routectl_service_name = "routectl"
        self._pfcp_agent_container_name = self._pfcp_agent_service_name = "pfcp-agent"
        self._bessd_container = self.unit.get_container(self._bessd_container_name)
        self._pfcp_agent_container = self.unit.get_container(self._pfcp_agent_container_name)
        self.fiveg_n3_provider = N3Provides(charm=self, relation_name="fiveg_n3")
        self.fiveg_n4_provider = N4Provides(charm=self, relation_name="fiveg_n4")
        self._metrics_endpoint = MetricsEndpointProvider(
            self,
            refresh_event=[self.on.update_status],
            jobs=[
                {
                    "static_configs": [{"targets": [f"*:{PROMETHEUS_PORT}"]}],
                }
            ],
        )
        self._logging = LogForwarder(charm=self, relation_name=LOGGING_RELATION_NAME)
        self.unit.set_ports(PROMETHEUS_PORT)
        try:
            self._charm_config: CharmConfig = CharmConfig.from_charm(charm=self)
        except CharmConfigInvalidError:
            return
        self._kubernetes_multus = KubernetesMultusCharmLib(
            cap_net_admin=True,
            namespace=self._namespace,
            statefulset_name=self.model.app.name,
            pod_name=self._pod_name,
            container_name=self._bessd_container_name,
            network_annotations=self._generate_network_annotations(),
            network_attachment_definitions=self._network_attachment_definitions_from_config(),
            privileged=self._get_privilege_required(),
        )
        self._kubernetes_volumes_patch = KubernetesHugePagesPatchCharmLib(
            namespace=self._namespace,
            statefulset_name=self.model.app.name,
            container_name=self._bessd_container_name,
            pod_name=self._pod_name,
            hugepages_volumes=self._volumes_request_from_config(),
        )
        self.k8s_client = K8sClient()
        self.k8s_service = K8sService(
            namespace=self._namespace,
            service_name=f"{self.app.name}-external",
            app_name=self.app.name,
            pfcp_port=PFCP_PORT,
        )
        self.framework.observe(self.on.update_status, self._on_config_changed)
        self.framework.observe(self.on.config_changed, self._on_config_changed)
        self.framework.observe(self.on.bessd_pebble_ready, self._on_bessd_pebble_ready)
        self.framework.observe(self.on.config_storage_attached, self._on_bessd_pebble_ready)
        self.framework.observe(self.on.pfcp_agent_pebble_ready, self._on_pfcp_agent_pebble_ready)
        self.framework.observe(
            self.fiveg_n3_provider.on.fiveg_n3_request, self._on_fiveg_n3_request
        )
        self.framework.observe(
            self.fiveg_n4_provider.on.fiveg_n4_request, self._on_fiveg_n4_request
        )
        self.framework.observe(self.on.remove, self._on_remove)

    def _get_privilege_required(self) -> bool:
        return self._charm_config.upf_mode == UpfMode.dpdk

    def _on_remove(self, _: RemoveEvent) -> None:
        # NOTE: We want to perform this removal only if the last remaining unit
        # is removed. This charm does not support scaling, so it *should* be
        # the only unit.
        #
        # However, to account for the case where the charm was scaled up, and
        # now needs to be scaled back down, we only remove the service if the
        # leader is removed. This is presumed to be the only healthy unit, and
        # therefore the last remaining one when removed (all other units will
        # block if they are not leader)
        #
        # This is a best effort removal of the service. There are edge cases
        # where the leader status is removed from the leader unit before all
        # hooks are finished running. In this case, we will leave behind a
        # dirty state in k8s, but it will be cleaned up when the juju model is
        # destroyed. It will be reused if the charm is re-deployed.
        self._kubernetes_multus.remove()
        if self.k8s_service.is_created():
            self.k8s_service.delete()

    def delete_pod(self):
        """Delete the pod."""
        self.k8s_client.delete(Pod, name=self._pod_name, namespace=self._namespace)

    @property
    def _namespace(self) -> str:
        """Return the k8s namespace."""
        return self.model.name

    @property
    def _pod_name(self) -> str:
        """Name of the unit's pod.

        Returns:
            str: A string containing the name of the current unit's pod.
        """
        return "-".join(self.model.unit.name.rsplit("/", 1))

    def _on_fiveg_n3_request(self, _: EventBase) -> None:
        """Handle 5G N3 requests events.

        Args:
            _: Juju event
        """
        if not self.unit.is_leader():
            return
        self._update_fiveg_n3_relation_data()

    def _on_fiveg_n4_request(self, _: EventBase) -> None:
        """Handle 5G N4 requests events.

        Args:
            _: Juju event
        """
        if not self.unit.is_leader():
            return
        self._update_fiveg_n4_relation_data()

    def _update_fiveg_n3_relation_data(self) -> None:
        """Publish UPF IP address in the `fiveg_n3` relation data bag."""
        cidr = self._get_network_ip_config(ACCESS_INTERFACE_NAME)
        if not cidr:
            logger.info("No IP address found for the access interface.")
            return
        upf_access_ip_address = cidr.split("/")[0]
        fiveg_n3_relations = self.model.relations.get("fiveg_n3")
        if not fiveg_n3_relations:
            logger.info("No `fiveg_n3` relations found.")
            return
        for fiveg_n3_relation in fiveg_n3_relations:
            self.fiveg_n3_provider.publish_upf_information(
                relation_id=fiveg_n3_relation.id,
                upf_ip_address=upf_access_ip_address,
            )

    def _update_fiveg_n4_relation_data(self) -> None:
        """Publish UPF hostname and the N4 port in the `fiveg_n4` relation data bag."""
        fiveg_n4_relations = self.model.relations.get("fiveg_n4")
        if not fiveg_n4_relations:
            logger.info("No `fiveg_n4` relations found.")
            return
        for fiveg_n4_relation in fiveg_n4_relations:
            self.fiveg_n4_provider.publish_upf_n4_information(
                relation_id=fiveg_n4_relation.id,
                upf_hostname=self._get_n4_upf_hostname(),
                upf_n4_port=PFCP_PORT,
            )

    def _get_n4_upf_hostname(self) -> str:
        """Return the UPF hostname to be exposed over the `fiveg_n4` relation.

        If a configuration is provided, it is returned. If that is
        not available, returns the hostname of the external LoadBalancer
        Service. If the LoadBalancer Service does not have a hostname,
        returns the internal Kubernetes service FQDN.

        Returns:
            str: Hostname of the UPF
        """
        if configured_hostname := self._charm_config.external_upf_hostname:
            return configured_hostname
        elif lb_hostname := self.k8s_service.get_hostname():
            return lb_hostname
        return self._upf_hostname

    def _volumes_request_from_config(self) -> List[HugePagesVolume]:
        """Return list of HugePages to be set based on the application config.

        Returns:
            list[HugePagesVolume]: list of HugePages to be set based on the application config.
        """
        if self._hugepages_are_required():
            return [HugePagesVolume(mount_path="/dev/hugepages", size="1Gi", limit="2Gi")]
        return []

    def _generate_network_annotations(self) -> List[NetworkAnnotation]:
        """Generate a list of NetworkAnnotations to be used by UPF's StatefulSet.

        Returns:
            List[NetworkAnnotation]: List of NetworkAnnotations
        """
        access_network_annotation = NetworkAnnotation(
            name=ACCESS_NETWORK_ATTACHMENT_DEFINITION_NAME,
            interface=ACCESS_INTERFACE_NAME,
        )
        core_network_annotation = NetworkAnnotation(
            name=CORE_NETWORK_ATTACHMENT_DEFINITION_NAME,
            interface=CORE_INTERFACE_NAME,
        )
        if self._charm_config.upf_mode == UpfMode.dpdk:
            access_ip = self._get_network_ip_config(ACCESS_INTERFACE_NAME)
            core_ip = self._get_network_ip_config(CORE_INTERFACE_NAME)
            access_network_annotation.mac = self._get_interface_mac_address(ACCESS_INTERFACE_NAME)
            access_network_annotation.ips = [access_ip] if access_ip else []
            core_network_annotation.mac = self._get_interface_mac_address(CORE_INTERFACE_NAME)
            core_network_annotation.ips = [core_ip] if core_ip else []
        return [access_network_annotation, core_network_annotation]

    def _network_attachment_definitions_from_config(self) -> list[NetworkAttachmentDefinition]:
        """Return list of Multus NetworkAttachmentDefinitions to be created based on config.

        Returns:
            network_attachment_definitions: list[NetworkAttachmentDefinition]
        """
        if self._charm_config.upf_mode == UpfMode.dpdk:
            access_nad = self._create_dpdk_access_nad_from_config()
            core_nad = self._create_dpdk_core_nad_from_config()
        else:
            access_nad = self._create_nad_from_config(ACCESS_INTERFACE_NAME)
            core_nad = self._create_nad_from_config(CORE_INTERFACE_NAME)

        return [access_nad, core_nad]

    def _create_nad_from_config(self, interface_name: str) -> NetworkAttachmentDefinition:
        """Return a NetworkAttachmentDefinition for the specified interface.

        Args:
            interface_name (str): Interface name to create the NetworkAttachmentDefinition from

        Returns:
            NetworkAttachmentDefinition: NetworkAttachmentDefinition object
        """
        nad_config = self._get_nad_base_config(interface_name)

        nad_config["ipam"].update(
            {"addresses": [{"address": self._get_network_ip_config(interface_name)}]}
        )

        cni_type = self._charm_config.cni_type

        # host interface name is used only by macvlan and host-device
        if host_interface := self._get_interface_config(interface_name):
            if cni_type == CNIType.macvlan:
                nad_config.update({"master": host_interface})
            elif cni_type == CNIType.host_device:
                nad_config.update({"device": host_interface})
        else:
            nad_config.update(
                {
                    "bridge": (
                        ACCESS_INTERFACE_BRIDGE_NAME
                        if interface_name == ACCESS_INTERFACE_NAME
                        else CORE_INTERFACE_BRIDGE_NAME
                    )
                }
            )
        nad_config.update({"type": cni_type})

        return NetworkAttachmentDefinition(
            metadata=ObjectMeta(
                name=(
                    CORE_NETWORK_ATTACHMENT_DEFINITION_NAME
                    if interface_name == CORE_INTERFACE_NAME
                    else ACCESS_NETWORK_ATTACHMENT_DEFINITION_NAME
                )
            ),
            spec={"config": json.dumps(nad_config)},
        )

    def _create_dpdk_access_nad_from_config(self) -> NetworkAttachmentDefinition:
        """Return a DPDK-compatible NetworkAttachmentDefinition for the Access interface.

        Returns:
            NetworkAttachmentDefinition: NetworkAttachmentDefinition object
        """
        access_nad_config = self._get_nad_base_config(ACCESS_INTERFACE_NAME)
        access_nad_config.update({"type": "vfioveth"})

        return NetworkAttachmentDefinition(
            metadata=ObjectMeta(
                name=ACCESS_NETWORK_ATTACHMENT_DEFINITION_NAME,
                annotations={
                    "k8s.v1.cni.cncf.io/resourceName": DPDK_ACCESS_INTERFACE_RESOURCE_NAME,
                },
            ),
            spec={"config": json.dumps(access_nad_config)},
        )

    def _create_dpdk_core_nad_from_config(self) -> NetworkAttachmentDefinition:
        """Return a DPDK-compatible NetworkAttachmentDefinition for the Core interface.

        Returns:
            NetworkAttachmentDefinition: NetworkAttachmentDefinition object
        """
        core_nad_config = self._get_nad_base_config(CORE_INTERFACE_NAME)
        core_nad_config.update({"type": "vfioveth"})

        return NetworkAttachmentDefinition(
            metadata=ObjectMeta(
                name=CORE_NETWORK_ATTACHMENT_DEFINITION_NAME,
                annotations={
                    "k8s.v1.cni.cncf.io/resourceName": DPDK_CORE_INTERFACE_RESOURCE_NAME,
                },
            ),
            spec={"config": json.dumps(core_nad_config)},
        )

    def _get_nad_base_config(self, interface_name: str) -> Dict[Any, Any]:
        """Get the base NetworkAttachmentDefinition.

        This config is extended according to charm config.

        Returns:
            config (dict): Base NAD config
        """
        base_nad = {
            "cniVersion": "0.3.1",
            "ipam": {
                "type": "static",
            },
            "capabilities": {"mac": True},
        }
        cni_type = self._charm_config.cni_type
        # MTU is optional for bridge, macvlan, dpdk
        # MTU is ignored by host-device
        if cni_type != CNIType.host_device:
            if interface_mtu := self._get_interface_mtu_config(interface_name):
                base_nad.update({"mtu": interface_mtu})
        return base_nad

    def _write_upf_config_file_to_bessd_container(self, content: str) -> None:
        push_file(
            container=self._bessd_container,
            path=f"{BESSD_CONTAINER_CONFIG_PATH}/{CONFIG_FILE_NAME}",
            source=content,
        )
        logger.info("Pushed %s config file", CONFIG_FILE_NAME)

    def _upf_config_file_is_written_to_bessd_container(self) -> bool:
        return path_exists(
            container=self._bessd_container,
            path=f"{BESSD_CONTAINER_CONFIG_PATH}/{CONFIG_FILE_NAME}",
        )

    def _existing_upf_config_file_content_matches(self, content: str) -> bool:
        try:
            existing_content = self._bessd_container.pull(
                path=f"{BESSD_CONTAINER_CONFIG_PATH}/{CONFIG_FILE_NAME}"
            )
        except ConnectionError:
            return False
        if existing_content.read() != content:
            return False
        return True

    def _hwcksum_config_matches_pod_config(self) -> bool:
        try:
            existing_content = json.loads(
                self._bessd_container.pull(
                    path=f"{BESSD_CONTAINER_CONFIG_PATH}/{CONFIG_FILE_NAME}"
                ).read()
            )
        except PathError:
            existing_content = {}
        except ConnectionError:
            existing_content = {}
        return existing_content.get("hwcksum") == self._charm_config.enable_hw_checksum

    def _on_collect_unit_status(self, event: CollectStatusEvent):  # noqa C901
        """Handle collect status event.

        Update workload version if present in container.
        """
        if not self.unit.is_leader():
            # NOTE: In cases where leader status is lost before the charm is
            # finished processing all teardown events, this prevents teardown
            # event code from running. Luckily, for this charm, none of the
            # teardown code is necessary to perform if we're removing the
            # charm.
            event.add_status(BlockedStatus("Scaling is not implemented for this charm"))
            logger.info("Scaling is not implemented for this charm")
            return
        try:  # workaround for https://github.com/canonical/operator/issues/736
            self._charm_config: CharmConfig = CharmConfig.from_charm(charm=self)
        except CharmConfigInvalidError as exc:
            event.add_status(BlockedStatus(exc.msg))
            logger.info(exc.msg)
            return
        if not self._is_cpu_compatible():
            event.add_status(BlockedStatus("CPU is not compatible, see logs for more details"))
            return
        if not self._hugepages_are_available():
            event.add_status(BlockedStatus("Not enough HugePages available"))
            return
        if not self._kubernetes_multus.multus_is_available():
            event.add_status(BlockedStatus("Multus is not installed or enabled"))
            logger.info("Multus is not installed or enabled")
            return
        if not self._bessd_container.can_connect():
            event.add_status(WaitingStatus("Waiting for bessd container to be ready"))
            logger.info("Waiting for bessd container to be ready")
            return
        if not self._pfcp_agent_container.can_connect():
            event.add_status(WaitingStatus("Waiting for pfcp-agent container to be ready"))
            logger.info("Waiting for pfcp-agent container to be ready")
            return
        self.unit.set_workload_version(self._get_workload_version())

        if not self._kubernetes_multus.is_ready():
            event.add_status(WaitingStatus("Waiting for Multus to be ready"))
            logger.info("Waiting for Multus to be ready")
            return
        if not self._route_exists(
            dst="default",
            via=self._get_network_gateway_ip_config(CORE_INTERFACE_NAME),
        ):
            event.add_status(WaitingStatus("Waiting for default route creation"))
            logger.info("Waiting for default route creation")
            return
        if not self._route_exists(
            dst=str(self._charm_config.gnb_subnet),
            via=self._get_network_gateway_ip_config(ACCESS_INTERFACE_NAME),
        ):
            event.add_status(WaitingStatus("Waiting for RAN route creation"))
            logger.info("Waiting for RAN route creation")
            return
        if not path_exists(container=self._bessd_container, path=BESSD_CONTAINER_CONFIG_PATH):
            event.add_status(
                WaitingStatus("Waiting for storage to be attached for bessd container")
            )
            logger.info("Waiting for storage to be attached for bessd container")
            return
        if not path_exists(
            container=self._pfcp_agent_container,
            path=PFCP_AGENT_CONTAINER_CONFIG_PATH,
        ):
            event.add_status(
                WaitingStatus("Waiting for storage to be attached for pfcp-agent container")
            )
            logger.info("Waiting for storage to be attached for pfcp-agent container")
            return
        if not service_is_running_on_container(self._bessd_container, self._bessd_service_name):
            event.add_status(WaitingStatus("Waiting for bessd service to run"))
            logger.info("Waiting for bessd service to run")
            return
        if not self._is_bessd_grpc_service_ready():
            event.add_status(
                WaitingStatus("Waiting for bessd service to accept configuration messages")
            )
            logger.info("Waiting for bessd service to accept configuration messages")
            return
        if not self._is_bessd_configured():
            event.add_status(WaitingStatus("Waiting for bessd configuration to complete"))
            logger.info("Waiting for bessd configuration to complete")
            return
        if not service_is_running_on_container(self._bessd_container, self._routectl_service_name):
            event.add_status(WaitingStatus("Waiting for routectl service to run"))
            logger.info("Waiting for routectl service to run")
            return
        if not service_is_running_on_container(
            self._pfcp_agent_container, self._pfcp_agent_service_name
        ):
            event.add_status(WaitingStatus("Waiting for pfcp agent service to run"))
            logger.info("Waiting for pfcp agent service to run")
            return
        event.add_status(ActiveStatus())

    def _on_config_changed(self, event: EventBase):
        """Handle for config changed events."""
        try:  # workaround for https://github.com/canonical/operator/issues/736
            self._charm_config: CharmConfig = CharmConfig.from_charm(charm=self)
        except CharmConfigInvalidError:
            return
        if not self.unit.is_leader():
            return
        if not self._is_cpu_compatible():
            return
        if not self._hugepages_are_available():
            return
        if not self.k8s_service.is_created():
            try:
                self.k8s_service.create()
            except K8sServiceError:
                return
        if not self._kubernetes_multus.multus_is_available():
            return
        self._kubernetes_multus.configure()
        self._kubernetes_volumes_patch.configure()
        if self._charm_config.upf_mode == UpfMode.dpdk:
            self._configure_bessd_for_dpdk()
        if not self._bessd_container.can_connect():
            return
        self._on_bessd_pebble_ready(event)
        self._update_fiveg_n3_relation_data()
        self._update_fiveg_n4_relation_data()

    def _get_workload_version(self) -> str:
        """Return the workload version.

        Checks for the presence of /etc/workload-version file
        and if present, returns the contents of that file. If
        the file is not present, an empty string is returned.

        Returns:
            string: A human readable string representing the
            version of the workload
        """
        if self._bessd_container.exists(path=f"{WORKLOAD_VERSION_FILE_NAME}"):
            version_file_content = self._bessd_container.pull(
                path=f"{WORKLOAD_VERSION_FILE_NAME}"
            ).read()
            return version_file_content
        return ""

    def _on_bessd_pebble_ready(self, _: EventBase) -> None:
        """Handle Pebble ready event."""
        try:
            self._charm_config: CharmConfig = CharmConfig.from_charm(charm=self)
        except CharmConfigInvalidError:
            return
        if not self.unit.is_leader():
            return
        if not self._is_cpu_compatible():
            return
        if not self._hugepages_are_available():
            return
        if not self._kubernetes_multus.multus_is_available():
            return
        if not self._kubernetes_multus.is_ready():
            return
        if not path_exists(container=self._bessd_container, path=BESSD_CONTAINER_CONFIG_PATH):
            return
        self._configure_and_start_bessd_workload()

    def _on_pfcp_agent_pebble_ready(self, _: EventBase) -> None:
        """Handle pfcp agent Pebble ready event."""
        if not self.unit.is_leader():
            return
        if not self._is_cpu_compatible():
            return
        if not self._hugepages_are_available():
            return
        if not path_exists(
            container=self._pfcp_agent_container,
            path=PFCP_AGENT_CONTAINER_CONFIG_PATH,
        ):
            return
        self._configure_pfcp_agent_workload()

    def _configure_and_start_bessd_workload(self) -> None:
        """Apply the necessary configuration and starts the bessd and the route_control services.

        This function is responsible for applying the configuration necessary to run the services
        being part of the `bessd` workload container (`bessd` and `routectl`). The configuration
        steps include creation of the UPF config file (upf.json), creation of routes
        for the `access` and `core` interfaces and blocking sending the ICMP port-unreachable
        packets by setting the relevant iptables rule. Once the configuration is done, workload
        services are created, started and configured.
        """
        recreate_pod, restart = self._create_upf_configuration_file()
        if not self._route_exists(
            dst="default",
            via=self._get_network_gateway_ip_config(CORE_INTERFACE_NAME),
        ):
            self._create_default_route()
        if not self._route_exists(
            dst=str(self._charm_config.gnb_subnet),
            via=self._get_network_gateway_ip_config(ACCESS_INTERFACE_NAME),
        ):
            self._create_ran_route()
        if not self._ip_tables_rule_exists():
            self._create_ip_tables_rule()

        self._create_and_configure_bessd_service(restart_service=restart)
        self._create_route_control_service(restart_service=restart)

        if recreate_pod:
            logger.warning("Recreating POD after changing hardware checksum offloading config")
            self.delete_pod()

    def _create_upf_configuration_file(self) -> tuple[bool, bool]:
        """Generate the content of the UPF configuration file and pushes it to the workload container.

        This function is responsible for rendering the UPF configuration file (upf.json)
        based on the template delivered along with the charm, configuration provided by the user
        and the environment-specific data. Rendered configuration is then written to a file
        in the `bessd` workload container, unless it already exists and the content of the existing
        file matches the rendered configuration. Any configuration change (writing new
        configuration file) requires the `bessd` workload container to be at least restarted.
        In case of changes involving enabling or disabling the hardware checksum offloading
        the entire UPF POD needs to be recreated. Return values are used to indicate what sort
        of restarts should be performed after calling this function.
        """  # noqa: E501
        restart = False
        recreate_pod = False
        core_ip_address = self._get_network_ip_config(CORE_INTERFACE_NAME)
        core_ip_masquerade = self._charm_config.core_ip_masquerade
        content = render_bessd_config_file(
            upf_hostname=self._upf_hostname,
            upf_mode=self._charm_config.upf_mode,
            access_interface_name=ACCESS_INTERFACE_NAME,
            core_interface_name=CORE_INTERFACE_NAME,
            core_ip_address=core_ip_address.split("/")[0]
            if (core_ip_address and core_ip_masquerade)
            else "",
            dnn=self._charm_config.dnn,
            pod_share_path=POD_SHARE_PATH,
            enable_hw_checksum=self._charm_config.enable_hw_checksum,
            log_level=self._charm_config.log_level,
        )
        if (
            not self._upf_config_file_is_written_to_bessd_container()
            or not self._existing_upf_config_file_content_matches(content=content)
        ):
            if not self._hwcksum_config_matches_pod_config():
                recreate_pod = True
            self._write_upf_config_file_to_bessd_container(content=content)
            restart = True
        return recreate_pod, restart

    def _create_and_configure_bessd_service(self, restart_service: bool):
        """Create the `bessd` service and configures it.

        This function adds the Pebble layer defining the `bessd` service. The Pebble layer will
        only be added if it doesn't already exist. Once it's added and the GRPC service
        is up and running, `bess` configuration script is ran.
        Through the `restart_service` argument, the function also allows to restart
        the `bessd` service (even if there was no change in the Pebble layer) if it is required
        (e.g. when the UPF configuration file has changed).
        """
        plan = self._bessd_container.get_plan()
        if not all(service in plan.services for service in self._bessd_pebble_layer.services):
            self._bessd_container.add_layer("bessd", self._bessd_pebble_layer, combine=True)
            restart_service = True
        if restart_service:
            self._bessd_container.restart(self._bessd_service_name)
            logger.info("Service `bessd` restarted")
        self._wait_for_bessd_grpc_service_to_be_ready(timeout=60)
        self._run_bess_configuration()

    def _create_route_control_service(self, restart_service: bool):
        """Create the `routectl` service.

        This function adds the Pebble layer defining the `routectl` service. The Pebble layer will
        only be added if it doesn't already exist.
        Through the `restart_service` argument, the function also allows to restart
        the `routectl` service (even if there was no change in the Pebble layer) if it is required
        (e.g. when the UPF configuration file has changed).
        """
        if not self._is_bessd_configured():
            return
        plan = self._bessd_container.get_plan()
        if not all(service in plan.services for service in self._routectl_pebble_layer.services):
            self._bessd_container.add_layer("routectl", self._routectl_pebble_layer, combine=True)
            restart_service = True
        if restart_service:
            self._bessd_container.restart(self._routectl_service_name)
            logger.info("Service `routectl` restarted")

    def _run_bess_configuration(self) -> None:
        """Run bessd configuration in workload."""
        if self._is_bessd_configured():
            return

        logger.info("Starting configuration of the `bessd` service")
        command = "/opt/bess/bessctl/bessctl run /opt/bess/bessctl/conf/up4"
        try:
            (stdout, stderr) = self._exec_command_in_bessd_workload(
                command=command,
                environment=self._bessd_environment_variables,
                timeout=30,
            )

            logger.info("Service `bessd` configuration script complete")
            for line in stdout.splitlines():
                logger.debug("`up4.bess`: %s", line)
            if stderr:
                for line in stderr.split():
                    logger.error("`up4.bess`: %s", line)
            return
        except ExecError as e:
            logger.info("Failed running configuration for bess: %s", e.stderr)
        except ChangeError:
            logger.info("Timeout executing: %s", command)

    def _wait_for_bessd_grpc_service_to_be_ready(self, timeout: float = 60):
        initial_time = time.time()

        while not self._is_bessd_grpc_service_ready():
            if time.time() - initial_time > timeout:
                raise TimeoutError("Timed out waiting for bessd gRPC server to become ready")
            time.sleep(2)

    def _is_bessd_grpc_service_ready(self) -> bool:
        """Check if bessd grpc service is ready.

        Examine the output from bessctl to see if it is able to communicate
        with bessd. This indicates the service is ready to accept configuration
        commands.

        Returns:
            bool:   True/False
        """
        command = "/opt/bess/bessctl/bessctl show version"
        try:
            self._exec_command_in_bessd_workload(
                command=command,
                timeout=10,
            )
            return True
        except ExecError as e:
            logger.info("gRPC Check: %s", e)
            return False

    def _is_bessd_configured(self) -> bool:
        """Check if bessd has been configured.

        Bess is considered as configured when the `accessRoutes` and `coreRoutes` modules
        are available and at least one worker is in the RUNNING state. This method examines
        the output of the `bessctl show` command to determine whether the above criteria are met.

        Returns:
            bool: Whether the `bessd` service is configured
        """
        show_accessRoutes_module_cmd = "/opt/bess/bessctl/bessctl show module accessRoutes"  # noqa: N806
        show_coreRoutes_module_cmd = "/opt/bess/bessctl/bessctl show module coreRoutes"  # noqa: N806
        show_worker_cmd = "/opt/bess/bessctl/bessctl show worker"
        try:
            (show_worker_stdout, _) = self._exec_command_in_bessd_workload(
                command=show_worker_cmd,
                timeout=10,
            )
            if "RUNNING" not in show_worker_stdout:
                return False
            logger.debug("bessd configured workers: %s", show_worker_stdout)
            (show_accessRoutes_module_stdout, _) = self._exec_command_in_bessd_workload(  # noqa: N806
                command=show_accessRoutes_module_cmd,
                timeout=10,
            )
            logger.debug(
                "bessd configured accessRoutes module: %s", show_accessRoutes_module_stdout
            )
            (show_coreRoutes_module_stdout, _) = self._exec_command_in_bessd_workload(  # noqa: N806
                command=show_coreRoutes_module_cmd,
                timeout=10,
            )
            logger.debug("bessd configured coreRoutes module: %s", show_coreRoutes_module_stdout)
            return True
        except ExecError as e:
            logger.error("Configuration check failed: %s", e)
            return False

    def _configure_bessd_for_dpdk(self) -> None:
        """Configure bessd container for DPDK."""
        dpdk = DPDK(
            statefulset_name=self.model.app.name,
            namespace=self._namespace,
            dpdk_access_interface_resource_name=DPDK_ACCESS_INTERFACE_RESOURCE_NAME,
            dpdk_core_interface_resource_name=DPDK_CORE_INTERFACE_RESOURCE_NAME,
        )
        if not dpdk.is_configured(container_name=self._bessd_container_name):
            dpdk.configure(container_name=self._bessd_container_name)

    def _route_exists(self, dst: str, via: str | None) -> bool:
        """Return whether the specified route exist."""
        try:
            stdout, stderr = self._exec_command_in_bessd_workload(command="ip route show")
        except ExecError as e:
            logger.error("Failed retrieving routes: %s", e.stderr)
            return False
        for line in stdout.splitlines():
            if f"{dst} via {via}" in line:
                return True
        return False

    def _create_default_route(self) -> None:
        """Create ip route towards core network."""
        try:
            self._exec_command_in_bessd_workload(
                command=f"ip route replace default via {self._get_network_gateway_ip_config(CORE_INTERFACE_NAME)} metric 110"  # noqa: E501
            )
        except ExecError as e:
            logger.error("Failed to create core network route: %s", e.stderr)
            return
        logger.info("Default core network route created")

    def _create_ran_route(self) -> None:
        """Create ip route towards gnb-subnet."""
        try:
            self._exec_command_in_bessd_workload(
                command=f"ip route replace {self._charm_config.gnb_subnet} via {self._get_network_gateway_ip_config(ACCESS_INTERFACE_NAME)}"  # noqa: E501
            )
        except ExecError as e:
            logger.error("Failed to create route to gnb-subnet: %s", e.stderr)
            return
        logger.info("Route to gnb-subnet created")

    def _ip_tables_rule_exists(self) -> bool:
        """Return whether iptables rule already exists using the `--check` parameter.

        Returns:
            bool: Whether iptables rule exists
        """
        try:
            self._exec_command_in_bessd_workload(
                command="iptables-legacy --check OUTPUT -p icmp --icmp-type port-unreachable -j DROP"  # noqa: E501
            )
            return True
        except ExecError:
            return False

    def _create_ip_tables_rule(self) -> None:
        """Create iptable rule in the OUTPUT chain to block ICMP port-unreachable packets."""
        try:
            self._exec_command_in_bessd_workload(
                command="iptables-legacy -I OUTPUT -p icmp --icmp-type port-unreachable -j DROP"
            )
        except ExecError as e:
            logger.error("Failed to create iptables rule for ICMP: %s", e.stderr)
            return
        logger.info("Iptables rule for ICMP created")

    def _exec_command_in_bessd_workload(
        self, command: str, timeout: Optional[int] = 30, environment: Optional[dict] = None
    ) -> Tuple[str, str | None]:
        """Execute command in bessd container.

        Args:
            command: Command to execute
            timeout: Timeout in seconds
            environment: Environment Variables
        """
        process = self._bessd_container.exec(
            command=command.split(),
            timeout=timeout,
            environment=environment,
        )
        return process.wait_output()

    def _configure_pfcp_agent_workload(self) -> None:
        """Configure pebble layer for `pfcp-agent` container."""
        restart_service = False
        plan = self._pfcp_agent_container.get_plan()
        layer = self._pfcp_agent_pebble_layer
        if plan.services != layer.services:
            self._pfcp_agent_container.add_layer(
                "pfcp", self._pfcp_agent_pebble_layer, combine=True
            )
            restart_service = True
        if restart_service:
            self._pfcp_agent_container.restart(self._pfcp_agent_service_name)
            logger.info("Service `pfcp` restarted")

    @property
    def _routectl_pebble_layer(self) -> Layer:
        return Layer(
            {
                "summary": "route_control layer",
                "description": "pebble config layer for route_control",
                "services": {
                    self._routectl_service_name: {
                        "override": "replace",
                        "startup": "enabled",
                        "command": f"/opt/bess/bessctl/conf/route_control.py -i {ACCESS_INTERFACE_NAME} {CORE_INTERFACE_NAME}",  # noqa: E501
                        "environment": self._routectl_environment_variables,
                    },
                },
            }
        )

    @property
    def _bessd_pebble_layer(self) -> Layer:
        return Layer(
            {
                "summary": "bessd layer",
                "description": "pebble config layer for bessd",
                "services": {
                    self._bessd_service_name: {
                        "override": "replace",
                        "startup": "enabled",
                        "command": self._generate_bessd_startup_command(),
                        "environment": self._bessd_environment_variables,
                    },
                },
                "checks": {
                    "online": {
                        "override": "replace",
                        "level": "ready",
                        "tcp": {"port": BESSD_PORT},
                    }
                },
            }
        )

    @property
    def _pfcp_agent_pebble_layer(self) -> Layer:
        return Layer(
            {
                "summary": "pfcp agent layer",
                "description": "pebble config layer for pfcp agent",
                "services": {
                    self._pfcp_agent_service_name: {
                        "override": "replace",
                        "startup": "enabled",
                        "command": f"pfcpiface -config {PFCP_AGENT_CONTAINER_CONFIG_PATH}/{CONFIG_FILE_NAME}",  # noqa: E501
                    },
                },
            }
        )

    @property
    def _bessd_environment_variables(self) -> dict:
        return {
            "CONF_FILE": f"{BESSD_CONTAINER_CONFIG_PATH}/{CONFIG_FILE_NAME}",
            "PYTHONPATH": "/opt/bess",
        }

    @property
    def _routectl_environment_variables(self) -> dict:
        return {
            "PYTHONPATH": "/opt/bess",
            "PYTHONUNBUFFERED": "1",
        }

    def _get_network_ip_config(self, interface_name: str) -> Optional[str]:
        """Retrieve the network IP address to use for the specified interface.

        Args:
            interface_name (str): Interface name to retrieve the network IP address from

        Returns:
            Optional[str]: The network IP address to use
        """
        if interface_name == ACCESS_INTERFACE_NAME:
            return str(self._charm_config.access_ip)
        elif interface_name == CORE_INTERFACE_NAME:
            return str(self._charm_config.core_ip)
        else:
            return None

    def _get_interface_config(self, interface_name: str) -> Optional[str]:
        """Retrieve the interface on the host to use for the specified interface.

        Args:
            interface_name (str): Interface name to retrieve the interface host from

        Returns:
            Optional[str]: The interface on the host to use
        """
        if interface_name == ACCESS_INTERFACE_NAME:
            return self._charm_config.access_interface
        elif interface_name == CORE_INTERFACE_NAME:
            return self._charm_config.core_interface
        else:
            return None

    def _get_interface_mac_address(self, interface_name: str) -> Optional[str]:
        """Retrieve the MAC address to use for the specified interface.

        Args:
            interface_name (str): Interface name to retrieve the MAC address from

        Returns:
            Optional[str]: The MAC address to use
        """
        if interface_name == ACCESS_INTERFACE_NAME:
            return self._charm_config.access_interface_mac_address
        elif interface_name == CORE_INTERFACE_NAME:
            return self._charm_config.core_interface_mac_address
        else:
            return None

    def _get_network_gateway_ip_config(self, interface_name: str) -> Optional[str]:
        """Retrieve the gateway IP address to use for the specified interface.

        Args:
            interface_name (str): Interface name to retrieve the gateway IP address from

        Returns:
            Optional[str]: The gateway IP address to use
        """
        if interface_name == ACCESS_INTERFACE_NAME:
            return str(self._charm_config.access_gateway_ip)
        elif interface_name == CORE_INTERFACE_NAME:
            return str(self._charm_config.core_gateway_ip)
        else:
            return None

    @property
    def _upf_hostname(self) -> str:
        """Build and returns the UPF hostname in the cluster.

        Returns:
            str: The UPF hostname.
        """
        return f"{self.model.app.name}-external.{self.model.name}.svc.cluster.local"

    def _is_cpu_compatible(self) -> bool:
        """Return whether the CPU meets requirements to run this charm.

        Returns:
            bool: Whether the CPU meets requirements to run this charm
        """
        if not all(
            required_extension in self._get_cpu_extensions()
            for required_extension in REQUIRED_CPU_EXTENSIONS
        ):
            logger.warning(
                "Please use a CPU that has the following capabilities: %s",
                ", ".join(REQUIRED_CPU_EXTENSIONS),
            )
            return False
        if self._hugepages_are_required():
            if not self._cpu_is_compatible_for_hugepages():
                logger.warning(
                    "Please use a CPU that has the following capabilities: %s",
                    ", ".join(REQUIRED_CPU_EXTENSIONS + REQUIRED_CPU_EXTENSIONS_HUGEPAGES),
                )
                return False
        return True

    @staticmethod
    def _get_cpu_extensions() -> list[str]:
        """Return a list of extensions (instructions) supported by the CPU.

        Returns:
            list: List of extensions (instructions) supported by the CPU.
        """
        cpu_info = check_output(["lscpu"]).decode().split("\n")
        cpu_flags = []
        for cpu_info_item in cpu_info:
            if "Flags:" in cpu_info_item:
                cpu_flags = cpu_info_item.split()
                del cpu_flags[0]
        return cpu_flags

    def _cpu_is_compatible_for_hugepages(self) -> bool:
        return all(
            required_extension in self._get_cpu_extensions()
            for required_extension in REQUIRED_CPU_EXTENSIONS_HUGEPAGES
        )

    def _hugepages_are_available(self) -> bool:
        """Check whether HugePages are available in the K8S nodes.

        Returns:
            bool: Whether HugePages are available in the K8S nodes
        """
        if not self._hugepages_are_required():
            return True
        nodes = self.k8s_client.list(Node)
        if not nodes:
            return False
        return all(
            int(node.status.allocatable.get("hugepages-1Gi", "0Gi").removesuffix("Gi")) >= 2
            for node in nodes
        )

    def _get_interface_mtu_config(self, interface_name) -> Optional[int]:
        """Retrieve the MTU to use for the specified interface.

        Args:
            interface_name (str): Interface name to retrieve the MTU from

        Returns:
            Optional[int]: The MTU to use for the specified interface
        """
        if interface_name == ACCESS_INTERFACE_NAME:
            return self._charm_config.access_interface_mtu_size
        elif interface_name == CORE_INTERFACE_NAME:
            return self._charm_config.core_interface_mtu_size
        else:
            return None

    def _hugepages_are_required(self) -> bool:
        """Return whether HugePages are required.

        Returns:
            bool: Whether HugePages are required
        """
        return self._charm_config.upf_mode == UpfMode.dpdk

    def _generate_bessd_startup_command(self) -> str:
        """Return bessd startup command.

        Returns:
            str: bessd startup command
        """
        hugepages_cmd = ""
        if not self._hugepages_are_required():
            hugepages_cmd = "-m 0"  # "-m 0" means that we are not using hugepages
        return f"/bin/bessd -f -grpc-url=0.0.0.0:{BESSD_PORT} {hugepages_cmd}"


def render_bessd_config_file(
    upf_hostname: str,
    upf_mode: str,
    access_interface_name: str,
    core_interface_name: str,
    core_ip_address: Optional[str],
    dnn: str,
    pod_share_path: str,
    enable_hw_checksum: bool,
    log_level: str,
) -> str:
    """Render the configuration file for the 5G UPF service.

    Args:
        upf_hostname: UPF hostname
        upf_mode: UPF mode
        access_interface_name: Access network interface name
        core_interface_name: Core network interface name
        core_ip_address: Core network IP address
        dnn: Data Network Name (DNN)
        pod_share_path: pod_share path
        enable_hw_checksum: Whether to enable hardware checksum or not
        log_level (str): Log level for the UPF.
    """
    jinja2_environment = Environment(loader=FileSystemLoader("src/templates/"))
    template = jinja2_environment.get_template(f"{CONFIG_FILE_NAME}.j2")
    content = template.render(
        upf_hostname=upf_hostname,
        mode=upf_mode,
        access_interface_name=access_interface_name,
        core_interface_name=core_interface_name,
        core_ip_address=core_ip_address,
        dnn=dnn,
        pod_share_path=pod_share_path,
        hwcksum=str(enable_hw_checksum).lower(),
        log_level=log_level,
    )
    return content


def service_is_running_on_container(container: Container, service_name: str) -> bool:
    """Return whether a Pebble service is running in a container.

    Args:
        container: Container object
        service_name: Service name

    Returns:
        bool: Whether service is running
    """
    if not container.can_connect():
        return False
    try:
        service = container.get_service(service_name)
    except ModelError:
        return False
    except ConnectionError:
        return False
    return service.is_running()


def push_file(
    container: Container,
    path: Union[str, PurePath],
    source: str,
) -> None:
    """Push source content to path in container.

    Args:
        container: Container object
        path: Path in which content is pushed
        source: Content to be pushed to container
    """
    try:
        container.push(path=path, source=source)
    except ConnectionError:
        return


def path_exists(
    container: Container,
    path: Union[str, PurePath],
) -> bool:
    """Return existence of path in container.

    Args:
        container: Container object
        path: Path to verify the existence of

    Returns:
        bool: existence of path in container
    """
    try:
        return container.exists(path=path)
    except ConnectionError:
        return False


if __name__ == "__main__":  # pragma: no cover
    main(UPFOperatorCharm)
