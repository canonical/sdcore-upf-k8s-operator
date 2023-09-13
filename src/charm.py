#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charmed operator for the SD-Core UPF service."""

import ipaddress
import json
import logging
import time
from subprocess import check_output
from typing import Optional

from charms.kubernetes_charm_libraries.v0.multus import (  # type: ignore[import]
    KubernetesMultusCharmLib,
    NetworkAnnotation,
    NetworkAttachmentDefinition,
)
from charms.observability_libs.v1.kubernetes_service_patch import (  # type: ignore[import]
    KubernetesServicePatch,
)
from charms.prometheus_k8s.v0.prometheus_scrape import (  # type: ignore[import]
    MetricsEndpointProvider,
)
from charms.sdcore_upf.v0.fiveg_n3 import N3Provides  # type: ignore[import]
from jinja2 import Environment, FileSystemLoader
from lightkube.core.client import Client
from lightkube.models.core_v1 import ServicePort, ServiceSpec
from lightkube.models.meta_v1 import ObjectMeta
from lightkube.resources.core_v1 import Service
from ops import RemoveEvent
from ops.charm import CharmBase
from ops.framework import EventBase
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, Container, ModelError, WaitingStatus
from ops.pebble import ExecError, Layer

logger = logging.getLogger(__name__)

BESSD_CONTAINER_CONFIG_PATH = "/etc/bess/conf"
PFCP_AGENT_CONTAINER_CONFIG_PATH = "/tmp/conf"
POD_SHARE_PATH = "/pod-share"
ACCESS_NETWORK_ATTACHMENT_DEFINITION_NAME = "access-net"
CORE_NETWORK_ATTACHMENT_DEFINITION_NAME = "core-net"
ACCESS_INTERFACE_NAME = "access"
CORE_INTERFACE_NAME = "core"
CONFIG_FILE_NAME = "upf.json"
BESSCTL_CONFIGURE_EXECUTED_FILE_NAME = "bessctl_configure_executed"
UPF_MODE = "af_packet"
BESSD_PORT = 10514
PROMETHEUS_PORT = 8080
PFCP_PORT = 8805
REQUIRED_CPU_EXTENSIONS = ["avx2", "rdrand"]


class IncompatibleCPUError(Exception):
    """Custom error to be raised when CPU doesn't support required instructions."""

    pass


class UPFOperatorCharm(CharmBase):
    """Main class to describe juju event handling for the 5G UPF operator."""

    def __init__(self, *args):
        super().__init__(*args)
        self._bessd_container_name = self._bessd_service_name = "bessd"
        self._routectl_service_name = "routectl"
        self._pfcp_agent_container_name = self._pfcp_agent_service_name = "pfcp-agent"
        self._bessd_container = self.unit.get_container(self._bessd_container_name)
        self._pfcp_agent_container = self.unit.get_container(self._pfcp_agent_container_name)
        self.fiveg_n3_provider = N3Provides(charm=self, relation_name="fiveg_n3")
        self._metrics_endpoint = MetricsEndpointProvider(
            self,
            jobs=[
                {
                    "static_configs": [{"targets": [f"*:{PROMETHEUS_PORT}"]}],
                }
            ],
        )
        self._service_patcher = KubernetesServicePatch(
            charm=self,
            ports=[
                ServicePort(name="pfcp", port=PFCP_PORT, protocol="UDP"),
                ServicePort(name="prometheus-exporter", port=PROMETHEUS_PORT),
            ],
        )
        self._kubernetes_multus = KubernetesMultusCharmLib(
            charm=self,
            container_name=self._bessd_container_name,
            cap_net_admin=True,
            network_annotations=[
                NetworkAnnotation(
                    name=ACCESS_NETWORK_ATTACHMENT_DEFINITION_NAME,
                    interface=ACCESS_INTERFACE_NAME,
                ),
                NetworkAnnotation(
                    name=CORE_NETWORK_ATTACHMENT_DEFINITION_NAME,
                    interface=CORE_INTERFACE_NAME,
                ),
            ],
            network_attachment_definitions_func=self._network_attachment_definitions_from_config,
        )
        self.framework.observe(self.on.config_changed, self._on_config_changed)
        self.framework.observe(self.on.bessd_pebble_ready, self._on_bessd_pebble_ready)
        self.framework.observe(self.on.pfcp_agent_pebble_ready, self._on_pfcp_agent_pebble_ready)
        self.framework.observe(
            self.fiveg_n3_provider.on.fiveg_n3_request, self._on_fiveg_n3_request
        )
        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.on.remove, self._on_remove)

    def _create_external_upf_service(self) -> None:
        client = Client()
        service = Service(
            apiVersion="v1",
            kind="Service",
            metadata=ObjectMeta(
                namespace=self._namespace,
                name=f"{self.app.name}-external",
                labels={
                    "app.kubernetes.io/name": self.app.name,
                },
            ),
            spec=ServiceSpec(
                selector={
                    "app.kubernetes.io/name": self.app.name,
                },
                ports=[
                    ServicePort(name="pfcp", port=PFCP_PORT, protocol="UDP"),
                ],
                type="LoadBalancer",
            ),
        )

        client.create(service)
        logger.info("Created external UPF service")

    def _on_remove(self, event: RemoveEvent) -> None:
        self._delete_external_upf_service()

    def _delete_external_upf_service(self) -> None:
        client = Client()
        client.delete(
            Service,
            name=f"{self.app.name}-external",
            namespace=self._namespace,
        )
        logger.info("Deleted external UPF service")

    @property
    def _namespace(self) -> str:
        """Returns the k8s namespace."""
        return self.model.name

    def _on_install(self, event: EventBase) -> None:
        """Handler for Juju install event.

        This handler enforces usage of a CPU which supports instructions required to run this
        charm. If the CPU doesn't meet the requirements, charm goes to Blocked state.

        Args:
            event: Juju event
        """
        if not self._is_cpu_compatible():
            raise IncompatibleCPUError(
                "\nCPU is not compatible!\n"
                "Please use a CPU that has the following capabilities: "
                f"{', '.join(REQUIRED_CPU_EXTENSIONS)}"
            )
        self._create_external_upf_service()

    def _on_fiveg_n3_request(self, event: EventBase) -> None:
        """Handles 5G N3 requests events.

        Args:
            event: Juju event
        """
        if not self.unit.is_leader():
            return
        self._update_fiveg_n3_relation_data()

    def _update_fiveg_n3_relation_data(self) -> None:
        """Publishes UPF IP address in the `fiveg_n3` relation data bag."""
        upf_access_ip_address = self._get_access_network_ip_config().split("/")[0]  # type: ignore[union-attr]  # noqa: E501
        fiveg_n3_relations = self.model.relations.get("fiveg_n3")
        if not fiveg_n3_relations:
            logger.info("No `fiveg_n3` relations found.")
            return
        for fiveg_n3_relation in fiveg_n3_relations:
            self.fiveg_n3_provider.publish_upf_information(
                relation_id=fiveg_n3_relation.id,
                upf_ip_address=upf_access_ip_address,
            )

    def _network_attachment_definitions_from_config(self) -> list[NetworkAttachmentDefinition]:
        """Returns list of Multus NetworkAttachmentDefinitions to be created based on config."""
        access_nad_config = {
            "cniVersion": "0.3.1",
            "ipam": {
                "type": "static",
                "routes": [
                    {
                        "dst": self._get_gnb_subnet_config(),
                        "gw": self._get_access_network_gateway_ip_config(),
                    },
                ],
                "addresses": [
                    {
                        "address": self._get_access_network_ip_config(),
                    }
                ],
            },
            "capabilities": {"mac": True},
        }
        if (access_interface := self._get_access_interface_config()) is not None:
            access_nad_config.update({"type": "macvlan", "master": access_interface})
        else:
            access_nad_config.update({"type": "bridge", "bridge": "access-br"})
        core_nad_config = {
            "cniVersion": "0.3.1",
            "ipam": {
                "type": "static",
                "addresses": [
                    {
                        "address": self._get_core_network_ip_config(),
                    }
                ],
            },
            "capabilities": {"mac": True},
        }
        if (core_interface := self._get_core_interface_config()) is not None:
            core_nad_config.update({"type": "macvlan", "master": core_interface})
        else:
            core_nad_config.update({"type": "bridge", "bridge": "core-br"})
        return [
            NetworkAttachmentDefinition(
                metadata=ObjectMeta(name=ACCESS_NETWORK_ATTACHMENT_DEFINITION_NAME),
                spec={"config": json.dumps(access_nad_config)},
            ),
            NetworkAttachmentDefinition(
                metadata=ObjectMeta(name=CORE_NETWORK_ATTACHMENT_DEFINITION_NAME),
                spec={"config": json.dumps(core_nad_config)},
            ),
        ]

    def _write_bessd_config_file(self, content: str) -> None:
        """Write the configuration file for the 5G UPF service.

        Args:
            content: Bessd config file content
        """
        self._bessd_container.push(
            path=f"{BESSD_CONTAINER_CONFIG_PATH}/{CONFIG_FILE_NAME}", source=content
        )
        logger.info("Pushed %s config file", CONFIG_FILE_NAME)

    @property
    def _upf_hostname(self) -> str:
        return f"{self.model.app.name}.{self.model.name}.svc.cluster.local"

    def _bessd_config_file_is_written(self) -> bool:
        """Returns whether the bessd config file was written to the workload container.

        Returns:
            bool: Whether the bessd config file was written
        """
        return self._bessd_container.exists(
            path=f"{BESSD_CONTAINER_CONFIG_PATH}/{CONFIG_FILE_NAME}"
        )

    def _bessd_config_file_content_matches(self, content: str) -> bool:
        """Returns whether the bessd config file content matches the provided content.

        Returns:
            bool: Whether the bessd config file content matches
        """
        existing_content = self._bessd_container.pull(
            path=f"{BESSD_CONTAINER_CONFIG_PATH}/{CONFIG_FILE_NAME}"
        )
        if existing_content.read() != content:
            return False
        return True

    def _on_config_changed(self, event: EventBase):
        """Handler for config changed events."""
        if not self.unit.is_leader():
            return
        if invalid_configs := self._get_invalid_configs():
            self.unit.status = BlockedStatus(
                f"The following configurations are not valid: {invalid_configs}"
            )
            return
        if not self._bessd_container.can_connect():
            self.unit.status = WaitingStatus("Waiting for bessd container to be ready")
            event.defer()
            return
        if not self._pfcp_agent_container.can_connect():
            self.unit.status = WaitingStatus("Waiting for pfcp agent container to be ready")
            event.defer()
            return
        self._on_bessd_pebble_ready(event)
        self._on_pfcp_agent_pebble_ready(event)

    def _on_bessd_pebble_ready(self, event: EventBase) -> None:
        """Handle Pebble ready event."""
        if not self.unit.is_leader():
            return
        if not self._kubernetes_multus.is_ready():
            self.unit.status = WaitingStatus("Waiting for Multus to be ready")
            event.defer()
            return
        if not self._bessd_container.exists(path=BESSD_CONTAINER_CONFIG_PATH):
            self.unit.status = WaitingStatus("Waiting for storage to be attached")
            event.defer()
            return
        self._configure_bessd_workload()
        self._set_unit_status()

    def _on_pfcp_agent_pebble_ready(self, event: EventBase) -> None:
        """Handle pfcp agent Pebble ready event."""
        if not self.unit.is_leader():
            return
        if not service_is_running_on_container(self._bessd_container, self._bessd_service_name):
            self.unit.status = WaitingStatus("Waiting for bessd service to run")
            event.defer()
            return
        self._configure_pfcp_agent_workload()
        self._update_fiveg_n3_relation_data()
        self._set_unit_status()

    def _configure_bessd_workload(self) -> None:
        """Configures bessd workload.

        Writes configuration file, creates routes, creates iptable rule and pebble layer.
        """
        restart = False
        content = render_bessd_config_file(
            upf_hostname=self._upf_hostname,
            upf_mode=UPF_MODE,
            access_interface_name=ACCESS_INTERFACE_NAME,
            core_interface_name=CORE_INTERFACE_NAME,
            dnn=self._get_dnn_config(),  # type: ignore[arg-type]
            pod_share_path=POD_SHARE_PATH,
        )
        if not self._bessd_config_file_is_written() or not self._bessd_config_file_content_matches(
            content=content
        ):
            self._write_bessd_config_file(content=content)
            restart = True
        self._create_default_route()
        if not self._ip_tables_rule_exists():
            self._create_ip_tables_rule()
        plan = self._bessd_container.get_plan()
        layer = self._bessd_pebble_layer
        if plan.services != layer.services:
            self._bessd_container.add_layer("bessd", self._bessd_pebble_layer, combine=True)
            restart = True
        if restart:
            self._bessd_container.restart(self._routectl_service_name)
            logger.info("Service `routectl` restarted")
            self._bessd_container.restart(self._bessd_service_name)
            logger.info("Service `bessd` restarted")
        self._run_bess_configuration()

    def _run_bess_configuration(self) -> None:
        """Runs bessd configuration in workload."""
        initial_time = time.time()
        timeout = 300
        while time.time() - initial_time <= timeout:
            try:
                if not self._is_bessctl_executed():
                    logger.info("Starting configuration of the `bessd` service")
                    self._exec_command_in_bessd_workload(
                        command="/opt/bess/bessctl/bessctl run /opt/bess/bessctl/conf/up4",
                        timeout=timeout,
                        environment=self._bessd_environment_variables,
                    )
                    message = "Service `bessd` configured"
                    logger.info(message)
                    self._create_bessctl_executed_validation_file(message)
                    return
                return
            except ExecError:
                logger.info("Failed running configuration for bess")
                time.sleep(2)
        raise TimeoutError("Timed out trying to run configuration for bess")

    def _is_bessctl_executed(self) -> bool:
        """Check if BESSD_CONFIG_CHECK_FILE_NAME exists.

        If bessctl configure is executed once this file exists.

        Returns:
            bool:   True/False
        """
        return self._bessd_container.exists(
            path=f"{BESSD_CONTAINER_CONFIG_PATH}/{BESSCTL_CONFIGURE_EXECUTED_FILE_NAME}"
        )

    def _create_bessctl_executed_validation_file(self, content) -> None:
        """This creates BESSCTL_CONFIGURE_EXECUTED_FILE_NAME under BESSD_CONTAINER_CONFIG_PATH."""
        self._bessd_container.push(
            path=f"{BESSD_CONTAINER_CONFIG_PATH}/{BESSCTL_CONFIGURE_EXECUTED_FILE_NAME}",
            source=content,
        )
        logger.info("Pushed %s configuration check file", BESSCTL_CONFIGURE_EXECUTED_FILE_NAME)

    def _get_invalid_configs(self) -> list[str]:
        """Returns list of invalid configurations.

        Returns:
            list: List of strings matching config keys.
        """
        invalid_configs = []
        if not self._get_dnn_config():
            invalid_configs.append("dnn")
        if not self._access_ip_config_is_valid():
            invalid_configs.append("access-ip")
        if not self._core_ip_config_is_valid():
            invalid_configs.append("core-ip")
        if not self._access_gateway_ip_config_is_valid():
            invalid_configs.append("access-gateway-ip")
        if not self._core_gateway_ip_config_is_valid():
            invalid_configs.append("core-gateway-ip")
        if not self._gnb_subnet_config_is_valid():
            invalid_configs.append("gnb-subnet")
        return invalid_configs

    def _create_default_route(self) -> None:
        """Creates ip route towards core network."""
        self._exec_command_in_bessd_workload(
            command=f"ip route replace default via {self._get_core_network_gateway_ip_config()} metric 110"  # noqa: E501
        )
        logger.info("Default core network route created")

    def _ip_tables_rule_exists(self) -> bool:
        """Returns whether iptables rule already exists using the `--check` parameter.

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
        """Creates iptable rule in the OUTPUT chain to block ICMP port-unreachable packets."""
        self._exec_command_in_bessd_workload(
            command="iptables-legacy -I OUTPUT -p icmp --icmp-type port-unreachable -j DROP"
        )
        logger.info("Iptables rule for ICMP created")

    def _exec_command_in_bessd_workload(
        self, command: str, timeout: Optional[int] = 30, environment: Optional[dict] = None
    ) -> tuple:
        """Executes command in bessd container.

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
        for line in process.stdout:
            logger.info(line)
        for line in process.stderr:
            logger.error(line)
        return process.wait_output()

    def _configure_pfcp_agent_workload(self) -> None:
        """Configures pebble layer for `pfcp-agent` container."""
        plan = self._pfcp_agent_container.get_plan()
        layer = self._pfcp_agent_pebble_layer
        if plan.services != layer.services:
            self._pfcp_agent_container.add_layer(
                "pfcp", self._pfcp_agent_pebble_layer, combine=True
            )
            self._pfcp_agent_container.restart(self._pfcp_agent_service_name)
            logger.info("Service `pfcp` restarted")

    def _set_unit_status(self) -> None:
        """Set the unit status based on config and container services running."""
        if invalid_configs := self._get_invalid_configs():
            self.unit.status = BlockedStatus(
                f"The following configurations are not valid: {invalid_configs}"
            )
            return
        if not service_is_running_on_container(self._bessd_container, self._bessd_service_name):
            self.unit.status = WaitingStatus("Waiting for bessd service to run")
            return
        if not service_is_running_on_container(self._bessd_container, self._routectl_service_name):
            self.unit.status = WaitingStatus("Waiting for routectl service to run")
            return
        if not service_is_running_on_container(
            self._pfcp_agent_container, self._pfcp_agent_service_name
        ):
            self.unit.status = WaitingStatus("Waiting for pfcp agent service to run")
            return
        self.unit.status = ActiveStatus()

    @property
    def _bessd_pebble_layer(self) -> Layer:
        return Layer(
            {
                "summary": "bessd layer",
                "description": "pebble config layer for bessd",
                "services": {
                    self._routectl_service_name: {
                        "override": "replace",
                        "startup": "enabled",
                        "command": f"/opt/bess/bessctl/conf/route_control.py -i {ACCESS_INTERFACE_NAME} {CORE_INTERFACE_NAME}",  # noqa: E501
                        "environment": self._routectl_environment_variables,
                    },
                    self._bessd_service_name: {
                        "override": "replace",
                        "startup": "enabled",
                        "command": f"/bin/bessd -f -grpc-url=0.0.0.0:{BESSD_PORT} -m 0",  # "-m 0" means that we are not using hugepages  # noqa: E501
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

    def _get_dnn_config(self) -> Optional[str]:
        return self.model.config.get("dnn")

    def _core_ip_config_is_valid(self) -> bool:
        """Checks whether the core-ip config is valid.

        Returns:
            bool: Whether the core-ip config is valid
        """
        core_ip = self._get_core_network_ip_config()
        if not core_ip:
            return False
        return ip_is_valid(core_ip)

    def _get_core_network_ip_config(self) -> Optional[str]:
        return self.model.config.get("core-ip")

    def _get_core_interface_config(self) -> Optional[str]:
        return self.model.config.get("core-interface")

    def _access_ip_config_is_valid(self) -> bool:
        """Checks whether the access-ip config is valid.

        Returns:
            bool: Whether the access-ip config is valid
        """
        access_ip = self._get_access_network_ip_config()
        if not access_ip:
            return False
        return ip_is_valid(access_ip)

    def _get_access_network_ip_config(self) -> Optional[str]:
        return self.model.config.get("access-ip")

    def _get_access_interface_config(self) -> Optional[str]:
        return self.model.config.get("access-interface")

    def _core_gateway_ip_config_is_valid(self) -> bool:
        """Checks whether the core-gateway-ip config is valid.

        Returns:
            bool: Whether the core-gateway-ip config is valid
        """
        core_gateway_ip = self._get_core_network_gateway_ip_config()
        if not core_gateway_ip:
            return False
        return ip_is_valid(core_gateway_ip)

    def _get_core_network_gateway_ip_config(self) -> Optional[str]:
        return self.model.config.get("core-gateway-ip")

    def _access_gateway_ip_config_is_valid(self) -> bool:
        """Checks whether the access-gateway-ip config is valid.

        Returns:
            bool: Whether the access-gateway-ip config is valid
        """
        access_gateway_ip = self._get_access_network_gateway_ip_config()
        if not access_gateway_ip:
            return False
        return ip_is_valid(access_gateway_ip)

    def _get_access_network_gateway_ip_config(self) -> Optional[str]:
        return self.model.config.get("access-gateway-ip")

    def _gnb_subnet_config_is_valid(self) -> bool:
        """Checks whether the gnb-subnet config is valid.

        Returns:
            bool: Whether the gnb-subnet config is valid
        """
        gnb_subnet = self._get_gnb_subnet_config()
        if not gnb_subnet:
            return False
        return ip_is_valid(gnb_subnet)

    def _get_gnb_subnet_config(self) -> Optional[str]:
        return self.model.config.get("gnb-subnet")

    def _is_cpu_compatible(self) -> bool:
        """Returns whether the CPU meets requirements to run this charm.

        Returns:
            bool: Whether the CPU meets requirements to run this charm
        """
        return all(
            required_extension in self._get_cpu_extensions()
            for required_extension in REQUIRED_CPU_EXTENSIONS
        )

    @staticmethod
    def _get_cpu_extensions() -> list[str]:
        """Returns a list of extensions (instructions) supported by the CPU.

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


def render_bessd_config_file(
    upf_hostname: str,
    upf_mode: str,
    access_interface_name: str,
    core_interface_name: str,
    dnn: str,
    pod_share_path: str,
) -> str:
    """Renders the configuration file for the 5G UPF service.

    Args:
        upf_hostname: UPF hostname
        upf_mode: UPF mode
        access_interface_name: Access network interface name
        core_interface_name: Core network interface name
        dnn: Data Network Name (DNN)
        pod_share_path: pod_share path
    """
    jinja2_environment = Environment(loader=FileSystemLoader("src/templates/"))
    template = jinja2_environment.get_template(f"{CONFIG_FILE_NAME}.j2")
    content = template.render(
        upf_hostname=upf_hostname,
        mode=upf_mode,
        access_interface_name=access_interface_name,
        core_interface_name=core_interface_name,
        dnn=dnn,
        pod_share_path=pod_share_path,
    )
    return content


def service_is_running_on_container(container: Container, service_name: str) -> bool:
    """Returns whether a Pebble service is running in a container.

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
    return service.is_running()


def ip_is_valid(ip_address: str) -> bool:
    """Check whether given IP config is valid.

    Args:
        ip_address (str): IP address

    Returns:
        bool: True if given IP address is valid
    """
    try:
        ipaddress.ip_network(ip_address, strict=False)
        return True
    except ValueError:
        return False


if __name__ == "__main__":  # pragma: no cover
    main(UPFOperatorCharm)
