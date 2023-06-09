#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charmed operator for the SD-Core UPF service."""

import ipaddress
import json
import logging
import time
from typing import Optional, Union

from charms.kubernetes_charm_libraries.v0.multus import (
    KubernetesMultusCharmLib,
    NetworkAnnotation,
    NetworkAttachmentDefinition,
)
from charms.observability_libs.v1.kubernetes_service_patch import KubernetesServicePatch
from charms.prometheus_k8s.v0.prometheus_scrape import MetricsEndpointProvider
from charms.sdcore_upf.v0.fiveg_n3 import N3Provides  # type: ignore[import]
from jinja2 import Environment, FileSystemLoader
from lightkube.models.core_v1 import ServicePort
from lightkube.models.meta_v1 import ObjectMeta
from ops.charm import CharmBase, ConfigChangedEvent, PebbleReadyEvent, EventBase
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
UPF_MODE = "af_packet"
BESSD_PORT = 10514
BESS_WEB_PORT = 8000
PROMETHEUS_PORT = 8080


class UPFOperatorCharm(CharmBase):
    """Main class to describe juju event handling for the 5G UPF operator."""

    def __init__(self, *args):
        super().__init__(*args)
        self._bessd_container_name = self._bessd_service_name = "bessd"
        self._routectl_container_name = self._routectl_service_name = "routectl"
        self._web_container_name = self._web_service_name = "web"
        self._pfcp_agent_container_name = self._pfcp_agent_service_name = "pfcp-agent"
        self._bessd_container = self.unit.get_container(self._bessd_container_name)
        self._routectl_container = self.unit.get_container(self._routectl_container_name)
        self._web_container = self.unit.get_container(self._web_container_name)
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
                ServicePort(name="pfcp", port=8805, protocol="UDP"),
                ServicePort(name="bess-web", port=BESS_WEB_PORT),
                ServicePort(name="prometheus-exporter", port=PROMETHEUS_PORT),
            ],
        )
        self._kubernetes_multus = KubernetesMultusCharmLib(
            charm=self,
            containers_requiring_net_admin_capability=[self._bessd_container_name],
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
        self.framework.observe(self.on.routectl_pebble_ready, self._on_routectl_pebble_ready)
        self.framework.observe(self.on.web_pebble_ready, self._on_web_pebble_ready)
        self.framework.observe(self.on.pfcp_agent_pebble_ready, self._on_pfcp_agent_pebble_ready)
        self.framework.observe(
            self.fiveg_n3_provider.on.fiveg_n3_request, self._update_fiveg_n3_relation_data
        )

    def _update_fiveg_n3_relation_data(self, event: EventBase) -> None:
        """Publishes UPF IP address in the `fiveg_n3` relation data bag.

        Args:
            event: Juju event
        """
        if not self.unit.is_leader():
            return
        if not self._access_ip_config_is_valid():
            self.unit.status = BlockedStatus("Invalid `access-ip` config provided")
            return
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

    def _on_config_changed(self, event: ConfigChangedEvent) -> None:
        if not self._bessd_container.can_connect():
            self.unit.status = WaitingStatus("Waiting for bessd container to be ready")
            event.defer()
            return
        self._on_bessd_pebble_ready(event)
        self._on_pfcp_agent_pebble_ready(event)

    def _network_attachment_definitions_from_config(self) -> list[NetworkAttachmentDefinition]:
        return [
            NetworkAttachmentDefinition(
                metadata=ObjectMeta(name=ACCESS_NETWORK_ATTACHMENT_DEFINITION_NAME),
                spec={
                    "config": json.dumps(
                        {
                            "cniVersion": "0.3.1",
                            "type": "macvlan",
                            "ipam": {
                                "type": "static",
                                "addresses": [
                                    {
                                        "address": self._get_access_network_ip_config(),
                                    }
                                ],
                            },
                            "capabilities": {"mac": True},
                        }
                    )
                },
            ),
            NetworkAttachmentDefinition(
                metadata=ObjectMeta(name=CORE_NETWORK_ATTACHMENT_DEFINITION_NAME),
                spec={
                    "config": json.dumps(
                        {
                            "cniVersion": "0.3.1",
                            "type": "macvlan",
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
                    )
                },
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

    @staticmethod
    def _render_bessd_config_file(
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

    def _on_bessd_pebble_ready(self, event: Union[PebbleReadyEvent, ConfigChangedEvent]) -> None:
        """Handle Pebble ready event."""
        if not self._bessd_container.can_connect():
            self.unit.status = WaitingStatus("Waiting for bessd container to be ready")
            event.defer()
            return
        if not self._kubernetes_multus.is_ready():
            self.unit.status = WaitingStatus("Waiting for Multus to be ready")
            event.defer()
            return
        self._configure_bessd_workload()
        self._set_unit_status()

    def _configure_bessd_workload(self) -> None:
        """Configures bessd workload.

        Writes configuration file, creates routes, creates iptable rule and pebble layer.
        """
        content = self._render_bessd_config_file(
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
        self._create_ip_tables_rule()
        self._create_access_route()
        self._create_core_route()
        self._bessd_container.add_layer("upf", self._bessd_pebble_layer, combine=True)
        self._bessd_container.replan()
        self._run_bess_configuration()

    def _run_bess_configuration(self) -> None:
        """Runs bessd configuration in workload."""
        initial_time = time.time()
        timeout = 30
        while time.time() - initial_time <= timeout:
            try:
                self._exec_command_in_bessd_workload(
                    command="bessctl run /opt/bess/bessctl/conf/up4",
                    environment=self._bessd_environment_variables,
                )
                return
            except ExecError:
                logger.info("Failed running configuration for bess")
                time.sleep(2)
        raise TimeoutError("Timed out trying to run configuration for bess")

    def _get_invalid_configs(self) -> list[str]:
        """Returns list of invalid configurations.

        Returns:
            list: List of strings matching config keys.
        """
        invalid_configs = []
        if not self._get_dnn_config():
            invalid_configs.append("dnn")
        if not self._get_access_network_ip_config():
            invalid_configs.append("access-ip")
        if not self._get_core_network_ip_config():
            invalid_configs.append("core-ip")
        if not self._get_access_network_gateway_ip_config():
            invalid_configs.append("access-gateway-ip")
        if not self._get_core_network_gateway_ip_config():
            invalid_configs.append("core-gateway-ip")
        if not self._get_gnb_subnet_config():
            invalid_configs.append("gnb-subnet")
        return invalid_configs

    def _exec_command_in_bessd_workload(
        self, command: str, environment: Optional[dict] = None
    ) -> tuple:
        """Executes command in bessd container.

        Args:
            command: Command to execute
            environment: Environment Variables
        """
        process = self._bessd_container.exec(
            command=command.split(),
            timeout=30,
            environment=environment,
        )
        return process.wait_output()

    def _create_access_route(self) -> None:
        self._exec_command_in_bessd_workload(
            command=f"ip route replace {self._get_gnb_subnet_config()} via {self._get_access_network_gateway_ip_config()}"  # noqa: E501
        )
        logger.info("Added route for access")

    def _create_core_route(self) -> None:
        self._exec_command_in_bessd_workload(
            command=f"ip route replace default via {self._get_core_network_gateway_ip_config()} metric 110"  # noqa: E501
        )
        logger.info("Added route for core")

    def _create_ip_tables_rule(self) -> None:
        self._exec_command_in_bessd_workload(
            command="iptables -I OUTPUT -p icmp --icmp-type port-unreachable -j DROP"
        )
        logger.info("Iptables rule for ICMP created")

    def _on_routectl_pebble_ready(self, event: PebbleReadyEvent) -> None:
        """Handle routectl Pebble ready event."""
        if not self._routectl_container.can_connect():
            self.unit.status = WaitingStatus("Waiting for routectl container to be ready")
            event.defer()
            return
        if not self._kubernetes_multus.is_ready():
            self.unit.status = WaitingStatus("Waiting for Multus to be ready")
            event.defer()
            return
        self._routectl_container.add_layer("routectl", self._routectl_pebble_layer, combine=True)
        self._routectl_container.replan()
        self._set_unit_status()

    def _on_web_pebble_ready(self, event: PebbleReadyEvent) -> None:
        """Handle web Pebble ready event."""
        if not self._web_container.can_connect():
            self.unit.status = WaitingStatus("Waiting for web container to be ready")
            event.defer()
            return
        if not self._kubernetes_multus.is_ready():
            self.unit.status = WaitingStatus("Waiting for Multus to be ready")
            event.defer()
            return
        self._web_container.add_layer("web", self._web_pebble_layer, combine=True)
        self._web_container.replan()
        self._set_unit_status()

    def _on_pfcp_agent_pebble_ready(
        self, event: Union[PebbleReadyEvent, ConfigChangedEvent]
    ) -> None:
        """Handle pfcp agent Pebble ready event."""
        if not self._pfcp_agent_container.can_connect():
            self.unit.status = WaitingStatus("Waiting for pfcp agent container to be ready")
            event.defer()
            return
        if not self._bessd_config_file_is_written():
            self.unit.status = WaitingStatus("Waiting for config file to be written")
            event.defer()
            return
        if not self._service_is_running_on_container(
            self._bessd_container, self._bessd_service_name
        ):
            self.unit.status = WaitingStatus("Waiting for bessd service to be running")
            event.defer()
            return
        if not self._kubernetes_multus.is_ready():
            self.unit.status = WaitingStatus("Waiting for Multus to be ready")
            event.defer()
            return
        self._pfcp_agent_container.add_layer("pfcp", self._pfcp_agent_pebble_layer, combine=True)
        self._pfcp_agent_container.replan()
        self._set_unit_status()

    def _set_unit_status(self) -> None:
        """Set the unit status based on config and container services running."""
        if invalid_configs := self._get_invalid_configs():
            self.unit.status = BlockedStatus(
                f"The following configurations are not valid: {invalid_configs}"
            )
            return
        if not self._service_is_running_on_container(
            self._bessd_container, self._bessd_service_name
        ):
            self.unit.status = WaitingStatus("Waiting for bessd service to run")
            return
        if not self._service_is_running_on_container(
            self._routectl_container, self._routectl_service_name
        ):
            self.unit.status = WaitingStatus("Waiting for routectl service to run")
            return
        if not self._service_is_running_on_container(self._web_container, self._web_service_name):
            self.unit.status = WaitingStatus("Waiting for web service to run")
            return
        if not self._service_is_running_on_container(
            self._pfcp_agent_container, self._pfcp_agent_service_name
        ):
            self.unit.status = WaitingStatus("Waiting for pfcp agent service to run")
            return
        self.unit.status = ActiveStatus()

    @staticmethod
    def _service_is_running_on_container(container: Container, service_name: str) -> bool:
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
                        "command": f"bessd -f -grpc-url=0.0.0.0:{BESSD_PORT} -m 0",  # "-m 0" means that we are not using hugepages  # noqa: E501
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
    def _routectl_pebble_layer(self) -> Layer:
        return Layer(
            {
                "summary": "routectl layer",
                "description": "pebble config layer for routectl",
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
    def _web_pebble_layer(self) -> Layer:
        return Layer(
            {
                "summary": "web layer",
                "description": "pebble config layer for web",
                "services": {
                    self._web_service_name: {
                        "override": "replace",
                        "startup": "enabled",
                        "command": f"bessctl http 0.0.0.0 {BESS_WEB_PORT}",
                    },
                },
                "checks": {
                    "online": {
                        "override": "replace",
                        "level": "ready",
                        "tcp": {"port": BESS_WEB_PORT},
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
        }

    @property
    def _routectl_environment_variables(self) -> dict:
        return {
            "PYTHONUNBUFFERED": "1",
        }

    def _get_dnn_config(self) -> Optional[str]:
        return self.model.config.get("dnn")

    def _get_core_network_ip_config(self) -> Optional[str]:
        return self.model.config.get("core-ip")

    def _access_ip_config_is_valid(self) -> bool:
        """Checks whether the access-ip config is valid.

        Returns:
            bool: Whether the access-ip config is valid
        """
        return self._ip_config_is_valid("access-ip")

    def _get_access_network_ip_config(self) -> Optional[str]:
        return self.model.config.get("access-ip")

    def _get_core_network_gateway_ip_config(self) -> Optional[str]:
        return self.model.config.get("core-gateway-ip")

    def _get_access_network_gateway_ip_config(self) -> Optional[str]:
        return self.model.config.get("access-gateway-ip")

    def _get_gnb_subnet_config(self) -> Optional[str]:
        return self.model.config.get("gnb-subnet")

    def _ip_config_is_valid(self, config_name: str) -> bool:
        """Check whether given IP config is valid.

        Args:
            config_name (str): Config parameter name

        Returns:
            bool: True if given IP config_name is valid
        """
        try:
            ipaddress.ip_network(self.model.config.get(config_name),
                                 strict=False)  # type: ignore[arg-type]  # noqa: E501
            return True
        except ValueError:
            return False


if __name__ == "__main__":  # pragma: no cover
    main(UPFOperatorCharm)
