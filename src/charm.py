#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charmed operator for the SDCORE UPF service."""

import logging
from typing import Optional

from charms.observability_libs.v1.kubernetes_service_patch import (  # type: ignore[import]  # noqa: E501
    KubernetesServicePatch,
)
from charms.prometheus_k8s.v0.prometheus_scrape import (  # type: ignore[import]  # noqa: E501
    MetricsEndpointProvider,
)
from jinja2 import Environment, FileSystemLoader
from lightkube.models.core_v1 import ServicePort
from ops.charm import CharmBase, PebbleReadyEvent
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, Container, ModelError, WaitingStatus
from ops.pebble import ExecError, Layer

from kubernetes_multus import (
    KubernetesMultusCharmLib,
    NetworkAnnotation,
    NetworkAttachmentDefinition,
)

logger = logging.getLogger(__name__)

BESSD_CONTAINER_CONFIG_PATH = "/etc/bess/conf"
PFCP_AGENT_CONTAINER_CONFIG_PATH = "/tmp/conf"
CONFIG_FILE_NAME = "upf.json"
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
        self.framework.observe(self.on.bessd_pebble_ready, self._on_bessd_pebble_ready)
        self.framework.observe(self.on.routectl_pebble_ready, self._on_routectl_pebble_ready)
        self.framework.observe(self.on.web_pebble_ready, self._on_web_pebble_ready)
        self.framework.observe(self.on.pfcp_agent_pebble_ready, self._on_pfcp_agent_pebble_ready)
        self.framework.observe(self.on.config_changed, self._on_bessd_pebble_ready)
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
                ServicePort(name="bess-web", port=8000),
                ServicePort(name="prometheus-exporter", port=PROMETHEUS_PORT),
            ],
        )
        self._kubernetes_multus = KubernetesMultusCharmLib(
            charm=self,
            network_attachment_definitions=[
                NetworkAttachmentDefinition(name="access-net"),
                NetworkAttachmentDefinition(name="core-net"),
            ],
            network_annotations=[
                NetworkAnnotation(name="access-net", interface="access"),
                NetworkAnnotation(name="core-net", interface="core"),
            ],
        )

    def _write_bessd_config_file(self) -> None:
        """Write the configuration file for the 5G UPF service."""
        jinja2_environment = Environment(loader=FileSystemLoader("src/templates/"))
        template = jinja2_environment.get_template(f"{CONFIG_FILE_NAME}.j2")
        content = template.render(
            upf_hostname=self._upf_hostname,
            mode="af_packet",
        )
        self._bessd_container.push(
            path=f"{BESSD_CONTAINER_CONFIG_PATH}/{CONFIG_FILE_NAME}", source=content
        )
        logger.info(f"Pushed {CONFIG_FILE_NAME} config file")

    @property
    def _upf_hostname(self) -> str:
        """Returns the UPF hostname.

        Returns:
            str: UPF Hostname
        """
        return f"{self.model.app.name}.{self.model.name}.svc.cluster.local"

    @property
    def _bessd_config_file_is_written(self) -> bool:
        """Returns whether the bessd config file was written to the workload container.

        Returns:
            bool: Whether the bessd config file was written
        """
        if not self._bessd_container.exists(f"{BESSD_CONTAINER_CONFIG_PATH}/{CONFIG_FILE_NAME}"):
            logger.info(f"Config file is not written: {CONFIG_FILE_NAME}")
            return False
        logger.info("Config file is written")
        return True

    @property
    def _pfcp_agent_config_file_is_written(self) -> bool:
        """Returns whether the pfcp agent config file was written to the workload container.

        Returns:
            bool: Whether the pfcp agent config file was written
        """
        if not self._pfcp_agent_container.exists(
            f"{PFCP_AGENT_CONTAINER_CONFIG_PATH}/{CONFIG_FILE_NAME}"
        ):
            logger.info(f"Config file is not written: {CONFIG_FILE_NAME}")
            return False
        logger.info("Config file is written")
        return True

    def _on_bessd_pebble_ready(self, event: PebbleReadyEvent) -> None:
        """Handle Pebble ready event for bessd container.

        Args:
            event: PebbleReadyEvent
        """
        if not self._bessd_config_file_is_written:
            self._write_bessd_config_file()
        if not self.access_network_gateway:
            self.unit.status = BlockedStatus("Please set a value for the `access-gateway` config.")
            return
        if not self.core_network_gateway:
            self.unit.status = BlockedStatus("Please set a value for the `core-gateway` config.")
            return
        if not self.gnb_subnet:
            self.unit.status = BlockedStatus("Please set a value for the `gnb-subnet` config.")
            return
        try:
            self._exec_command_in_bessd_workload(
                command=[
                    "ip",
                    "route",
                    "replace",
                    self.gnb_subnet,
                    "via",
                    self.access_network_gateway,
                ]
            )
            self._exec_command_in_bessd_workload(
                command=[
                    "ip",
                    "route",
                    "replace",
                    "default",
                    "via",
                    self.core_network_gateway,
                    "metric",
                    "110",
                ],
            )
            self._exec_command_in_bessd_workload(
                command=[
                    "iptables",
                    "-I",
                    "OUTPUT",
                    "-p",
                    "icmp",
                    "--icmp-type",
                    "port-unreachable",
                    "-j",
                    "DROP",
                ],
            )
        except ExecError:
            self.unit.status = WaitingStatus("Cannot execute command in workload, waiting.")
            event.defer()
            return
        self._bessd_container.add_layer("upf", self._bessd_pebble_layer, combine=True)
        self._bessd_container.replan()
        self._exec_command_in_bessd_workload(
            command=["bessctl run /opt/bess/bessctl/conf/up4"],
            environment=self._bessd_environment_variables,
        )
        self._set_unit_status()

    def _exec_command_in_bessd_workload(
        self, command: list, environment: Optional[dict] = None
    ) -> None:
        """Executes command in bessd container.

        Args:
            command: Command to execute
            environment: Environment Variables
        """
        process = self._bessd_container.exec(command=command, timeout=30, environment=environment)
        try:
            process.wait_output()
        except ExecError as e:
            logger.error("Exited with code %d. Stderr:", e.exit_code)
            if e.stderr:
                for line in e.stderr.splitlines():
                    logger.error("    %s", line)
            raise e

    def _on_routectl_pebble_ready(self, event: PebbleReadyEvent) -> None:
        """Handle Pebble ready event for routectl container.

        Args:
            event: PebbleReadyEvent
        """
        self._routectl_container.add_layer("routectl", self._routectl_pebble_layer, combine=True)
        self._routectl_container.replan()
        self._set_unit_status()

    def _on_web_pebble_ready(self, event: PebbleReadyEvent) -> None:
        """Handle Pebble ready event for web container.

        Args:
            event: PebbleReadyEvent
        """
        self._web_container.add_layer("web", self._web_pebble_layer, combine=True)
        self._web_container.replan()
        self._set_unit_status()

    def _on_pfcp_agent_pebble_ready(self, event: PebbleReadyEvent) -> None:
        """Handle Pebble ready event for pfcp agent container.

        Args:
            event: PebbleReadyEvent
        """
        if not self._pfcp_agent_config_file_is_written:
            self.unit.status = WaitingStatus("Waiting for pfcp agent config file to be written")
            event.defer()
            return
        if not self._service_is_running(self._bessd_container, self._bessd_service_name):
            self.unit.status = WaitingStatus("Waiting for bessd service to be running")
            event.defer()
            return
        self._pfcp_agent_container.add_layer("pfcp", self._pfcp_agent_pebble_layer, combine=True)
        self._pfcp_agent_container.replan()
        self._set_unit_status()

    def _set_unit_status(self) -> None:
        """Set the application status based on container services being running."""
        if not self._service_is_running(self._bessd_container, self._bessd_service_name):
            self.unit.status = WaitingStatus("Waiting for bessd service to run")
            return
        if not self._service_is_running(self._routectl_container, self._routectl_service_name):
            self.unit.status = WaitingStatus("Waiting for routectl service to run")
            return
        if not self._service_is_running(self._web_container, self._web_service_name):
            self.unit.status = WaitingStatus("Waiting for web service to run")
            return
        if not self._service_is_running(self._pfcp_agent_container, self._pfcp_agent_service_name):
            self.unit.status = WaitingStatus("Waiting for pfcp agent service to run")
            return
        self.unit.status = ActiveStatus()

    @staticmethod
    def _service_is_running(container: Container, service_name: str) -> bool:
        """Returns whether a Linux service is running in a container.

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
        """Returns pebble layer for the bessd container.

        Returns:
            Layer: Pebble Layer
        """
        return Layer(
            {
                "summary": "bessd layer",
                "description": "pebble config layer for bessd",
                "services": {
                    self._bessd_service_name: {
                        "override": "replace",
                        "startup": "enabled",
                        "command": "bessd -f -grpc-url=0.0.0.0:10514 -m 0",  # "-m 0" means that we are not using hugepages  # noqa: E501
                        "environment": self._bessd_environment_variables,
                    },
                },
            }
        )

    @property
    def _routectl_pebble_layer(self) -> Layer:
        """Returns pebble layer for the routectl container.

        Returns:
            Layer: Pebble Layer
        """
        return Layer(
            {
                "summary": "routectl layer",
                "description": "pebble config layer for routectl",
                "services": {
                    self._routectl_service_name: {
                        "override": "replace",
                        "startup": "enabled",
                        "command": "/opt/bess/bessctl/conf/route_control.py -i access core",
                        "environment": self._routectl_environment_variables,
                    },
                },
            }
        )

    @property
    def _web_pebble_layer(self) -> Layer:
        """Returns pebble layer for the web container.

        Returns:
            Layer: Pebble Layer
        """
        return Layer(
            {
                "summary": "web layer",
                "description": "pebble config layer for web",
                "services": {
                    self._web_service_name: {
                        "override": "replace",
                        "startup": "enabled",
                        "command": "bessctl http 0.0.0.0 8000",
                    },
                },
            }
        )

    @property
    def _pfcp_agent_pebble_layer(self) -> Layer:
        """Returns pebble layer for the pfcp agent container.

        Returns:
            Layer: Pebble Layer
        """
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
        """Returns environment variables for the bessd service.

        Returns:
            dict: Environment variables
        """
        return {
            "CONF_FILE": f"{BESSD_CONTAINER_CONFIG_PATH}/{CONFIG_FILE_NAME}",
        }

    @property
    def _routectl_environment_variables(self) -> dict:
        """Returns environment variables for the routectl service.

        Returns:
            dict: Environment variables
        """
        return {
            "PYTHONUNBUFFERED": "1",
        }

    @property
    def core_network_gateway(self) -> Optional[str]:
        """Core network gateway IP address."""
        return self.model.config.get("core-gateway")

    @property
    def access_network_gateway(self) -> Optional[str]:
        """Access network gateway IP address."""
        return self.model.config.get("access-gateway")

    @property
    def gnb_subnet(self) -> Optional[str]:
        """Gnodeb subnet."""
        return self.model.config.get("gnb-subnet")


if __name__ == "__main__":
    main(UPFOperatorCharm)
