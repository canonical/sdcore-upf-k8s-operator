# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


import os
import tempfile

import scenario
from ops.pebble import Layer, ServiceStatus

from tests.unit.fixtures import UPFUnitTestFixtures


class TestCharmBessdPebbleReady(UPFUnitTestFixtures):
    def test_given_bessd_container_ready_when_bessd_pebble_ready_then_config_file_is_created(
        self,
    ):
        gnb_subnet = "2.2.2.0/24"
        core_gateway_ip = "1.2.3.4"
        access_gateway_ip = "2.1.1.1"
        self.mock_check_output.return_value = b"Flags: avx2 ssse3 fma cx16 rdrand"
        with tempfile.TemporaryDirectory() as temp_file:
            bessd_config_mount = scenario.Mount(
                location="/etc/bess/conf/",
                src=temp_file,
            )
            pfcp_agent_container = scenario.Container(
                name="pfcp-agent",
                can_connect=True,
                layers={
                    "pfcp-agent": Layer({"services": {"pfcp-agent": {}}}),
                },
                service_status={"pfcp-agent": ServiceStatus.ACTIVE},
            )
            bessd_container = scenario.Container(
                name="bessd",
                mounts={"config": bessd_config_mount},
                can_connect=True,
                exec_mock={
                    ("ip", "route", "show"): scenario.ExecOutput(
                        return_code=0,
                        stdout=f"default via {core_gateway_ip}\n {gnb_subnet} via {access_gateway_ip}",  # noqa: E501
                        stderr="",
                    ),
                    ("/opt/bess/bessctl/bessctl", "show", "version"): scenario.ExecOutput(
                        return_code=0,
                        stdout="",
                        stderr="",
                    ),
                    ("/opt/bess/bessctl/bessctl", "show", "worker"): scenario.ExecOutput(
                        return_code=0,
                        stdout="RUNNING",
                        stderr="",
                    ),
                    (
                        "/opt/bess/bessctl/bessctl",
                        "show",
                        "module",
                        "accessRoutes",
                    ): scenario.ExecOutput(
                        return_code=0,
                        stdout="",
                        stderr="",
                    ),
                    (
                        "/opt/bess/bessctl/bessctl",
                        "show",
                        "module",
                        "coreRoutes",
                    ): scenario.ExecOutput(
                        return_code=0,
                        stdout="",
                        stderr="",
                    ),
                    (
                        "iptables-legacy",
                        "--check",
                        "OUTPUT",
                        "-p",
                        "icmp",
                        "--icmp-type",
                        "port-unreachable",
                        "-j",
                        "DROP",
                    ): scenario.ExecOutput(
                        return_code=0,
                        stdout="",
                        stderr="",
                    ),
                },
            )
            self.mock_k8s_service.is_created.return_value = True
            state_in = scenario.State(
                leader=True,
                containers=[bessd_container, pfcp_agent_container],
                config={
                    "core-gateway-ip": core_gateway_ip,
                    "access-gateway-ip": access_gateway_ip,
                    "gnb-subnet": gnb_subnet,
                },
                model=scenario.Model(name="whatever"),
            )

            self.ctx.run(bessd_container.pebble_ready_event, state_in)

            with open("tests/unit/expected_upf.json", "r") as f:
                expected_upf_config = f.read()

            with open(f"{temp_file}/upf.json", "r") as f:
                actual_upf_config = f.read()

            assert actual_upf_config.strip() == expected_upf_config.strip()

    def test_given_config_file_already_written_when_bessd_pebble_ready_then_config_file_is_not_pushed(  # noqa: E501
        self,
    ):
        gnb_subnet = "2.2.2.0/24"
        core_gateway_ip = "1.2.3.4"
        access_gateway_ip = "2.1.1.1"
        self.mock_check_output.return_value = b"Flags: avx2 ssse3 fma cx16 rdrand"
        with tempfile.TemporaryDirectory() as temp_file:
            bessd_config_mount = scenario.Mount(
                location="/etc/bess/conf/",
                src=temp_file,
            )
            pfcp_agent_container = scenario.Container(
                name="pfcp-agent",
                can_connect=True,
                layers={
                    "pfcp-agent": Layer({"services": {"pfcp-agent": {}}}),
                },
                service_status={"pfcp-agent": ServiceStatus.ACTIVE},
            )
            bessd_container = scenario.Container(
                name="bessd",
                mounts={"config": bessd_config_mount},
                can_connect=True,
                exec_mock={
                    ("ip", "route", "show"): scenario.ExecOutput(
                        return_code=0,
                        stdout=f"default via {core_gateway_ip}\n {gnb_subnet} via {access_gateway_ip}",  # noqa: E501
                        stderr="",
                    ),
                    ("/opt/bess/bessctl/bessctl", "show", "version"): scenario.ExecOutput(
                        return_code=0,
                        stdout="",
                        stderr="",
                    ),
                    ("/opt/bess/bessctl/bessctl", "show", "worker"): scenario.ExecOutput(
                        return_code=0,
                        stdout="RUNNING",
                        stderr="",
                    ),
                    (
                        "/opt/bess/bessctl/bessctl",
                        "show",
                        "module",
                        "accessRoutes",
                    ): scenario.ExecOutput(
                        return_code=0,
                        stdout="",
                        stderr="",
                    ),
                    (
                        "/opt/bess/bessctl/bessctl",
                        "show",
                        "module",
                        "coreRoutes",
                    ): scenario.ExecOutput(
                        return_code=0,
                        stdout="",
                        stderr="",
                    ),
                    (
                        "iptables-legacy",
                        "--check",
                        "OUTPUT",
                        "-p",
                        "icmp",
                        "--icmp-type",
                        "port-unreachable",
                        "-j",
                        "DROP",
                    ): scenario.ExecOutput(
                        return_code=0,
                        stdout="",
                        stderr="",
                    ),
                },
            )
            self.mock_k8s_service.is_created.return_value = True
            state_in = scenario.State(
                leader=True,
                containers=[bessd_container, pfcp_agent_container],
                config={
                    "core-gateway-ip": core_gateway_ip,
                    "access-gateway-ip": access_gateway_ip,
                    "gnb-subnet": gnb_subnet,
                },
                model=scenario.Model(name="whatever"),
            )
            with open("tests/unit/expected_upf.json", "r") as f:
                expected_upf_config = f.read()
            with open(f"{temp_file}/upf.json", "w") as f:
                f.write(expected_upf_config.strip())
            config_modification_time = os.stat(f"{temp_file}/upf.json").st_mtime

            self.ctx.run(bessd_container.pebble_ready_event, state_in)

            with open(f"{temp_file}/upf.json", "r") as f:
                actual_upf_config = f.read()
            assert actual_upf_config.strip() == expected_upf_config.strip()
            assert os.stat(f"{temp_file}/upf.json").st_mtime == config_modification_time

    def test_given_bessd_container_ready_when_bessd_pebble_ready_then_pebble_layer_is_created(
        self,
    ):
        gnb_subnet = "2.2.2.0/24"
        core_gateway_ip = "1.2.3.4"
        access_gateway_ip = "2.1.1.1"
        self.mock_check_output.return_value = b"Flags: avx2 ssse3 fma cx16 rdrand"
        with tempfile.TemporaryDirectory() as temp_file:
            bessd_config_mount = scenario.Mount(
                location="/etc/bess/conf/",
                src=temp_file,
            )
            pfcp_agent_container = scenario.Container(
                name="pfcp-agent",
                can_connect=True,
                layers={
                    "pfcp-agent": Layer({"services": {"pfcp-agent": {}}}),
                },
                service_status={"pfcp-agent": ServiceStatus.ACTIVE},
            )
            bessd_container = scenario.Container(
                name="bessd",
                mounts={"config": bessd_config_mount},
                can_connect=True,
                exec_mock={
                    ("ip", "route", "show"): scenario.ExecOutput(
                        return_code=0,
                        stdout=f"default via {core_gateway_ip}\n {gnb_subnet} via {access_gateway_ip}",  # noqa: E501
                        stderr="",
                    ),
                    ("/opt/bess/bessctl/bessctl", "show", "version"): scenario.ExecOutput(
                        return_code=0,
                        stdout="",
                        stderr="",
                    ),
                    ("/opt/bess/bessctl/bessctl", "show", "worker"): scenario.ExecOutput(
                        return_code=0,
                        stdout="RUNNING",
                        stderr="",
                    ),
                    (
                        "/opt/bess/bessctl/bessctl",
                        "show",
                        "module",
                        "accessRoutes",
                    ): scenario.ExecOutput(
                        return_code=0,
                        stdout="",
                        stderr="",
                    ),
                    (
                        "/opt/bess/bessctl/bessctl",
                        "show",
                        "module",
                        "coreRoutes",
                    ): scenario.ExecOutput(
                        return_code=0,
                        stdout="",
                        stderr="",
                    ),
                    (
                        "iptables-legacy",
                        "--check",
                        "OUTPUT",
                        "-p",
                        "icmp",
                        "--icmp-type",
                        "port-unreachable",
                        "-j",
                        "DROP",
                    ): scenario.ExecOutput(
                        return_code=0,
                        stdout="",
                        stderr="",
                    ),
                },
            )
            self.mock_k8s_service.is_created.return_value = True
            state_in = scenario.State(
                leader=True,
                containers=[bessd_container, pfcp_agent_container],
                config={
                    "core-gateway-ip": core_gateway_ip,
                    "access-gateway-ip": access_gateway_ip,
                    "gnb-subnet": gnb_subnet,
                },
            )

            state_out = self.ctx.run(bessd_container.pebble_ready_event, state_in)

            assert state_out.containers[0].layers == {
                "bessd": Layer(
                    {
                        "summary": "bessd layer",
                        "description": "pebble config layer for bessd",
                        "services": {
                            "bessd": {
                                "startup": "enabled",
                                "override": "replace",
                                "command": "/bin/bessd -f -grpc-url=0.0.0.0:10514 -m 0",
                                "environment": {
                                    "CONF_FILE": "/etc/bess/conf/upf.json",
                                    "PYTHONPATH": "/opt/bess",
                                },
                            }
                        },
                        "checks": {
                            "online": {
                                "override": "replace",
                                "level": "ready",
                                "tcp": {"port": 10514},
                            }
                        },
                    }
                ),
                "routectl": Layer(
                    {
                        "summary": "route_control layer",
                        "description": "pebble config layer for route_control",
                        "services": {
                            "routectl": {
                                "startup": "enabled",
                                "override": "replace",
                                "command": "/opt/bess/bessctl/conf/route_control.py -i access core",  # noqa: E501
                                "environment": {
                                    "PYTHONPATH": "/opt/bess",
                                    "PYTHONUNBUFFERED": "1",
                                },
                            }
                        },
                    }
                ),
            }
