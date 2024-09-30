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
                source=temp_file,
            )
            pfcp_agent_container = scenario.Container(
                name="pfcp-agent",
                can_connect=True,
                layers={
                    "pfcp-agent": Layer({"services": {"pfcp-agent": {}}}),
                },
                service_statuses={"pfcp-agent": ServiceStatus.ACTIVE},
            )
            bessd_container = scenario.Container(
                name="bessd",
                mounts={"config": bessd_config_mount},
                can_connect=True,
                execs={
                    scenario.Exec(
                        command_prefix=["ip", "route", "show"],
                        return_code=0,
                        stdout=f"default via {core_gateway_ip}\n {gnb_subnet} via {access_gateway_ip}",  # noqa: E501
                    ),
                    scenario.Exec(
                        command_prefix=["/opt/bess/bessctl/bessctl", "show", "version"],
                        return_code=0,
                    ),
                    scenario.Exec(
                        command_prefix=["/opt/bess/bessctl/bessctl", "show", "worker"],
                        return_code=0,
                        stdout="RUNNING",
                    ),
                    scenario.Exec(
                        command_prefix=[
                            "/opt/bess/bessctl/bessctl",
                            "show",
                            "module",
                            "accessRoutes",
                        ],
                        return_code=0,
                    ),
                    scenario.Exec(
                        command_prefix=[
                            "/opt/bess/bessctl/bessctl",
                            "show",
                            "module",
                            "coreRoutes",
                        ],
                        return_code=0,
                    ),
                },
            )
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

            self.ctx.run(self.ctx.on.pebble_ready(bessd_container), state_in)

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
                source=temp_file,
            )
            pfcp_agent_container = scenario.Container(
                name="pfcp-agent",
                can_connect=True,
                layers={
                    "pfcp-agent": Layer({"services": {"pfcp-agent": {}}}),
                },
                service_statuses={"pfcp-agent": ServiceStatus.ACTIVE},
            )
            bessd_container = scenario.Container(
                name="bessd",
                mounts={"config": bessd_config_mount},
                can_connect=True,
                execs={
                    scenario.Exec(
                        command_prefix=["ip", "route", "show"],
                        return_code=0,
                        stdout=f"default via {core_gateway_ip}\n {gnb_subnet} via {access_gateway_ip}",  # noqa: E501
                    ),
                    scenario.Exec(
                        command_prefix=["/opt/bess/bessctl/bessctl", "show", "version"],
                        return_code=0,
                    ),
                    scenario.Exec(
                        command_prefix=["/opt/bess/bessctl/bessctl", "show", "worker"],
                        return_code=0,
                        stdout="RUNNING",
                    ),
                    scenario.Exec(
                        command_prefix=[
                            "/opt/bess/bessctl/bessctl",
                            "show",
                            "module",
                            "accessRoutes",
                        ],
                        return_code=0,
                    ),
                    scenario.Exec(
                        command_prefix=[
                            "/opt/bess/bessctl/bessctl",
                            "show",
                            "module",
                            "coreRoutes",
                        ],
                        return_code=0,
                    ),
                },
            )
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

            self.ctx.run(self.ctx.on.pebble_ready(bessd_container), state_in)

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
                source=temp_file,
            )
            pfcp_agent_container = scenario.Container(
                name="pfcp-agent",
                can_connect=True,
                layers={
                    "pfcp-agent": Layer({"services": {"pfcp-agent": {}}}),
                },
                service_statuses={"pfcp-agent": ServiceStatus.ACTIVE},
            )
            bessd_container = scenario.Container(
                name="bessd",
                mounts={"config": bessd_config_mount},
                can_connect=True,
                execs={
                    scenario.Exec(
                        command_prefix=["ip", "route", "show"],
                        return_code=0,
                        stdout=f"default via {core_gateway_ip}\n {gnb_subnet} via {access_gateway_ip}",  # noqa: E501
                    ),
                    scenario.Exec(
                        command_prefix=["/opt/bess/bessctl/bessctl", "show", "version"],
                        return_code=0,
                    ),
                    scenario.Exec(
                        command_prefix=["/opt/bess/bessctl/bessctl", "show", "worker"],
                        return_code=0,
                        stdout="RUNNING",
                    ),
                    scenario.Exec(
                        command_prefix=[
                            "/opt/bess/bessctl/bessctl",
                            "show",
                            "module",
                            "accessRoutes",
                        ],
                        return_code=0,
                    ),
                    scenario.Exec(
                        command_prefix=[
                            "/opt/bess/bessctl/bessctl",
                            "show",
                            "module",
                            "coreRoutes",
                        ],
                        return_code=0,
                    ),
                },
            )
            state_in = scenario.State(
                leader=True,
                containers=[bessd_container, pfcp_agent_container],
                config={
                    "core-gateway-ip": core_gateway_ip,
                    "access-gateway-ip": access_gateway_ip,
                    "gnb-subnet": gnb_subnet,
                },
            )

            state_out = self.ctx.run(self.ctx.on.pebble_ready(bessd_container), state_in)

            container = state_out.get_container("bessd")
            assert container.layers == {
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

    def test_given_bessd_not_configured_when_bessd_pebble_ready_then_bessd_configured(
        self, caplog
    ):
        gnb_subnet = "2.2.2.0/24"
        core_gateway_ip = "1.2.3.4"
        access_gateway_ip = "2.1.1.1"
        self.mock_check_output.return_value = b"Flags: avx2 ssse3 fma cx16 rdrand"
        with tempfile.TemporaryDirectory() as temp_file:
            bessd_config_mount = scenario.Mount(
                location="/etc/bess/conf/",
                source=temp_file,
            )
            pfcp_agent_container = scenario.Container(
                name="pfcp-agent",
                can_connect=True,
                layers={
                    "pfcp-agent": Layer({"services": {"pfcp-agent": {}}}),
                },
                service_statuses={"pfcp-agent": ServiceStatus.ACTIVE},
            )
            bessd_container = scenario.Container(
                name="bessd",
                mounts={"config": bessd_config_mount},
                can_connect=True,
                execs={
                    scenario.Exec(
                        command_prefix=["/opt/bess/bessctl/bessctl", "show", "version"],
                        return_code=0,
                    ),
                    scenario.Exec(
                        command_prefix=[
                            "/opt/bess/bessctl/bessctl",
                            "run",
                            "/opt/bess/bessctl/conf/up4",
                        ],
                        return_code=0,
                        stdout="",
                    ),
                },
            )
            state_in = scenario.State(
                leader=True,
                containers=[bessd_container, pfcp_agent_container],
                config={
                    "core-gateway-ip": core_gateway_ip,
                    "access-gateway-ip": access_gateway_ip,
                    "gnb-subnet": gnb_subnet,
                },
            )

            self.ctx.run(self.ctx.on.pebble_ready(bessd_container), state_in)

            assert self.ctx.exec_history[bessd_container.name][1].command == [
                "/opt/bess/bessctl/bessctl",
                "run",
                "/opt/bess/bessctl/conf/up4",
            ]

    def test_given_routes_not_created_when_bessd_pebble_ready_then_routes_created(self, caplog):
        gnb_subnet = "2.2.2.0/24"
        core_gateway_ip = "1.2.3.4"
        access_gateway_ip = "2.1.1.1"
        self.mock_check_output.return_value = b"Flags: avx2 ssse3 fma cx16 rdrand"
        with tempfile.TemporaryDirectory() as temp_file:
            bessd_config_mount = scenario.Mount(
                location="/etc/bess/conf/",
                source=temp_file,
            )
            pfcp_agent_container = scenario.Container(
                name="pfcp-agent",
                can_connect=True,
                layers={
                    "pfcp-agent": Layer({"services": {"pfcp-agent": {}}}),
                },
                service_statuses={"pfcp-agent": ServiceStatus.ACTIVE},
            )
            bessd_container = scenario.Container(
                name="bessd",
                mounts={"config": bessd_config_mount},
                can_connect=True,
                execs={
                    scenario.Exec(
                        command_prefix=["ip", "route", "show"],
                        return_code=0,
                        stdout="",  # route not created
                    ),
                    scenario.Exec(
                        command_prefix=["/opt/bess/bessctl/bessctl", "show", "version"],
                        return_code=0,
                    ),
                    scenario.Exec(
                        command_prefix=[
                            "ip",
                            "route",
                            "replace",
                            "default",
                            "via",
                            core_gateway_ip,
                            "metric",
                            "110",
                        ],
                        return_code=0,
                    ),
                    scenario.Exec(
                        command_prefix=[
                            "ip",
                            "route",
                            "replace",
                            gnb_subnet,
                            "via",
                            access_gateway_ip,
                        ],
                        return_code=0,
                    ),
                },
            )
            state_in = scenario.State(
                leader=True,
                containers=[bessd_container, pfcp_agent_container],
                config={
                    "core-gateway-ip": core_gateway_ip,
                    "access-gateway-ip": access_gateway_ip,
                    "gnb-subnet": gnb_subnet,
                },
            )

            self.ctx.run(self.ctx.on.pebble_ready(bessd_container), state_in)

            assert self.ctx.exec_history[bessd_container.name][1].command == [
                "ip",
                "route",
                "replace",
                "default",
                "via",
                core_gateway_ip,
                "metric",
                "110",
            ]
            assert self.ctx.exec_history[bessd_container.name][3].command == [
                "ip",
                "route",
                "replace",
                gnb_subnet,
                "via",
                access_gateway_ip,
            ]

    def test_given_iptables_rule_not_created_when_bessd_pebble_ready_then_rule_created(
        self,
    ):
        gnb_subnet = "2.2.2.0/24"
        core_gateway_ip = "1.2.3.4"
        access_gateway_ip = "2.1.1.1"
        self.mock_check_output.return_value = b"Flags: avx2 ssse3 fma cx16 rdrand"
        with tempfile.TemporaryDirectory() as temp_file:
            bessd_config_mount = scenario.Mount(
                location="/etc/bess/conf/",
                source=temp_file,
            )
            pfcp_agent_container = scenario.Container(
                name="pfcp-agent",
                can_connect=True,
                layers={
                    "pfcp-agent": Layer({"services": {"pfcp-agent": {}}}),
                },
                service_statuses={"pfcp-agent": ServiceStatus.ACTIVE},
            )
            bessd_container = scenario.Container(
                name="bessd",
                mounts={"config": bessd_config_mount},
                can_connect=True,
                execs={
                    scenario.Exec(
                        command_prefix=["/opt/bess/bessctl/bessctl", "show", "version"],
                        return_code=0,
                    ),
                    scenario.Exec(
                        command_prefix=[
                            "iptables-legacy",
                            "-I",
                            "OUTPUT",
                            "-p",
                            "icmp",
                            "--icmp-type",
                            "port-unreachable",
                            "-j",
                            "DROP",
                        ],
                        return_code=0,
                    ),
                },
            )
            state_in = scenario.State(
                leader=True,
                containers=[bessd_container, pfcp_agent_container],
                config={
                    "core-gateway-ip": core_gateway_ip,
                    "access-gateway-ip": access_gateway_ip,
                    "gnb-subnet": gnb_subnet,
                },
            )

            self.ctx.run(self.ctx.on.pebble_ready(bessd_container), state_in)

            assert self.ctx.exec_history[bessd_container.name][0].command == [
                "iptables-legacy",
                "-I",
                "OUTPUT",
                "-p",
                "icmp",
                "--icmp-type",
                "port-unreachable",
                "-j",
                "DROP",
            ]
