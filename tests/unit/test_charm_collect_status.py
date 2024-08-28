# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import tempfile

import pytest
import scenario
from ops import ActiveStatus, BlockedStatus, WaitingStatus
from ops.pebble import Layer, ServiceStatus

from tests.unit.fixtures import UPFUnitTestFixtures


class TestCharmCollectUnitStatus(UPFUnitTestFixtures):
    def test_given_unit_not_leader_when_collect_unit_status_then_status_is_blocked(
        self,
    ):
        state_in = scenario.State(
            leader=False,
        )

        state_out = self.ctx.run("collect_unit_status", state_in)

        assert state_out.unit_status == BlockedStatus("Scaling is not implemented for this charm")

    @pytest.mark.parametrize(
        "config_param,value",
        [
            pytest.param("cni-type", "invalid"),
            pytest.param("upf-mode", "invalid"),
            pytest.param("dnn", ""),
            pytest.param("gnb-subnet", ""),
            pytest.param("gnb-subnet", "1111.11112.11113.22224"),
            pytest.param("access-interface-mac-address", "invalid"),
            pytest.param("access-interface-mac-address", "11:22:33:44:55:66:77"),
            pytest.param("access-ip", ""),
            pytest.param("access-gateway-ip", ""),
            pytest.param("access-gateway-ip", "111.111.111.1111"),
            pytest.param("access-interface-mtu-size", 0),
            pytest.param("access-interface-mtu-size", 999999999),
            pytest.param("core-interface-mac-address", "invalid"),
            pytest.param("core-interface-mac-address", "11:22:33:44:55:66:77"),
            pytest.param("core-ip", ""),
            pytest.param("core-gateway-ip", ""),
            pytest.param("core-gateway-ip", "111.111.111.1111"),
            pytest.param("core-interface-mtu-size", 0),
            pytest.param("core-interface-mtu-size", 999999999),
        ],
    )
    def test_given_invalid_config_when_collect_unit_status_then_status_is_blocked(
        self, config_param, value
    ):
        state_in = scenario.State(
            leader=True,
            config={
                config_param: value,
            },
        )

        state_out = self.ctx.run("collect_unit_status", state_in)

        assert state_out.unit_status == BlockedStatus(
            f"The following configurations are not valid: ['{config_param}']"
        )

    def test_given_upf_mode_set_to_dpdk_and_hugepages_enabled_but_mac_addresses_of_access_and_core_interfaces_not_set_when_collect_unit_status_then_status_is_blocked(  # noqa: E501
        self,
    ):
        state_in = scenario.State(
            leader=True,
            config={"cni-type": "vfioveth", "upf-mode": "dpdk"},
        )

        state_out = self.ctx.run("collect_unit_status", state_in)

        assert state_out.unit_status == BlockedStatus(
            "The following configurations are not valid: ['access-interface-mac-address', 'core-interface-mac-address']"  # noqa: E501
        )

    def test_given_cpu_incompatible_when_collect_unit_status_then_status_is_blocked(
        self,
    ):
        self.mock_check_output.return_value = b"Flags: ssse3 fma cx16 rdrand"
        state_in = scenario.State(
            leader=True,
        )

        state_out = self.ctx.run("collect_unit_status", state_in)

        assert state_out.unit_status == BlockedStatus(
            "CPU is not compatible, see logs for more details"
        )

    def test_given_hugepages_unavailable_when_collect_unit_status_then_status_is_blocked(
        self,
    ):
        self.mock_check_output.return_value = b"Flags: avx2 ssse3 fma cx16 rdrand pdpe1gb"
        self.mock_client_list.return_value = []
        state_in = scenario.State(
            leader=True,
            config={
                "cni-type": "vfioveth",
                "upf-mode": "dpdk",
                "access-interface-mac-address": "11:22:33:44:55:66",
                "core-interface-mac-address": "11:22:33:44:55:77",
            },
        )

        state_out = self.ctx.run("collect_unit_status", state_in)

        assert state_out.unit_status == BlockedStatus("Not enough HugePages available")

    def test_given_multus_not_available_when_collect_unit_status_then_status_is_blocked(self):
        self.mock_check_output.return_value = b"Flags: avx2 ssse3 fma cx16 rdrand"
        self.mock_client_list.return_value = []
        self.mock_multus_is_available.return_value = False
        state_in = scenario.State(
            leader=True,
            config={},
        )

        state_out = self.ctx.run("collect_unit_status", state_in)

        assert state_out.unit_status == BlockedStatus("Multus is not installed or enabled")

    def test_given_cant_connect_to_bessd_container_when_collect_unit_status_then_status_is_waiting(
        self,
    ):
        self.mock_check_output.return_value = b"Flags: avx2 ssse3 fma cx16 rdrand"
        self.mock_client_list.return_value = []
        self.mock_multus_is_available.return_value = True
        bessd_container = scenario.Container(
            name="bessd",
            can_connect=False,
        )
        state_in = scenario.State(
            leader=True,
            containers=[bessd_container],
        )

        state_out = self.ctx.run("collect_unit_status", state_in)

        assert state_out.unit_status == WaitingStatus("Waiting for bessd container to be ready")

    def test_given_multus_not_ready_when_collect_unit_status_then_status_is_waiting(self):
        self.mock_check_output.return_value = b"Flags: avx2 ssse3 fma cx16 rdrand"
        self.mock_client_list.return_value = []
        self.mock_multus_is_available.return_value = True
        self.mock_multus_is_ready.return_value = False
        bessd_container = scenario.Container(
            name="bessd",
            can_connect=True,
        )
        state_in = scenario.State(
            leader=True,
            containers=[bessd_container],
        )

        state_out = self.ctx.run("collect_unit_status", state_in)

        assert state_out.unit_status == WaitingStatus("Waiting for Multus to be ready")

    def test_given_default_route_not_created_when_collect_unit_status_then_status_is_waiting(self):
        self.mock_check_output.return_value = b"Flags: avx2 ssse3 fma cx16 rdrand"
        self.mock_client_list.return_value = []
        self.mock_multus_is_available.return_value = True
        self.mock_multus_is_ready.return_value = True
        bessd_container = scenario.Container(
            name="bessd",
            can_connect=True,
            exec_mock={
                ("ip", "route", "show"): scenario.ExecOutput(
                    return_code=0,
                    stdout="",
                    stderr="",
                )
            },
        )
        state_in = scenario.State(
            leader=True,
            containers=[bessd_container],
        )

        state_out = self.ctx.run("collect_unit_status", state_in)

        assert state_out.unit_status == WaitingStatus("Waiting for default route creation")

    def test_given_gnb_route_not_created_when_collect_unit_status_then_status_is_waiting(self):
        self.mock_check_output.return_value = b"Flags: avx2 ssse3 fma cx16 rdrand"
        self.mock_client_list.return_value = []
        self.mock_multus_is_available.return_value = True
        self.mock_multus_is_ready.return_value = True
        core_gateway_ip = "1.2.3.4"
        bessd_container = scenario.Container(
            name="bessd",
            can_connect=True,
            exec_mock={
                ("ip", "route", "show"): scenario.ExecOutput(
                    return_code=0,
                    stdout=f"default via {core_gateway_ip}",
                    stderr="",
                )
            },
        )
        state_in = scenario.State(
            leader=True,
            containers=[bessd_container],
            config={
                "core-gateway-ip": core_gateway_ip,
                "access-gateway-ip": "1.2.3.1",
            },
        )

        state_out = self.ctx.run("collect_unit_status", state_in)

        assert state_out.unit_status == WaitingStatus("Waiting for RAN route creation")

    def test_given_storage_not_attached_when_collect_unit_status_then_status_is_waiting(self):
        self.mock_check_output.return_value = b"Flags: avx2 ssse3 fma cx16 rdrand"
        self.mock_client_list.return_value = []
        self.mock_multus_is_available.return_value = True
        self.mock_multus_is_ready.return_value = True
        gnb_subnet = "2.2.2.0/24"
        core_gateway_ip = "1.2.3.4"
        access_gateway_ip = "2.1.1.1"
        bessd_container = scenario.Container(
            name="bessd",
            can_connect=True,
            exec_mock={
                ("ip", "route", "show"): scenario.ExecOutput(
                    return_code=0,
                    stdout=f"default via {core_gateway_ip}\n {gnb_subnet} via {access_gateway_ip}",
                    stderr="",
                )
            },
        )
        state_in = scenario.State(
            leader=True,
            containers=[bessd_container],
            config={
                "core-gateway-ip": core_gateway_ip,
                "access-gateway-ip": access_gateway_ip,
                "gnb-subnet": gnb_subnet,
            },
        )

        state_out = self.ctx.run("collect_unit_status", state_in)

        assert state_out.unit_status == WaitingStatus("Waiting for storage to be attached")

    def test_given_bessd_service_not_running_when_collect_unit_status_then_status_is_waiting(self):
        self.mock_check_output.return_value = b"Flags: avx2 ssse3 fma cx16 rdrand"
        self.mock_client_list.return_value = []
        self.mock_multus_is_available.return_value = True
        self.mock_multus_is_ready.return_value = True
        gnb_subnet = "2.2.2.0/24"
        core_gateway_ip = "1.2.3.4"
        access_gateway_ip = "2.1.1.1"
        with tempfile.TemporaryDirectory() as temp_file:
            bessd_config_mount = scenario.Mount(
                location="/etc/bess/conf/",
                src=temp_file,
            )
            bessd_container = scenario.Container(
                name="bessd",
                can_connect=True,
                mounts={
                    "config": bessd_config_mount,
                },
                exec_mock={
                    ("ip", "route", "show"): scenario.ExecOutput(
                        return_code=0,
                        stdout=f"default via {core_gateway_ip}\n {gnb_subnet} via {access_gateway_ip}",  # noqa: E501
                        stderr="",
                    )
                },
            )
            state_in = scenario.State(
                leader=True,
                containers=[bessd_container],
                config={
                    "core-gateway-ip": core_gateway_ip,
                    "access-gateway-ip": access_gateway_ip,
                    "gnb-subnet": gnb_subnet,
                },
            )

            state_out = self.ctx.run("collect_unit_status", state_in)

            assert state_out.unit_status == WaitingStatus("Waiting for bessd service to run")

    def test_given_grpc_service_not_ready_when_collect_unit_status_then_status_is_waiting(self):
        self.mock_check_output.return_value = b"Flags: avx2 ssse3 fma cx16 rdrand"
        self.mock_client_list.return_value = []
        self.mock_multus_is_available.return_value = True
        self.mock_multus_is_ready.return_value = True
        gnb_subnet = "2.2.2.0/24"
        core_gateway_ip = "1.2.3.4"
        access_gateway_ip = "2.1.1.1"
        with tempfile.TemporaryDirectory() as temp_file:
            bessd_config_mount = scenario.Mount(
                location="/etc/bess/conf/",
                src=temp_file,
            )
            bessd_container = scenario.Container(
                name="bessd",
                can_connect=True,
                mounts={
                    "config": bessd_config_mount,
                },
                layers={"bessd": Layer({"services": {"bessd": {}}})},
                service_status={"bessd": ServiceStatus.ACTIVE},
                exec_mock={
                    ("ip", "route", "show"): scenario.ExecOutput(
                        return_code=0,
                        stdout=f"default via {core_gateway_ip}\n {gnb_subnet} via {access_gateway_ip}",  # noqa: E501
                        stderr="",
                    ),
                    ("/opt/bess/bessctl/bessctl", "show", "version"): scenario.ExecOutput(
                        return_code=1,
                        stdout="",
                        stderr="",
                    ),
                },
            )
            state_in = scenario.State(
                leader=True,
                containers=[bessd_container],
                config={
                    "core-gateway-ip": core_gateway_ip,
                    "access-gateway-ip": access_gateway_ip,
                    "gnb-subnet": gnb_subnet,
                },
            )

            state_out = self.ctx.run("collect_unit_status", state_in)

            assert state_out.unit_status == WaitingStatus(
                "Waiting for bessd service to accept configuration messages"
            )

    def test_given_bessd_not_configured_when_collect_unit_status_then_status_is_waiting(self):
        self.mock_check_output.return_value = b"Flags: avx2 ssse3 fma cx16 rdrand"
        self.mock_client_list.return_value = []
        self.mock_multus_is_available.return_value = True
        self.mock_multus_is_ready.return_value = True
        gnb_subnet = "2.2.2.0/24"
        core_gateway_ip = "1.2.3.4"
        access_gateway_ip = "2.1.1.1"
        with tempfile.TemporaryDirectory() as temp_file:
            bessd_config_mount = scenario.Mount(
                location="/etc/bess/conf/",
                src=temp_file,
            )
            bessd_container = scenario.Container(
                name="bessd",
                can_connect=True,
                mounts={
                    "config": bessd_config_mount,
                },
                layers={"bessd": Layer({"services": {"bessd": {}}})},
                service_status={"bessd": ServiceStatus.ACTIVE},
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
                        return_code=1,
                        stdout="",
                        stderr="",
                    ),
                },
            )
            state_in = scenario.State(
                leader=True,
                containers=[bessd_container],
                config={
                    "core-gateway-ip": core_gateway_ip,
                    "access-gateway-ip": access_gateway_ip,
                    "gnb-subnet": gnb_subnet,
                },
            )

            state_out = self.ctx.run("collect_unit_status", state_in)

            assert state_out.unit_status == WaitingStatus(
                "Waiting for bessd configuration to complete"
            )

    def test_given_routectl_service_not_running_when_collect_unit_status_then_status_is_waiting(
        self,
    ):
        self.mock_check_output.return_value = b"Flags: avx2 ssse3 fma cx16 rdrand"
        self.mock_client_list.return_value = []
        self.mock_multus_is_available.return_value = True
        self.mock_multus_is_ready.return_value = True
        gnb_subnet = "2.2.2.0/24"
        core_gateway_ip = "1.2.3.4"
        access_gateway_ip = "2.1.1.1"
        with tempfile.TemporaryDirectory() as temp_file:
            bessd_config_mount = scenario.Mount(
                location="/etc/bess/conf/",
                src=temp_file,
            )
            bessd_container = scenario.Container(
                name="bessd",
                can_connect=True,
                mounts={
                    "config": bessd_config_mount,
                },
                layers={"bessd": Layer({"services": {"bessd": {}}})},
                service_status={"bessd": ServiceStatus.ACTIVE},
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
                },
            )
            state_in = scenario.State(
                leader=True,
                containers=[bessd_container],
                config={
                    "core-gateway-ip": core_gateway_ip,
                    "access-gateway-ip": access_gateway_ip,
                    "gnb-subnet": gnb_subnet,
                },
            )

            state_out = self.ctx.run("collect_unit_status", state_in)

        assert state_out.unit_status == WaitingStatus("Waiting for routectl service to run")

    def test_given_pfcp_service_not_running_when_collect_unit_status_then_status_is_waiting(self):
        self.mock_check_output.return_value = b"Flags: avx2 ssse3 fma cx16 rdrand"
        self.mock_client_list.return_value = []
        self.mock_multus_is_available.return_value = True
        self.mock_multus_is_ready.return_value = True
        gnb_subnet = "2.2.2.0/24"
        core_gateway_ip = "1.2.3.4"
        access_gateway_ip = "2.1.1.1"
        with tempfile.TemporaryDirectory() as temp_file:
            bessd_config_mount = scenario.Mount(
                location="/etc/bess/conf/",
                src=temp_file,
            )
            pfcp_agent_container = scenario.Container(
                name="pfcp-agent",
                can_connect=True,
            )
            bessd_container = scenario.Container(
                name="bessd",
                can_connect=True,
                mounts={
                    "config": bessd_config_mount,
                },
                layers={
                    "bessd": Layer({"services": {"bessd": {}, "routectl": {}}}),
                },
                service_status={"bessd": ServiceStatus.ACTIVE, "routectl": ServiceStatus.ACTIVE},
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

            state_out = self.ctx.run("collect_unit_status", state_in)

        assert state_out.unit_status == WaitingStatus("Waiting for pfcp agent service to run")

    def test_given_services_are_running_when_collect_unit_status_then_status_is_waiting(self):
        self.mock_check_output.return_value = b"Flags: avx2 ssse3 fma cx16 rdrand"
        self.mock_client_list.return_value = []
        self.mock_multus_is_available.return_value = True
        self.mock_multus_is_ready.return_value = True
        gnb_subnet = "2.2.2.0/24"
        core_gateway_ip = "1.2.3.4"
        access_gateway_ip = "2.1.1.1"
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
                can_connect=True,
                mounts={
                    "config": bessd_config_mount,
                },
                layers={
                    "bessd": Layer({"services": {"bessd": {}, "routectl": {}}}),
                },
                service_status={"bessd": ServiceStatus.ACTIVE, "routectl": ServiceStatus.ACTIVE},
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

            state_out = self.ctx.run("collect_unit_status", state_in)

        assert state_out.unit_status == ActiveStatus()
