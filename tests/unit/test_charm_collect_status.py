# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import tempfile
from unittest.mock import MagicMock

import pytest
from ops import ActiveStatus, BlockedStatus, WaitingStatus, testing
from ops.pebble import Layer, ServiceStatus

from tests.unit.fixtures import UPFUnitTestFixtures


class TestCharmCollectUnitStatus(UPFUnitTestFixtures):
    def test_given_unit_not_leader_when_collect_unit_status_then_status_is_blocked(
        self,
    ):
        state_in = testing.State(
            leader=False,
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

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
        state_in = testing.State(
            leader=True,
            config={
                config_param: value,
            },
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == BlockedStatus(
            f"The following configurations are not valid: ['{config_param}']"
        )

    def test_given_upf_mode_set_to_dpdk_and_hugepages_enabled_but_mac_addresses_of_access_and_core_interfaces_not_set_when_collect_unit_status_then_status_is_blocked(  # noqa: E501
        self,
    ):
        state_in = testing.State(
            leader=True,
            config={"upf-mode": "dpdk"},
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == BlockedStatus(
            "The following configurations are not valid: ['access-interface-mac-address', 'core-interface-mac-address']"  # noqa: E501
        )

    def test_given_cpu_incompatible_when_collect_unit_status_then_status_is_blocked(
        self,
    ):
        self.mock_check_output.return_value = b"Flags: ssse3 fma cx16 rdrand"
        state_in = testing.State(
            leader=True,
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == BlockedStatus(
            "CPU is not compatible, see logs for more details"
        )

    def test_given_hugepages_unavailable_when_collect_unit_status_then_status_is_blocked(
        self,
    ):
        self.mock_check_output.return_value = b"Flags: avx2 ssse3 fma cx16 rdrand pdpe1gb"
        self.mock_k8sclient_list.return_value = []
        state_in = testing.State(
            leader=True,
            config={
                "upf-mode": "dpdk",
                "access-interface-mac-address": "11:22:33:44:55:66",
                "core-interface-mac-address": "11:22:33:44:55:77",
            },
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == BlockedStatus("Not enough HugePages available")

    @pytest.mark.parametrize(
        "allocatable",
        [
            {},
            {"sriov": 2},
            {"hugepages-1Gi": "0Gi"},
            {"hugepages-1Gi": "0"},
            {"hugepages-1Gi": "1Gi"},
            {"hugepages-1Gi": "1"},
        ],
    )
    def test_given_not_enough_hugepages_available_when_collect_unit_status_then_status_is_blocked(
        self, allocatable
    ):
        self.mock_check_output.return_value = b"Flags: avx2 ssse3 fma cx16 rdrand pdpe1gb"
        node_mock = MagicMock()
        node_mock.status.allocatable = allocatable
        self.mock_k8sclient_list.return_value = [node_mock]
        state_in = testing.State(
            leader=True,
            config={
                "upf-mode": "dpdk",
                "access-interface-mac-address": "11:22:33:44:55:66",
                "core-interface-mac-address": "11:22:33:44:55:77",
            },
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == BlockedStatus("Not enough HugePages available")

    @pytest.mark.parametrize(
        "allocatable",
        [
            {"hugepages-1Gi": "2Gi"},
            {"hugepages-1Gi": "2"},
            {"hugepages-1Gi": "10Gi"},
            {"hugepages-1Gi": "10"},
        ],
    )
    def test_given_enough_hugepages_available_when_collect_unit_status_then_status_is_not_blocked_for_hugepages(  # noqa: E501
        self, allocatable
    ):
        self.mock_check_output.return_value = b"Flags: avx2 ssse3 fma cx16 rdrand pdpe1gb"
        node_mock = MagicMock()
        node_mock.status.allocatable = allocatable
        self.mock_k8sclient_list.return_value = [node_mock]
        self.mock_multus_is_available.return_value = False
        state_in = testing.State(
            leader=True,
            config={
                "upf-mode": "dpdk",
                "access-interface-mac-address": "11:22:33:44:55:66",
                "core-interface-mac-address": "11:22:33:44:55:77",
            },
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status != BlockedStatus("Not enough HugePages available")

    def test_given_multus_not_available_when_collect_unit_status_then_status_is_blocked(self):
        self.mock_check_output.return_value = b"Flags: avx2 ssse3 fma cx16 rdrand"
        self.mock_client_list.return_value = []
        self.mock_multus_is_available.return_value = False
        state_in = testing.State(
            leader=True,
            config={},
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == BlockedStatus("Multus is not installed or enabled")

    def test_given_cant_connect_to_bessd_container_when_collect_unit_status_then_status_is_waiting(
        self,
    ):
        self.mock_check_output.return_value = b"Flags: avx2 ssse3 fma cx16 rdrand"
        self.mock_client_list.return_value = []
        self.mock_multus_is_available.return_value = True
        bessd_container = testing.Container(
            name="bessd",
            can_connect=False,
        )
        state_in = testing.State(
            leader=True,
            containers=[bessd_container],
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == WaitingStatus("Waiting for bessd container to be ready")

    def test_given_multus_not_ready_when_collect_unit_status_then_status_is_waiting(self):
        self.mock_check_output.return_value = b"Flags: avx2 ssse3 fma cx16 rdrand"
        self.mock_client_list.return_value = []
        self.mock_multus_is_available.return_value = True
        self.mock_multus_is_ready.return_value = False
        bessd_container = testing.Container(
            name="bessd",
            can_connect=True,
        )
        pfcp_agent_container = testing.Container(
            name="pfcp-agent",
            can_connect=True,
        )
        state_in = testing.State(
            leader=True,
            containers=[bessd_container, pfcp_agent_container],
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == WaitingStatus("Waiting for Multus to be ready")

    def test_given_default_route_not_created_when_collect_unit_status_then_status_is_waiting(self):
        self.mock_check_output.return_value = b"Flags: avx2 ssse3 fma cx16 rdrand"
        self.mock_client_list.return_value = []
        self.mock_multus_is_available.return_value = True
        self.mock_multus_is_ready.return_value = True
        pfcp_agent_container = testing.Container(
            name="pfcp-agent",
            can_connect=True,
        )
        bessd_container = testing.Container(
            name="bessd",
            can_connect=True,
            execs={
                testing.Exec(
                    command_prefix=["ip", "route", "show"],
                    return_code=0,
                    stdout="",
                ),
            },
        )
        state_in = testing.State(
            leader=True,
            containers=[bessd_container, pfcp_agent_container],
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == WaitingStatus("Waiting for default route creation")

    def test_given_gnb_route_not_created_when_collect_unit_status_then_status_is_waiting(self):
        self.mock_check_output.return_value = b"Flags: avx2 ssse3 fma cx16 rdrand"
        self.mock_client_list.return_value = []
        self.mock_multus_is_available.return_value = True
        self.mock_multus_is_ready.return_value = True
        core_gateway_ip = "1.2.3.4"
        pfcp_agent_container = testing.Container(
            name="pfcp-agent",
            can_connect=True,
        )
        bessd_container = testing.Container(
            name="bessd",
            can_connect=True,
            execs={
                testing.Exec(
                    command_prefix=["ip", "route", "show"],
                    return_code=0,
                    stdout=f"default via {core_gateway_ip}",
                ),
            },
        )
        state_in = testing.State(
            leader=True,
            containers=[bessd_container, pfcp_agent_container],
            config={
                "core-gateway-ip": core_gateway_ip,
                "access-gateway-ip": "1.2.3.1",
            },
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == WaitingStatus("Waiting for RAN route creation")

    def test_given_storage_not_attached_when_collect_unit_status_then_status_is_waiting(self):
        self.mock_check_output.return_value = b"Flags: avx2 ssse3 fma cx16 rdrand"
        self.mock_client_list.return_value = []
        self.mock_multus_is_available.return_value = True
        self.mock_multus_is_ready.return_value = True
        gnb_subnet = "2.2.2.0/24"
        core_gateway_ip = "1.2.3.4"
        access_gateway_ip = "2.1.1.1"
        pfcp_agent_container = testing.Container(
            name="pfcp-agent",
            can_connect=True,
        )
        bessd_container = testing.Container(
            name="bessd",
            can_connect=True,
            execs={
                testing.Exec(
                    command_prefix=["ip", "route", "show"],
                    return_code=0,
                    stdout=f"default via {core_gateway_ip}\n {gnb_subnet} via {access_gateway_ip}",
                ),
            },
        )
        state_in = testing.State(
            leader=True,
            containers=[bessd_container, pfcp_agent_container],
            config={
                "core-gateway-ip": core_gateway_ip,
                "access-gateway-ip": access_gateway_ip,
                "gnb-subnet": gnb_subnet,
            },
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == WaitingStatus(
            "Waiting for storage to be attached for bessd container"
        )

    def test_given_bessd_service_not_running_when_collect_unit_status_then_status_is_waiting(self):
        self.mock_check_output.return_value = b"Flags: avx2 ssse3 fma cx16 rdrand"
        self.mock_client_list.return_value = []
        self.mock_multus_is_available.return_value = True
        self.mock_multus_is_ready.return_value = True
        gnb_subnet = "2.2.2.0/24"
        core_gateway_ip = "1.2.3.4"
        access_gateway_ip = "2.1.1.1"
        with tempfile.TemporaryDirectory() as temp_file:
            bessd_config_mount = testing.Mount(
                location="/etc/bess/conf/",
                source=temp_file,
            )
            pfcp_agent_config_mount = testing.Mount(
                location="/tmp/conf/",
                source=temp_file,
            )
            pfcp_agent_container = testing.Container(
                name="pfcp-agent",
                can_connect=True,
                mounts={
                    "config": pfcp_agent_config_mount,
                },
            )
            bessd_container = testing.Container(
                name="bessd",
                can_connect=True,
                mounts={
                    "config": bessd_config_mount,
                },
                execs={
                    testing.Exec(
                        command_prefix=["ip", "route", "show"],
                        return_code=0,
                        stdout=f"default via {core_gateway_ip}\n {gnb_subnet} via {access_gateway_ip}",  # noqa: E501
                    ),
                },
            )
            state_in = testing.State(
                leader=True,
                containers=[bessd_container, pfcp_agent_container],
                config={
                    "core-gateway-ip": core_gateway_ip,
                    "access-gateway-ip": access_gateway_ip,
                    "gnb-subnet": gnb_subnet,
                },
            )

            state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

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
            bessd_config_mount = testing.Mount(
                location="/etc/bess/conf/",
                source=temp_file,
            )
            pfcp_agent_config_mount = testing.Mount(
                location="/tmp/conf/",
                source=temp_file,
            )
            pfcp_agent_container = testing.Container(
                name="pfcp-agent",
                can_connect=True,
                mounts={
                    "config": pfcp_agent_config_mount,
                },
            )
            bessd_container = testing.Container(
                name="bessd",
                can_connect=True,
                mounts={
                    "config": bessd_config_mount,
                },
                layers={"bessd": Layer({"services": {"bessd": {}}})},
                service_statuses={"bessd": ServiceStatus.ACTIVE},
                execs={
                    testing.Exec(
                        command_prefix=["ip", "route", "show"],
                        return_code=0,
                        stdout=f"default via {core_gateway_ip}\n {gnb_subnet} via {access_gateway_ip}",  # noqa: E501
                    ),
                    testing.Exec(
                        command_prefix=["/opt/bess/bessctl/bessctl", "show", "version"],
                        return_code=1,
                    ),
                },
            )
            state_in = testing.State(
                leader=True,
                containers=[bessd_container, pfcp_agent_container],
                config={
                    "core-gateway-ip": core_gateway_ip,
                    "access-gateway-ip": access_gateway_ip,
                    "gnb-subnet": gnb_subnet,
                },
            )

            state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

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
            bessd_config_mount = testing.Mount(
                location="/etc/bess/conf/",
                source=temp_file,
            )
            pfcp_agent_config_mount = testing.Mount(
                location="/tmp/conf/",
                source=temp_file,
            )
            pfcp_agent_container = testing.Container(
                name="pfcp-agent",
                can_connect=True,
                mounts={
                    "config": pfcp_agent_config_mount,
                },
            )
            bessd_container = testing.Container(
                name="bessd",
                can_connect=True,
                mounts={
                    "config": bessd_config_mount,
                },
                layers={"bessd": Layer({"services": {"bessd": {}}})},
                service_statuses={"bessd": ServiceStatus.ACTIVE},
                execs={
                    testing.Exec(
                        command_prefix=["ip", "route", "show"],
                        return_code=0,
                        stdout=f"default via {core_gateway_ip}\n {gnb_subnet} via {access_gateway_ip}",  # noqa: E501
                    ),
                    testing.Exec(
                        command_prefix=["/opt/bess/bessctl/bessctl", "show", "version"],
                        return_code=0,
                    ),
                    testing.Exec(
                        command_prefix=["/opt/bess/bessctl/bessctl", "show", "worker"],
                        return_code=1,
                    ),
                },
            )
            state_in = testing.State(
                leader=True,
                containers=[bessd_container, pfcp_agent_container],
                config={
                    "core-gateway-ip": core_gateway_ip,
                    "access-gateway-ip": access_gateway_ip,
                    "gnb-subnet": gnb_subnet,
                },
            )

            state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

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
            bessd_config_mount = testing.Mount(
                location="/etc/bess/conf/",
                source=temp_file,
            )
            pfcp_agent_config_mount = testing.Mount(
                location="/tmp/conf/",
                source=temp_file,
            )
            pfcp_agent_container = testing.Container(
                name="pfcp-agent",
                can_connect=True,
                mounts={
                    "config": pfcp_agent_config_mount,
                },
            )
            bessd_container = testing.Container(
                name="bessd",
                can_connect=True,
                mounts={
                    "config": bessd_config_mount,
                },
                layers={"bessd": Layer({"services": {"bessd": {}}})},
                service_statuses={"bessd": ServiceStatus.ACTIVE},
                execs={
                    testing.Exec(
                        command_prefix=["ip", "route", "show"],
                        return_code=0,
                        stdout=f"default via {core_gateway_ip}\n {gnb_subnet} via {access_gateway_ip}",  # noqa: E501
                    ),
                    testing.Exec(
                        command_prefix=["/opt/bess/bessctl/bessctl", "show", "version"],
                        return_code=0,
                    ),
                    testing.Exec(
                        command_prefix=["/opt/bess/bessctl/bessctl", "show", "worker"],
                        return_code=0,
                        stdout="RUNNING",
                    ),
                    testing.Exec(
                        command_prefix=[
                            "/opt/bess/bessctl/bessctl",
                            "show",
                            "module",
                            "accessRoutes",
                        ],
                        return_code=0,
                    ),
                    testing.Exec(
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
            state_in = testing.State(
                leader=True,
                containers=[bessd_container, pfcp_agent_container],
                config={
                    "core-gateway-ip": core_gateway_ip,
                    "access-gateway-ip": access_gateway_ip,
                    "gnb-subnet": gnb_subnet,
                },
            )

            state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == WaitingStatus("Waiting for routectl service to run")

    def test_given_pfcp_agent_storage_not_attached_when_collect_unit_status_then_status_is_waiting(
        self,
    ):  # noqa: E501
        self.mock_check_output.return_value = b"Flags: avx2 ssse3 fma cx16 rdrand"
        self.mock_client_list.return_value = []
        self.mock_multus_is_available.return_value = True
        self.mock_multus_is_ready.return_value = True
        gnb_subnet = "2.2.2.0/24"
        core_gateway_ip = "1.2.3.4"
        access_gateway_ip = "2.1.1.1"
        with tempfile.TemporaryDirectory() as temp_file:
            bessd_config_mount = testing.Mount(
                location="/etc/bess/conf/",
                source=temp_file,
            )
            pfcp_agent_container = testing.Container(
                name="pfcp-agent",
                can_connect=True,
            )
            bessd_container = testing.Container(
                name="bessd",
                can_connect=True,
                mounts={
                    "config": bessd_config_mount,
                },
                layers={
                    "bessd": Layer({"services": {"bessd": {}, "routectl": {}}}),
                },
                service_statuses={"bessd": ServiceStatus.ACTIVE, "routectl": ServiceStatus.ACTIVE},
                execs={
                    testing.Exec(
                        command_prefix=["ip", "route", "show"],
                        return_code=0,
                        stdout=f"default via {core_gateway_ip}\n {gnb_subnet} via {access_gateway_ip}",  # noqa: E501
                    ),
                    testing.Exec(
                        command_prefix=["/opt/bess/bessctl/bessctl", "show", "version"],
                        return_code=0,
                    ),
                    testing.Exec(
                        command_prefix=["/opt/bess/bessctl/bessctl", "show", "worker"],
                        return_code=0,
                        stdout="RUNNING",
                    ),
                    testing.Exec(
                        command_prefix=[
                            "/opt/bess/bessctl/bessctl",
                            "show",
                            "module",
                            "accessRoutes",
                        ],
                        return_code=0,
                    ),
                    testing.Exec(
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
            state_in = testing.State(
                leader=True,
                containers=[bessd_container, pfcp_agent_container],
                config={
                    "core-gateway-ip": core_gateway_ip,
                    "access-gateway-ip": access_gateway_ip,
                    "gnb-subnet": gnb_subnet,
                },
            )

            state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == WaitingStatus(
            "Waiting for storage to be attached for pfcp-agent container"
        )

    def test_given_pfcp_service_not_running_when_collect_unit_status_then_status_is_waiting(self):
        self.mock_check_output.return_value = b"Flags: avx2 ssse3 fma cx16 rdrand"
        self.mock_client_list.return_value = []
        self.mock_multus_is_available.return_value = True
        self.mock_multus_is_ready.return_value = True
        gnb_subnet = "2.2.2.0/24"
        core_gateway_ip = "1.2.3.4"
        access_gateway_ip = "2.1.1.1"
        with tempfile.TemporaryDirectory() as temp_file:
            bessd_config_mount = testing.Mount(
                location="/etc/bess/conf/",
                source=temp_file,
            )
            pfcp_agent_config_mount = testing.Mount(
                location="/tmp/conf/",
                source=temp_file,
            )
            pfcp_agent_container = testing.Container(
                name="pfcp-agent",
                can_connect=True,
                mounts={
                    "config": pfcp_agent_config_mount,
                },
            )
            bessd_container = testing.Container(
                name="bessd",
                can_connect=True,
                mounts={
                    "config": bessd_config_mount,
                },
                layers={
                    "bessd": Layer({"services": {"bessd": {}, "routectl": {}}}),
                },
                service_statuses={"bessd": ServiceStatus.ACTIVE, "routectl": ServiceStatus.ACTIVE},
                execs={
                    testing.Exec(
                        command_prefix=["ip", "route", "show"],
                        return_code=0,
                        stdout=f"default via {core_gateway_ip}\n {gnb_subnet} via {access_gateway_ip}",  # noqa: E501
                    ),
                    testing.Exec(
                        command_prefix=["/opt/bess/bessctl/bessctl", "show", "version"],
                        return_code=0,
                    ),
                    testing.Exec(
                        command_prefix=["/opt/bess/bessctl/bessctl", "show", "worker"],
                        return_code=0,
                        stdout="RUNNING",
                    ),
                    testing.Exec(
                        command_prefix=[
                            "/opt/bess/bessctl/bessctl",
                            "show",
                            "module",
                            "accessRoutes",
                        ],
                        return_code=0,
                    ),
                    testing.Exec(
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
            state_in = testing.State(
                leader=True,
                containers=[bessd_container, pfcp_agent_container],
                config={
                    "core-gateway-ip": core_gateway_ip,
                    "access-gateway-ip": access_gateway_ip,
                    "gnb-subnet": gnb_subnet,
                },
            )

            state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

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
            bessd_config_mount = testing.Mount(
                location="/etc/bess/conf/",
                source=temp_file,
            )
            pfcp_agent_config_mount = testing.Mount(
                location="/tmp/conf/",
                source=temp_file,
            )
            pfcp_agent_container = testing.Container(
                name="pfcp-agent",
                can_connect=True,
                mounts={
                    "config": pfcp_agent_config_mount,
                },
                layers={
                    "pfcp": Layer({"services": {"pfcp-agent": {}}}),
                },
                service_statuses={"pfcp-agent": ServiceStatus.ACTIVE},
            )
            bessd_container = testing.Container(
                name="bessd",
                can_connect=True,
                mounts={
                    "config": bessd_config_mount,
                },
                layers={
                    "bessd": Layer({"services": {"bessd": {}, "routectl": {}}}),
                },
                service_statuses={"bessd": ServiceStatus.ACTIVE, "routectl": ServiceStatus.ACTIVE},
                execs={
                    testing.Exec(
                        command_prefix=["ip", "route", "show"],
                        return_code=0,
                        stdout=f"default via {core_gateway_ip}\n {gnb_subnet} via {access_gateway_ip}",  # noqa: E501
                    ),
                    testing.Exec(
                        command_prefix=["/opt/bess/bessctl/bessctl", "show", "version"],
                        return_code=0,
                    ),
                    testing.Exec(
                        command_prefix=["/opt/bess/bessctl/bessctl", "show", "worker"],
                        return_code=0,
                        stdout="RUNNING",
                    ),
                    testing.Exec(
                        command_prefix=[
                            "/opt/bess/bessctl/bessctl",
                            "show",
                            "module",
                            "accessRoutes",
                        ],
                        return_code=0,
                    ),
                    testing.Exec(
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
            state_in = testing.State(
                leader=True,
                containers=[bessd_container, pfcp_agent_container],
                config={
                    "core-gateway-ip": core_gateway_ip,
                    "access-gateway-ip": access_gateway_ip,
                    "gnb-subnet": gnb_subnet,
                },
            )

            state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.unit_status == ActiveStatus()

    def test_given_no_workload_version_when_collect_unit_status_then_workload_version_is_not_set(  # noqa: E501
        self,
    ):
        self.mock_check_output.return_value = b"Flags: avx2 ssse3 fma cx16 rdrand"
        self.mock_client_list.return_value = []
        self.mock_multus_is_available.return_value = True
        self.mock_multus_is_ready.return_value = False

        bessd_container = testing.Container(
            name="bessd",
            can_connect=True,
        )
        pfcp_agent_container = testing.Container(
            name="pfcp-agent",
            can_connect=True,
        )
        state_in = testing.State(
            leader=True,
            containers=[bessd_container, pfcp_agent_container],
        )

        state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.workload_version == ""

    def test_given_workload_version_file_when_collect_unit_status_then_workload_version_is_set(  # noqa: E501
        self,
    ):
        self.mock_check_output.return_value = b"Flags: avx2 ssse3 fma cx16 rdrand"
        self.mock_client_list.return_value = []
        self.mock_multus_is_available.return_value = True
        self.mock_multus_is_ready.return_value = False

        with tempfile.TemporaryDirectory() as temp_file:
            workload_version_mount = testing.Mount(
                location="/etc",
                source=temp_file,
            )

            bessd_container = testing.Container(
                name="bessd",
                can_connect=True,
                mounts={"workload-version": workload_version_mount},
            )
            pfcp_agent_container = testing.Container(
                name="pfcp-agent",
                can_connect=True,
            )
            state_in = testing.State(
                leader=True,
                containers=[bessd_container, pfcp_agent_container],
            )
            with open(f"{temp_file}/workload-version", "w") as f:
                f.write("1.2.3")

            state_out = self.ctx.run(self.ctx.on.collect_unit_status(), state_in)

        assert state_out.workload_version == "1.2.3"
