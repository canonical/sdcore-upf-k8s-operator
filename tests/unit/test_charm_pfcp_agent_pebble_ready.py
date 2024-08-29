# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


import scenario
from ops.pebble import Layer, ServiceStatus

from tests.unit.fixtures import UPFUnitTestFixtures


class TestCharmPFCPAgentPebbleReady(UPFUnitTestFixtures):
    def test_given_pfcp_agent_container_ready_when_pfcp_agent_pebble_ready_then_pebble_layer_is_created(  # noqa: E501
        self,
    ):
        gnb_subnet = "2.2.2.0/24"
        core_gateway_ip = "1.2.3.4"
        access_gateway_ip = "2.1.1.1"
        self.mock_check_output.return_value = b"Flags: avx2 ssse3 fma cx16 rdrand"
        pfcp_agent_container = scenario.Container(
            name="pfcp-agent",
            can_connect=True,
            layers={
                "pfcp-agent": Layer({"services": {"pfcp-agent": {}}}),
            },
        )
        bessd_container = scenario.Container(
            name="bessd",
            can_connect=True,
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
            layers={
                "bessd": Layer(
                    {
                        "services": {"bessd": {}},
                    }
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

        state_out = self.ctx.run(pfcp_agent_container.pebble_ready_event, state_in)

        assert state_out.containers[1].layers == {
            "pfcp-agent": Layer({"services": {"pfcp-agent": {}}}),
            "pfcp": Layer(
                {
                    "summary": "pfcp agent layer",
                    "description": "pebble config layer for pfcp agent",
                    "services": {
                        "pfcp-agent": {
                            "startup": "enabled",
                            "override": "replace",
                            "command": "pfcpiface -config /tmp/conf/upf.json",
                        }
                    },
                }
            ),
        }
