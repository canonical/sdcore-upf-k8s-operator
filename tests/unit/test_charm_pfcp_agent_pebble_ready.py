# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
import tempfile

from ops import testing
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
        with tempfile.TemporaryDirectory() as temp_file:
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
                execs={
                    testing.Exec(
                        command_prefix=["ip", "route", "show"],
                        return_code=0,
                        stdout="",
                    ),
                },
                service_statuses={"bessd": ServiceStatus.ACTIVE},
                layers={
                    "bessd": Layer(
                        {
                            "services": {"bessd": {}},
                        }
                    ),
                },
            )
            self.mock_k8s_service.is_created.return_value = True
            state_in = testing.State(
                leader=True,
                containers=[bessd_container, pfcp_agent_container],
                config={
                    "core-gateway-ip": core_gateway_ip,
                    "access-gateway-ip": access_gateway_ip,
                    "gnb-subnet": gnb_subnet,
                },
            )

            state_out = self.ctx.run(self.ctx.on.pebble_ready(pfcp_agent_container), state_in)

            container = state_out.get_container("pfcp-agent")
            assert container.layers == {
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
