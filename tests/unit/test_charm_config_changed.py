# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


import scenario

from tests.unit.fixtures import UPFUnitTestFixtures


class TestCharmConfigChanged(UPFUnitTestFixtures):
    def test_given_dpdk_when_config_changed_then_bessd_configured_for_dpdk(
        self,
    ):
        self.mock_check_output.return_value = b"Flags: avx2 ssse3 fma cx16 rdrand pdpe1gb"
        self.mock_k8s_service.is_created.return_value = True
        self.mock_dpdk.is_configured.return_value = False
        bessd_container = scenario.Container(
            name="bessd",
            can_connect=False,
        )

        state_in = scenario.State(
            leader=True,
            containers=[bessd_container],
            config={
                "upf-mode": "dpdk",
                "access-interface-mac-address": "11:22:33:44:55:66",
                "core-interface-mac-address": "11:22:33:44:55:77",
            },
        )

        self.ctx.run("config_changed", state_in)

        self.mock_dpdk.configure.assert_called_once_with(container_name="bessd")
