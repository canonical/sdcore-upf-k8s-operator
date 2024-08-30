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

    def test_given_n3_integration_when_config_changed_then_n3_information_published(
        self,
    ):
        self.mock_check_output.return_value = b"Flags: avx2 ssse3 fma cx16 rdrand pdpe1gb"
        self.mock_k8s_service.is_created.return_value = True
        bessd_container = scenario.Container(
            name="bessd",
            can_connect=True,
            exec_mock={
                ("ip", "route", "show"): scenario.ExecOutput(
                    return_code=0,
                    stdout="",
                    stderr="",
                ),
            },
        )
        n3_relation = scenario.Relation(
            endpoint="fiveg_n3",
            interface="fiveg_n3",
        )

        state_in = scenario.State(
            leader=True,
            containers=[bessd_container],
            relations=[n3_relation],
            config={"access-ip": "1.2.3.4"},
        )

        self.ctx.run("config_changed", state_in)

        self.mock_n3_provides_publish_upf_information.assert_called_once_with(
            relation_id=n3_relation.relation_id,
            upf_ip_address="1.2.3.4",
        )

    def test_given_n4_integration_when_config_changed_then_n4_information_published(
        self,
    ):
        self.mock_check_output.return_value = b"Flags: avx2 ssse3 fma cx16 rdrand pdpe1gb"
        self.mock_k8s_service.is_created.return_value = True
        self.mock_k8s_service.get_hostname.return_value = "my-hostname"
        bessd_container = scenario.Container(
            name="bessd",
            can_connect=True,
            exec_mock={
                ("ip", "route", "show"): scenario.ExecOutput(
                    return_code=0,
                    stdout="",
                    stderr="",
                ),
            },
        )
        n4_relation = scenario.Relation(
            endpoint="fiveg_n4",
            interface="fiveg_n4",
        )

        state_in = scenario.State(
            leader=True,
            containers=[bessd_container],
            relations=[n4_relation],
        )

        self.ctx.run("config_changed", state_in)

        self.mock_n4_provides_publish_upf_information.assert_called_once_with(
            relation_id=n4_relation.relation_id,
            upf_hostname="my-hostname",
            upf_n4_port=8805,
        )
