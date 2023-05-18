# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest
from io import StringIO
from unittest.mock import Mock, call, patch

from ops import testing
from ops.model import ActiveStatus, BlockedStatus, WaitingStatus
from ops.pebble import ExecError

from charm import UPFOperatorCharm


class TestCharm(unittest.TestCase):
    @patch("lightkube.core.client.GenericSyncClient")
    @patch(
        "charm.KubernetesServicePatch",
        lambda charm, ports: None,
    )
    def setUp(self, patch_k8s_client):
        self.namespace = "whatever"
        self.harness = testing.Harness(UPFOperatorCharm)
        self.harness.set_model_name(name=self.namespace)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    @staticmethod
    def _read_file(path: str) -> str:
        """Reads a file and returns as a string.

        Args:
            path (str): path to the file.

        Returns:
            str: content of the file.
        """
        with open(path, "r") as f:
            content = f.read()
        return content

    @patch(
        "charms.kubernetes_charm_libraries.v0.multus.KubernetesMultusCharmLib.multus_is_configured"
    )
    @patch("ops.model.Container.exec", new=Mock)
    @patch("ops.model.Container.exists")
    @patch("ops.model.Container.push")
    def test_given_bessd_config_file_not_written_when_configure_then_config_file_is_written(  # noqa: E501
        self,
        patch_push,
        patch_exists,
        patch_multus_is_configured,
    ):
        patch_exists.side_effect = [True, False]
        patch_multus_is_configured.return_value = True
        self.harness.set_can_connect(container="bessd", val=True)
        self.harness.set_can_connect(container="routectl", val=True)
        self.harness.set_can_connect(container="web", val=True)
        self.harness.set_can_connect(container="pfcp-agent", val=True)

        self.harness.charm._configure(event=Mock())

        expected_config_file_content = self._read_file("tests/unit/expected_upf.json")

        patch_push.assert_any_call(
            path="/etc/bess/conf/upf.json",
            source=expected_config_file_content,
        )

    @patch(
        "charms.kubernetes_charm_libraries.v0.multus.KubernetesMultusCharmLib.multus_is_configured"
    )
    @patch("ops.model.Container.exec", new=Mock)
    @patch("ops.model.Container.exists")
    @patch("ops.model.Container.push")
    @patch("ops.model.Container.pull")
    def test_given_bessd_config_file_matches_when_configure_then_config_file_is_not_re_written(
        self,
        patch_pull,
        patch_push,
        patch_exists,
        patch_multus_is_configured,
    ):
        expected_upf_content = self._read_file("tests/unit/expected_upf.json")
        patch_pull.return_value = StringIO(expected_upf_content)
        patch_exists.return_value = [True, True]
        patch_multus_is_configured.return_value = True
        self.harness.set_can_connect(container="bessd", val=True)
        self.harness.set_can_connect(container="routectl", val=True)
        self.harness.set_can_connect(container="web", val=True)
        self.harness.set_can_connect(container="pfcp-agent", val=True)

        self.harness.charm._configure(event=Mock())

        patch_push.assert_not_called()

    @patch(
        "charms.kubernetes_charm_libraries.v0.multus.KubernetesMultusCharmLib.multus_is_configured"
    )
    @patch("ops.model.Container.push", new=Mock)
    @patch("ops.model.Container.exec", new=Mock)
    @patch("ops.model.Container.pull", new=Mock)
    @patch("ops.model.Container.exists")
    def test_given_when_configure_then_expected_pebble_plan_is_applied(  # noqa: E501
        self,
        patch_exists,
        patch_multus_is_configured,
    ):
        patch_exists.return_value = True
        patch_multus_is_configured.return_value = True
        self.harness.set_can_connect(container="routectl", val=True)
        self.harness.set_can_connect(container="web", val=True)
        self.harness.set_can_connect(container="pfcp-agent", val=True)
        self.harness.set_can_connect(container="bessd", val=True)

        self.harness.charm._configure(event=Mock())

        expected_plan = {
            "services": {
                "bessd": {
                    "startup": "enabled",
                    "override": "replace",
                    "command": "bessd -f -grpc-url=0.0.0.0:10514 -m 0",
                    "environment": {"CONF_FILE": "/etc/bess/conf/upf.json"},
                }
            }
        }

        updated_plan = self.harness.get_container_pebble_plan("bessd").to_dict()

        self.assertEqual(expected_plan, updated_plan)

    def test_given_bad_config_when_configure_then_status_is_blocked(self):
        self.harness.update_config(key_values={"dnn": ""})

        self.assertEqual(
            self.harness.model.unit.status,
            BlockedStatus("The following configurations are not valid: ['dnn']"),
        )

    @patch(
        "charms.kubernetes_charm_libraries.v0.multus.KubernetesMultusCharmLib.multus_is_configured"
    )
    @patch("ops.model.Container.push", new=Mock)
    @patch("ops.model.Container.exec")
    @patch("ops.model.Container.pull", new=Mock)
    @patch("ops.model.Container.exists")
    def test_given_can_connect_to_bessd_when_configure_then_ip_routes_are_created(
        self, patch_exists, patch_exec, patch_multus_is_configured
    ):
        patch_exists.return_value = True
        patch_multus_is_configured.return_value = True
        self.harness.set_can_connect(container="routectl", val=True)
        self.harness.set_can_connect(container="web", val=True)
        self.harness.set_can_connect(container="pfcp-agent", val=True)
        self.harness.set_can_connect(container="bessd", val=True)

        self.harness.charm._configure(event=Mock())

        patch_exec.assert_any_call(
            command=["ip", "route", "replace", "192.168.251.0/24", "via", "192.168.252.1"],
            timeout=30,
            environment=None,
        )
        patch_exec.assert_any_call(
            command=[
                "ip",
                "route",
                "replace",
                "default",
                "via",
                "192.168.250.1",
                "metric",
                "110",
            ],
            timeout=30,
            environment=None,
        )

    @patch(
        "charms.kubernetes_charm_libraries.v0.multus.KubernetesMultusCharmLib.multus_is_configured"
    )
    @patch("ops.model.Container.push", new=Mock)
    @patch("ops.model.Container.exec")
    @patch("ops.model.Container.pull", new=Mock)
    @patch("ops.model.Container.exists")
    def test_given_iptables_rule_is_not_created_when_configure_then_rule_is_created(
        self, patch_exists, patch_exec, patch_multus_is_configured
    ):
        patch_exec.side_effect = [
            Mock(),
            Mock(),
            Mock(),
            ExecError(command=[], exit_code=1, stdout="", stderr=""),
            Mock(),
            Mock(),
        ]
        patch_exists.return_value = True
        patch_multus_is_configured.return_value = True
        self.harness.set_can_connect(container="routectl", val=True)
        self.harness.set_can_connect(container="web", val=True)
        self.harness.set_can_connect(container="pfcp-agent", val=True)
        self.harness.set_can_connect(container="bessd", val=True)

        self.harness.charm._configure(event=Mock())

        patch_exec.assert_any_call(
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
            timeout=30,
            environment=None,
        )

    @patch(
        "charms.kubernetes_charm_libraries.v0.multus.KubernetesMultusCharmLib.multus_is_configured"
    )
    @patch("ops.model.Container.push", new=Mock)
    @patch(
        "ops.model.Container.exec",
    )
    @patch("ops.model.Container.pull", new=Mock)
    @patch("ops.model.Container.exists")
    def test_given_iptables_rule_is_created_when_configure_then_rule_is_not_re_created(
        self, patch_exists, patch_exec, patch_multus_is_configured
    ):
        patch_exists.return_value = True
        patch_multus_is_configured.return_value = True
        self.harness.set_can_connect(container="routectl", val=True)
        self.harness.set_can_connect(container="web", val=True)
        self.harness.set_can_connect(container="pfcp-agent", val=True)
        self.harness.set_can_connect(container="bessd", val=True)

        self.harness.charm._configure(event=Mock())

        assert (
            call(
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
                timeout=30,
                environment=None,
            )
            not in patch_exec.mock_calls
        )

    @patch(
        "charms.kubernetes_charm_libraries.v0.multus.KubernetesMultusCharmLib.multus_is_configured"
    )
    @patch("ops.model.Container.push", new=Mock)
    @patch("ops.model.Container.exec")
    @patch("ops.model.Container.pull", new=Mock)
    @patch("ops.model.Container.exists")
    def test_given_can_connect_to_bessd_when_configure_then_bessctl_configure_is_executed(
        self, patch_exists, patch_exec, patch_multus_is_configured
    ):
        patch_exists.return_value = True
        patch_multus_is_configured.return_value = True
        self.harness.set_can_connect(container="routectl", val=True)
        self.harness.set_can_connect(container="web", val=True)
        self.harness.set_can_connect(container="pfcp-agent", val=True)
        self.harness.set_can_connect(container="bessd", val=True)

        self.harness.charm._configure(event=Mock())

        patch_exec.assert_any_call(
            command=["bessctl", "run", "/opt/bess/bessctl/conf/up4"],
            timeout=30,
            environment={"CONF_FILE": "/etc/bess/conf/upf.json"},
        )

    @patch(
        "charms.kubernetes_charm_libraries.v0.multus.KubernetesMultusCharmLib.multus_is_configured"
    )
    @patch("ops.model.Container.push", new=Mock)
    @patch("ops.model.Container.exec", new=Mock)
    @patch("ops.model.Container.pull", new=Mock)
    @patch("ops.model.Container.exists")
    def test_given_config_file_exists_when_configure_then_pebble_plan_is_applied(
        self,
        patch_exists,
        patch_multus_is_configured,
    ):
        patch_exists.return_value = True
        patch_multus_is_configured.return_value = True
        self.harness.set_can_connect(container="routectl", val=True)
        self.harness.set_can_connect(container="web", val=True)
        self.harness.set_can_connect(container="pfcp-agent", val=True)
        self.harness.set_can_connect(container="bessd", val=True)

        self.harness.charm._configure(event=Mock())

        expected_plan = {
            "services": {
                "routectl": {
                    "startup": "enabled",
                    "override": "replace",
                    "command": "/opt/bess/bessctl/conf/route_control.py -i access core",
                    "environment": {"PYTHONUNBUFFERED": "1"},
                }
            }
        }

        updated_plan = self.harness.get_container_pebble_plan("routectl").to_dict()

        self.assertEqual(expected_plan, updated_plan)

    @patch(
        "charms.kubernetes_charm_libraries.v0.multus.KubernetesMultusCharmLib.multus_is_configured"
    )
    @patch("ops.model.Container.push", new=Mock)
    @patch("ops.model.Container.exec", new=Mock)
    @patch("ops.model.Container.pull", new=Mock)
    @patch("ops.model.Container.exists")
    def test_given_can_connect_when_configure_then_pebble_plan_is_applied(
        self,
        patch_exists,
        patch_multus_is_configured,
    ):
        patch_exists.return_value = True
        patch_multus_is_configured.return_value = True
        self.harness.set_can_connect(container="routectl", val=True)
        self.harness.set_can_connect(container="web", val=True)
        self.harness.set_can_connect(container="pfcp-agent", val=True)
        self.harness.set_can_connect(container="bessd", val=True)

        self.harness.charm._configure(event=Mock())

        expected_plan = {
            "services": {
                "web": {
                    "startup": "enabled",
                    "override": "replace",
                    "command": "bessctl http 0.0.0.0 8000",
                }
            }
        }

        updated_plan = self.harness.get_container_pebble_plan("web").to_dict()

        self.assertEqual(expected_plan, updated_plan)

    @patch(
        "charms.kubernetes_charm_libraries.v0.multus.KubernetesMultusCharmLib.multus_is_configured"
    )
    @patch("ops.model.Container.push", new=Mock)
    @patch("ops.model.Container.exec", new=Mock)
    @patch("ops.model.Container.pull", new=Mock)
    @patch("ops.model.Container.exists")
    def test_given_bessd_service_is_running_when_configure_then_pebble_plan_is_applied(  # noqa: E501
        self,
        patch_exists,
        patch_multus_is_configured,
    ):
        patch_exists.return_value = True
        patch_multus_is_configured.return_value = True
        self.harness.set_can_connect(container="routectl", val=True)
        self.harness.set_can_connect(container="web", val=True)
        self.harness.set_can_connect(container="pfcp-agent", val=True)
        self.harness.set_can_connect(container="bessd", val=True)

        self.harness.charm._configure(event=Mock())

        expected_plan = {
            "services": {
                "pfcp-agent": {
                    "startup": "enabled",
                    "override": "replace",
                    "command": "pfcpiface -config /tmp/conf/upf.json",
                }
            }
        }

        updated_plan = self.harness.get_container_pebble_plan("pfcp-agent").to_dict()

        self.assertEqual(expected_plan, updated_plan)

    @patch(
        "charms.kubernetes_charm_libraries.v0.multus.KubernetesMultusCharmLib.multus_is_configured"
    )
    @patch("ops.model.Container.exec", new=Mock())
    @patch("ops.model.Container.exists")
    def test_given_cant_connect_to_bessd_container_when_configure_then_status_is_waiting(
        self,
        patch_exists,
        patch_multus_is_configured,
    ):
        patch_exists.return_value = True
        patch_multus_is_configured.return_value = True
        self.harness.set_can_connect(container="bessd", val=False)
        self.harness.set_can_connect(container="routectl", val=True)
        self.harness.set_can_connect(container="web", val=True)
        self.harness.set_can_connect(container="pfcp-agent", val=True)

        self.harness.charm._configure(event=Mock())

        self.assertEqual(
            self.harness.model.unit.status,
            WaitingStatus("Waiting to be able to connect to the `bessd` container"),
        )

    @patch(
        "charms.kubernetes_charm_libraries.v0.multus.KubernetesMultusCharmLib.multus_is_configured"
    )
    @patch("ops.model.Container.exec", new=Mock())
    @patch("ops.model.Container.exists")
    def test_given_cant_connect_to_web_container_when_configure_then_status_is_waiting(
        self,
        patch_exists,
        patch_multus_is_configured,
    ):
        patch_exists.return_value = True
        patch_multus_is_configured.return_value = True
        self.harness.set_can_connect(container="web", val=False)
        self.harness.set_can_connect(container="routectl", val=True)
        self.harness.set_can_connect(container="bessd", val=True)
        self.harness.set_can_connect(container="pfcp-agent", val=True)

        self.harness.charm._configure(event=Mock())

        self.assertEqual(
            self.harness.model.unit.status,
            WaitingStatus("Waiting to be able to connect to the `web` container"),
        )

    @patch(
        "charms.kubernetes_charm_libraries.v0.multus.KubernetesMultusCharmLib.multus_is_configured"
    )
    @patch("ops.model.Container.exec", new=Mock())
    @patch("ops.model.Container.exists")
    def test_given_cant_connect_to_routectl_container_when_configure_then_status_is_waiting(
        self,
        patch_exists,
        patch_multus_is_configured,
    ):
        patch_exists.return_value = True
        patch_multus_is_configured.return_value = True
        self.harness.set_can_connect(container="routectl", val=False)
        self.harness.set_can_connect(container="bessd", val=True)
        self.harness.set_can_connect(container="web", val=True)
        self.harness.set_can_connect(container="pfcp-agent", val=True)

        self.harness.charm._configure(event=Mock())

        self.assertEqual(
            self.harness.model.unit.status,
            WaitingStatus("Waiting to be able to connect to the `routectl` container"),
        )

    @patch(
        "charms.kubernetes_charm_libraries.v0.multus.KubernetesMultusCharmLib.multus_is_configured"
    )
    @patch("ops.model.Container.exec", new=Mock())
    @patch("ops.model.Container.exists")
    def test_given_cant_connect_to_pfcp_agent_container_when_configure_then_status_is_waiting(
        self,
        patch_exists,
        patch_multus_is_configured,
    ):
        patch_exists.return_value = True
        patch_multus_is_configured.return_value = True
        self.harness.set_can_connect(container="routectl", val=True)
        self.harness.set_can_connect(container="bessd", val=True)
        self.harness.set_can_connect(container="web", val=True)
        self.harness.set_can_connect(container="pfcp-agent", val=False)

        self.harness.charm._configure(event=Mock())

        self.assertEqual(
            self.harness.model.unit.status,
            WaitingStatus("Waiting to be able to connect to the `pfcp-agent` container"),
        )

    @patch(
        "charms.kubernetes_charm_libraries.v0.multus.KubernetesMultusCharmLib.multus_is_configured"
    )
    @patch("ops.model.Container.exec")
    @patch("ops.model.Container.exists")
    def test_given_bess_pod_doesnt_have_net_admin_capability_when_configure_then_status_is_waiting(
        self,
        patch_exists,
        patch_exec,
        patch_multus_is_configured,
    ):
        patch_exec.side_effect = ExecError(command=[], exit_code=1, stdout="", stderr="")
        patch_exists.return_value = True
        patch_multus_is_configured.return_value = True
        self.harness.set_can_connect(container="routectl", val=True)
        self.harness.set_can_connect(container="bessd", val=True)
        self.harness.set_can_connect(container="web", val=True)
        self.harness.set_can_connect(container="pfcp-agent", val=True)

        self.harness.charm._configure(event=Mock())

        self.assertEqual(
            self.harness.model.unit.status,
            WaitingStatus("Waiting for pod to have NET_ADMIN capability"),
        )

    @patch(
        "charms.kubernetes_charm_libraries.v0.multus.KubernetesMultusCharmLib.multus_is_configured"
    )
    @patch("ops.model.Container.exec", new=Mock)
    @patch("ops.model.Container.exists")
    def test_given_storage_not_attached_when_configure_then_status_is_waiting(
        self,
        patch_exists,
        patch_multus_is_configured,
    ):
        patch_exists.return_value = False
        patch_multus_is_configured.return_value = True
        self.harness.set_can_connect(container="routectl", val=True)
        self.harness.set_can_connect(container="bessd", val=True)
        self.harness.set_can_connect(container="web", val=True)
        self.harness.set_can_connect(container="pfcp-agent", val=True)

        self.harness.charm._configure(event=Mock())

        self.assertEqual(
            self.harness.model.unit.status,
            WaitingStatus("Waiting for storage to be attached"),
        )

    @patch(
        "charms.kubernetes_charm_libraries.v0.multus.KubernetesMultusCharmLib.multus_is_configured"
    )
    def test_given_multus_not_configured_when_configure_then_status_is_waiting(
        self,
        patch_multus_is_configured,
    ):
        patch_multus_is_configured.return_value = False

        self.harness.charm._configure(event=Mock())

        self.assertEqual(
            self.harness.model.unit.status,
            WaitingStatus("Waiting for statefulset to be patched"),
        )

    @patch(
        "charms.kubernetes_charm_libraries.v0.multus.KubernetesMultusCharmLib.multus_is_configured"
    )
    @patch("ops.model.Container.push", new=Mock)
    @patch("ops.model.Container.exec", new=Mock)
    @patch("ops.model.Container.pull", new=Mock)
    @patch("ops.model.Container.exists")
    def test_given_config_file_is_written_and_all_services_are_running_when_configure_then_status_is_active(  # noqa: E501
        self,
        patch_exists,
        patch_multus_is_configured,
    ):
        patch_exists.return_value = True
        patch_multus_is_configured.return_value = True

        self.harness.set_can_connect(container="bessd", val=True)
        self.harness.set_can_connect(container="routectl", val=True)
        self.harness.set_can_connect(container="web", val=True)
        self.harness.set_can_connect(container="pfcp-agent", val=True)

        self.harness.charm._configure(event=Mock())

        self.assertEqual(self.harness.model.unit.status, ActiveStatus())
