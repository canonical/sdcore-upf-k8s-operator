# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import unittest
from unittest.mock import Mock, call, patch

from ops import testing
from ops.model import ActiveStatus, BlockedStatus, ModelError, WaitingStatus

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
    def test_given_bessd_config_file_not_written_when_bessd_pebble_ready_then_config_file_is_written(  # noqa: E501
        self,
        patch_push,
        patch_exists,
        patch_multus_is_configured,
    ):
        patch_exists.side_effect = [True, False]
        patch_multus_is_configured.return_value = True

        self.harness.container_pebble_ready(container_name="bessd")

        expected_config_file_content = self._read_file("tests/unit/expected_upf.json")

        patch_push.assert_has_calls(
            [
                call(
                    path="/etc/bess/conf/upf.json",
                    source=expected_config_file_content,
                ),
            ]
        )

    @patch("ops.model.Container.exec", new=Mock)
    @patch("ops.model.Container.exists")
    @patch("ops.model.Container.push")
    def test_given_bessd_config_file_written_when_bessd_pebble_ready_then_config_file_is_not_written(  # noqa: E501
        self,
        patch_push,
        patch_exists,
    ):
        patch_exists.return_value = True

        self.harness.container_pebble_ready(container_name="bessd")

        patch_push.assert_not_called()

    @patch(
        "charms.kubernetes_charm_libraries.v0.multus.KubernetesMultusCharmLib.multus_is_configured"
    )
    @patch("ops.model.Container.push", new=Mock())
    @patch("ops.model.Container.exec", new=Mock())
    @patch("ops.model.Container.exists")
    def test_given_bessd_config_file_is_written_when_bessd_pebble_ready_then_expected_pebble_plan_is_applied(  # noqa: E501
        self,
        patch_exists,
        patch_multus_is_configured,
    ):
        patch_exists.return_value = True
        patch_multus_is_configured.return_value = True

        self.harness.container_pebble_ready(container_name="bessd")

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

    def test_given_bad_config_when_config_changed_then_status_is_blocked(self):
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
    @patch("ops.model.Container.exists")
    def test_given_bessd_config_file_is_written_when_bessd_pebble_ready_then_initial_commands_are_executed(  # noqa: E501
        self, patch_exists, patch_exec, patch_multus_is_configured
    ):
        patch_exists.return_value = True
        patch_multus_is_configured.return_value = True

        self.harness.container_pebble_ready(container_name="bessd")

        patch_exec.assert_has_calls(
            calls=[
                call(
                    command=["ip", "route", "replace", "192.168.251.0/24", "via", "192.168.252.1"],
                    timeout=30,
                    environment=None,
                ),
                call().wait_output(),
                call(
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
                ),
                call().wait_output(),
                call(
                    command=[
                        "iptables",
                        "--check",
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
                ),
                call().wait_output(),
                call(
                    command=["bessctl", "run", "/opt/bess/bessctl/conf/up4"],
                    timeout=30,
                    environment={"CONF_FILE": "/etc/bess/conf/upf.json"},
                ),
                call().wait_output(),
            ],
        )

    @patch("ops.model.Container.exists")
    def test_given_config_file_exists_when_routectl_pebble_ready_then_pebble_plan_is_applied(
        self, patch_exists
    ):
        patch_exists.return_value = True

        self.harness.container_pebble_ready(container_name="routectl")

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

    @patch("ops.model.Container.exists")
    def test_given_can_connect_when_web_pebble_ready_then_pebble_plan_is_applied(
        self, patch_exists
    ):
        patch_exists.return_value = True

        self.harness.container_pebble_ready(container_name="web")

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
    @patch("ops.model.Container.exists")
    def test_given_bessd_service_is_running_when_pfcp_agent_pebble_ready_then_pebble_plan_is_applied(  # noqa: E501
        self,
        patch_exists,
        patch_multus_is_configured,
    ):
        patch_exists.return_value = True
        patch_multus_is_configured.return_value = True
        self.harness.container_pebble_ready(container_name="bessd")

        self.harness.container_pebble_ready(container_name="pfcp-agent")

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

    @patch("ops.model.Container.exec", new=Mock())
    @patch("ops.model.Container.exists")
    def test_given_pfcp_agent_config_file_not_written_when_pfcp_agent_pebble_ready_then_status_is_waiting(  # noqa: E501
        self,
        patch_exists,
    ):
        patch_exists.side_effect = [True, False]
        self.harness.set_can_connect(container="bessd", val=True)

        self.harness.container_pebble_ready(container_name="pfcp-agent")

        self.assertEqual(
            self.harness.model.unit.status,
            WaitingStatus("Waiting for pfcp agent config file to be written"),
        )

    @patch("ops.model.Container.exec", new=Mock())
    @patch("ops.model.Container.exists")
    def test_given_cant_connect_to_bessd_container_when_pfcp_agent_pebble_ready_then_status_is_waiting(  # noqa: E501
        self,
        patch_exists,
    ):
        patch_exists.return_value = True
        self.harness.set_can_connect(container="bessd", val=False)

        self.harness.container_pebble_ready(container_name="pfcp-agent")

        self.assertEqual(
            self.harness.model.unit.status,
            WaitingStatus("Waiting for bessd service to be running"),
        )

    @patch("ops.model.Container.get_service")
    @patch("ops.model.Container.exec", new=Mock())
    @patch("ops.model.Container.exists")
    def test_given_bessd_service_not_running_when_pfcp_agent_pebble_ready_then_status_is_waiting(
        self, patch_exists, patch_get_service
    ):
        patch_exists.return_value = True
        self.harness.set_can_connect(container="bessd", val=True)
        patch_get_service.side_effect = ModelError()

        self.harness.container_pebble_ready(container_name="pfcp-agent")

        self.assertEqual(
            self.harness.model.unit.status,
            WaitingStatus("Waiting for bessd service to be running"),
        )

    @patch(
        "charms.kubernetes_charm_libraries.v0.multus.KubernetesMultusCharmLib.multus_is_configured"
    )
    @patch("ops.model.Container.push", new=Mock)
    @patch("ops.model.Container.exec", new=Mock)
    @patch("ops.model.Container.exists")
    def test_given_config_file_is_written_and_all_services_are_running_when_pebble_ready_then_status_is_active(  # noqa: E501
        self,
        patch_exists,
        patch_multus_is_configured,
    ):
        patch_exists.return_value = True
        patch_multus_is_configured.return_value = True

        self.harness.container_pebble_ready("bessd")
        self.harness.container_pebble_ready("routectl")
        self.harness.container_pebble_ready("web")
        self.harness.container_pebble_ready("pfcp-agent")

        self.assertEqual(self.harness.model.unit.status, ActiveStatus())
