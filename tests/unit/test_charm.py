# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import unittest
from io import StringIO
from unittest.mock import MagicMock, Mock, call, patch

from lightkube.models.core_v1 import ServicePort, ServiceSpec
from lightkube.models.meta_v1 import ObjectMeta
from lightkube.resources.core_v1 import Service
from ops import testing
from ops.model import ActiveStatus, BlockedStatus, MaintenanceStatus, WaitingStatus
from ops.pebble import ExecError

from charm import IncompatibleCPUError, UPFOperatorCharm


def read_file(path: str) -> str:
    """Reads a file and returns as a string.

    Args:
        path (str): path to the file.

    Returns:
        str: content of the file.
    """
    with open(path, "r") as f:
        content = f.read()
    return content


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

    def test_given_bad_config_when_config_changed_then_status_is_blocked(self):
        self.harness.set_leader(is_leader=True)

        self.harness.update_config(key_values={"dnn": ""})

        self.assertEqual(
            self.harness.model.unit.status,
            BlockedStatus("The following configurations are not valid: ['dnn']"),
        )

    @patch("charms.kubernetes_charm_libraries.v0.multus.KubernetesMultusCharmLib.is_ready")
    @patch("ops.model.Container.exec", new=MagicMock)
    @patch("ops.model.Container.exists")
    @patch("ops.model.Container.push")
    def test_given_bessd_config_file_not_yet_written_when_bessd_pebble_ready_then_config_file_is_written(  # noqa: E501
        self,
        patch_push,
        patch_exists,
        patch_is_ready,
    ):
        self.harness.set_leader(is_leader=True)
        patch_exists.side_effect = [True, False, False]
        patch_is_ready.return_value = True

        self.harness.container_pebble_ready(container_name="bessd")

        expected_config_file_content = read_file("tests/unit/expected_upf.json")

        patch_push.assert_any_call(
            path="/etc/bess/conf/upf.json",
            source=expected_config_file_content,
        )

    @patch("charms.kubernetes_charm_libraries.v0.multus.KubernetesMultusCharmLib.is_ready")
    @patch("ops.model.Container.exec", new=MagicMock)
    @patch("ops.model.Container.exists")
    @patch("ops.model.Container.push")
    @patch("ops.model.Container.pull")
    def test_given_bessd_config_file_matches_when_bessd_pebble_ready_then_config_file_is_not_rewritten(  # noqa: E501
        self,
        patch_pull,
        patch_push,
        patch_exists,
        patch_is_ready,
    ):
        self.harness.set_leader(is_leader=True)
        expected_upf_content = read_file("tests/unit/expected_upf.json")
        patch_pull.return_value = StringIO(expected_upf_content)
        patch_exists.return_value = [True, True]
        patch_is_ready.return_value = True

        self.harness.container_pebble_ready(container_name="bessd")

        patch_push.assert_not_called()

    @patch("charms.kubernetes_charm_libraries.v0.multus.KubernetesMultusCharmLib.is_ready")
    @patch("ops.model.Container.push", new=Mock)
    @patch("ops.model.Container.exec", new=MagicMock)
    @patch("ops.model.Container.pull", new=Mock)
    @patch("ops.model.Container.exists")
    def test_given_when_bessd_pebble_ready_then_expected_pebble_plan_is_applied(  # noqa: E501
        self,
        patch_exists,
        patch_is_ready,
    ):
        self.harness.set_leader(is_leader=True)
        patch_exists.return_value = True
        patch_is_ready.return_value = True

        self.harness.container_pebble_ready(container_name="bessd")

        expected_plan = {
            "services": {
                "bessd": {
                    "startup": "enabled",
                    "override": "replace",
                    "command": "/bin/bessd -f -grpc-url=0.0.0.0:10514 -m 0",
                    "environment": {
                        "CONF_FILE": "/etc/bess/conf/upf.json",
                        "PYTHONPATH": "/opt/bess",
                    },
                },
                "routectl": {
                    "startup": "enabled",
                    "override": "replace",
                    "command": "/opt/bess/bessctl/conf/route_control.py -i access core",
                    "environment": {
                        "PYTHONPATH": "/opt/bess",
                        "PYTHONUNBUFFERED": "1",
                    },
                },
            }
        }

        updated_plan = self.harness.get_container_pebble_plan("bessd").to_dict()

        self.assertEqual(expected_plan, updated_plan)

    @patch("charms.kubernetes_charm_libraries.v0.multus.KubernetesMultusCharmLib.is_ready")
    @patch("ops.model.Container.push", new=Mock)
    @patch("ops.model.Container.exec")
    @patch("ops.model.Container.pull", new=Mock)
    @patch("ops.model.Container.exists")
    def test_given_can_connect_to_bessd_when_bessd_pebble_ready_then_ip_route_is_created(
        self, patch_exists, patch_exec, patch_is_ready
    ):
        self.harness.set_leader(is_leader=True)
        patch_exists.return_value = True
        patch_is_ready.return_value = True

        self.harness.container_pebble_ready(container_name="bessd")

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

    @patch("charms.kubernetes_charm_libraries.v0.multus.KubernetesMultusCharmLib.is_ready")
    @patch("ops.model.Container.push", new=Mock)
    @patch("ops.model.Container.exec")
    @patch("ops.model.Container.pull", new=Mock)
    @patch("ops.model.Container.exists")
    def test_given_iptables_rule_is_not_yet_created_when_bessd_pebble_ready_then_rule_is_created(
        self, patch_exists, patch_exec, patch_is_ready
    ):
        self.harness.set_leader(is_leader=True)
        patch_exec.side_effect = [
            MagicMock(),
            ExecError(command=[], exit_code=1, stdout="", stderr=""),
            MagicMock(),
            MagicMock(),
        ]
        patch_exists.return_value = True
        patch_is_ready.return_value = True

        self.harness.container_pebble_ready(container_name="bessd")

        patch_exec.assert_any_call(
            command=[
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
            timeout=30,
            environment=None,
        )

    @patch("charms.kubernetes_charm_libraries.v0.multus.KubernetesMultusCharmLib.is_ready")
    @patch("ops.model.Container.push", new=Mock)
    @patch("ops.model.Container.exec")
    @patch("ops.model.Container.pull", new=Mock)
    @patch("ops.model.Container.exists")
    def test_given_iptables_rule_is_created_when_bessd_pebble_ready_then_rule_is_not_re_created(
        self, patch_exists, patch_exec, patch_is_ready
    ):
        self.harness.set_leader(is_leader=True)
        patch_exists.return_value = True
        patch_is_ready.return_value = True

        self.harness.container_pebble_ready(container_name="bessd")

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
                timeout=300,
                environment=None,
            )
            not in patch_exec.mock_calls
        )

    @patch("charms.kubernetes_charm_libraries.v0.multus.KubernetesMultusCharmLib.is_ready")
    @patch("ops.model.Container.push", new=Mock)
    @patch("ops.model.Container.exec")
    @patch("ops.model.Container.pull", new=Mock)
    @patch("ops.model.Container.exists")
    def test_given_can_connect_to_bessd_when_bessd_pebble_ready_then_bessctl_configure_is_executed(
        self, patch_exists, patch_exec, patch_is_ready
    ):
        self.harness.set_leader(is_leader=True)
        patch_exists.side_effect = [True, True, False]
        patch_is_ready.return_value = True

        self.harness.container_pebble_ready(container_name="bessd")

        patch_exec.assert_any_call(
            command=["/opt/bess/bessctl/bessctl", "run", "/opt/bess/bessctl/conf/up4"],
            timeout=300,
            environment={"CONF_FILE": "/etc/bess/conf/upf.json", "PYTHONPATH": "/opt/bess"},
        )

    @patch("lib.charms.kubernetes_charm_libraries.v0.multus.KubernetesMultusCharmLib.is_ready")
    @patch("ops.model.Container.push", new=Mock)
    @patch("ops.model.Container.exec")
    @patch("ops.model.Container.pull", new=Mock)
    @patch("ops.model.Container.exists")
    def test_given_connects_and_bessctl_executed_file_exists_then_bessctl_configure_not_executed(
        self, patch_exists, patch_exec, patch_is_ready
    ):
        self.harness.set_leader(is_leader=True)
        patch_exists.side_effect = [True, True, True]
        patch_is_ready.return_value = True

        self.harness.container_pebble_ready(container_name="bessd")

        assert (
            call(
                command=["/opt/bess/bessctl/bessctl", "run", "/opt/bess/bessctl/conf/up4"],
                timeout=30,
                environment={"CONF_FILE": "/etc/bess/conf/upf.json", "PYTHONPATH": "/opt/bess"},
            )
            not in patch_exec.mock_calls
        )

    @patch("charms.kubernetes_charm_libraries.v0.multus.KubernetesMultusCharmLib.is_ready")
    @patch("ops.model.Container.push", new=Mock)
    @patch("ops.model.Container.exec")
    @patch("ops.model.Container.pull", new=Mock)
    @patch("ops.model.Container.exists")
    def test_given_connects_and_bessctl_executed_file_dont_exist_then_bessctl_configure_executed(
        self, patch_exists, patch_exec, patch_is_ready
    ):
        self.harness.set_leader(is_leader=True)
        patch_exists.side_effect = [True, True, False]
        patch_is_ready.return_value = True

        self.harness.container_pebble_ready(container_name="bessd")

        patch_exec.assert_any_call(
            command=["/opt/bess/bessctl/bessctl", "run", "/opt/bess/bessctl/conf/up4"],
            timeout=300,
            environment={"CONF_FILE": "/etc/bess/conf/upf.json", "PYTHONPATH": "/opt/bess"},
        )

    @patch("charms.kubernetes_charm_libraries.v0.multus.KubernetesMultusCharmLib.is_ready")
    @patch("ops.model.Container.exec", new=Mock)
    @patch("ops.model.Container.exists")
    def test_given_storage_not_attached_when_bessd_pebble_ready_then_status_is_waiting(
        self,
        patch_exists,
        patch_is_ready,
    ):
        self.harness.set_leader(is_leader=True)
        patch_exists.return_value = False
        patch_is_ready.return_value = True

        self.harness.container_pebble_ready(container_name="bessd")

        self.assertEqual(
            self.harness.model.unit.status,
            WaitingStatus("Waiting for storage to be attached"),
        )

    @patch("charms.kubernetes_charm_libraries.v0.multus.KubernetesMultusCharmLib.is_ready")
    def test_given_multus_not_configured_when_bessd_pebble_ready_then_status_is_waiting(
        self,
        patch_is_ready,
    ):
        self.harness.set_leader(is_leader=True)
        patch_is_ready.return_value = False

        self.harness.container_pebble_ready(container_name="bessd")

        self.assertEqual(
            self.harness.model.unit.status,
            WaitingStatus("Waiting for Multus to be ready"),
        )

    @patch("ops.model.Container.get_service")
    @patch("charms.kubernetes_charm_libraries.v0.multus.KubernetesMultusCharmLib.is_ready")
    @patch("ops.model.Container.push", new=Mock)
    @patch("ops.model.Container.exec", new=MagicMock)
    @patch("ops.model.Container.pull", new=Mock)
    @patch("ops.model.Container.exists")
    def test_given_config_file_is_written_and_all_services_are_running_when_bessd_pebble_ready_then_status_is_active(  # noqa: E501
        self,
        patch_exists,
        patch_is_ready,
        patch_get_service,
    ):
        service_info_mock = Mock()
        service_info_mock.is_running.return_value = True
        patch_get_service.return_value = service_info_mock
        self.harness.set_leader(is_leader=True)
        patch_exists.return_value = True
        patch_is_ready.return_value = True
        self.harness.set_can_connect(container="pfcp-agent", val=True)

        self.harness.container_pebble_ready(container_name="bessd")

        self.assertEqual(self.harness.model.unit.status, ActiveStatus())

    @patch("ops.model.Container.get_service")
    def test_given_bessd_service_is_running_when_pfcp_agent_pebble_ready_then_pebble_plan_is_applied(  # noqa: E501
        self,
        patch_get_service,
    ):
        service_info_mock = Mock()
        service_info_mock.is_running.return_value = True
        patch_get_service.return_value = service_info_mock
        self.harness.set_leader(is_leader=True)
        self.harness.set_can_connect(container="bessd", val=True)

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

    def test_given_cant_connect_to_bessd_container_when_pfcp_agent_pebble_ready_then_status_is_waiting(  # noqa: E501
        self,
    ):
        self.harness.set_leader(is_leader=True)
        self.harness.set_can_connect(container="bessd", val=False)

        self.harness.container_pebble_ready(container_name="pfcp-agent")

        self.assertEqual(
            self.harness.model.unit.status, WaitingStatus("Waiting for bessd service to run")
        )

    @patch("charms.sdcore_upf.v0.fiveg_n3.N3Provides.publish_upf_information")
    def test_given_fiveg_n3_relation_created_when_fiveg_n3_request_then_upf_ip_address_is_published(  # noqa: E501
        self, patched_publish_upf_information
    ):
        self.harness.set_leader(is_leader=True)
        test_upf_access_ip_cidr = "1.2.3.4/21"
        self.harness.update_config(key_values={"access-ip": test_upf_access_ip_cidr})

        n3_relation_id = self.harness.add_relation("fiveg_n3", "n3_requirer_app")
        self.harness.add_relation_unit(n3_relation_id, "n3_requirer_app/0")

        patched_publish_upf_information.assert_called_once_with(
            relation_id=n3_relation_id, upf_ip_address=test_upf_access_ip_cidr.split("/")[0]
        )

    @patch("charms.sdcore_upf.v0.fiveg_n3.N3Provides.publish_upf_information")
    def test_given_unit_is_not_leader_when_fiveg_n3_request_then_upf_ip_address_is_not_published(
        self, patched_publish_upf_information
    ):
        test_upf_access_ip_cidr = "1.2.3.4/21"
        self.harness.update_config(key_values={"access-ip": test_upf_access_ip_cidr})

        n3_relation_id = self.harness.add_relation("fiveg_n3", "n3_requirer_app")
        self.harness.add_relation_unit(n3_relation_id, "n3_requirer_app/0")

        patched_publish_upf_information.assert_not_called()

    @patch("charms.sdcore_upf.v0.fiveg_n3.N3Provides.publish_upf_information")
    @patch("charms.kubernetes_charm_libraries.v0.multus.KubernetesMultusCharmLib.is_ready")
    @patch("ops.model.Container.push", new=Mock)
    @patch("ops.model.Container.exec", new=MagicMock)
    @patch("ops.model.Container.pull", new=Mock)
    @patch("ops.model.Container.exists")
    def test_given_fiveg_n3_relation_exists_when_access_ip_config_changed_then_new_upf_ip_address_is_published(  # noqa: E501
        self, patch_exists, patch_multus_is_ready, patched_publish_upf_information
    ):
        patch_exists.return_value = True
        patch_multus_is_ready.return_value = True
        self.harness.set_can_connect(container="bessd", val=True)
        self.harness.set_can_connect(container="pfcp-agent", val=True)
        self.harness.set_leader(is_leader=True)
        n3_relation_id = self.harness.add_relation("fiveg_n3", "n3_requirer_app")
        self.harness.add_relation_unit(n3_relation_id, "n3_requirer_app/0")
        test_upf_access_ip_cidr = "1.2.3.4/21"
        expected_calls = [
            call(relation_id=n3_relation_id, upf_ip_address="192.168.252.3"),
            call(relation_id=n3_relation_id, upf_ip_address=test_upf_access_ip_cidr.split("/")[0]),
        ]

        self.harness.update_config(key_values={"access-ip": test_upf_access_ip_cidr})

        patched_publish_upf_information.assert_has_calls(expected_calls)

    @patch("charms.sdcore_upf.v0.fiveg_n3.N3Provides.publish_upf_information")
    @patch("charms.kubernetes_charm_libraries.v0.multus.KubernetesMultusCharmLib.is_ready")
    @patch("ops.model.Container.push", new=Mock)
    @patch("ops.model.Container.exec", new=Mock)
    @patch("ops.model.Container.pull", new=Mock)
    @patch("ops.model.Container.exists")
    def test_given_fiveg_n3_relation_exists_when_access_ip_config_changed_to_invalid_cidr_then_new_upf_ip_address_is_not_published(  # noqa: E501
        self, patch_exists, patch_multus_is_ready, patched_publish_upf_information
    ):
        patch_exists.return_value = True
        patch_multus_is_ready.return_value = True
        self.harness.set_can_connect(container="bessd", val=True)
        self.harness.set_can_connect(container="pfcp-agent", val=True)
        self.harness.set_leader(is_leader=True)
        n3_relation_id = self.harness.add_relation("fiveg_n3", "n3_requirer_app")
        self.harness.add_relation_unit(n3_relation_id, "n3_requirer_app/0")
        invalid_test_upf_access_ip_cidr = "1111.2.3.4/21"

        self.harness.update_config(key_values={"access-ip": invalid_test_upf_access_ip_cidr})

        patched_publish_upf_information.assert_called_once_with(
            relation_id=n3_relation_id, upf_ip_address="192.168.252.3"
        )

    def test_given_default_config_when_network_attachment_definitions_from_config_is_called_then_no_interface_specified_in_nad(  # noqa: E501
        self,
    ):
        self.harness.disable_hooks()
        self.harness.update_config(
            key_values={
                "access-ip": "192.168.252.3/24",
                "access-gateway-ip": "192.168.252.1",
                "gnb-subnet": "192.168.251.0/24",
                "core-ip": "192.168.250.3/24",
                "core-gateway-ip": "192.168.250.1",
            }
        )
        nads = self.harness.charm._network_attachment_definitions_from_config()
        for nad in nads:
            config = json.loads(nad.spec["config"])
            self.assertNotIn("master", config)
            self.assertEqual("bridge", config["type"])
            self.assertIn(config["bridge"], ("core-br", "access-br"))

    def test_given_default_config_with_interfaces_when_network_attachment_definitions_from_config_is_called_then_interfaces_specified_in_nad(  # noqa: E501
        self,
    ):
        self.harness.disable_hooks()
        self.harness.update_config(
            key_values={
                "access-interface": "access-net",
                "access-ip": "192.168.252.3/24",
                "access-gateway-ip": "192.168.252.1",
                "gnb-subnet": "192.168.251.0/24",
                "core-interface": "core-net",
                "core-ip": "192.168.250.3/24",
                "core-gateway-ip": "192.168.250.1",
            }
        )
        nads = self.harness.charm._network_attachment_definitions_from_config()
        for nad in nads:
            config = json.loads(nad.spec["config"])
            self.assertEqual(config["master"], nad.metadata.name)
            self.assertEqual(config["type"], "macvlan")

    @patch("charm.check_output")
    @patch("charm.Client", new=Mock)
    def test_given_cpu_not_supporting_required_instructions_when_install_then_incompatiblecpuerror_is_raised(  # noqa: E501
        self, patched_check_output
    ):
        patched_check_output.return_value = b"Flags: ssse3 fma cx16 rdrand"

        with self.assertRaises(IncompatibleCPUError):
            self.harness.charm.on.install.emit()

    @patch("charm.check_output")
    @patch("charm.Client", new=Mock)
    def test_given_cpu_supporting_required_instructions_when_install_then_charm_goes_to_maintenance_status(  # noqa: E501
        self, patched_check_output
    ):
        patched_check_output.return_value = b"Flags: avx2 ssse3 fma cx16 rdrand"

        self.harness.charm.on.install.emit()

        self.assertEqual(self.harness.model.unit.status, MaintenanceStatus())

    @patch("charm.Client")
    def test_when_install_then_external_service_is_created(self, patch_client):
        self.harness.charm.on.install.emit()

        expected_service = Service(
            apiVersion="v1",
            kind="Service",
            metadata=ObjectMeta(
                namespace=self.namespace,
                name=f"{self.harness.charm.app.name}-external",
                labels={
                    "app.kubernetes.io/name": self.harness.charm.app.name,
                },
            ),
            spec=ServiceSpec(
                selector={
                    "app.kubernetes.io/name": self.harness.charm.app.name,
                },
                ports=[
                    ServicePort(name="pfcp", port=8805, protocol="UDP"),
                ],
                type="LoadBalancer",
            ),
        )

        patch_client.return_value.create.assert_called_once_with(expected_service)

    @patch("charm.Client")
    def test_when_remove_then_external_service_is_deleted(self, patch_client):
        self.harness.charm.on.remove.emit()

        patch_client.return_value.delete.assert_called_once_with(
            Service,
            name=f"{self.harness.charm.app.name}-external",
            namespace=self.namespace,
        )
