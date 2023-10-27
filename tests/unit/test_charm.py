# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import unittest
from unittest.mock import MagicMock, Mock, call, patch

from charms.kubernetes_charm_libraries.v0.multus import (  # type: ignore[import]
    NetworkAttachmentDefinition,
)
from lightkube.models.core_v1 import ServicePort, ServiceSpec
from lightkube.models.meta_v1 import ObjectMeta
from lightkube.resources.core_v1 import Service
from ops import testing
from ops.model import ActiveStatus, BlockedStatus, MaintenanceStatus, WaitingStatus
from ops.pebble import ExecError

from charm import IncompatibleCPUError, UPFOperatorCharm

MULTUS_LIBRARY_PATH = "charms.kubernetes_charm_libraries.v0.multus"
HUGEPAGES_LIBRARY_PATH = "charms.kubernetes_charm_libraries.v0.hugepages_volumes_patch"
TOO_BIG_MTU_SIZE = 65536  # Out of range
TOO_SMALL_MTU_SIZE = 1199  # Out of range
ZERO_MTU_SIZE = 0  # Out of range
VALID_MTU_SIZE_1 = 65535  # Upper edge value
VALID_MTU_SIZE_2 = 1200  # Lower edge value
TEST_PFCP_PORT = 1234
ACCESS_INTERFACE_NAME = "access-net"
DEFAULT_ACCESS_IP = "192.168.252.3/24"
INVALID_ACCESS_IP = "192.168.252.3/44"
VALID_ACCESS_IP = "192.168.252.5/24"
ACCESS_GW_IP = "192.168.252.1"
GNB_SUBNET = "192.168.251.0/24"
CORE_IP = "192.168.250.3/24"
CORE_GW_IP = "192.168.250.1"


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


def update_nad_labels(nads: list[NetworkAttachmentDefinition], app_name: str) -> None:
    """Sets NetworkAttachmentDefinition metadata labels.

    Args:
        nads: list of NetworkAttachmentDefinition
        app_name: application name
    """
    for nad in nads:
        nad.metadata.labels = {"app.juju.is/created-by": app_name}


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

        self.root = self.harness.get_filesystem_root("bessd")
        (self.root / "etc/bess/conf").mkdir(parents=True)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    def test_given_bad_config_when_config_changed_then_status_is_blocked(self):
        self.harness.set_leader(is_leader=True)

        self.harness.update_config(key_values={"dnn": ""})

        self.assertEqual(
            self.harness.model.unit.status,
            BlockedStatus("The following configurations are not valid: ['dnn']"),
        )

    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready")
    @patch("ops.model.Container.exec", new=MagicMock)
    def test_given_bessd_config_file_not_yet_written_when_bessd_pebble_ready_then_config_file_is_written(  # noqa: E501
        self,
        patch_is_ready,
    ):
        self.harness.set_leader(is_leader=True)

        self.harness.container_pebble_ready(container_name="bessd")

        expected_config_file_content = read_file("tests/unit/expected_upf.json")

        self.assertEqual(
            (self.root / "etc/bess/conf/upf.json").read_text(), expected_config_file_content
        )

    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready")
    @patch("ops.model.Container.exec", new=MagicMock)
    def test_given_bessd_config_file_not_yet_written_when_config_storage_attached_then_config_file_is_written(  # noqa: E501
        self,
        patch_is_ready,
    ):
        self.harness.set_leader(is_leader=True)

        self.harness.set_can_connect("bessd", True)
        (self.root / "etc/bess/conf").rmdir()
        self.harness.add_storage(storage_name="config", count=1)
        self.harness.attach_storage(storage_id="config/0")

        expected_config_file_content = read_file("tests/unit/expected_upf.json")

        self.assertEqual(
            (self.root / "etc/bess/conf/upf.json").read_text(), expected_config_file_content
        )

    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready")
    @patch("ops.model.Container.exec", new=MagicMock)
    def test_given_bessd_config_file_matches_when_bessd_pebble_ready_then_config_file_is_not_changed(  # noqa: E501
        self,
        patch_is_ready,
    ):
        self.harness.set_leader(is_leader=True)
        patch_is_ready.return_value = True
        expected_upf_content = read_file("tests/unit/expected_upf.json")
        (self.root / "etc/bess/conf/upf.json").write_text(expected_upf_content)

        self.harness.container_pebble_ready(container_name="bessd")

        self.assertEqual((self.root / "etc/bess/conf/upf.json").read_text(), expected_upf_content)

    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready")
    @patch("ops.model.Container.exec", new=MagicMock)
    def test_given_when_bessd_pebble_ready_then_expected_pebble_plan_is_applied(  # noqa: E501
        self,
        patch_is_ready,
    ):
        self.harness.set_leader(is_leader=True)
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

    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready")
    @patch("ops.model.Container.exec")
    def test_given_can_connect_to_bessd_when_bessd_pebble_ready_then_ip_route_is_created(
        self, patch_exec, patch_is_ready
    ):
        self.harness.set_leader(is_leader=True)
        patch_is_ready.return_value = True

        self.harness.container_pebble_ready(container_name="bessd")

        patch_exec.assert_any_call(
            command=[
                "ip",
                "route",
                "replace",
                "default",
                "via",
                CORE_GW_IP,
                "metric",
                "110",
            ],
            timeout=30,
            environment=None,
        )

    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready")
    @patch("ops.model.Container.exec")
    def test_given_iptables_rule_is_not_yet_created_when_bessd_pebble_ready_then_rule_is_created(
        self, patch_exec, patch_is_ready
    ):
        self.harness.set_leader(is_leader=True)
        patch_exec.side_effect = [
            MagicMock(),
            ExecError(command=[], exit_code=1, stdout="", stderr=""),
            MagicMock(),
            MagicMock(),
        ]
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

    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready")
    @patch("ops.model.Container.exec")
    def test_given_iptables_rule_is_created_when_bessd_pebble_ready_then_rule_is_not_re_created(
        self, patch_exec, patch_is_ready
    ):
        self.harness.set_leader(is_leader=True)
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

    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready")
    @patch("ops.model.Container.exec")
    def test_given_can_connect_to_bessd_when_bessd_pebble_ready_then_bessctl_configure_is_executed(
        self, patch_exec, patch_is_ready
    ):
        self.harness.set_leader(is_leader=True)
        patch_is_ready.return_value = True

        self.harness.container_pebble_ready(container_name="bessd")

        patch_exec.assert_any_call(
            command=["/opt/bess/bessctl/bessctl", "run", "/opt/bess/bessctl/conf/up4"],
            timeout=300,
            environment={"CONF_FILE": "/etc/bess/conf/upf.json", "PYTHONPATH": "/opt/bess"},
        )

    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready")
    @patch("ops.model.Container.exec")
    def test_given_connects_and_bessctl_executed_file_exists_then_bessctl_configure_not_executed(
        self, patch_exec, patch_is_ready
    ):
        self.harness.set_leader(is_leader=True)
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

    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready")
    @patch("ops.model.Container.exec")
    def test_given_connects_and_bessctl_executed_file_dont_exist_then_bessctl_configure_executed(
        self, patch_exec, patch_is_ready
    ):
        self.harness.set_leader(is_leader=True)
        patch_is_ready.return_value = True

        self.harness.container_pebble_ready(container_name="bessd")

        patch_exec.assert_any_call(
            command=["/opt/bess/bessctl/bessctl", "run", "/opt/bess/bessctl/conf/up4"],
            timeout=300,
            environment={"CONF_FILE": "/etc/bess/conf/upf.json", "PYTHONPATH": "/opt/bess"},
        )

    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready")
    @patch("ops.model.Container.exec", new=Mock)
    def test_given_storage_not_attached_when_bessd_pebble_ready_then_status_is_waiting(
        self,
        patch_is_ready,
    ):
        self.harness.set_leader(is_leader=True)
        patch_is_ready.return_value = True
        (self.root / "etc/bess/conf").rmdir()

        self.harness.container_pebble_ready(container_name="bessd")

        self.assertEqual(
            self.harness.model.unit.status,
            WaitingStatus("Waiting for storage to be attached"),
        )

    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready")
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
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready")
    @patch("ops.model.Container.exec", new=MagicMock)
    def test_given_config_file_is_written_and_all_services_are_running_when_bessd_pebble_ready_then_status_is_active(  # noqa: E501
        self,
        patch_is_ready,
        patch_get_service,
    ):
        service_info_mock = Mock()
        service_info_mock.is_running.return_value = True
        patch_get_service.return_value = service_info_mock
        self.harness.set_leader(is_leader=True)
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

    @patch(f"{HUGEPAGES_LIBRARY_PATH}.KubernetesHugePagesPatchCharmLib.is_patched")
    @patch("charms.sdcore_upf.v0.fiveg_n3.N3Provides.publish_upf_information")
    def test_given_fiveg_n3_relation_created_when_fiveg_n3_request_then_upf_ip_address_is_published(  # noqa: E501
        self,
        patched_publish_upf_information,
        patch_hugepages_is_patched,
    ):
        patch_hugepages_is_patched.return_value = True
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

    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesClient", new=Mock)
    @patch("charms.sdcore_upf.v0.fiveg_n3.N3Provides.publish_upf_information")
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready")
    @patch(f"{HUGEPAGES_LIBRARY_PATH}.KubernetesHugePagesPatchCharmLib.is_patched")
    @patch("ops.model.Container.exec", new=MagicMock)
    def test_given_fiveg_n3_relation_exists_when_access_ip_config_changed_then_new_upf_ip_address_is_published(  # noqa: E501
        self,
        patch_multus_is_ready,
        patch_hugepages_is_patched,
        patched_publish_upf_information,
    ):
        patch_multus_is_ready.return_value = True
        patch_hugepages_is_patched.return_value = True
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
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready")
    @patch("ops.model.Container.exec", new=Mock)
    def test_given_fiveg_n3_relation_exists_when_access_ip_config_changed_to_invalid_cidr_then_new_upf_ip_address_is_not_published(  # noqa: E501
        self, patch_multus_is_ready, patched_publish_upf_information
    ):
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

    @patch("charms.sdcore_upf.v0.fiveg_n4.N4Provides.publish_upf_n4_information")
    def test_given_unit_is_not_leader_when_fiveg_n4_request_then_upf_hostname_is_not_published(
        self, patched_publish_upf_n4_information
    ):
        test_external_upf_hostname = "test-upf.external.hostname.com"
        self.harness.update_config(
            key_values={"external-upf-hostname": test_external_upf_hostname}
        )

        n4_relation_id = self.harness.add_relation("fiveg_n4", "n4_requirer_app")
        self.harness.add_relation_unit(n4_relation_id, "n4_requirer_app/0")

        patched_publish_upf_n4_information.assert_not_called()

    @patch(f"{HUGEPAGES_LIBRARY_PATH}.KubernetesHugePagesPatchCharmLib.is_patched")
    @patch("charms.sdcore_upf.v0.fiveg_n4.N4Provides.publish_upf_n4_information")
    @patch("charm.PFCP_PORT", TEST_PFCP_PORT)
    def test_given_external_upf_hostname_config_set_and_fiveg_n4_relation_created_when_fiveg_n4_request_then_upf_hostname_and_n4_port_is_published(  # noqa: E501
        self,
        patched_publish_upf_n4_information,
        patch_hugepages_is_patched,
    ):
        patch_hugepages_is_patched.return_value = True
        self.harness.set_leader(is_leader=True)
        test_external_upf_hostname = "test-upf.external.hostname.com"
        self.harness.update_config(
            key_values={"external-upf-hostname": test_external_upf_hostname}
        )

        n4_relation_id = self.harness.add_relation("fiveg_n4", "n4_requirer_app")
        self.harness.add_relation_unit(n4_relation_id, "n4_requirer_app/0")

        patched_publish_upf_n4_information.assert_called_once_with(
            relation_id=n4_relation_id,
            upf_hostname=test_external_upf_hostname,
            upf_n4_port=TEST_PFCP_PORT,
        )

    @patch("lightkube.core.client.GenericSyncClient", new=Mock)
    @patch("lightkube.core.client.Client.get")
    @patch("charms.sdcore_upf.v0.fiveg_n4.N4Provides.publish_upf_n4_information")
    @patch("charm.PFCP_PORT", TEST_PFCP_PORT)
    def test_given_external_upf_hostname_config_not_set_but_external_upf_service_hostname_available_and_fiveg_n4_relation_created_when_fiveg_n4_request_then_upf_hostname_and_n4_port_is_published(  # noqa: E501
        self, patched_publish_upf_n4_information, patched_lightkube_client_get
    ):
        self.harness.set_leader(is_leader=True)
        test_external_upf_service_hostname = "test-upf.external.service.hostname.com"
        service = Mock(
            status=Mock(
                loadBalancer=Mock(
                    ingress=[Mock(ip="1.1.1.1", hostname=test_external_upf_service_hostname)]
                )
            )
        )
        patched_lightkube_client_get.return_value = service

        n4_relation_id = self.harness.add_relation("fiveg_n4", "n4_requirer_app")
        self.harness.add_relation_unit(n4_relation_id, "n4_requirer_app/0")

        patched_publish_upf_n4_information.assert_called_once_with(
            relation_id=n4_relation_id,
            upf_hostname=test_external_upf_service_hostname,
            upf_n4_port=TEST_PFCP_PORT,
        )

    @patch("lightkube.core.client.GenericSyncClient", new=Mock)
    @patch("lightkube.core.client.Client.get")
    @patch("charms.sdcore_upf.v0.fiveg_n4.N4Provides.publish_upf_n4_information")
    @patch("charm.PFCP_PORT", TEST_PFCP_PORT)
    def test_given_external_upf_hostname_config_not_set_and_external_upf_service_hostname_not_available_and_fiveg_n4_relation_created_when_fiveg_n4_request_then_upf_hostname_and_n4_port_is_published(  # noqa: E501
        self, patched_publish_upf_n4_information, patched_lightkube_client_get
    ):
        self.harness.set_leader(is_leader=True)
        service = Mock(status=Mock(loadBalancer=Mock(ingress=[Mock(ip="1.1.1.1", spec=["ip"])])))
        patched_lightkube_client_get.return_value = service

        n4_relation_id = self.harness.add_relation("fiveg_n4", "n4_requirer_app")
        self.harness.add_relation_unit(n4_relation_id, "n4_requirer_app/0")

        patched_publish_upf_n4_information.assert_called_once_with(
            relation_id=n4_relation_id,
            upf_hostname=f"{self.harness.charm.app.name}-external.{self.namespace}"
            ".svc.cluster.local",
            upf_n4_port=TEST_PFCP_PORT,
        )

    @patch("charms.sdcore_upf.v0.fiveg_n4.N4Provides.publish_upf_n4_information")
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready")
    @patch(f"{HUGEPAGES_LIBRARY_PATH}.KubernetesHugePagesPatchCharmLib.is_patched")
    @patch("ops.model.Container.exec", new=MagicMock)
    @patch("charm.PFCP_PORT", TEST_PFCP_PORT)
    def test_given_fiveg_n4_relation_exists_when_external_upf_hostname_config_changed_then_new_upf_hostname_is_published(  # noqa: E501
        self,
        patch_multus_is_ready,
        patch_hugepages_is_ready,
        patched_publish_upf_n4_information,
    ):
        test_external_upf_hostname = "test-upf.external.hostname.com"
        patch_multus_is_ready.return_value = True
        patch_hugepages_is_ready.return_value = True
        self.harness.set_can_connect(container="bessd", val=True)
        self.harness.set_can_connect(container="pfcp-agent", val=True)
        self.harness.set_leader(is_leader=True)
        self.harness.update_config(key_values={"external-upf-hostname": "whatever.com"})
        n4_relation_id = self.harness.add_relation("fiveg_n4", "n4_requirer_app")
        self.harness.add_relation_unit(n4_relation_id, "n4_requirer_app/0")
        expected_calls = [
            call(
                relation_id=n4_relation_id, upf_hostname="whatever.com", upf_n4_port=TEST_PFCP_PORT
            ),
            call(
                relation_id=n4_relation_id,
                upf_hostname=test_external_upf_hostname,
                upf_n4_port=TEST_PFCP_PORT,
            ),
        ]

        self.harness.update_config(
            key_values={"external-upf-hostname": test_external_upf_hostname}
        )

        patched_publish_upf_n4_information.assert_has_calls(expected_calls)

    @patch(f"{HUGEPAGES_LIBRARY_PATH}.KubernetesHugePagesPatchCharmLib.is_patched")
    def test_given_default_config_when_network_attachment_definitions_from_config_is_called_then_no_interface_specified_in_nad(  # noqa: E501
        self,
        patch_hugepages_is_patched,
    ):
        patch_hugepages_is_patched.return_value = True
        self.harness.set_leader(is_leader=True)
        self.harness.update_config(
            key_values={
                "access-ip": DEFAULT_ACCESS_IP,
                "access-gateway-ip": ACCESS_GW_IP,
                "gnb-subnet": GNB_SUBNET,
                "core-ip": CORE_IP,
                "core-gateway-ip": CORE_GW_IP,
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
                "access-interface": ACCESS_INTERFACE_NAME,
                "access-ip": DEFAULT_ACCESS_IP,
                "access-gateway-ip": ACCESS_GW_IP,
                "gnb-subnet": GNB_SUBNET,
                "core-interface": "core-net",
                "core-ip": CORE_IP,
                "core-gateway-ip": CORE_GW_IP,
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

        patch_client.return_value.apply.assert_called_once_with(
            expected_service, field_manager="controller"
        )

    @patch("charm.Client")
    def test_when_remove_then_external_service_is_deleted(self, patch_client):
        self.harness.charm.on.remove.emit()

        patch_client.return_value.delete.assert_called_once_with(
            Service,
            name=f"{self.harness.charm.app.name}-external",
            namespace=self.namespace,
        )

    @patch(f"{HUGEPAGES_LIBRARY_PATH}.KubernetesHugePagesPatchCharmLib.is_patched")
    def test_given_default_config_when_network_attachment_definitions_from_config_is_called_then_no_interface_mtu_specified_in_nad(  # noqa: E501
        self,
        patch_hugepages_is_patched,
    ):
        patch_hugepages_is_patched.return_value = True
        self.harness.set_leader(is_leader=True)
        self.harness.update_config(
            key_values={
                "access-ip": "192.168.252.3/24",
                "access-gateway-ip": ACCESS_GW_IP,
                "gnb-subnet": GNB_SUBNET,
                "core-ip": CORE_IP,
                "core-gateway-ip": CORE_GW_IP,
            }
        )
        nads = self.harness.charm._network_attachment_definitions_from_config()
        for nad in nads:
            config = json.loads(nad.spec["config"])
            self.assertNotIn("mtu", config)

    @patch(f"{HUGEPAGES_LIBRARY_PATH}.KubernetesHugePagesPatchCharmLib.is_patched")
    def test_given_default_config_with_interfaces_mtu_sizes_when_network_attachment_definitions_from_config_is_called_then_mtu_sizes_specified_in_nad(  # noqa: E501
        self,
        patch_hugepages_is_patched,
    ):
        patch_hugepages_is_patched.return_value = True
        self.harness.set_leader(is_leader=True)
        self.harness.update_config(
            key_values={
                "access-ip": "192.168.252.3/24",
                "access-gateway-ip": ACCESS_GW_IP,
                "access-interface-mtu-size": VALID_MTU_SIZE_1,
                "gnb-subnet": GNB_SUBNET,
                "core-ip": CORE_IP,
                "core-gateway-ip": CORE_GW_IP,
                "core-interface-mtu-size": VALID_MTU_SIZE_1,
            }
        )
        nads = self.harness.charm._network_attachment_definitions_from_config()
        for nad in nads:
            config = json.loads(nad.spec["config"])
            self.assertEqual(config["mtu"], 65535)

    def test_given_default_config_with_interfaces_too_small_and_too_big_mtu_sizes_when_network_attachment_definitions_from_config_is_called_then_status_is_blocked(  # noqa: E501
        self,
    ):
        self.harness.set_leader(is_leader=True)
        self.harness.update_config(
            key_values={
                "access-interface-mtu-size": TOO_SMALL_MTU_SIZE,
                "core-interface-mtu-size": TOO_BIG_MTU_SIZE,
            }
        )
        self.assertEqual(
            self.harness.model.unit.status,
            BlockedStatus(
                "The following configurations are not valid: ['access-interface-mtu-size', 'core-interface-mtu-size']"  # noqa: E501, W505
            ),
        )

    def test_given_default_config_with_interfaces_zero_mtu_sizes_when_network_attachment_definitions_from_config_is_called_then_status_is_blocked(  # noqa: E501
        self,
    ):
        self.harness.set_leader(is_leader=True)
        self.harness.update_config(
            key_values={
                "access-interface-mtu-size": ZERO_MTU_SIZE,
                "core-interface-mtu-size": ZERO_MTU_SIZE,
            }
        )
        self.assertEqual(
            self.harness.model.unit.status,
            BlockedStatus(
                "The following configurations are not valid: ['access-interface-mtu-size', 'core-interface-mtu-size']"  # noqa: E501, W505
            ),
        )

    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesClient", new=Mock)
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesClient.list_network_attachment_definitions")
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready")
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.delete_pod")
    @patch(f"{HUGEPAGES_LIBRARY_PATH}.KubernetesHugePagesPatchCharmLib.is_patched")
    @patch("ops.model.Container.exec", new=MagicMock)
    def test_given_container_can_connect_bessd_pebble_ready_when_core_net_mtu_config_changed_to_a_different_valid_value_then_delete_pod_is_called(  # noqa: E501
        self,
        patch_hugepages_is_patched,
        patch_delete_pod,
        patch_multus_is_ready,
        patch_list_na_definitions,
    ):
        patch_hugepages_is_patched.return_value = True
        patch_multus_is_ready.return_value = True
        self.harness.set_can_connect(container="bessd", val=True)
        self.harness.set_can_connect(container="pfcp-agent", val=True)
        self.harness.set_leader(is_leader=True)
        original_nads = self.harness.charm._network_attachment_definitions_from_config()
        update_nad_labels(original_nads, self.harness.charm.app.name)
        patch_list_na_definitions.return_value = original_nads
        self.harness.update_config(key_values={"core-interface-mtu-size": VALID_MTU_SIZE_1})
        patch_delete_pod.assert_called_once()

    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesClient", new=Mock)
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesClient.list_network_attachment_definitions")
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready")
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.delete_pod")
    @patch(f"{HUGEPAGES_LIBRARY_PATH}.KubernetesHugePagesPatchCharmLib.is_patched")
    @patch("ops.model.Container.exec", new=MagicMock)
    def test_given_container_can_connect_bessd_pebble_ready_when_core_net_mtu_config_changed_to_different_valid_values_then_delete_pod_called_twice(  # noqa: E501
        self,
        patch_hugepages_is_patched,
        patch_delete_pod,
        patch_multus_is_ready,
        patch_list_na_definitions,
    ):
        patch_hugepages_is_patched.return_value = True
        patch_multus_is_ready.return_value = True
        self.harness.set_can_connect(container="bessd", val=True)
        self.harness.set_can_connect(container="pfcp-agent", val=True)
        self.harness.set_leader(is_leader=True)
        original_nads = self.harness.charm._network_attachment_definitions_from_config()
        update_nad_labels(original_nads, self.harness.charm.app.name)
        patch_list_na_definitions.return_value = original_nads
        self.harness.update_config(key_values={"core-interface-mtu-size": VALID_MTU_SIZE_1})
        modified_nads = self.harness.charm._network_attachment_definitions_from_config()
        update_nad_labels(modified_nads, self.harness.charm.app.name)
        patch_list_na_definitions.return_value = modified_nads
        self.harness.update_config(key_values={"core-interface-mtu-size": VALID_MTU_SIZE_2})
        self.assertEqual(patch_delete_pod.call_count, 2)

    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesClient", new=Mock)
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesClient.list_network_attachment_definitions")
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready")
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesClient.delete_pod")
    @patch(f"{HUGEPAGES_LIBRARY_PATH}.KubernetesHugePagesPatchCharmLib.is_patched")
    @patch("ops.model.Container.exec", new=MagicMock)
    def test_given_container_can_connect_bessd_pebble_ready_when_core_net_mtu_config_changed_to_same_valid_value_multiple_times_then_delete_pod_called_once(  # noqa: E501
        self,
        patch_hugepages_is_patched,
        patch_delete_pod,
        patch_multus_is_ready,
        patch_list_na_definitions,
    ):
        """Delete pod is called for the first config change, setting the same config value does not trigger pod restarts."""  # noqa: E501, W505
        patch_hugepages_is_patched.return_value = True
        patch_multus_is_ready.return_value = True
        self.harness.set_can_connect(container="bessd", val=True)
        self.harness.set_can_connect(container="pfcp-agent", val=True)
        self.harness.set_leader(is_leader=True)
        original_nads = self.harness.charm._network_attachment_definitions_from_config()
        update_nad_labels(original_nads, self.harness.charm.app.name)
        patch_list_na_definitions.return_value = original_nads
        self.harness.update_config(key_values={"core-interface-mtu-size": VALID_MTU_SIZE_2})
        patch_delete_pod.assert_called_once()
        nads_after_first_config_change = (
            self.harness.charm._network_attachment_definitions_from_config()
        )
        update_nad_labels(nads_after_first_config_change, self.harness.charm.app.name)
        patch_list_na_definitions.return_value = nads_after_first_config_change
        self.harness.update_config(key_values={"core-interface-mtu-size": VALID_MTU_SIZE_2})
        patch_delete_pod.assert_called_once()
        nads_after_second_config_change = (
            self.harness.charm._network_attachment_definitions_from_config()
        )
        update_nad_labels(nads_after_second_config_change, self.harness.charm.app.name)
        for nad in nads_after_second_config_change:
            nad.metadata.labels = {"app.juju.is/created-by": self.harness.charm.app.name}
        patch_list_na_definitions.return_value = nads_after_second_config_change
        self.harness.update_config(key_values={"core-interface-mtu-size": VALID_MTU_SIZE_2})
        patch_delete_pod.assert_called_once()

    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesClient", new=Mock)
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesClient.list_network_attachment_definitions")
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready")
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.delete_pod")
    @patch("ops.model.Container.exec", new=MagicMock)
    def test_given_container_can_connect_bessd_pebble_ready_when_core_net_mtu_config_changed_to_an_invalid_value_then_delete_pod_is_not_called(  # noqa: E501
        self,
        patch_delete_pod,
        patch_multus_is_ready,
        patch_list_na_definitions,
    ):
        patch_multus_is_ready.return_value = True
        self.harness.set_can_connect(container="bessd", val=True)
        self.harness.set_can_connect(container="pfcp-agent", val=True)
        self.harness.set_leader(is_leader=True)
        original_nads = self.harness.charm._network_attachment_definitions_from_config()
        update_nad_labels(original_nads, self.harness.charm.app.name)
        patch_list_na_definitions.return_value = original_nads
        self.harness.update_config(key_values={"core-interface-mtu-size": TOO_BIG_MTU_SIZE})
        patch_delete_pod.assert_not_called()
