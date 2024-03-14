# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import unittest
from unittest.mock import Mock, call, patch

from charms.kubernetes_charm_libraries.v0.multus import (  # type: ignore[import]
    NetworkAnnotation,
    NetworkAttachmentDefinition,
)
from httpx import HTTPStatusError
from lightkube.models.core_v1 import Node, NodeStatus, ServicePort, ServiceSpec
from lightkube.models.meta_v1 import ObjectMeta
from lightkube.resources.core_v1 import Service
from ops import ActiveStatus, BlockedStatus, MaintenanceStatus, WaitingStatus, testing

from charm import (
    ACCESS_INTERFACE_NAME,
    ACCESS_NETWORK_ATTACHMENT_DEFINITION_NAME,
    CORE_INTERFACE_NAME,
    CORE_NETWORK_ATTACHMENT_DEFINITION_NAME,
    DPDK_ACCESS_INTERFACE_RESOURCE_NAME,
    DPDK_CORE_INTERFACE_RESOURCE_NAME,
    UPFOperatorCharm,
)

MULTUS_LIBRARY_PATH = "charms.kubernetes_charm_libraries.v0.multus"
HUGEPAGES_LIBRARY_PATH = "charms.kubernetes_charm_libraries.v0.hugepages_volumes_patch"
TOO_BIG_MTU_SIZE = 65536  # Out of range
TOO_SMALL_MTU_SIZE = 1199  # Out of range
ZERO_MTU_SIZE = 0  # Out of range
VALID_MTU_SIZE_1 = 65535  # Upper edge value
VALID_MTU_SIZE_2 = 1200  # Lower edge value
TEST_PFCP_PORT = 1234
DEFAULT_ACCESS_IP = "192.168.252.3/24"
INVALID_ACCESS_IP = "192.168.252.3/44"
VALID_ACCESS_IP = "192.168.252.5/24"
ACCESS_GW_IP = "192.168.252.1"
GNB_SUBNET = "192.168.251.0/24"
VALID_CORE_IP = "192.168.250.3/24"
CORE_GW_IP = "192.168.250.1"
VALID_ACCESS_MAC = "00-b0-d0-63-c2-26"
INVALID_ACCESS_MAC = "something"
VALID_CORE_MAC = "00-b0-d0-63-c2-36"
INVALID_CORE_MAC = "wrong"


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

    def reinstantiate_charm(self):
        charm = self.harness.charm
        self.harness.framework._forget(charm)
        self.harness.framework._forget(charm.on)
        self.harness.framework._forget(charm.fiveg_n3_provider)
        self.harness.framework._forget(charm.fiveg_n3_provider.on)
        self.harness.framework._forget(charm.fiveg_n4_provider)
        self.harness.framework._forget(charm.fiveg_n4_provider.on)
        self.harness.framework._forget(charm._metrics_endpoint)
        self.harness.framework._forget(charm._logging)
        self.harness.framework._forget(charm._kubernetes_multus)
        self.harness.framework._forget(charm._kubernetes_volumes_patch)
        self.harness._charm = None
        self.harness.begin()

    def setUp(self):
        self.patch_k8s_client = patch("lightkube.core.client.GenericSyncClient")
        self.patch_k8s_client.start()
        self.namespace = "whatever"
        self.harness = testing.Harness(UPFOperatorCharm)
        self.harness.set_model_name(name=self.namespace)
        self.harness.set_leader(is_leader=True)

        self.maxDiff = None
        self.root = self.harness.get_filesystem_root("bessd")
        (self.root / "etc/bess/conf").mkdir(parents=True)
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    @patch(
        f"{HUGEPAGES_LIBRARY_PATH}.KubernetesHugePagesPatchCharmLib.is_patched",
        Mock(return_value=True),
    )
    @patch("lightkube.core.client.Client.list")
    def test_given_bad_config_when_config_changed_then_status_is_blocked(self, patched_list):
        patched_list.side_effect = [
            [Node(status=NodeStatus(allocatable={"hugepages-1Gi": "3Gi"}))],
            [],
            [],
        ]
        self.harness.update_config(key_values={"dnn": ""})
        self.reinstantiate_charm()

        self.assertEqual(
            self.harness.model.unit.status,
            BlockedStatus("The following configurations are not valid: ['dnn']"),
        )

    @patch(
        f"{HUGEPAGES_LIBRARY_PATH}.KubernetesHugePagesPatchCharmLib.is_patched",
        Mock(return_value=True),
    )
    @patch("lightkube.core.client.Client.list")
    def test_given_empty_upf_mode_when_config_changed_then_status_is_blocked(self, patched_list):
        patched_list.side_effect = [
            [Node(status=NodeStatus(allocatable={"hugepages-1Gi": "3Gi"}))],
            [],
            [],
        ]
        self.harness.update_config(key_values={"upf-mode": ""})
        self.reinstantiate_charm()

        self.assertEqual(
            self.harness.model.unit.status,
            BlockedStatus("The following configurations are not valid: ['upf-mode']"),
        )

    @patch(
        f"{HUGEPAGES_LIBRARY_PATH}.KubernetesHugePagesPatchCharmLib.is_patched",
        Mock(return_value=True),
    )
    @patch("lightkube.core.client.Client.list")
    def test_given_unsupported_upf_mode_when_config_changed_then_status_is_blocked(
        self, patched_list
    ):
        patched_list.side_effect = [
            [Node(status=NodeStatus(allocatable={"hugepages-1Gi": "3Gi"}))],
            [],
            [],
        ]
        self.harness.update_config(key_values={"upf-mode": "unsupported"})
        self.reinstantiate_charm()

        self.assertEqual(
            self.harness.model.unit.status,
            BlockedStatus("The following configurations are not valid: ['upf-mode']"),
        )

    @patch(
        f"{HUGEPAGES_LIBRARY_PATH}.KubernetesHugePagesPatchCharmLib.is_patched",
        Mock(return_value=True),
    )
    @patch("charm.check_output")
    @patch("lightkube.core.client.Client.list")
    def test_given_upf_mode_set_to_dpdk_but_other_required_configs_not_set_when_config_changed_then_status_is_blocked(  # noqa: E501
        self, patched_list, patched_check_output
    ):
        patched_check_output.return_value = b"Flags: avx2 ssse3 fma cx16 rdrand pdpe1gb"
        patched_list.side_effect = [
            [Node(status=NodeStatus(allocatable={"hugepages-1Gi": "3Gi"}))],
            [],
            [],
        ]
        self.harness.update_config(key_values={"cni-type": "vfioveth", "upf-mode": "dpdk"})
        self.reinstantiate_charm()

        self.assertEqual(
            self.harness.model.unit.status,
            BlockedStatus(
                "The following configurations are not valid: ['access-interface-mac-address', 'core-interface-mac-address']"  # noqa: E501, W505
            ),
        )

    @patch(
        f"{HUGEPAGES_LIBRARY_PATH}.KubernetesHugePagesPatchCharmLib.is_patched",
        Mock(return_value=True),
    )
    @patch("charm.check_output")
    @patch("lightkube.core.client.Client.list")
    def test_given_upf_mode_set_to_dpdk_and_hugepages_enabled_but_mac_addresses_of_access_and_core_interfaces_not_set_when_config_changed_then_status_is_blocked(  # noqa: E501
        self, patched_list, patched_check_output
    ):
        patched_check_output.return_value = b"Flags: avx2 ssse3 fma cx16 rdrand pdpe1gb"
        patched_list.side_effect = [
            [Node(status=NodeStatus(allocatable={"hugepages-1Gi": "3Gi"}))],
            [],
            [],
        ]
        self.harness.update_config(key_values={"cni-type": "vfioveth", "upf-mode": "dpdk"})
        self.reinstantiate_charm()

        self.assertEqual(
            self.harness.model.unit.status,
            BlockedStatus(
                "The following configurations are not valid: ['access-interface-mac-address', 'core-interface-mac-address']"  # noqa: E501, W505
            ),
        )

    @patch(
        f"{HUGEPAGES_LIBRARY_PATH}.KubernetesHugePagesPatchCharmLib.is_patched",
        Mock(return_value=True),
    )
    @patch("charm.check_output")
    @patch("lightkube.core.client.Client.list")
    def test_given_upf_mode_set_to_dpdk_and_hugepages_enabled_but_access_interface_mac_addresses_is_invalid_when_config_changed_then_status_is_blocked(  # noqa: E501
        self, patched_list, patched_check_output
    ):
        patched_check_output.return_value = b"Flags: avx2 ssse3 fma cx16 rdrand pdpe1gb"
        patched_list.side_effect = [
            [Node(status=NodeStatus(allocatable={"hugepages-1Gi": "3Gi"}))],
            [],
            [],
        ]
        self.harness.update_config(
            key_values={
                "cni-type": "vfioveth",
                "upf-mode": "dpdk",
                "access-interface-mac-address": INVALID_ACCESS_MAC,
                "core-interface-mac-address": VALID_CORE_MAC,
            }
        )
        self.reinstantiate_charm()

        self.assertEqual(
            self.harness.model.unit.status,
            BlockedStatus(
                "The following configurations are not valid: ['access-interface-mac-address']"
            ),
        )

    @patch(
        f"{HUGEPAGES_LIBRARY_PATH}.KubernetesHugePagesPatchCharmLib.is_patched",
        Mock(return_value=True),
    )
    @patch("charm.check_output")
    @patch("lightkube.core.client.Client.list")
    def test_given_upf_mode_set_to_dpdk_and_hugepages_enabled_but_core_interface_mac_addresses_is_invalid_when_config_changed_then_status_is_blocked(  # noqa: E501
        self, patched_list, patched_check_output
    ):
        patched_check_output.return_value = b"Flags: avx2 ssse3 fma cx16 rdrand pdpe1gb"
        patched_list.side_effect = [
            [Node(status=NodeStatus(allocatable={"hugepages-1Gi": "3Gi"}))],
            [],
            [],
        ]
        self.harness.update_config(
            key_values={
                "cni-type": "vfioveth",
                "upf-mode": "dpdk",
                "access-interface-mac-address": VALID_ACCESS_MAC,
                "core-interface-mac-address": INVALID_CORE_MAC,
            }
        )
        self.reinstantiate_charm()

        self.assertEqual(
            self.harness.model.unit.status,
            BlockedStatus(
                "The following configurations are not valid: ['core-interface-mac-address']"
            ),
        )

    @patch("ops.model.Container.get_service")
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready")
    def test_given_bessd_config_file_not_yet_written_when_bessd_pebble_ready_then_config_file_is_written(  # noqa: E501
        self,
        _,
        __,
    ):
        self.harness.handle_exec("bessd", [], result=0)
        self.harness.set_can_connect("bessd", True)
        self.harness.set_can_connect("pfcp-agent", True)
        self.harness.container_pebble_ready(container_name="bessd")
        expected_config_file_content = read_file("tests/unit/expected_upf.json").strip()

        self.assertEqual(
            (self.root / "etc/bess/conf/upf.json").read_text(), expected_config_file_content
        )

    @patch("ops.model.Container.get_service")
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready")
    def test_given_bessd_config_file_not_yet_written_when_config_storage_attached_then_config_file_is_written(  # noqa: E501
        self, _, __
    ):
        self.harness.handle_exec("bessd", [], result=0)
        self.harness.set_can_connect("bessd", True)
        self.harness.set_can_connect("pfcp-agent", True)
        (self.root / "etc/bess/conf").rmdir()
        self.harness.add_storage(storage_name="config", count=1)
        self.harness.attach_storage(storage_id="config/0")

        expected_config_file_content = read_file("tests/unit/expected_upf.json").strip()

        self.assertEqual(
            (self.root / "etc/bess/conf/upf.json").read_text(), expected_config_file_content
        )

    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready")
    def test_given_bessd_config_file_matches_when_bessd_pebble_ready_then_config_file_is_not_changed(  # noqa: E501
        self,
        patch_is_ready,
    ):
        self.harness.handle_exec("bessd", [], result=0)
        patch_is_ready.return_value = True
        expected_upf_content = read_file("tests/unit/expected_upf.json").strip()
        (self.root / "etc/bess/conf/upf.json").write_text(expected_upf_content)

        self.harness.container_pebble_ready(container_name="bessd")

        self.assertEqual((self.root / "etc/bess/conf/upf.json").read_text(), expected_upf_content)

    @patch("ops.model.Container.get_service")
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready")
    def test_given_when_bessd_pebble_ready_then_expected_pebble_plan_is_applied(  # noqa: E501
        self,
        patch_is_ready,
        _,
    ):
        self.harness.handle_exec("bessd", [], result=0)
        self.harness.set_can_connect("bessd", True)
        self.harness.set_can_connect("pfcp-agent", True)
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
            },
            "checks": {
                "online": {
                    "override": "replace",
                    "level": "ready",
                    "tcp": {"port": 10514},
                }
            },
        }

        updated_plan = self.harness.get_container_pebble_plan("bessd").to_dict()

        self.assertEqual(expected_plan, updated_plan)

    @patch("ops.model.Container.get_service")
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready")
    def test_given_can_connect_to_bessd_when_bessd_pebble_ready_then_ip_route_is_created(
        self, patch_is_ready, _
    ):
        self.harness.set_can_connect("bessd", True)
        self.harness.set_can_connect("pfcp-agent", True)
        ip_route_replace_called = False
        timeout = 0
        environment = {}
        replace_gnb_subnet_route_cmd = ["ip", "route", "replace", GNB_SUBNET, "via", ACCESS_GW_IP]

        def ip_handler(args: testing.ExecArgs) -> testing.ExecResult:
            nonlocal ip_route_replace_called
            nonlocal timeout
            nonlocal environment
            ip_route_replace_called = True
            timeout = args.timeout
            environment = args.environment
            return testing.ExecResult(exit_code=0)

        replace_default_route_cmd = [
            "ip",
            "route",
            "replace",
            "default",
            "via",
            CORE_GW_IP,
            "metric",
            "110",
        ]

        self.harness.handle_exec("bessd", replace_default_route_cmd, handler=ip_handler)
        self.harness.handle_exec("bessd", replace_gnb_subnet_route_cmd, result=0)
        self.harness.handle_exec("bessd", ["iptables-legacy"], result=0)
        self.harness.handle_exec("bessd", ["/opt/bess/bessctl/bessctl"], result=0)
        patch_is_ready.return_value = True

        self.harness.container_pebble_ready(container_name="bessd")

        self.assertTrue(ip_route_replace_called)
        self.assertEqual(timeout, 30)
        self.assertEqual(environment, {})

    @patch("ops.model.Container.get_service")
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready")
    def test_given_can_connect_to_bessd_when_bessd_pebble_ready_then_gnb_subnet_route_is_created(
        self, patch_is_ready, _
    ):
        self.harness.set_can_connect("bessd", True)
        self.harness.set_can_connect("pfcp-agent", True)
        gnb_subnet_route_replace_called = False
        timeout = 0
        environment = {}
        replace_default_route_cmd = [
            "ip",
            "route",
            "replace",
            "default",
            "via",
            CORE_GW_IP,
            "metric",
            "110",
        ]

        def ip_handler(args: testing.ExecArgs) -> testing.ExecResult:
            nonlocal gnb_subnet_route_replace_called
            nonlocal timeout
            nonlocal environment
            gnb_subnet_route_replace_called = True
            timeout = args.timeout
            environment = args.environment
            return testing.ExecResult(exit_code=0)

        replace_gnb_subnet_route_cmd = ["ip", "route", "replace", GNB_SUBNET, "via", ACCESS_GW_IP]

        self.harness.handle_exec("bessd", replace_gnb_subnet_route_cmd, handler=ip_handler)
        self.harness.handle_exec("bessd", replace_default_route_cmd, result=0)
        self.harness.handle_exec("bessd", ["iptables-legacy"], result=0)
        self.harness.handle_exec("bessd", ["/opt/bess/bessctl/bessctl"], result=0)
        patch_is_ready.return_value = True

        self.harness.container_pebble_ready(container_name="bessd")

        self.assertTrue(gnb_subnet_route_replace_called)
        self.assertEqual(timeout, 30)
        self.assertEqual(environment, {})

    @patch("ops.model.Container.get_service")
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready")
    def test_given_iptables_rule_is_not_yet_created_when_bessd_pebble_ready_then_rule_is_created(
        self, patch_is_ready, _
    ):
        self.harness.set_can_connect("bessd", True)
        self.harness.set_can_connect("pfcp-agent", True)
        iptables_drop_called = False
        timeout = 0
        environment = {}

        iptables_check_cmd = [
            "iptables-legacy",
            "--check",
            "OUTPUT",
            "-p",
            "icmp",
            "--icmp-type",
            "port-unreachable",
            "-j",
            "DROP",
        ]
        iptables_drop_cmd = [
            "iptables-legacy",
            "-I",
            "OUTPUT",
            "-p",
            "icmp",
            "--icmp-type",
            "port-unreachable",
            "-j",
            "DROP",
        ]

        def iptables_handler(args: testing.ExecArgs) -> testing.ExecResult:
            nonlocal iptables_drop_called
            nonlocal timeout
            nonlocal environment
            iptables_drop_called = True
            timeout = args.timeout
            environment = args.environment
            return testing.ExecResult(exit_code=0)

        self.harness.handle_exec("bessd", ["ip", "route"], result=0)
        self.harness.handle_exec("bessd", iptables_check_cmd, result=1)
        self.harness.handle_exec("bessd", iptables_drop_cmd, handler=iptables_handler)
        self.harness.handle_exec("bessd", ["/opt/bess/bessctl/bessctl"], result=0)
        patch_is_ready.return_value = True

        self.harness.container_pebble_ready(container_name="bessd")
        self.assertTrue(iptables_drop_called)
        self.assertEqual(timeout, 30)
        self.assertEqual(environment, {})

    @patch("ops.model.Container.get_service")
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready")
    def test_given_iptables_rule_is_created_when_bessd_pebble_ready_then_rule_is_not_re_created(
        self, patch_is_ready, _
    ):
        self.harness.set_can_connect("bessd", True)
        self.harness.set_can_connect("pfcp-agent", True)
        iptables_drop_called = False

        iptables_drop_cmd = [
            "iptables-legacy",
            "-I",
            "OUTPUT",
            "-p",
            "icmp",
            "--icmp-type",
            "port-unreachable",
            "-j",
            "DROP",
        ]

        def iptables_handler(_: testing.ExecArgs) -> testing.ExecResult:
            nonlocal iptables_drop_called
            iptables_drop_called = True
            return testing.ExecResult(exit_code=0)

        self.harness.handle_exec("bessd", ["ip", "route"], result=0)
        self.harness.handle_exec("bessd", iptables_drop_cmd, handler=iptables_handler)
        self.harness.handle_exec("bessd", ["iptables-legacy"], result=0)
        self.harness.handle_exec("bessd", ["/opt/bess/bessctl/bessctl"], result=0)
        patch_is_ready.return_value = True

        self.harness.container_pebble_ready(container_name="bessd")

        self.assertFalse(iptables_drop_called)

    @patch("ops.model.Container.get_service")
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready")
    def test_given_can_connect_to_bessd_when_bessd_pebble_ready_then_bessctl_configure_is_executed(
        self, patch_is_ready, _
    ):
        self.harness.set_can_connect("bessd", True)
        self.harness.set_can_connect("pfcp-agent", True)
        bessctl_called = False
        timeout = 0
        environment = {}

        bessctl_cmd = ["/opt/bess/bessctl/bessctl", "run", "/opt/bess/bessctl/conf/up4"]

        def bessctl_handler(args: testing.ExecArgs) -> testing.ExecResult:
            nonlocal bessctl_called
            nonlocal timeout
            nonlocal environment
            bessctl_called = True
            timeout = args.timeout
            environment = args.environment
            return testing.ExecResult(exit_code=0)

        self.harness.handle_exec("bessd", ["ip"], result=0)
        self.harness.handle_exec("bessd", ["iptables-legacy"], result=0)
        self.harness.handle_exec("bessd", bessctl_cmd, handler=bessctl_handler)
        patch_is_ready.return_value = True

        self.harness.container_pebble_ready(container_name="bessd")

        self.assertTrue(bessctl_called)
        self.assertEqual(timeout, 30)
        self.assertEqual(
            environment, {"CONF_FILE": "/etc/bess/conf/upf.json", "PYTHONPATH": "/opt/bess"}
        )

    @patch("ops.model.Container.get_service")
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready")
    def test_given_connects_and_bessctl_executed_file_exists_then_bessctl_configure_not_executed(
        self, patch_is_ready, _
    ):
        self.harness.set_can_connect("bessd", True)
        self.harness.set_can_connect("pfcp-agent", True)
        (self.root / "bessctl_configure_executed").write_text("")

        bessctl_called = False

        bessctl_cmd = ["/opt/bess/bessctl/bessctl", "run", "/opt/bess/bessctl/conf/up4"]

        def bessctl_handler(_: testing.ExecArgs) -> testing.ExecResult:
            nonlocal bessctl_called
            bessctl_called = True
            return testing.ExecResult(exit_code=0)

        self.harness.handle_exec("bessd", ["ip"], result=0)
        self.harness.handle_exec("bessd", ["iptables-legacy"], result=0)
        self.harness.handle_exec("bessd", bessctl_cmd, handler=bessctl_handler)
        patch_is_ready.return_value = True

        self.harness.container_pebble_ready(container_name="bessd")

        self.assertFalse(bessctl_called)

    @patch("ops.model.Container.get_service")
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready")
    def test_given_connects_and_bessctl_executed_file_dont_exist_then_bessctl_configure_executed(
        self, patch_is_ready, _
    ):
        self.harness.set_can_connect("bessd", True)
        self.harness.set_can_connect("pfcp-agent", True)
        bessctl_called = False
        timeout = 0
        environment = {}

        bessctl_cmd = ["/opt/bess/bessctl/bessctl", "run", "/opt/bess/bessctl/conf/up4"]

        def bessctl_handler(args: testing.ExecArgs) -> testing.ExecResult:
            nonlocal bessctl_called
            nonlocal timeout
            nonlocal environment
            bessctl_called = True
            timeout = args.timeout
            environment = args.environment
            return testing.ExecResult(exit_code=0)

        self.harness.handle_exec("bessd", ["ip"], result=0)
        self.harness.handle_exec("bessd", ["iptables-legacy"], result=0)
        self.harness.handle_exec("bessd", bessctl_cmd, handler=bessctl_handler)

        patch_is_ready.return_value = True

        self.harness.container_pebble_ready(container_name="bessd")

        self.assertTrue(bessctl_called)
        self.assertEqual(timeout, 30)
        self.assertEqual(
            environment, {"CONF_FILE": "/etc/bess/conf/upf.json", "PYTHONPATH": "/opt/bess"}
        )

    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready")
    def test_given_storage_not_attached_when_bessd_pebble_ready_then_status_is_waiting(
        self,
        patch_is_ready,
    ):
        self.harness.handle_exec("bessd", [], result=0)
        patch_is_ready.return_value = True
        (self.root / "etc/bess/conf").rmdir()

        self.harness.container_pebble_ready(container_name="bessd")
        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.model.unit.status,
            WaitingStatus("Waiting for storage to be attached"),
        )

    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready")
    def test_given_multus_not_configured_when_bessd_pebble_ready_then_status_is_waiting(
        self,
        patch_is_ready,
    ):
        patch_is_ready.return_value = False

        self.harness.container_pebble_ready(container_name="bessd")
        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.model.unit.status,
            WaitingStatus("Waiting for Multus to be ready"),
        )

    @patch("ops.model.Container.get_service")
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready")
    def test_given_config_file_is_written_and_all_services_are_running_when_bessd_pebble_ready_then_status_is_active(  # noqa: E501
        self,
        patch_is_ready,
        patch_get_service,
    ):
        self.harness.handle_exec("bessd", [], result=0)
        service_info_mock = Mock()
        service_info_mock.is_running.return_value = True
        patch_get_service.return_value = service_info_mock
        patch_is_ready.return_value = True
        self.harness.set_can_connect(container="pfcp-agent", val=True)

        self.harness.container_pebble_ready(container_name="bessd")
        self.harness.evaluate_status()

        self.assertEqual(self.harness.model.unit.status, ActiveStatus())

    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready")
    @patch("ops.model.Container.get_service")
    def test_given_bessd_service_is_running_when_pfcp_agent_pebble_ready_then_pebble_plan_is_applied(  # noqa: E501
        self,
        patch_get_service,
        patch_multus_is_ready,
    ):
        service_info_mock = Mock()
        service_info_mock.is_running.return_value = True
        patch_get_service.return_value = service_info_mock
        patch_multus_is_ready.return_value = True
        self.harness.set_can_connect(container="bessd", val=True)

        self.harness.container_pebble_ready(container_name="pfcp-agent")
        self.harness.evaluate_status()
        self.assertEqual(self.harness.charm.unit.status, ActiveStatus())

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
        self.harness.set_can_connect(container="bessd", val=False)

        self.harness.container_pebble_ready(container_name="pfcp-agent")
        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.model.unit.status,
            WaitingStatus("Waiting for bessd container to be ready"),
        )

    @patch(f"{HUGEPAGES_LIBRARY_PATH}.KubernetesHugePagesPatchCharmLib.is_patched")
    @patch("charms.sdcore_upf_k8s.v0.fiveg_n3.N3Provides.publish_upf_information")
    def test_given_fiveg_n3_relation_created_when_fiveg_n3_request_then_upf_ip_address_is_published(  # noqa: E501
        self,
        patched_publish_upf_information,
        patch_hugepages_is_patched,
    ):
        patch_hugepages_is_patched.return_value = True
        test_upf_access_ip_cidr = "1.2.3.4/21"
        self.harness.update_config(key_values={"access-ip": test_upf_access_ip_cidr})

        n3_relation_id = self.harness.add_relation("fiveg_n3", "n3_requirer_app")
        self.harness.add_relation_unit(n3_relation_id, "n3_requirer_app/0")

        patched_publish_upf_information.assert_called_once_with(
            relation_id=n3_relation_id, upf_ip_address=test_upf_access_ip_cidr.split("/")[0]
        )

    @patch("charms.sdcore_upf_k8s.v0.fiveg_n3.N3Provides.publish_upf_information")
    def test_given_unit_is_not_leader_when_fiveg_n3_request_then_upf_ip_address_is_not_published(
        self, patched_publish_upf_information
    ):
        self.harness.set_leader(is_leader=False)
        test_upf_access_ip_cidr = "1.2.3.4/21"
        self.harness.update_config(key_values={"access-ip": test_upf_access_ip_cidr})

        n3_relation_id = self.harness.add_relation("fiveg_n3", "n3_requirer_app")
        self.harness.add_relation_unit(n3_relation_id, "n3_requirer_app/0")

        patched_publish_upf_information.assert_not_called()

    @patch("ops.model.Container.get_service")
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesClient", new=Mock)
    @patch("charms.sdcore_upf_k8s.v0.fiveg_n3.N3Provides.publish_upf_information")
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready")
    @patch(f"{HUGEPAGES_LIBRARY_PATH}.KubernetesHugePagesPatchCharmLib.is_patched")
    def test_given_fiveg_n3_relation_exists_when_access_ip_config_changed_then_new_upf_ip_address_is_published(  # noqa: E501
        self,
        patch_multus_is_ready,
        patch_hugepages_is_patched,
        patched_publish_upf_information,
        _,
    ):
        self.harness.handle_exec("bessd", [], result=0)
        patch_multus_is_ready.return_value = True
        patch_hugepages_is_patched.return_value = True
        self.harness.set_can_connect(container="bessd", val=True)
        self.harness.set_can_connect(container="pfcp-agent", val=True)
        n3_relation_id = self.harness.add_relation("fiveg_n3", "n3_requirer_app")
        self.harness.add_relation_unit(n3_relation_id, "n3_requirer_app/0")
        test_upf_access_ip_cidr = "1.2.3.4/21"
        expected_calls = [
            call(relation_id=n3_relation_id, upf_ip_address="192.168.252.3"),
            call(relation_id=n3_relation_id, upf_ip_address=test_upf_access_ip_cidr.split("/")[0]),
        ]

        self.harness.update_config(key_values={"access-ip": test_upf_access_ip_cidr})

        patched_publish_upf_information.assert_has_calls(expected_calls)

    @patch("charms.sdcore_upf_k8s.v0.fiveg_n3.N3Provides.publish_upf_information")
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready")
    def test_given_fiveg_n3_relation_exists_when_access_ip_config_changed_to_invalid_cidr_then_new_upf_ip_address_is_not_published(  # noqa: E501
        self, patch_multus_is_ready, patched_publish_upf_information
    ):
        self.harness.handle_exec("bessd", [], result=0)
        patch_multus_is_ready.return_value = True
        self.harness.set_can_connect(container="bessd", val=True)
        self.harness.set_can_connect(container="pfcp-agent", val=True)
        n3_relation_id = self.harness.add_relation("fiveg_n3", "n3_requirer_app")
        self.harness.add_relation_unit(n3_relation_id, "n3_requirer_app/0")
        invalid_test_upf_access_ip_cidr = "1111.2.3.4/21"

        self.harness.update_config(key_values={"access-ip": invalid_test_upf_access_ip_cidr})

        patched_publish_upf_information.assert_called_once_with(
            relation_id=n3_relation_id, upf_ip_address="192.168.252.3"
        )

    @patch("charms.sdcore_upf_k8s.v0.fiveg_n4.N4Provides.publish_upf_n4_information")
    def test_given_unit_is_not_leader_when_fiveg_n4_request_then_upf_hostname_is_not_published(
        self, patched_publish_upf_n4_information
    ):
        self.harness.set_leader(is_leader=False)
        test_external_upf_hostname = "test-upf.external.hostname.com"
        self.harness.update_config(
            key_values={"external-upf-hostname": test_external_upf_hostname}
        )

        n4_relation_id = self.harness.add_relation("fiveg_n4", "n4_requirer_app")
        self.harness.add_relation_unit(n4_relation_id, "n4_requirer_app/0")

        patched_publish_upf_n4_information.assert_not_called()

    @patch(f"{HUGEPAGES_LIBRARY_PATH}.KubernetesHugePagesPatchCharmLib.is_patched")
    @patch("charms.sdcore_upf_k8s.v0.fiveg_n4.N4Provides.publish_upf_n4_information")
    @patch("charm.PFCP_PORT", TEST_PFCP_PORT)
    def test_given_external_upf_hostname_config_set_and_fiveg_n4_relation_created_when_fiveg_n4_request_then_upf_hostname_and_n4_port_is_published(  # noqa: E501
        self,
        patched_publish_upf_n4_information,
        patch_hugepages_is_patched,
    ):
        patch_hugepages_is_patched.return_value = True
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

    @patch("lightkube.core.client.Client.get")
    @patch("charms.sdcore_upf_k8s.v0.fiveg_n4.N4Provides.publish_upf_n4_information")
    @patch("charm.PFCP_PORT", TEST_PFCP_PORT)
    def test_given_external_upf_hostname_config_not_set_but_external_upf_service_hostname_available_and_fiveg_n4_relation_created_when_fiveg_n4_request_then_upf_hostname_and_n4_port_is_published(  # noqa: E501
        self, patched_publish_upf_n4_information, patched_lightkube_client_get
    ):
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

    @patch("lightkube.core.client.Client.get")
    @patch("charms.sdcore_upf_k8s.v0.fiveg_n4.N4Provides.publish_upf_n4_information")
    @patch("charm.PFCP_PORT", TEST_PFCP_PORT)
    def test_given_external_upf_hostname_config_not_set_and_external_upf_service_hostname_not_available_and_fiveg_n4_relation_created_when_fiveg_n4_request_then_upf_hostname_and_n4_port_is_published(  # noqa: E501
        self, patched_publish_upf_n4_information, patched_lightkube_client_get
    ):
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

    @patch("lightkube.core.client.Client.get")
    @patch("charms.sdcore_upf_k8s.v0.fiveg_n4.N4Provides.publish_upf_n4_information")
    @patch("charm.PFCP_PORT", TEST_PFCP_PORT)
    def test_given_external_upf_hostname_config_not_set_and_metallb_not_available_and_fiveg_n4_relation_created_when_fiveg_n4_request_then_upf_hostname_and_n4_port_is_published(  # noqa: E501
        self, patched_publish_upf_n4_information, patched_lightkube_client_get
    ):
        service = Mock(status=Mock(loadBalancer=Mock(ingress=None)))
        patched_lightkube_client_get.return_value = service

        n4_relation_id = self.harness.add_relation("fiveg_n4", "n4_requirer_app")
        self.harness.add_relation_unit(n4_relation_id, "n4_requirer_app/0")

        patched_publish_upf_n4_information.assert_called_once_with(
            relation_id=n4_relation_id,
            upf_hostname=f"{self.harness.charm.app.name}-external.{self.namespace}"
            ".svc.cluster.local",
            upf_n4_port=TEST_PFCP_PORT,
        )

    @patch("ops.model.Container.get_service")
    @patch("charms.sdcore_upf_k8s.v0.fiveg_n4.N4Provides.publish_upf_n4_information")
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready")
    @patch(f"{HUGEPAGES_LIBRARY_PATH}.KubernetesHugePagesPatchCharmLib.is_patched")
    @patch("charm.PFCP_PORT", TEST_PFCP_PORT)
    def test_given_fiveg_n4_relation_exists_when_external_upf_hostname_config_changed_then_new_upf_hostname_is_published(  # noqa: E501
        self,
        patch_multus_is_ready,
        patch_hugepages_is_ready,
        patched_publish_upf_n4_information,
        _,
    ):
        self.harness.handle_exec("bessd", [], result=0)
        test_external_upf_hostname = "test-upf.external.hostname.com"
        patch_multus_is_ready.return_value = True
        patch_hugepages_is_ready.return_value = True
        self.harness.set_can_connect(container="bessd", val=True)
        self.harness.set_can_connect(container="pfcp-agent", val=True)
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
        self.harness.update_config(
            key_values={
                "access-ip": DEFAULT_ACCESS_IP,
                "access-gateway-ip": ACCESS_GW_IP,
                "gnb-subnet": GNB_SUBNET,
                "core-ip": VALID_CORE_IP,
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
                "core-interface": CORE_INTERFACE_NAME,
                "core-ip": VALID_CORE_IP,
                "core-gateway-ip": CORE_GW_IP,
                "cni-type": "macvlan",
            }
        )
        self.reinstantiate_charm()
        nads = self.harness.charm._network_attachment_definitions_from_config()
        for nad in nads:
            config = json.loads(nad.spec["config"])
            self.assertTrue(ACCESS_INTERFACE_NAME or CORE_INTERFACE_NAME in config["master"])
            self.assertEqual(config["type"], "macvlan")

    @patch("lightkube.core.client.Client.create")
    @patch("ops.model.Container.get_service")
    @patch("lightkube.core.client.Client.list")
    @patch(
        f"{HUGEPAGES_LIBRARY_PATH}.KubernetesHugePagesPatchCharmLib.is_patched",
        Mock(return_value=True),
    )
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready", Mock(return_value=True))
    @patch("charm.DPDK.is_configured", Mock(return_value=True))
    def test_given_upf_configured_to_run_in_dpdk_mode_when_create_network_attachment_definitions_then_2_nads_are_returned(  # noqa: E501
        self, patched_list, patch_get_service, kubernetes_create_object
    ):
        self.harness.set_can_connect("bessd", True)
        self.harness.set_can_connect("pfcp-agent", True)
        service_info_mock = Mock()
        service_info_mock.is_running.return_value = True
        patch_get_service.return_value = service_info_mock
        patched_list.side_effect = [
            [Node(status=NodeStatus(allocatable={"hugepages-1Gi": "3Gi"}))],
            [],
            [],
            [],
        ]
        self.harness.update_config(
            key_values={
                "cni-type": "vfioveth",
                "upf-mode": "dpdk",
                "access-interface-mac-address": VALID_ACCESS_MAC,
                "core-interface-mac-address": VALID_CORE_MAC,
            }
        )

        create_nad_calls = kubernetes_create_object.call_args_list
        self.assertEqual(len(create_nad_calls), 2)

    @patch("lightkube.core.client.Client.create")
    @patch("ops.model.Container.get_service")
    @patch("lightkube.core.client.Client.list")
    @patch(
        f"{HUGEPAGES_LIBRARY_PATH}.KubernetesHugePagesPatchCharmLib.is_patched",
        Mock(return_value=True),
    )
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready", Mock(return_value=True))
    @patch("charm.DPDK.is_configured", Mock(return_value=True))
    def test_given_upf_configured_to_run_in_dpdk_mode_when_create_network_attachment_definitions_then_nad_type_is_vfioveth(  # noqa: E501
        self, patched_list, patch_get_service, kubernetes_create_object
    ):
        self.harness.set_can_connect("bessd", True)
        self.harness.set_can_connect("pfcp-agent", True)
        service_info_mock = Mock()
        service_info_mock.is_running.return_value = True
        patch_get_service.return_value = service_info_mock
        patched_list.side_effect = [
            [Node(status=NodeStatus(allocatable={"hugepages-1Gi": "3Gi"}))],
            [],
            [],
            [],
        ]
        self.harness.update_config(
            key_values={
                "cni-type": "vfioveth",
                "upf-mode": "dpdk",
                "access-interface-mac-address": VALID_ACCESS_MAC,
                "core-interface-mac-address": VALID_CORE_MAC,
            }
        )

        create_nad_calls = kubernetes_create_object.call_args_list
        for create_nad_call in create_nad_calls:
            create_nad_call_args = next(
                iter(filter(lambda call_item: isinstance(call_item, dict), create_nad_call))
            )
            nad_config = json.loads(create_nad_call_args.get("obj").spec.get("config"))
            self.assertEqual(nad_config["type"], "vfioveth")

    @patch("lightkube.core.client.Client.create")
    @patch("ops.model.Container.get_service")
    @patch("lightkube.core.client.Client.list")
    @patch(
        f"{HUGEPAGES_LIBRARY_PATH}.KubernetesHugePagesPatchCharmLib.is_patched",
        Mock(return_value=True),
    )
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready", Mock(return_value=True))
    @patch("charm.DPDK.is_configured", Mock(return_value=True))
    def test_given_upf_configured_to_run_in_dpdk_mode_when_create_network_attachment_definitions_then_access_nad_has_valid_dpdk_access_resource_specified_in_annotations(  # noqa: E501
        self, patched_list, patch_get_service, kubernetes_create_object
    ):
        self.harness.set_can_connect("bessd", True)
        self.harness.set_can_connect("pfcp-agent", True)
        service_info_mock = Mock()
        service_info_mock.is_running.return_value = True
        patch_get_service.return_value = service_info_mock
        patched_list.side_effect = [
            [Node(status=NodeStatus(allocatable={"hugepages-1Gi": "3Gi"}))],
            [],
            [],
            [],
        ]
        self.harness.update_config(
            key_values={
                "cni-type": "vfioveth",
                "upf-mode": "dpdk",
                "access-interface-mac-address": VALID_ACCESS_MAC,
                "core-interface-mac-address": VALID_CORE_MAC,
            }
        )

        def _get_create_access_nad_call(mock_call):
            return next(
                iter(
                    filter(
                        lambda call_item: isinstance(call_item, dict)
                        and call_item.get("obj").metadata.name  # noqa: W503
                        == ACCESS_NETWORK_ATTACHMENT_DEFINITION_NAME,  # noqa: W503
                        mock_call,
                    )
                ),
                None,
            )

        create_nad_calls = kubernetes_create_object.mock_calls
        create_access_nad_calls = [
            _get_create_access_nad_call(create_nad_call)
            for create_nad_call in create_nad_calls
            if _get_create_access_nad_call(create_nad_call)
        ]
        self.assertEqual(len(create_access_nad_calls), 1)
        nad_annotations = create_access_nad_calls[0].get("obj").metadata.annotations
        self.assertTrue(
            DPDK_ACCESS_INTERFACE_RESOURCE_NAME
            in nad_annotations["k8s.v1.cni.cncf.io/resourceName"]
        )

    @patch("lightkube.core.client.Client.create")
    @patch("ops.model.Container.get_service")
    @patch("lightkube.core.client.Client.list")
    @patch(
        f"{HUGEPAGES_LIBRARY_PATH}.KubernetesHugePagesPatchCharmLib.is_patched",
        Mock(return_value=True),
    )
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready", Mock(return_value=True))
    @patch("charm.DPDK.is_configured", Mock(return_value=True))
    def test_given_upf_configured_to_run_in_dpdk_mode_when_create_network_attachment_definitions_then_core_nad_has_valid_dpdk_core_resource_specified_in_annotations(  # noqa: E501
        self, patched_list, patch_get_service, kubernetes_create_object
    ):
        self.harness.set_can_connect("bessd", True)
        self.harness.set_can_connect("pfcp-agent", True)
        service_info_mock = Mock()
        service_info_mock.is_running.return_value = True
        patch_get_service.return_value = service_info_mock
        patched_list.side_effect = [
            [Node(status=NodeStatus(allocatable={"hugepages-1Gi": "3Gi"}))],
            [],
            [],
            [],
        ]
        self.harness.update_config(
            key_values={
                "cni-type": "vfioveth",
                "upf-mode": "dpdk",
                "access-interface-mac-address": VALID_ACCESS_MAC,
                "core-interface-mac-address": VALID_CORE_MAC,
            }
        )

        def _get_create_core_nad_call(mock_call):
            return next(
                iter(
                    filter(
                        lambda call_item: isinstance(call_item, dict)
                        and call_item.get("obj").metadata.name  # noqa: W503
                        == CORE_NETWORK_ATTACHMENT_DEFINITION_NAME,  # noqa: W503
                        mock_call,
                    )
                ),
                None,
            )

        create_nad_calls = kubernetes_create_object.mock_calls
        create_core_nad_calls = [
            _get_create_core_nad_call(create_nad_call)
            for create_nad_call in create_nad_calls
            if _get_create_core_nad_call(create_nad_call)
        ]
        self.assertEqual(len(create_core_nad_calls), 1)
        nad_annotations = create_core_nad_calls[0].get("obj").metadata.annotations
        self.assertTrue(
            DPDK_CORE_INTERFACE_RESOURCE_NAME in nad_annotations["k8s.v1.cni.cncf.io/resourceName"]
        )

    @patch("lightkube.core.client.Client.patch")
    @patch("ops.model.Container.get_service")
    @patch(
        f"{HUGEPAGES_LIBRARY_PATH}.KubernetesHugePagesPatchCharmLib.is_patched",
        Mock(return_value=True),
    )
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready", Mock(return_value=True))
    @patch("charm.DPDK.is_configured", Mock(return_value=True))
    def test_given_upf_charm_configured_to_run_in_default_mode_when_patch_statefulset_then_2_network_annotations_are_created(  # noqa: E501
        self, patch_get_service, kubernetes_statefulset_patch
    ):
        self.harness.set_can_connect("bessd", True)
        self.harness.set_can_connect("pfcp-agent", True)
        self.harness.handle_exec("bessd", [], result=0)
        service_info_mock = Mock()
        service_info_mock.is_running.return_value = True
        patch_get_service.return_value = service_info_mock
        self.harness.update_config()
        patch_statefulset = kubernetes_statefulset_patch.call_args_list[0]
        patch_statefulset_call_args = next(
            iter(
                filter(
                    lambda call_item: isinstance(call_item, dict)
                    and "StatefulSet" in str(call_item.get("obj"))  # noqa: W503
                    and call_item.get("name") == self.harness.charm.app.name,  # noqa: W503
                    patch_statefulset,
                )
            )
        )
        network_annotations = json.loads(
            patch_statefulset_call_args.get("obj").spec.template.metadata.annotations.get(
                NetworkAnnotation.NETWORK_ANNOTATION_RESOURCE_KEY
            )
        )
        self.assertEqual(len(network_annotations), 2)

    @patch("lightkube.core.client.Client.patch")
    @patch("ops.model.Container.get_service")
    @patch(
        f"{HUGEPAGES_LIBRARY_PATH}.KubernetesHugePagesPatchCharmLib.is_patched",
        Mock(return_value=True),
    )
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready", Mock(return_value=True))
    @patch("charm.DPDK.is_configured", Mock(return_value=True))
    def test_given_upf_charm_configured_to_run_in_default_mode_when_generate_network_annotations_is_called_then_access_network_annotation_created(  # noqa: E501
        self, patch_get_service, kubernetes_statefulset_patch
    ):
        self.harness.set_can_connect("bessd", True)
        self.harness.set_can_connect("pfcp-agent", True)
        self.harness.handle_exec("bessd", [], result=0)
        service_info_mock = Mock()
        service_info_mock.is_running.return_value = True
        patch_get_service.return_value = service_info_mock
        self.harness.update_config()
        patch_statefulset = kubernetes_statefulset_patch.call_args_list[0]
        patch_statefulset_call_args = next(
            iter(
                filter(
                    lambda call_item: isinstance(call_item, dict)
                    and "StatefulSet" in str(call_item.get("obj"))  # noqa: W503
                    and call_item.get("name") == self.harness.charm.app.name,  # noqa: W503
                    patch_statefulset,
                )
            )
        )
        network_annotations = json.loads(
            patch_statefulset_call_args.get("obj").spec.template.metadata.annotations.get(
                NetworkAnnotation.NETWORK_ANNOTATION_RESOURCE_KEY
            )
        )
        access_network_annotation = next(
            iter(
                filter(
                    lambda network_annotation: network_annotation.get("name")
                    == ACCESS_NETWORK_ATTACHMENT_DEFINITION_NAME,  # noqa: W503
                    network_annotations,
                )
            )
        )
        self.assertTrue(access_network_annotation)
        self.assertEqual(access_network_annotation.get("interface"), ACCESS_INTERFACE_NAME)

    @patch("lightkube.core.client.Client.patch")
    @patch("ops.model.Container.get_service")
    @patch(
        f"{HUGEPAGES_LIBRARY_PATH}.KubernetesHugePagesPatchCharmLib.is_patched",
        Mock(return_value=True),
    )
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready", Mock(return_value=True))
    @patch("charm.DPDK.is_configured", Mock(return_value=True))
    def test_given_upf_charm_configured_to_run_in_default_mode_when_generate_network_annotations_is_called_then_access_network_annotation_created_without_dpdk_specific_data(  # noqa: E501
        self, patch_get_service, kubernetes_statefulset_patch
    ):
        self.harness.set_can_connect("bessd", True)
        self.harness.set_can_connect("pfcp-agent", True)
        self.harness.handle_exec("bessd", [], result=0)
        service_info_mock = Mock()
        service_info_mock.is_running.return_value = True
        patch_get_service.return_value = service_info_mock
        self.harness.update_config()
        patch_statefulset = kubernetes_statefulset_patch.call_args_list[0]
        patch_statefulset_call_args = next(
            iter(
                filter(
                    lambda call_item: isinstance(call_item, dict)
                    and "StatefulSet" in str(call_item.get("obj"))  # noqa: W503
                    and call_item.get("name") == self.harness.charm.app.name,  # noqa: W503
                    patch_statefulset,
                )
            )
        )
        network_annotations = json.loads(
            patch_statefulset_call_args.get("obj").spec.template.metadata.annotations.get(
                NetworkAnnotation.NETWORK_ANNOTATION_RESOURCE_KEY
            )
        )
        access_network_annotation = next(
            iter(
                filter(
                    lambda network_annotation: network_annotation.get("name")
                    == ACCESS_NETWORK_ATTACHMENT_DEFINITION_NAME,  # noqa: W503
                    network_annotations,
                )
            )
        )
        self.assertFalse(access_network_annotation.get("mac"))
        self.assertFalse(access_network_annotation.get("ips"))

    @patch("lightkube.core.client.Client.patch")
    @patch("ops.model.Container.get_service")
    @patch(
        f"{HUGEPAGES_LIBRARY_PATH}.KubernetesHugePagesPatchCharmLib.is_patched",
        Mock(return_value=True),
    )
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready", Mock(return_value=True))
    @patch("charm.DPDK.is_configured", Mock(return_value=True))
    def test_given_upf_charm_configured_to_run_in_default_mode_when_generate_network_annotations_is_called_then_core_network_annotation_created(  # noqa: E501
        self, patch_get_service, kubernetes_statefulset_patch
    ):
        self.harness.set_can_connect("bessd", True)
        self.harness.set_can_connect("pfcp-agent", True)
        self.harness.handle_exec("bessd", [], result=0)
        service_info_mock = Mock()
        service_info_mock.is_running.return_value = True
        patch_get_service.return_value = service_info_mock
        self.harness.update_config()
        patch_statefulset = kubernetes_statefulset_patch.call_args_list[0]
        patch_statefulset_call_args = next(
            iter(
                filter(
                    lambda call_item: isinstance(call_item, dict)
                    and "StatefulSet" in str(call_item.get("obj"))  # noqa: W503
                    and call_item.get("name") == self.harness.charm.app.name,  # noqa: W503
                    patch_statefulset,
                )
            )
        )
        network_annotations = json.loads(
            patch_statefulset_call_args.get("obj").spec.template.metadata.annotations.get(
                NetworkAnnotation.NETWORK_ANNOTATION_RESOURCE_KEY
            )
        )
        access_network_annotation = next(
            iter(
                filter(
                    lambda network_annotation: network_annotation.get("name")
                    == CORE_NETWORK_ATTACHMENT_DEFINITION_NAME,  # noqa: W503
                    network_annotations,
                )
            )
        )
        self.assertTrue(access_network_annotation)
        self.assertEqual(access_network_annotation.get("interface"), CORE_INTERFACE_NAME)

    @patch("lightkube.core.client.Client.patch")
    @patch("ops.model.Container.get_service")
    @patch(
        f"{HUGEPAGES_LIBRARY_PATH}.KubernetesHugePagesPatchCharmLib.is_patched",
        Mock(return_value=True),
    )
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready", Mock(return_value=True))
    @patch("charm.DPDK.is_configured", Mock(return_value=True))
    def test_given_upf_charm_configured_to_run_in_default_mode_when_generate_network_annotations_is_called_then_core_network_annotation_created_without_dpdk_specific_data(  # noqa: E501
        self, patch_get_service, kubernetes_statefulset_patch
    ):
        self.harness.set_can_connect("bessd", True)
        self.harness.set_can_connect("pfcp-agent", True)
        self.harness.handle_exec("bessd", [], result=0)
        service_info_mock = Mock()
        service_info_mock.is_running.return_value = True
        patch_get_service.return_value = service_info_mock
        self.harness.update_config()
        patch_statefulset = kubernetes_statefulset_patch.call_args_list[0]
        patch_statefulset_call_args = next(
            iter(
                filter(
                    lambda call_item: isinstance(call_item, dict)
                    and "StatefulSet" in str(call_item.get("obj"))  # noqa: W503
                    and call_item.get("name") == self.harness.charm.app.name,  # noqa: W503
                    patch_statefulset,
                )
            )
        )
        network_annotations = json.loads(
            patch_statefulset_call_args.get("obj").spec.template.metadata.annotations.get(
                NetworkAnnotation.NETWORK_ANNOTATION_RESOURCE_KEY
            )
        )
        access_network_annotation = next(
            iter(
                filter(
                    lambda network_annotation: network_annotation.get("name")
                    == CORE_NETWORK_ATTACHMENT_DEFINITION_NAME,  # noqa: W503
                    network_annotations,
                )
            )
        )
        self.assertFalse(access_network_annotation.get("mac"))
        self.assertFalse(access_network_annotation.get("ips"))

    @patch("lightkube.core.client.Client.patch")
    @patch("ops.model.Container.get_service")
    @patch("lightkube.core.client.Client.list")
    @patch(
        f"{HUGEPAGES_LIBRARY_PATH}.KubernetesHugePagesPatchCharmLib.is_patched",
        Mock(return_value=True),
    )
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready", Mock(return_value=True))
    @patch("charm.DPDK.is_configured", Mock(return_value=True))
    def test_given_upf_charm_configured_to_run_in_dpdk_mode_when_patch_statefulset_then_2_network_annotations_are_created(  # noqa: E501
        self, patched_list, patch_get_service, kubernetes_statefulset_patch
    ):
        self.harness.set_can_connect("bessd", True)
        self.harness.set_can_connect("pfcp-agent", True)
        self.harness.handle_exec("bessd", [], result=0)
        service_info_mock = Mock()
        service_info_mock.is_running.return_value = True
        patch_get_service.return_value = service_info_mock
        patched_list.side_effect = [
            [Node(status=NodeStatus(allocatable={"hugepages-1Gi": "3Gi"}))],
            [],
            [],
            [],
        ]
        self.harness.update_config(
            key_values={
                "cni-type": "vfioveth",
                "upf-mode": "dpdk",
                "access-interface-mac-address": VALID_ACCESS_MAC,
                "core-interface-mac-address": VALID_CORE_MAC,
            }
        )
        patch_statefulset = kubernetes_statefulset_patch.call_args_list[0]
        patch_statefulset_call_args = next(
            iter(
                filter(
                    lambda call_item: isinstance(call_item, dict)
                    and "StatefulSet" in str(call_item.get("obj"))  # noqa: W503
                    and call_item.get("name") == self.harness.charm.app.name,  # noqa: W503
                    patch_statefulset,
                )
            )
        )
        network_annotations = json.loads(
            patch_statefulset_call_args.get("obj").spec.template.metadata.annotations.get(
                NetworkAnnotation.NETWORK_ANNOTATION_RESOURCE_KEY
            )
        )
        self.assertEqual(len(network_annotations), 2)

    @patch("lightkube.core.client.Client.patch")
    @patch("ops.model.Container.get_service")
    @patch("lightkube.core.client.Client.list")
    @patch(
        f"{HUGEPAGES_LIBRARY_PATH}.KubernetesHugePagesPatchCharmLib.is_patched",
        Mock(return_value=True),
    )
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready", Mock(return_value=True))
    @patch("charm.DPDK.is_configured", Mock(return_value=True))
    def test_given_upf_charm_configured_to_run_in_dpdk_mode_when_generate_network_annotations_is_called_then_access_network_annotation_created(  # noqa: E501
        self, patched_list, patch_get_service, kubernetes_statefulset_patch
    ):
        self.harness.set_can_connect("bessd", True)
        self.harness.set_can_connect("pfcp-agent", True)
        self.harness.handle_exec("bessd", [], result=0)
        service_info_mock = Mock()
        service_info_mock.is_running.return_value = True
        patch_get_service.return_value = service_info_mock
        patched_list.side_effect = [
            [Node(status=NodeStatus(allocatable={"hugepages-1Gi": "3Gi"}))],
            [],
            [],
            [],
        ]
        self.harness.update_config(
            key_values={
                "cni-type": "vfioveth",
                "upf-mode": "dpdk",
                "access-ip": VALID_ACCESS_IP,
                "access-interface-mac-address": VALID_ACCESS_MAC,
                "core-interface-mac-address": VALID_CORE_MAC,
            }
        )
        patch_statefulset = kubernetes_statefulset_patch.call_args_list[0]
        patch_statefulset_call_args = next(
            iter(
                filter(
                    lambda call_item: isinstance(call_item, dict)
                    and "StatefulSet" in str(call_item.get("obj"))  # noqa: W503
                    and call_item.get("name") == self.harness.charm.app.name,  # noqa: W503
                    patch_statefulset,
                )
            )
        )
        network_annotations = json.loads(
            patch_statefulset_call_args.get("obj").spec.template.metadata.annotations.get(
                NetworkAnnotation.NETWORK_ANNOTATION_RESOURCE_KEY
            )
        )
        access_network_annotation = next(
            iter(
                filter(
                    lambda network_annotation: network_annotation.get("name")
                    == ACCESS_NETWORK_ATTACHMENT_DEFINITION_NAME,  # noqa: W503
                    network_annotations,
                )
            )
        )
        self.assertTrue(access_network_annotation)
        self.assertEqual(access_network_annotation.get("interface"), ACCESS_INTERFACE_NAME)
        self.assertEqual(access_network_annotation.get("mac"), VALID_ACCESS_MAC)
        self.assertEqual(access_network_annotation.get("ips"), [VALID_ACCESS_IP])

    @patch("lightkube.core.client.Client.patch")
    @patch("ops.model.Container.get_service")
    @patch("lightkube.core.client.Client.list")
    @patch(
        f"{HUGEPAGES_LIBRARY_PATH}.KubernetesHugePagesPatchCharmLib.is_patched",
        Mock(return_value=True),
    )
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready", Mock(return_value=True))
    @patch("charm.DPDK.is_configured", Mock(return_value=True))
    def test_given_upf_charm_configured_to_run_in_dpdk_mode_when_generate_network_annotations_is_called_then_core_network_annotation_created(  # noqa: E501
        self, patched_list, patch_get_service, kubernetes_statefulset_patch
    ):
        self.harness.set_can_connect("bessd", True)
        self.harness.set_can_connect("pfcp-agent", True)
        self.harness.handle_exec("bessd", [], result=0)
        service_info_mock = Mock()
        service_info_mock.is_running.return_value = True
        patch_get_service.return_value = service_info_mock
        patched_list.side_effect = [
            [Node(status=NodeStatus(allocatable={"hugepages-1Gi": "3Gi"}))],
            [],
            [],
            [],
        ]
        self.harness.update_config(
            key_values={
                "cni-type": "vfioveth",
                "upf-mode": "dpdk",
                "core-ip": VALID_CORE_IP,
                "access-interface-mac-address": VALID_ACCESS_MAC,
                "core-interface-mac-address": VALID_CORE_MAC,
            }
        )
        patch_statefulset = kubernetes_statefulset_patch.call_args_list[0]
        patch_statefulset_call_args = next(
            iter(
                filter(
                    lambda call_item: isinstance(call_item, dict)
                    and "StatefulSet" in str(call_item.get("obj"))  # noqa: W503
                    and call_item.get("name") == self.harness.charm.app.name,  # noqa: W503
                    patch_statefulset,
                )
            )
        )
        network_annotations = json.loads(
            patch_statefulset_call_args.get("obj").spec.template.metadata.annotations.get(
                NetworkAnnotation.NETWORK_ANNOTATION_RESOURCE_KEY
            )
        )
        access_network_annotation = next(
            iter(
                filter(
                    lambda network_annotation: network_annotation.get("name")
                    == CORE_NETWORK_ATTACHMENT_DEFINITION_NAME,  # noqa: W503
                    network_annotations,
                )
            )
        )
        self.assertTrue(access_network_annotation)
        self.assertEqual(access_network_annotation.get("interface"), CORE_INTERFACE_NAME)
        self.assertEqual(access_network_annotation.get("mac"), VALID_CORE_MAC)
        self.assertEqual(access_network_annotation.get("ips"), [VALID_CORE_IP])

    @patch("charm.check_output")
    @patch("charm.Client", new=Mock)
    def test_given_cpu_not_supporting_required_instructions_when_install_then_charm_goes_to_blocked_status(  # noqa: E501
        self, patched_check_output
    ):
        patched_check_output.return_value = b"Flags: ssse3 fma cx16 rdrand"
        self.harness.charm.on.install.emit()
        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.model.unit.status,
            BlockedStatus("Please use a CPU that has the following capabilities: avx2, rdrand"),
        )

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
            expected_service, field_manager="sdcore-upf-k8s"
        )

    @patch("charm.Client")
    def test_given_service_exists_on_remove_then_external_service_is_deleted(self, patch_client):
        self.harness.charm.on.remove.emit()

        patch_client.return_value.delete.assert_called_once_with(
            Service,
            name=f"{self.harness.charm.app.name}-external",
            namespace=self.namespace,
        )

    @patch("charm.Client")
    def test_given_service_does_not_exist_on_remove_then_no_exception_is_thrown(
        self, patch_client
    ):
        patch_client.return_value.delete.side_effect = HTTPStatusError(
            message='services "upf-external" not found',
            request=None,
            response=None,
        )
        self.harness.charm.on.remove.emit()

        patch_client.return_value.delete.assert_called_once_with(
            Service,
            name=f"{self.harness.charm.app.name}-external",
            namespace=self.namespace,
        )

    @patch("lightkube.core.client.Client.create")
    @patch("ops.model.Container.get_service")
    @patch(
        f"{HUGEPAGES_LIBRARY_PATH}.KubernetesHugePagesPatchCharmLib.is_patched",
        Mock(return_value=True),
    )
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready", Mock(return_value=True))
    @patch("charm.DPDK.is_configured", Mock(return_value=True))
    def test_given_default_config_when_create_network_attachment_definitions_then_interface_mtu_not_set_in_the_network_attachment_definitions(  # noqa: E501
        self, patch_get_service, kubernetes_create_object
    ):
        service_info_mock = Mock()
        service_info_mock.is_running.return_value = True
        patch_get_service.return_value = service_info_mock
        self.harness.update_config(
            key_values={
                "access-ip": "192.168.252.3/24",
                "access-gateway-ip": ACCESS_GW_IP,
                "gnb-subnet": GNB_SUBNET,
                "core-ip": VALID_CORE_IP,
                "core-gateway-ip": CORE_GW_IP,
            }
        )

        create_nad_calls = kubernetes_create_object.call_args_list
        for create_nad_call in create_nad_calls:
            create_nad_call_args = next(
                iter(filter(lambda call_item: isinstance(call_item, dict), create_nad_call))
            )
            nad_config = json.loads(create_nad_call_args.get("obj").spec.get("config"))
            self.assertNotIn("mtu", nad_config)

    @patch("charm.check_output")
    @patch("charm.Client", new=Mock)
    @patch(f"{HUGEPAGES_LIBRARY_PATH}.KubernetesHugePagesPatchCharmLib.is_patched")
    def test_given_cpu_not_supporting_required_hugepages_instructions_when_hugepages_enabled_then_charm_goes_to_blocked_status(  # noqa: E501
        self, patch_hugepages_is_patched, patched_check_output
    ):
        patch_hugepages_is_patched.return_value = False
        patched_check_output.return_value = b"Flags: ssse3 fma cx16 rdrand"

        self.harness.update_config(
            key_values={
                "cni-type": "vfioveth",
                "upf-mode": "dpdk",
                "access-interface-mac-address": "00-B0-D0-63-C2-26",
                "core-interface-mac-address": "00-B0-D0-63-C2-26",
            }
        )
        self.reinstantiate_charm()
        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.model.unit.status,
            BlockedStatus("Please use a CPU that has the following capabilities: avx2, rdrand"),
        )

    @patch("charm.check_output")
    @patch("lightkube.core.client.Client.list")
    @patch(f"{HUGEPAGES_LIBRARY_PATH}.KubernetesHugePagesPatchCharmLib.is_patched")
    @patch("dpdk.DPDK.is_configured")
    def test_given_cpu_supporting_required_hugepages_instructions_when_hugepages_enabled_then_charm_goes_to_waiting_status(  # noqa: E501
        self,
        patch_dpdk_is_configured,
        patch_hugepages_is_patched,
        patch_list,
        patched_check_output,
    ):
        patch_dpdk_is_configured.return_value = True
        patch_hugepages_is_patched.return_value = True
        patched_check_output.return_value = b"Flags: avx2 ssse3 fma cx16 rdrand pdpe1gb"
        patch_list.side_effect = [
            [Node(status=NodeStatus(allocatable={"hugepages-1Gi": "3Gi"}))],
            [],
            [Node(status=NodeStatus(allocatable={"hugepages-1Gi": "3Gi"}))],
            [],
        ]

        self.harness.update_config(
            key_values={
                "cni-type": "vfioveth",
                "upf-mode": "dpdk",
                "access-interface-mac-address": "00-B0-D0-63-C2-26",
                "core-interface-mac-address": "00-B0-D0-63-C2-26",
            }
        )
        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.model.unit.status,
            WaitingStatus("Waiting for bessd container to be ready"),
        )

    @patch("charm.check_output")
    @patch("lightkube.core.client.Client.list")
    @patch(f"{HUGEPAGES_LIBRARY_PATH}.KubernetesHugePagesPatchCharmLib.is_patched")
    def test_given_cpu_supporting_required_hugepages_instructions_and_not_available_hugepages_when_hugepages_enabled_then_charm_goes_to_blocked_status(  # noqa: E501
        self, patch_hugepages_is_patched, patch_list, patched_check_output
    ):
        patch_hugepages_is_patched.return_value = False
        patched_check_output.return_value = b"Flags: avx2 ssse3 fma cx16 rdrand pdpe1gb"
        patch_list.return_value = [Node(status=NodeStatus(allocatable={"hugepages-1Gi": "1Gi"}))]

        self.harness.update_config(
            key_values={
                "cni-type": "vfioveth",
                "upf-mode": "dpdk",
                "access-interface-mac-address": "00-B0-D0-63-C2-26",
                "core-interface-mac-address": "00-B0-D0-63-C2-26",
            }
        )
        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.model.unit.status, BlockedStatus("Not enough HugePages available")
        )

    @patch("charm.check_output")
    @patch("lightkube.core.client.Client.list")
    @patch(f"{HUGEPAGES_LIBRARY_PATH}.KubernetesHugePagesPatchCharmLib.is_patched")
    @patch("dpdk.DPDK.is_configured")
    def test_given_hugepages_not_available_then_hugepages_available_when_update_status_then_charm_goes_to_waiting_status(  # noqa: E501
        self,
        patch_dpdk_is_configured,
        patch_hugepages_is_patched,
        patch_list,
        patched_check_output,
    ):
        patch_dpdk_is_configured.return_value = True
        patch_hugepages_is_patched.return_value = True
        patched_check_output.return_value = b"Flags: avx2 ssse3 fma cx16 rdrand pdpe1gb"
        patch_list.side_effect = [
            [Node(status=NodeStatus(allocatable={"hugepages-1Gi": "1Gi"}))],
            [],
            [],
            [Node(status=NodeStatus(allocatable={"hugepages-1Gi": "2Gi"}))],
            [],
            [],
        ]

        self.harness.update_config(
            key_values={
                "cni-type": "vfioveth",
                "upf-mode": "dpdk",
                "access-interface-mac-address": "00-B0-D0-63-C2-26",
                "core-interface-mac-address": "00-B0-D0-63-C2-26",
            }
        )
        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.model.unit.status, BlockedStatus("Not enough HugePages available")
        )

        self.harness.charm.on.update_status.emit()
        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.model.unit.status,
            WaitingStatus("Waiting for bessd container to be ready"),
        )

    @patch("charm.check_output")
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.multus_is_available")
    @patch(f"{HUGEPAGES_LIBRARY_PATH}.KubernetesHugePagesPatchCharmLib.is_patched")
    def test_given_multus_disabled_then_enabled_when_update_status_then_status_is_active(
        self, patch_hugepages_is_patched, patch_multus_available, patched_check_output
    ):
        patch_hugepages_is_patched.return_value = True
        patch_multus_available.side_effect = [False, False, False, True]
        patched_check_output.return_value = b"Flags: avx2 ssse3 fma cx16 rdrand pdpe1gb"
        self.harness.charm.on.update_status.emit()
        self.harness.evaluate_status()
        self.assertEqual(
            self.harness.model.unit.status, BlockedStatus("Multus is not installed or enabled")
        )
        self.harness.charm.on.update_status.emit()
        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.model.unit.status,
            WaitingStatus("Waiting for bessd container to be ready"),
        )

    @patch(f"{HUGEPAGES_LIBRARY_PATH}.KubernetesHugePagesPatchCharmLib.is_patched")
    def test_given_default_config_when_network_attachment_definitions_from_config_is_called_then_no_interface_mtu_specified_in_nad(  # noqa: E501
        self,
        patch_hugepages_is_patched,
    ):
        patch_hugepages_is_patched.return_value = True
        self.harness.update_config(
            key_values={
                "access-ip": "192.168.252.3/24",
                "access-gateway-ip": ACCESS_GW_IP,
                "gnb-subnet": GNB_SUBNET,
                "core-ip": VALID_CORE_IP,
                "core-gateway-ip": CORE_GW_IP,
            }
        )
        nads = self.harness.charm._network_attachment_definitions_from_config()
        for nad in nads:
            config = json.loads(nad.spec["config"])
            self.assertNotIn("mtu", config)

    @patch("lightkube.core.client.Client.create")
    @patch("ops.model.Container.get_service")
    @patch(
        f"{HUGEPAGES_LIBRARY_PATH}.KubernetesHugePagesPatchCharmLib.is_patched",
        Mock(return_value=True),
    )
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready", Mock(return_value=True))
    @patch("charm.DPDK.is_configured", Mock(return_value=True))
    def test_given_default_config_with_interfaces_mtu_sizes_when_create_network_attachment_definitions_then_interface_mtu_set_in_the_network_attachment_definitions(  # noqa: E501
        self, patch_get_service, kubernetes_create_object
    ):
        service_info_mock = Mock()
        service_info_mock.is_running.return_value = True
        patch_get_service.return_value = service_info_mock
        self.harness.update_config(
            key_values={
                "access-ip": "192.168.252.3/24",
                "access-gateway-ip": ACCESS_GW_IP,
                "access-interface-mtu-size": VALID_MTU_SIZE_1,
                "gnb-subnet": GNB_SUBNET,
                "core-ip": VALID_CORE_IP,
                "core-gateway-ip": CORE_GW_IP,
                "core-interface-mtu-size": VALID_MTU_SIZE_1,
            }
        )

        create_nad_calls = kubernetes_create_object.call_args_list
        for create_nad_call in create_nad_calls:
            create_nad_call_args = next(
                iter(filter(lambda call_item: isinstance(call_item, dict), create_nad_call))
            )
            nad_config = json.loads(create_nad_call_args.get("obj").spec.get("config"))
            self.assertEqual(nad_config["mtu"], VALID_MTU_SIZE_1)

    def test_given_default_config_with_interfaces_too_small_and_too_big_mtu_sizes_when_network_attachment_definitions_from_config_is_called_then_status_is_blocked(  # noqa: E501
        self,
    ):
        self.harness.update_config(
            key_values={
                "access-interface-mtu-size": TOO_SMALL_MTU_SIZE,
                "core-interface-mtu-size": TOO_BIG_MTU_SIZE,
            }
        )
        self.harness.evaluate_status()
        self.assertEqual(
            self.harness.model.unit.status,
            BlockedStatus(
                "The following configurations are not valid: ['access-interface-mtu-size', 'core-interface-mtu-size']"  # noqa: E501, W505
            ),
        )

    @patch(
        f"{HUGEPAGES_LIBRARY_PATH}.KubernetesHugePagesPatchCharmLib.is_patched",
        Mock(return_value=True),
    )
    def test_given_default_config_with_interfaces_zero_mtu_sizes_when_network_attachment_definitions_from_config_is_called_then_status_is_blocked(  # noqa: E501
        self,
    ):
        self.harness.update_config(
            key_values={
                "access-interface-mtu-size": ZERO_MTU_SIZE,
                "core-interface-mtu-size": ZERO_MTU_SIZE,
            }
        )
        self.reinstantiate_charm()
        self.assertEqual(
            self.harness.model.unit.status,
            BlockedStatus(
                "The following configurations are not valid: ['access-interface-mtu-size', 'core-interface-mtu-size']"  # noqa: E501, W505
            ),
        )

    @patch("ops.model.Container.get_service")
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesClient", new=Mock)
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesClient.list_network_attachment_definitions")
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready")
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.delete_pod")
    @patch(f"{HUGEPAGES_LIBRARY_PATH}.KubernetesHugePagesPatchCharmLib.is_patched")
    def test_given_container_can_connect_bessd_pebble_ready_when_core_net_mtu_config_changed_to_a_different_valid_value_then_delete_pod_is_called(  # noqa: E501
        self,
        patch_hugepages_is_patched,
        patch_delete_pod,
        patch_multus_is_ready,
        patch_list_na_definitions,
        _,
    ):
        self.harness.handle_exec("bessd", [], result=0)
        patch_hugepages_is_patched.return_value = True
        patch_multus_is_ready.return_value = True
        self.harness.set_can_connect(container="bessd", val=True)
        self.harness.set_can_connect(container="pfcp-agent", val=True)
        original_nads = self.harness.charm._network_attachment_definitions_from_config()
        update_nad_labels(original_nads, self.harness.charm.app.name)
        patch_list_na_definitions.return_value = original_nads
        self.harness.update_config(key_values={"core-interface-mtu-size": VALID_MTU_SIZE_1})
        patch_delete_pod.assert_called_once()

    @patch("ops.model.Container.get_service")
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesClient", new=Mock)
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesClient.list_network_attachment_definitions")
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready")
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.delete_pod")
    @patch(f"{HUGEPAGES_LIBRARY_PATH}.KubernetesHugePagesPatchCharmLib.is_patched")
    def test_given_container_can_connect_bessd_pebble_ready_when_core_net_mtu_config_changed_to_different_valid_values_then_delete_pod_called_twice(  # noqa: E501
        self,
        patch_hugepages_is_patched,
        patch_delete_pod,
        patch_multus_is_ready,
        patch_list_na_definitions,
        _,
    ):
        self.harness.handle_exec("bessd", [], result=0)
        patch_hugepages_is_patched.return_value = True
        patch_multus_is_ready.return_value = True
        self.harness.set_can_connect(container="bessd", val=True)
        self.harness.set_can_connect(container="pfcp-agent", val=True)
        original_nads = self.harness.charm._network_attachment_definitions_from_config()
        update_nad_labels(original_nads, self.harness.charm.app.name)
        patch_list_na_definitions.return_value = original_nads
        self.harness.update_config(key_values={"core-interface-mtu-size": VALID_MTU_SIZE_1})
        modified_nads = self.harness.charm._network_attachment_definitions_from_config()
        update_nad_labels(modified_nads, self.harness.charm.app.name)
        patch_list_na_definitions.return_value = modified_nads
        self.harness.update_config(key_values={"core-interface-mtu-size": VALID_MTU_SIZE_2})
        self.assertEqual(patch_delete_pod.call_count, 2)

    @patch("ops.model.Container.get_service")
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesClient", new=Mock)
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesClient.list_network_attachment_definitions")
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready")
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesClient.delete_pod")
    @patch(f"{HUGEPAGES_LIBRARY_PATH}.KubernetesHugePagesPatchCharmLib.is_patched")
    def test_given_container_can_connect_bessd_pebble_ready_when_core_net_mtu_config_changed_to_same_valid_value_multiple_times_then_delete_pod_called_once(  # noqa: E501
        self,
        patch_hugepages_is_patched,
        patch_delete_pod,
        patch_multus_is_ready,
        patch_list_na_definitions,
        _,
    ):
        self.harness.handle_exec("bessd", [], result=0)
        """Delete pod is called for the first config change, setting the same config value does not trigger pod restarts."""  # noqa: E501, W505
        patch_hugepages_is_patched.return_value = True
        patch_multus_is_ready.return_value = True
        self.harness.set_can_connect(container="bessd", val=True)
        self.harness.set_can_connect(container="pfcp-agent", val=True)
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

    @patch("ops.model.Container.get_service")
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesClient", new=Mock)
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesClient.list_network_attachment_definitions")
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready")
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.delete_pod")
    @patch(
        f"{HUGEPAGES_LIBRARY_PATH}.KubernetesHugePagesPatchCharmLib.is_patched",
        Mock(return_value=True),
    )
    def test_given_container_can_connect_bessd_pebble_ready_when_core_net_mtu_config_changed_to_an_invalid_value_then_delete_pod_is_not_called(  # noqa: E501
        self,
        patch_delete_pod,
        patch_multus_is_ready,
        patch_list_na_definitions,
        _,
    ):
        self.harness.handle_exec("bessd", [], result=0)
        patch_multus_is_ready.return_value = True
        self.harness.set_can_connect(container="bessd", val=True)
        self.harness.set_can_connect(container="pfcp-agent", val=True)
        original_nads = self.harness.charm._network_attachment_definitions_from_config()
        update_nad_labels(original_nads, self.harness.charm.app.name)
        patch_list_na_definitions.return_value = original_nads
        self.harness.update_config(key_values={"core-interface-mtu-size": TOO_BIG_MTU_SIZE})
        self.reinstantiate_charm()
        patch_delete_pod.assert_not_called()

    @patch("ops.model.Container.get_service")
    @patch(
        f"{HUGEPAGES_LIBRARY_PATH}.KubernetesHugePagesPatchCharmLib.is_patched",
        Mock(return_value=True),
    )
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready")
    def test_given_hardware_checksum_is_enabled_when_bessd_pebble_ready_then_config_file_has_hwcksum_enabled(  # noqa: E501
        self,
        _,
        __,
    ):
        self.harness.handle_exec("bessd", [], result=0)
        self.harness.set_can_connect("bessd", True)
        self.harness.set_can_connect("pfcp-agent", True)
        self.harness.update_config(key_values={"enable-hw-checksum": False})
        self.reinstantiate_charm()
        self.harness.container_pebble_ready(container_name="bessd")

        config = json.loads((self.root / "etc/bess/conf/upf.json").read_text())
        self.assertIn("hwcksum", config)
        self.assertFalse(config["hwcksum"])

    @patch("ops.model.Container.get_service")
    @patch("charm.UPFOperatorCharm.delete_pod")
    @patch(f"{MULTUS_LIBRARY_PATH}.KubernetesMultusCharmLib.is_ready")
    @patch(f"{HUGEPAGES_LIBRARY_PATH}.KubernetesHugePagesPatchCharmLib.is_patched")
    def test_given_hardware_checksum_is_enabled_when_value_changes_then_delete_pod_is_called_once(  # noqa: E501
        self,
        patch_hugepages_is_patched,
        patch_multus_is_ready,
        patch_delete_pod,
        _,
    ):
        self.harness.handle_exec("bessd", [], result=0)
        patch_hugepages_is_patched.return_value = True
        patch_multus_is_ready.return_value = True
        self.harness.set_can_connect(container="bessd", val=True)
        self.harness.set_can_connect(container="pfcp-agent", val=True)
        self.harness.update_config(key_values={"enable-hw-checksum": False})
        patch_delete_pod.assert_called_once()
