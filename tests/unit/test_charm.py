# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import json
from unittest.mock import Mock, call, patch

import pytest
from charms.kubernetes_charm_libraries.v0.multus import (
    NetworkAnnotation,
    NetworkAttachmentDefinition,
)
from lightkube.models.core_v1 import Node, NodeStatus
from ops import ActiveStatus, BlockedStatus, MaintenanceStatus, WaitingStatus, testing
from ops.pebble import ConnectionError

from charm import (
    ACCESS_INTERFACE_NAME,
    ACCESS_NETWORK_ATTACHMENT_DEFINITION_NAME,
    CORE_INTERFACE_NAME,
    CORE_NETWORK_ATTACHMENT_DEFINITION_NAME,
    DPDK_ACCESS_INTERFACE_RESOURCE_NAME,
    DPDK_CORE_INTERFACE_RESOURCE_NAME,
    UPFOperatorCharm,
)

MULTUS_LIBRARY = "charms.kubernetes_charm_libraries.v0.multus.KubernetesMultusCharmLib"
K8S_CLIENT = "charms.kubernetes_charm_libraries.v0.multus.KubernetesClient"
HUGEPAGES_LIBRARY = (
    "charms.kubernetes_charm_libraries.v0.hugepages_volumes_patch.KubernetesHugePagesPatchCharmLib"  # noqa E501
)
TOO_BIG_MTU_SIZE = 65536  # Out of range
TOO_SMALL_MTU_SIZE = 1199  # Out of range
ZERO_MTU_SIZE = 0  # Out of range
VALID_MTU_SIZE_1 = 65535  # Upper edge value
VALID_MTU_SIZE_2 = 1200  # Lower edge value
TEST_PFCP_PORT = 1234
DEFAULT_ACCESS_IP = "192.168.252.3/24"
VALID_ACCESS_IP = "192.168.252.5/24"
ACCESS_GW_IP = "192.168.252.1"
GNB_SUBNET = "192.168.251.0/24"
VALID_CORE_IP = "192.168.250.3/24"
CORE_GW_IP = "192.168.250.1"
VALID_ACCESS_MAC = "00-b0-d0-63-c2-26"
INVALID_ACCESS_MAC = "something"
VALID_CORE_MAC = "00-b0-d0-63-c2-36"
INVALID_CORE_MAC = "wrong"
NAMESPACE = "whatever"


def read_file(path: str) -> str:
    """Read a file and return its content as a string."""
    with open(path, "r") as f:
        content = f.read()
    return content


def set_nad_metadata_labels(nads: list[NetworkAttachmentDefinition], app_name: str) -> None:
    for nad in nads:
        assert nad.metadata
        nad.metadata.labels = {"app.juju.is/created-by": app_name}


class TestCharmInitialisation:
    patcher_k8s_client = patch("lightkube.core.client.GenericSyncClient")
    patcher_check_output = patch("charm.check_output")
    patcher_client_list = patch("lightkube.core.client.Client.list")
    patcher_delete_pod = patch(f"{MULTUS_LIBRARY}.delete_pod")
    patcher_huge_pages_is_patched = patch(
        f"{HUGEPAGES_LIBRARY}.is_patched",
    )
    patcher_list_na_definitions = patch(f"{K8S_CLIENT}.list_network_attachment_definitions")
    patcher_multus_is_ready = patch(f"{MULTUS_LIBRARY}.is_ready")

    @pytest.fixture()
    def setUp(self):
        TestCharmInitialisation.patcher_k8s_client.start()
        self.mock_client_list = TestCharmInitialisation.patcher_client_list.start()
        self.mock_cpu_info = TestCharmInitialisation.patcher_check_output.start()
        self.mock_delete_pod = TestCharmInitialisation.patcher_delete_pod.start()
        self.mock_huge_pages_is_enabled = (
            TestCharmInitialisation.patcher_huge_pages_is_patched.start()
        )
        self.mock_list_na_definitions = TestCharmInitialisation.patcher_list_na_definitions.start()
        self.mock_multus_is_ready = TestCharmInitialisation.patcher_multus_is_ready.start()

    @staticmethod
    def tearDown() -> None:
        patch.stopall()

    @pytest.fixture(autouse=True)
    def setup_harness(self, setUp, request):
        self.harness = testing.Harness(UPFOperatorCharm)
        self.harness.set_model_name(name=NAMESPACE)
        self.harness.set_leader(is_leader=True)
        self.add_storage()
        yield self.harness
        self.harness.cleanup()
        request.addfinalizer(self.tearDown)

    def add_storage(self) -> None:
        self.root = self.harness.get_filesystem_root("bessd")
        (self.root / "etc/bess/conf").mkdir(parents=True)

    @pytest.mark.parametrize(
        "config_param,invalid_value",
        [
            pytest.param("dnn", "", id="empty_dnn"),
            pytest.param("upf-mode", "", id="empty_upf_mode"),
            pytest.param("upf-mode", "unsupported", id="unsupported_upf_mode"),
        ],
    )
    def test_given_bad_config_when_config_changed_then_status_is_blocked(
        self, config_param, invalid_value
    ):
        self.mock_huge_pages_is_enabled.return_value = True
        self.mock_client_list.side_effect = [
            [Node(status=NodeStatus(allocatable={"hugepages-1Gi": "3Gi"}))],
        ]
        self.harness.update_config(key_values={config_param: invalid_value})
        self.harness.begin()
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == BlockedStatus(
            f"The following configurations are not valid: ['{config_param}']"
        )

    def test_given_upf_mode_set_to_dpdk_and_hugepages_enabled_but_mac_addresses_of_access_and_core_interfaces_not_set_when_config_changed_then_status_is_blocked(  # noqa: E501
        self,
    ):
        self.mock_huge_pages_is_enabled.return_value = True
        self.mock_cpu_info.return_value = b"Flags: avx2 ssse3 fma cx16 rdrand pdpe1gb"
        self.mock_client_list.side_effect = [
            [Node(status=NodeStatus(allocatable={"hugepages-1Gi": "3Gi"}))],
            [],
            [],
        ]
        self.harness.update_config(key_values={"cni-type": "vfioveth", "upf-mode": "dpdk"})
        self.harness.begin()
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == BlockedStatus(
            "The following configurations are not valid: ['access-interface-mac-address', 'core-interface-mac-address']"  # noqa: E501, W505
        )

    @pytest.mark.parametrize(
        "access_mac_address, core_mac_address, invalid_param_name",
        [
            pytest.param(
                INVALID_ACCESS_MAC,
                VALID_CORE_MAC,
                "access-interface-mac-address",
                id="invalid_access_mac",  # noqa: E501
            ),
            pytest.param(
                VALID_ACCESS_MAC,
                INVALID_CORE_MAC,
                "core-interface-mac-address",
                id="invalid_core_mac",  # noqa: E501
            ),
            pytest.param(
                INVALID_ACCESS_MAC,
                INVALID_CORE_MAC,
                "access-interface-mac-address', 'core-interface-mac-address",
                id="invalid_access_and_core_mac",  # noqa: E501
            ),
        ],
    )
    def test_given_upf_mode_set_to_dpdk_and_hugepages_enabled_but_mac_address_is_invalid_when_config_changed_then_status_is_blocked(  # noqa: E501
        self, access_mac_address, core_mac_address, invalid_param_name
    ):
        self.mock_huge_pages_is_enabled.return_value = True
        self.mock_cpu_info.return_value = b"Flags: avx2 ssse3 fma cx16 rdrand pdpe1gb"
        self.mock_client_list.side_effect = [
            [Node(status=NodeStatus(allocatable={"hugepages-1Gi": "3Gi"}))],
            [],
            [],
        ]
        self.harness.update_config(
            key_values={
                "cni-type": "vfioveth",
                "upf-mode": "dpdk",
                "access-interface-mac-address": access_mac_address,
                "core-interface-mac-address": core_mac_address,
            }
        )
        self.harness.begin()
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == BlockedStatus(
            f"The following configurations are not valid: ['{invalid_param_name}']"
        )

    def test_given_cpu_not_supporting_required_hugepages_instructions_when_hugepages_enabled_then_charm_goes_to_blocked_status(  # noqa: E501
        self,
    ):
        self.mock_huge_pages_is_enabled.return_value = False
        self.mock_cpu_info.return_value = b"Flags: ssse3 fma cx16 rdrand"
        self.harness.update_config(
            key_values={
                "cni-type": "vfioveth",
                "upf-mode": "dpdk",
                "access-interface-mac-address": VALID_ACCESS_MAC,
                "core-interface-mac-address": VALID_CORE_MAC,
            }
        )
        self.harness.begin()
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == BlockedStatus(
            "CPU is not compatible, see logs for more details"
        )

    @pytest.mark.parametrize(
        "access_mtu_size, core_mtu_size, invalid_param_name",
        [
            pytest.param(
                ZERO_MTU_SIZE,
                VALID_MTU_SIZE_2,
                "access-interface-mtu-size",
                id="zero_mtu_size_access_interface",  # noqa: E501
            ),
            pytest.param(
                TOO_SMALL_MTU_SIZE,
                VALID_MTU_SIZE_2,
                "access-interface-mtu-size",
                id="too_small_mtu_size_access_interface",  # noqa: E501
            ),
            pytest.param(
                VALID_MTU_SIZE_1,
                ZERO_MTU_SIZE,
                "core-interface-mtu-size",
                id="zero_mtu_size_core_interface",  # noqa: E501
            ),
            pytest.param(
                VALID_MTU_SIZE_1,
                TOO_BIG_MTU_SIZE,
                "core-interface-mtu-size",
                id="too_big_mtu_size_core_interface",  # noqa: E501
            ),
            pytest.param(
                ZERO_MTU_SIZE,
                ZERO_MTU_SIZE,
                "access-interface-mtu-size', 'core-interface-mtu-size",
                id="zero_mtu_size_access_and_core_interface",  # noqa: E501
            ),
        ],
    )
    def test_given_default_config_with_interfaces_invalid_mtu_sizes_when_network_attachment_definitions_from_config_is_called_then_status_is_blocked(  # noqa: E501
        self, access_mtu_size, core_mtu_size, invalid_param_name
    ):
        self.mock_huge_pages_is_enabled.return_value = True
        self.harness.update_config(
            key_values={
                "access-interface-mtu-size": access_mtu_size,
                "core-interface-mtu-size": core_mtu_size,
            }
        )
        self.harness.begin()
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == BlockedStatus(
            f"The following configurations are not valid: ['{invalid_param_name}']"
        )

    def test_given_container_can_connect_bessd_pebble_ready_when_core_net_mtu_config_changed_to_an_invalid_value_then_delete_pod_is_not_called(  # noqa: E501
        self,
    ):
        self.mock_huge_pages_is_enabled.return_value = True
        self.mock_multus_is_ready.return_value = True
        self.harness.handle_exec("bessd", [], result=0)
        self.harness.set_can_connect(container="bessd", val=True)
        self.harness.set_can_connect(container="pfcp-agent", val=True)
        self.harness.begin()
        original_nads = self.harness.charm._network_attachment_definitions_from_config()
        set_nad_metadata_labels(original_nads, self.harness.charm.app.name)
        self.mock_list_na_definitions.return_value = original_nads

        self.harness.update_config(key_values={"core-interface-mtu-size": TOO_BIG_MTU_SIZE})

        self.mock_delete_pod.assert_not_called()

    def test_given_hardware_checksum_is_enabled_when_bessd_pebble_ready_then_config_file_has_hwcksum_enabled(  # noqa: E501
        self,
    ):
        self.mock_cpu_info.return_value = b"Flags: avx2 ssse3 fma cx16 rdrand pdpe1gb"
        self.mock_multus_is_ready.return_value = True
        self.mock_huge_pages_is_enabled.return_value = True
        self.harness.handle_exec("bessd", [], result=0)
        self.harness.set_can_connect("bessd", True)
        self.harness.set_can_connect("pfcp-agent", True)
        self.harness.update_config(key_values={"enable-hw-checksum": False})
        self.harness.begin()
        self.harness.container_pebble_ready(container_name="bessd")

        config = json.loads((self.root / "etc/bess/conf/upf.json").read_text())
        assert "hwcksum" in config
        assert config["hwcksum"] is False

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
        self.harness.begin()
        nads = self.harness.charm._network_attachment_definitions_from_config()
        for nad in nads:
            assert nad.spec
            config = json.loads(nad.spec["config"])
            assert ACCESS_INTERFACE_NAME or CORE_INTERFACE_NAME in config["master"]
            assert config["type"] == "macvlan"


class TestCharm:
    patcher_k8s_service_is_created = patch("charm.K8sService.is_created")
    patcher_k8s_service_create = patch("charm.K8sService.create")
    patcher_k8s_service_delete = patch("charm.K8sService.delete")
    patcher_k8s_service_get_hostname = patch("charm.K8sService.get_hostname")
    patcher_check_output = patch("charm.check_output")
    patcher_client_create = patch("lightkube.core.client.Client.create")
    patcher_client_delete = patch("lightkube.core.client.Client.delete")
    patcher_client_get = patch("lightkube.core.client.Client.get")
    patcher_client_list = patch("lightkube.core.client.Client.list")
    patcher_delete_pod = patch(f"{MULTUS_LIBRARY}.delete_pod")
    patcher_dpdk_is_configured = patch("charm.DPDK.is_configured")
    patcher_get_service = patch("ops.model.Container.get_service")
    patcher_huge_pages_is_patched = patch(f"{HUGEPAGES_LIBRARY}.is_patched")
    patcher_k8s_client = patch("lightkube.core.client.GenericSyncClient")
    patcher_k8s_statefulset_patch = patch("lightkube.core.client.Client.patch")
    patcher_list_na_definitions = patch(f"{K8S_CLIENT}.list_network_attachment_definitions")
    patcher_multus_is_ready = patch(f"{MULTUS_LIBRARY}.is_ready")
    patcher_pfcp_port = patch("charm.PFCP_PORT", TEST_PFCP_PORT)
    patcher_publish_upf_n3_information = patch(
        "charms.sdcore_upf_k8s.v0.fiveg_n3.N3Provides.publish_upf_information"
    )
    patcher_publish_upf_n4_information = patch(
        "charms.sdcore_upf_k8s.v0.fiveg_n4.N4Provides.publish_upf_n4_information"
    )

    @pytest.fixture()
    def setUp(self):
        self.mock_k8s_service_is_created = TestCharm.patcher_k8s_service_is_created.start()
        self.mock_k8s_service_create = TestCharm.patcher_k8s_service_create.start()
        self.mock_k8s_service_delete = TestCharm.patcher_k8s_service_delete.start()
        self.mock_k8s_service_get_hostname = TestCharm.patcher_k8s_service_get_hostname.start()
        TestCharm.patcher_k8s_client.start()
        TestCharm.patcher_pfcp_port.start()
        self.mock_client_create = TestCharm.patcher_client_create.start()
        self.mock_client_list = TestCharm.patcher_client_list.start()
        self.mock_client_delete = TestCharm.patcher_client_delete.start()
        self.mock_dpdk_is_configured = TestCharm.patcher_dpdk_is_configured.start()
        self.mock_get_service = TestCharm.patcher_get_service.start()
        self.mock_huge_pages_is_enabled = TestCharm.patcher_huge_pages_is_patched.start()
        self.mock_k8s_statefulset_patch = TestCharm.patcher_k8s_statefulset_patch.start()
        self.mock_multus_is_ready = TestCharm.patcher_multus_is_ready.start()
        self.mock_publish_upf_n3_information = TestCharm.patcher_publish_upf_n3_information.start()
        self.mock_publish_upf_n4_information = TestCharm.patcher_publish_upf_n4_information.start()

    @staticmethod
    def tearDown() -> None:
        patch.stopall()

    @pytest.fixture(autouse=True)
    def setup_harness(self, setUp, request):
        self.harness = testing.Harness(UPFOperatorCharm)
        self.harness.set_model_name(name=NAMESPACE)
        self.harness.set_leader(is_leader=True)
        self.set_up_storage()
        self.harness.begin()
        yield self.harness
        self.harness.cleanup()
        request.addfinalizer(self.tearDown)

    @pytest.fixture()
    def set_can_connect_containers(self) -> None:
        self.harness.set_can_connect("bessd", True)
        self.harness.set_can_connect("pfcp-agent", True)

    @pytest.fixture()
    def enable_huge_pages_multus_and_dpdk(self) -> None:
        self.mock_huge_pages_is_enabled.return_value = True
        self.mock_multus_is_ready.return_value = True
        self.mock_dpdk_is_configured.return_value = True

    def set_up_storage(self) -> None:
        self.root = self.harness.get_filesystem_root("bessd")
        (self.root / "etc/bess/conf").mkdir(parents=True)

    def mock_running_service(self) -> None:
        service_info_mock = Mock()
        service_info_mock.is_running.return_value = True
        self.mock_get_service.return_value = service_info_mock

    def add_fiveg_n3_relation(self) -> int:
        relation_id = self.harness.add_relation("fiveg_n3", "n3_requirer_app")
        self.harness.add_relation_unit(relation_id, "n3_requirer_app/0")
        return relation_id

    def add_fiveg_n4_relation(self) -> int:
        relation_id = self.harness.add_relation("fiveg_n4", "n4_requirer_app")
        self.harness.add_relation_unit(relation_id, "n4_requirer_app/0")
        return relation_id

    def test_given_bessd_config_file_not_yet_written_when_bessd_pebble_ready_then_config_file_is_written(  # noqa: E501
        self, set_can_connect_containers
    ):
        self.harness.handle_exec("bessd", [], result=0)
        self.harness.container_pebble_ready(container_name="bessd")
        expected_config_file_content = read_file("tests/unit/expected_upf.json").strip()

        assert (self.root / "etc/bess/conf/upf.json").read_text() == expected_config_file_content

    def test_given_bessd_config_file_not_yet_written_when_config_storage_attached_then_config_file_is_written(  # noqa: E501
        self, set_can_connect_containers
    ):
        self.harness.handle_exec("bessd", [], result=0)
        (self.root / "etc/bess/conf").rmdir()
        self.harness.add_storage(storage_name="config", count=1)
        self.harness.attach_storage(storage_id="config/0")

        expected_config_file_content = read_file("tests/unit/expected_upf.json").strip()

        assert (self.root / "etc/bess/conf/upf.json").read_text() == expected_config_file_content

    def test_given_bessd_config_file_matches_when_bessd_pebble_ready_then_config_file_is_not_changed(  # noqa: E501
        self,
    ):
        self.harness.handle_exec("bessd", [], result=0)
        self.mock_multus_is_ready.return_value = True
        expected_upf_content = read_file("tests/unit/expected_upf.json").strip()
        (self.root / "etc/bess/conf/upf.json").write_text(expected_upf_content)

        self.harness.container_pebble_ready(container_name="bessd")

        assert (self.root / "etc/bess/conf/upf.json").read_text() == expected_upf_content

    def test_given_bess_configured_when_bessd_pebble_ready_then_expected_pebble_plan_is_applied(  # noqa: E501
        self, set_can_connect_containers
    ):
        grpc_check_cmd = "/opt/bess/bessctl/bessctl show version".split()
        accessRoutes_check_cmd = "/opt/bess/bessctl/bessctl show module accessRoutes".split()  # noqa: N806
        coreRoutes_check_cmd = "/opt/bess/bessctl/bessctl show module coreRoutes".split()  # noqa: N806
        config_check_cmd = "/opt/bess/bessctl/bessctl show worker".split()
        bessctl_cmd = ["/opt/bess/bessctl/bessctl", "run", "/opt/bess/bessctl/conf/up4"]

        self.harness.handle_exec("bessd", ["ip"], result=0)
        self.harness.handle_exec("bessd", ["iptables-legacy"], result=0)
        self.harness.handle_exec("bessd", grpc_check_cmd, result=0)
        self.harness.handle_exec("bessd", accessRoutes_check_cmd, result=0)
        self.harness.handle_exec("bessd", coreRoutes_check_cmd, result=0)
        self.harness.handle_exec("bessd", config_check_cmd, result="RUNNING")
        self.harness.handle_exec("bessd", bessctl_cmd, result=0)
        self.mock_multus_is_ready.return_value = True

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
        assert expected_plan == updated_plan

    def test_given_bess_not_configured_when_bessd_pebble_ready_then_routectl_service_not_started(  # noqa: E501
        self, set_can_connect_containers
    ):
        grpc_check_cmd = "/opt/bess/bessctl/bessctl show version".split()
        accessRoutes_check_cmd = "/opt/bess/bessctl/bessctl show module accessRoutes".split()  # noqa: N806
        coreRoutes_check_cmd = "/opt/bess/bessctl/bessctl show module coreRoutes".split()  # noqa: N806
        config_check_cmd = "/opt/bess/bessctl/bessctl show worker".split()
        bessctl_cmd = ["/opt/bess/bessctl/bessctl", "run", "/opt/bess/bessctl/conf/up4"]

        self.harness.handle_exec("bessd", ["ip"], result=0)
        self.harness.handle_exec("bessd", ["iptables-legacy"], result=0)
        self.harness.handle_exec("bessd", grpc_check_cmd, result=0)
        self.harness.handle_exec("bessd", accessRoutes_check_cmd, result=1)
        self.harness.handle_exec("bessd", coreRoutes_check_cmd, result=0)
        self.harness.handle_exec("bessd", config_check_cmd, result="RUNNING")
        self.harness.handle_exec("bessd", bessctl_cmd, result=0)
        self.mock_multus_is_ready.return_value = True

        self.harness.container_pebble_ready(container_name="bessd")

        assert "routectl" not in self.harness.get_container_pebble_plan("bessd").services

    def test_given_can_connect_to_bessd_when_bessd_pebble_ready_then_ip_route_is_created(
        self, set_can_connect_containers
    ):
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
        ip_route_show_cmd = ["ip", "route", "show"]

        self.harness.handle_exec("bessd", replace_default_route_cmd, handler=ip_handler)
        self.harness.handle_exec("bessd", replace_gnb_subnet_route_cmd, result=0)
        self.harness.handle_exec("bessd", ["iptables-legacy"], result=0)
        self.harness.handle_exec("bessd", ["/opt/bess/bessctl/bessctl"], result=0)
        self.harness.handle_exec("bessd", ip_route_show_cmd, result="")
        self.mock_multus_is_ready.return_value = True

        self.harness.container_pebble_ready(container_name="bessd")

        assert ip_route_replace_called
        assert timeout == 30
        assert environment == {}

    def test_given_can_connect_to_bessd_when_bessd_pebble_ready_then_gnb_subnet_route_is_created(
        self, set_can_connect_containers
    ):
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
        ip_route_show_cmd = ["ip", "route", "show"]

        self.harness.handle_exec("bessd", replace_gnb_subnet_route_cmd, handler=ip_handler)
        self.harness.handle_exec("bessd", replace_default_route_cmd, result=0)
        self.harness.handle_exec("bessd", ["iptables-legacy"], result=0)
        self.harness.handle_exec("bessd", ["/opt/bess/bessctl/bessctl"], result=0)
        self.harness.handle_exec("bessd", ip_route_show_cmd, result="")
        self.mock_multus_is_ready.return_value = True

        self.harness.container_pebble_ready(container_name="bessd")

        assert gnb_subnet_route_replace_called
        assert timeout == 30
        assert environment == {}

    def test_given_iptables_rule_is_not_yet_created_when_bessd_pebble_ready_then_rule_is_created(
        self, set_can_connect_containers
    ):
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
        self.mock_multus_is_ready.return_value = True

        self.harness.container_pebble_ready(container_name="bessd")

        assert iptables_drop_called
        assert timeout == 30
        assert environment == {}

    def test_given_iptables_rule_is_created_when_bessd_pebble_ready_then_rule_is_not_re_created(
        self, set_can_connect_containers
    ):
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
        self.mock_multus_is_ready.return_value = True

        self.harness.container_pebble_ready(container_name="bessd")

        assert not iptables_drop_called

    @pytest.mark.parametrize(
        "access_routes_check_out, core_routes_check_out, config_check_out",
        [
            (1, 0, "RUNNING"),
            (0, 1, "RUNNING"),
            (0, 0, 1),
        ],
    )
    def test_given_can_connect_to_bessd_when_bessd_pebble_ready_then_bessctl_configure_is_executed(
        self,
        access_routes_check_out,
        core_routes_check_out,
        config_check_out,
        set_can_connect_containers,
    ):
        bessctl_called = False
        timeout = 0
        environment = {}

        grpc_check_cmd = "/opt/bess/bessctl/bessctl show version".split()
        accessRoutes_check_cmd = "/opt/bess/bessctl/bessctl show module accessRoutes".split()  # noqa: N806
        coreRoutes_check_cmd = "/opt/bess/bessctl/bessctl show module coreRoutes".split()  # noqa: N806
        config_check_cmd = "/opt/bess/bessctl/bessctl show worker".split()
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
        self.harness.handle_exec("bessd", grpc_check_cmd, result=0)
        self.harness.handle_exec("bessd", accessRoutes_check_cmd, result=access_routes_check_out)
        self.harness.handle_exec("bessd", coreRoutes_check_cmd, result=core_routes_check_out)
        self.harness.handle_exec("bessd", config_check_cmd, result=config_check_out)
        self.harness.handle_exec("bessd", bessctl_cmd, handler=bessctl_handler)
        self.mock_multus_is_ready.return_value = True

        self.harness.container_pebble_ready(container_name="bessd")

        assert bessctl_called
        assert timeout == 30
        assert environment == {"CONF_FILE": "/etc/bess/conf/upf.json", "PYTHONPATH": "/opt/bess"}

    def test_given_connects_and_bess_configured_then_bessctl_configure_not_executed(
        self, set_can_connect_containers
    ):
        bessctl_called = False
        grpc_check_cmd = "/opt/bess/bessctl/bessctl show version".split()
        accessRoutes_check_cmd = "/opt/bess/bessctl/bessctl show module accessRoutes".split()  # noqa: N806
        coreRoutes_check_cmd = "/opt/bess/bessctl/bessctl show module coreRoutes".split()  # noqa: N806
        config_check_cmd = "/opt/bess/bessctl/bessctl show worker".split()
        bessctl_cmd = ["/opt/bess/bessctl/bessctl", "run", "/opt/bess/bessctl/conf/up4"]

        def bessctl_handler(_: testing.ExecArgs) -> testing.ExecResult:
            nonlocal bessctl_called
            bessctl_called = True
            return testing.ExecResult(exit_code=0)

        self.harness.handle_exec("bessd", ["ip"], result=0)
        self.harness.handle_exec("bessd", ["iptables-legacy"], result=0)
        self.harness.handle_exec("bessd", grpc_check_cmd, result=0)
        self.harness.handle_exec("bessd", accessRoutes_check_cmd, result=0)
        self.harness.handle_exec("bessd", coreRoutes_check_cmd, result=0)
        self.harness.handle_exec("bessd", config_check_cmd, result="RUNNING")
        self.harness.handle_exec("bessd", bessctl_cmd, handler=bessctl_handler)
        self.mock_multus_is_ready.return_value = True

        self.harness.container_pebble_ready(container_name="bessd")

        assert not bessctl_called

    def test_given_storage_not_attached_when_collect_status_ready_then_status_is_waiting(
        self, set_can_connect_containers
    ):
        ip_route_show_cmd = ["ip", "route", "show"]
        ip_route_show_result = f"{GNB_SUBNET} via {ACCESS_GW_IP}\ndefault via {CORE_GW_IP}"

        self.harness.handle_exec("bessd", ip_route_show_cmd, result=ip_route_show_result)
        self.harness.handle_exec("bessd", [], result=0)
        self.mock_multus_is_ready.return_value = True
        (self.root / "etc/bess/conf").rmdir()

        self.harness.evaluate_status()

        assert self.harness.model.unit.status == WaitingStatus(
            "Waiting for storage to be attached"
        )

    def test_given_multus_not_configured_when_collect_status_then_status_is_waiting(
        self, set_can_connect_containers
    ):
        self.mock_multus_is_ready.return_value = False

        self.harness.evaluate_status()

        assert self.harness.model.unit.status == WaitingStatus("Waiting for Multus to be ready")

    def test_given_config_file_is_written_and_all_services_are_running_when_collect_status_then_status_is_active(  # noqa: E501
        self, set_can_connect_containers
    ):
        ip_route_show_cmd = ["ip", "route", "show"]
        ip_route_show_result = f"{GNB_SUBNET} via {ACCESS_GW_IP}\ndefault via {CORE_GW_IP}"

        self.harness.handle_exec("bessd", ip_route_show_cmd, result=ip_route_show_result)
        self.harness.handle_exec("bessd", [], result="RUNNING")
        self.mock_running_service()
        self.mock_multus_is_ready.return_value = True

        self.harness.evaluate_status()

        assert self.harness.model.unit.status == ActiveStatus()

    def test_given_bessd_service_is_running_when_pfcp_agent_pebble_ready_then_pebble_plan_is_applied(  # noqa: E501
        self,
    ):
        self.mock_running_service()
        self.mock_multus_is_ready.return_value = True
        self.harness.set_can_connect(container="bessd", val=True)
        grpc_check_cmd = "/opt/bess/bessctl/bessctl show version".split()
        accessRoutes_check_cmd = "/opt/bess/bessctl/bessctl show module accessRoutes".split()  # noqa: N806
        coreRoutes_check_cmd = "/opt/bess/bessctl/bessctl show module coreRoutes".split()  # noqa: N806
        config_check_cmd = "/opt/bess/bessctl/bessctl show worker".split()
        ip_route_show_cmd = ["ip", "route", "show"]
        ip_route_show_result = f"{GNB_SUBNET} via {ACCESS_GW_IP}\ndefault via {CORE_GW_IP}"

        self.harness.handle_exec("bessd", ip_route_show_cmd, result=ip_route_show_result)
        self.harness.handle_exec("bessd", grpc_check_cmd, result=0)
        self.harness.handle_exec("bessd", accessRoutes_check_cmd, result=0)
        self.harness.handle_exec("bessd", coreRoutes_check_cmd, result=0)
        self.harness.handle_exec("bessd", config_check_cmd, result="RUNNING")

        self.harness.container_pebble_ready(container_name="pfcp-agent")
        self.harness.evaluate_status()
        assert self.harness.charm.unit.status == ActiveStatus()

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
        assert expected_plan == updated_plan

    def test_given_cant_connect_to_bessd_container_when_collect_status_then_status_is_waiting(  # noqa: E501
        self,
    ):
        self.harness.set_can_connect(container="bessd", val=False)

        self.harness.evaluate_status()

        assert self.harness.model.unit.status == WaitingStatus(
            "Waiting for bessd container to be ready"
        )

    def test_given_pebble_connection_error_when_collect_status_then_status_is_waiting(  # noqa: E501
        self, set_can_connect_containers
    ):
        ip_route_show_cmd = ["ip", "route", "show"]
        ip_route_show_result = f"{GNB_SUBNET} via {ACCESS_GW_IP}\ndefault via {CORE_GW_IP}"
        self.harness.handle_exec("bessd", ip_route_show_cmd, result=ip_route_show_result)
        self.harness.handle_exec("bessd", [], result=0)
        self.mock_get_service.side_effect = ConnectionError()
        self.mock_multus_is_ready.return_value = True

        self.harness.evaluate_status()

        assert self.harness.model.unit.status == WaitingStatus("Waiting for bessd service to run")

    def test_given_default_route_not_created_when_collect_status_then_status_is_waiting(
        self, set_can_connect_containers
    ):
        ip_route_show_cmd = ["ip", "route", "show"]
        self.harness.handle_exec("bessd", ip_route_show_cmd, result="")
        self.harness.handle_exec("bessd", [], result=0)
        self.mock_multus_is_ready.return_value = True

        self.harness.evaluate_status()

        assert self.harness.model.unit.status == WaitingStatus(
            "Waiting for default route creation"
        )

    def test_given_ran_route_not_created_when_collect_status_then_status_is_waiting(
        self, set_can_connect_containers
    ):
        ip_route_show_cmd = ["ip", "route", "show"]
        self.harness.handle_exec("bessd", ip_route_show_cmd, result=f"default via {CORE_GW_IP}")
        self.harness.handle_exec("bessd", [], result=0)
        self.mock_multus_is_ready.return_value = True

        self.harness.evaluate_status()

        assert self.harness.model.unit.status == WaitingStatus("Waiting for RAN route creation")

    def test_given_fiveg_n3_relation_created_when_fiveg_n3_request_then_upf_ip_address_is_published(  # noqa: E501
        self,
    ):
        test_upf_access_ip_cidr = "1.2.3.4/21"
        self.harness.update_config(key_values={"access-ip": test_upf_access_ip_cidr})

        n3_relation_id = self.add_fiveg_n3_relation()

        self.mock_publish_upf_n3_information.assert_called_once_with(
            relation_id=n3_relation_id, upf_ip_address=test_upf_access_ip_cidr.split("/")[0]
        )

    def test_given_unit_is_not_leader_when_fiveg_n3_request_then_upf_ip_address_is_not_published(
        self,
    ):
        self.harness.set_leader(is_leader=False)
        test_upf_access_ip_cidr = "1.2.3.4/21"
        self.harness.update_config(key_values={"access-ip": test_upf_access_ip_cidr})

        self.add_fiveg_n3_relation()

        self.mock_publish_upf_n3_information.assert_not_called()

    def test_given_fiveg_n3_relation_exists_when_access_ip_config_changed_then_new_upf_ip_address_is_published(  # noqa: E501
        self, set_can_connect_containers
    ):
        self.harness.handle_exec("bessd", [], result=0)
        self.mock_multus_is_ready.return_value = True
        self.mock_huge_pages_is_enabled.return_value = True
        n3_relation_id = self.add_fiveg_n3_relation()
        test_upf_access_ip_cidr = "1.2.3.4/21"
        expected_calls = [
            call(relation_id=n3_relation_id, upf_ip_address="192.168.252.3"),
            call(relation_id=n3_relation_id, upf_ip_address=test_upf_access_ip_cidr.split("/")[0]),
        ]

        self.harness.update_config(key_values={"access-ip": test_upf_access_ip_cidr})

        self.mock_publish_upf_n3_information.assert_has_calls(expected_calls)

    def test_given_fiveg_n3_relation_exists_when_access_ip_config_changed_to_invalid_cidr_then_new_upf_ip_address_is_not_published(  # noqa: E501
        self, set_can_connect_containers
    ):
        self.harness.handle_exec("bessd", [], result=0)
        self.mock_multus_is_ready.return_value = True
        n3_relation_id = self.add_fiveg_n3_relation()

        invalid_test_upf_access_ip_cidr = "1111.2.3.4/21"
        self.harness.update_config(key_values={"access-ip": invalid_test_upf_access_ip_cidr})

        self.mock_publish_upf_n3_information.assert_called_once_with(
            relation_id=n3_relation_id, upf_ip_address="192.168.252.3"
        )

    def test_given_unit_is_not_leader_when_fiveg_n4_request_then_upf_hostname_is_not_published(
        self,
    ):
        self.harness.set_leader(is_leader=False)
        test_external_upf_hostname = "test-upf.external.hostname.com"
        self.harness.update_config(
            key_values={"external-upf-hostname": test_external_upf_hostname}
        )

        self.add_fiveg_n4_relation()

        self.mock_publish_upf_n4_information.assert_not_called()

    def test_given_external_upf_hostname_config_set_and_fiveg_n4_relation_created_when_fiveg_n4_request_then_upf_hostname_and_n4_port_is_published(  # noqa: E501
        self,
    ):
        test_external_upf_hostname = "test-upf.external.hostname.com"
        self.harness.update_config(
            key_values={"external-upf-hostname": test_external_upf_hostname}
        )

        n4_relation_id = self.add_fiveg_n4_relation()

        self.mock_publish_upf_n4_information.assert_called_once_with(
            relation_id=n4_relation_id,
            upf_hostname=test_external_upf_hostname,
            upf_n4_port=TEST_PFCP_PORT,
        )

    def test_given_external_upf_hostname_config_not_set_but_external_upf_service_hostname_available_and_fiveg_n4_relation_created_when_fiveg_n4_request_then_upf_hostname_and_n4_port_is_published(  # noqa: E501
        self,
    ):
        test_external_upf_service_hostname = "test-upf.external.service.hostname.com"
        self.mock_k8s_service_get_hostname.return_value = test_external_upf_service_hostname

        n4_relation_id = self.add_fiveg_n4_relation()

        self.mock_publish_upf_n4_information.assert_called_once_with(
            relation_id=n4_relation_id,
            upf_hostname=test_external_upf_service_hostname,
            upf_n4_port=TEST_PFCP_PORT,
        )

    def test_given_external_upf_hostname_config_not_set_and_external_upf_service_hostname_not_available_and_fiveg_n4_relation_created_when_fiveg_n4_request_then_upf_hostname_and_n4_port_is_published(  # noqa: E501
        self,
    ):
        self.mock_k8s_service_get_hostname.return_value = None

        n4_relation_id = self.add_fiveg_n4_relation()

        self.mock_publish_upf_n4_information.assert_called_once_with(
            relation_id=n4_relation_id,
            upf_hostname=f"{self.harness.charm.app.name}-external.{NAMESPACE}"
            ".svc.cluster.local",
            upf_n4_port=TEST_PFCP_PORT,
        )

    def test_given_fiveg_n4_relation_exists_when_external_upf_hostname_config_changed_then_new_upf_hostname_is_published(  # noqa: E501
        self, set_can_connect_containers
    ):
        self.harness.handle_exec("bessd", [], result=0)
        test_external_upf_hostname = "test-upf.external.hostname.com"
        self.mock_multus_is_ready.return_value = True
        self.mock_huge_pages_is_enabled.return_value = True
        self.harness.update_config(key_values={"external-upf-hostname": "whatever.com"})
        n4_relation_id = self.add_fiveg_n4_relation()

        self.harness.update_config(
            key_values={"external-upf-hostname": test_external_upf_hostname}
        )

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
        self.mock_publish_upf_n4_information.assert_has_calls(expected_calls)

    def test_given_default_config_when_network_attachment_definitions_from_config_is_called_then_no_interface_specified_in_nad(  # noqa: E501
        self,
    ):
        self.mock_huge_pages_is_enabled.return_value = True
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
            assert nad.spec
            config = json.loads(nad.spec["config"])
            assert "master" not in config
            assert "bridge" == config["type"]
            assert config["bridge"] in ("core-br", "access-br")

    def test_given_upf_configured_to_run_in_dpdk_mode_when_create_network_attachment_definitions_then_2_nads_are_returned(  # noqa: E501
        self, set_can_connect_containers, enable_huge_pages_multus_and_dpdk
    ):
        self.mock_running_service()
        self.mock_client_list.side_effect = [
            [Node(status=NodeStatus(allocatable={"hugepages-1Gi": "3Gi"}))],
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

        create_nad_calls = self.mock_client_create.call_args_list
        assert len(create_nad_calls) == 2

    def test_given_upf_configured_to_run_in_dpdk_mode_when_create_network_attachment_definitions_then_nad_type_is_vfioveth(  # noqa: E501
        self, set_can_connect_containers, enable_huge_pages_multus_and_dpdk
    ):
        self.mock_running_service()
        self.mock_client_list.side_effect = [
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

        create_nad_calls = self.mock_client_create.call_args_list
        for create_nad_call in create_nad_calls:
            create_nad_call_args = next(
                iter(filter(lambda call_item: isinstance(call_item, dict), create_nad_call))
            )
            nad_config = json.loads(create_nad_call_args.get("obj").spec.get("config"))
            assert nad_config["type"] == "vfioveth"

    def test_given_upf_configured_to_run_in_dpdk_mode_when_create_network_attachment_definitions_then_access_nad_has_valid_dpdk_access_resource_specified_in_annotations(  # noqa: E501
        self, set_can_connect_containers, enable_huge_pages_multus_and_dpdk
    ):
        self.mock_running_service()
        self.mock_client_list.side_effect = [
            [Node(status=NodeStatus(allocatable={"hugepages-1Gi": "3Gi"}))],
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
                        and call_item.get("obj").metadata.name  # type: ignore
                        == ACCESS_NETWORK_ATTACHMENT_DEFINITION_NAME,
                        mock_call,
                    )
                ),
                None,
            )

        create_nad_calls = self.mock_client_create.mock_calls
        create_access_nad_calls = [
            _get_create_access_nad_call(create_nad_call)
            for create_nad_call in create_nad_calls
            if _get_create_access_nad_call(create_nad_call)
        ]
        assert len(create_access_nad_calls) == 1
        assert create_access_nad_calls[0]
        nad_annotations = create_access_nad_calls[0].get("obj").metadata.annotations
        assert (
            DPDK_ACCESS_INTERFACE_RESOURCE_NAME
            in nad_annotations["k8s.v1.cni.cncf.io/resourceName"]
        )

    def test_given_upf_configured_to_run_in_dpdk_mode_when_create_network_attachment_definitions_then_core_nad_has_valid_dpdk_core_resource_specified_in_annotations(  # noqa: E501
        self, set_can_connect_containers, enable_huge_pages_multus_and_dpdk
    ):
        self.mock_running_service()
        self.mock_client_list.side_effect = [
            [Node(status=NodeStatus(allocatable={"hugepages-1Gi": "3Gi"}))],
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
                        and call_item.get("obj").metadata.name  # type: ignore
                        == CORE_NETWORK_ATTACHMENT_DEFINITION_NAME,
                        mock_call,
                    )
                ),
                None,
            )

        create_nad_calls = self.mock_client_create.mock_calls
        create_core_nad_calls = [
            _get_create_core_nad_call(create_nad_call)
            for create_nad_call in create_nad_calls
            if _get_create_core_nad_call(create_nad_call)
        ]
        assert len(create_core_nad_calls) == 1
        assert create_core_nad_calls[0]
        nad_annotations = create_core_nad_calls[0].get("obj").metadata.annotations
        assert (
            DPDK_CORE_INTERFACE_RESOURCE_NAME in nad_annotations["k8s.v1.cni.cncf.io/resourceName"]
        )

    def test_given_upf_configured_to_run_in_dpdk_mode_and_mtu_is_set_when_create_network_attachment_definitions_then_nads_have_mtu_specified(  # noqa: E501
        self, set_can_connect_containers, enable_huge_pages_multus_and_dpdk
    ):
        self.mock_running_service()
        self.mock_client_list.side_effect = [
            [Node(status=NodeStatus(allocatable={"hugepages-1Gi": "3Gi"}))],
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
                "access-interface-mtu-size": 9000,
                "core-interface-mtu-size": 9000,
            }
        )

        nads = self.harness.charm._network_attachment_definitions_from_config()
        for nad in nads:
            assert nad.spec
            config = json.loads(nad.spec["config"])
            assert "mtu" in config
            assert config["mtu"] == 9000

    def test_given_upf_charm_configured_to_run_in_default_mode_when_patch_statefulset_then_2_network_annotations_are_created(  # noqa: E501
        self, set_can_connect_containers, enable_huge_pages_multus_and_dpdk
    ):
        self.harness.handle_exec("bessd", [], result=0)
        self.mock_running_service()
        self.harness.update_config()
        patch_statefulset = self.mock_k8s_statefulset_patch.call_args_list[0]
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
        assert len(network_annotations) == 2

    def test_given_upf_charm_configured_to_run_in_default_mode_when_generate_network_annotations_is_called_then_access_network_annotation_created(  # noqa: E501
        self, set_can_connect_containers, enable_huge_pages_multus_and_dpdk
    ):
        self.harness.handle_exec("bessd", [], result=0)
        self.mock_running_service()
        self.harness.update_config()
        patch_statefulset = self.mock_k8s_statefulset_patch.call_args_list[0]
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
        assert access_network_annotation
        assert access_network_annotation.get("interface") == ACCESS_INTERFACE_NAME

    def test_given_upf_charm_configured_to_run_in_default_mode_when_generate_network_annotations_is_called_then_access_network_annotation_created_without_dpdk_specific_data(  # noqa: E501
        self, set_can_connect_containers, enable_huge_pages_multus_and_dpdk
    ):
        self.harness.handle_exec("bessd", [], result=0)
        self.mock_running_service()
        self.harness.update_config()
        patch_statefulset = self.mock_k8s_statefulset_patch.call_args_list[0]
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
        assert not access_network_annotation.get("mac")
        assert not access_network_annotation.get("ips")

    def test_given_upf_charm_configured_to_run_in_default_mode_when_generate_network_annotations_is_called_then_core_network_annotation_created(  # noqa: E501
        self, set_can_connect_containers, enable_huge_pages_multus_and_dpdk
    ):
        self.harness.handle_exec("bessd", [], result=0)
        self.mock_running_service()
        self.harness.update_config()
        patch_statefulset = self.mock_k8s_statefulset_patch.call_args_list[0]
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
        assert access_network_annotation
        assert access_network_annotation.get("interface") == CORE_INTERFACE_NAME

    def test_given_upf_charm_configured_to_run_in_default_mode_when_generate_network_annotations_is_called_then_core_network_annotation_created_without_dpdk_specific_data(  # noqa: E501
        self, set_can_connect_containers, enable_huge_pages_multus_and_dpdk
    ):
        self.harness.handle_exec("bessd", [], result=0)
        self.mock_running_service()
        self.harness.update_config()
        patch_statefulset = self.mock_k8s_statefulset_patch.call_args_list[0]
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
        assert not access_network_annotation.get("mac")
        assert not access_network_annotation.get("ips")

    def test_given_upf_charm_configured_to_run_in_dpdk_mode_when_patch_statefulset_then_2_network_annotations_are_created(  # noqa: E501
        self, set_can_connect_containers, enable_huge_pages_multus_and_dpdk
    ):
        self.harness.handle_exec("bessd", [], result=0)
        self.mock_running_service()
        self.mock_client_list.side_effect = [
            [Node(status=NodeStatus(allocatable={"hugepages-1Gi": "3Gi"}))],
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
        patch_statefulset = self.mock_k8s_statefulset_patch.call_args_list[0]
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
        assert len(network_annotations) == 2

    def test_given_upf_charm_configured_to_run_in_dpdk_mode_when_generate_network_annotations_is_called_then_access_network_annotation_created(  # noqa: E501
        self, set_can_connect_containers, enable_huge_pages_multus_and_dpdk
    ):
        self.harness.handle_exec("bessd", [], result=0)
        self.mock_running_service()
        self.mock_client_list.side_effect = [
            [Node(status=NodeStatus(allocatable={"hugepages-1Gi": "3Gi"}))],
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
        patch_statefulset = self.mock_k8s_statefulset_patch.call_args_list[0]
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
        assert access_network_annotation
        assert access_network_annotation.get("interface") == ACCESS_INTERFACE_NAME
        assert access_network_annotation.get("mac") == VALID_ACCESS_MAC
        assert access_network_annotation.get("ips") == [VALID_ACCESS_IP]

    def test_given_upf_charm_configured_to_run_in_dpdk_mode_when_generate_network_annotations_is_called_then_core_network_annotation_created(  # noqa: E501
        self, set_can_connect_containers, enable_huge_pages_multus_and_dpdk
    ):
        self.harness.handle_exec("bessd", [], result=0)
        self.mock_running_service()
        self.mock_client_list.side_effect = [
            [Node(status=NodeStatus(allocatable={"hugepages-1Gi": "3Gi"}))],
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
        patch_statefulset = self.mock_k8s_statefulset_patch.call_args_list[0]
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
        assert access_network_annotation
        assert access_network_annotation.get("interface") == CORE_INTERFACE_NAME
        assert access_network_annotation.get("mac") == VALID_CORE_MAC
        assert access_network_annotation.get("ips") == [VALID_CORE_IP]

    def test_given_cpu_not_supporting_required_instructions_on_collect_status_then_goes_to_blocked_status(  # noqa: E501
        self,
    ):
        mock_cpu_info = TestCharm.patcher_check_output.start()
        mock_cpu_info.return_value = b"Flags: ssse3 fma cx16 rdrand"

        self.harness.evaluate_status()

        assert self.harness.model.unit.status == BlockedStatus(
            "CPU is not compatible, see logs for more details"
        )

    def test_given_cpu_supporting_required_instructions_when_install_then_charm_goes_to_maintenance_status(  # noqa: E501
        self,
    ):
        mock_cpu_info = TestCharm.patcher_check_output.start()
        mock_cpu_info.return_value = b"Flags: avx2 ssse3 fma cx16 rdrand"

        self.harness.charm.on.install.emit()

        assert self.harness.model.unit.status == MaintenanceStatus()

    def test_given_external_k8s_service_not_created_when_config_changed_then_is_created(self):
        self.mock_k8s_service_is_created.return_value = False
        self.harness.update_config()

        self.mock_k8s_service_create.assert_called_once()

    def test_given_service_exists_on_remove_then_external_service_is_deleted(self):
        self.mock_k8s_service_is_created.return_value = True
        self.harness.charm.on.remove.emit()

        self.mock_k8s_service_delete.assert_called_once()

    def test_given_service_does_not_exist_on_remove_then_service_not_deleted(self):
        self.mock_k8s_service_is_created.return_value = False
        self.harness.charm.on.remove.emit()

        self.mock_k8s_service_delete.assert_not_called()

    def test_given_default_config_when_create_network_attachment_definitions_then_interface_mtu_not_set_in_the_network_attachment_definitions(  # noqa: E501
        self, enable_huge_pages_multus_and_dpdk
    ):
        self.mock_running_service()
        self.harness.update_config(
            key_values={
                "access-ip": DEFAULT_ACCESS_IP,
                "access-gateway-ip": ACCESS_GW_IP,
                "gnb-subnet": GNB_SUBNET,
                "core-ip": VALID_CORE_IP,
                "core-gateway-ip": CORE_GW_IP,
            }
        )

        create_nad_calls = self.mock_client_create.call_args_list
        for create_nad_call in create_nad_calls:
            create_nad_call_args = next(
                iter(filter(lambda call_item: isinstance(call_item, dict), create_nad_call))
            )
            nad_config = json.loads(create_nad_call_args.get("obj").spec.get("config"))
            assert "mtu" not in nad_config

    def test_given_cpu_supporting_required_hugepages_instructions_when_hugepages_enabled_then_charm_goes_to_waiting_status(  # noqa: E501
        self,
    ):
        self.mock_dpdk_is_configured.return_value = True
        self.mock_huge_pages_is_enabled.return_value = True
        self.mock_cpu_info = TestCharm.patcher_check_output.start()
        self.mock_cpu_info.return_value = b"Flags: avx2 ssse3 fma cx16 rdrand pdpe1gb"
        self.mock_client_list.side_effect = [
            [Node(status=NodeStatus(allocatable={"hugepages-1Gi": "3Gi"}))],
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

        assert self.harness.model.unit.status == WaitingStatus(
            "Waiting for bessd container to be ready"
        )

    def test_given_cpu_supporting_required_hugepages_instructions_and_not_available_hugepages_when_hugepages_enabled_then_charm_goes_to_blocked_status(  # noqa: E501
        self,
    ):
        self.mock_huge_pages_is_enabled.return_value = False
        self.mock_cpu_info = TestCharm.patcher_check_output.start()
        self.mock_cpu_info.return_value = b"Flags: avx2 ssse3 fma cx16 rdrand pdpe1gb"
        self.mock_client_list.return_value = [
            Node(status=NodeStatus(allocatable={"hugepages-1Gi": "1Gi"}))
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

        assert self.harness.model.unit.status == BlockedStatus("Not enough HugePages available")

    def test_given_hugepages_not_available_then_hugepages_available_when_update_status_then_charm_goes_to_waiting_status(  # noqa: E501
        self,
    ):
        self.mock_dpdk_is_configured.return_value = True
        self.mock_huge_pages_is_enabled.return_value = True
        self.mock_cpu_info = TestCharm.patcher_check_output.start()
        self.mock_cpu_info.return_value = b"Flags: avx2 ssse3 fma cx16 rdrand pdpe1gb"
        self.mock_client_list.side_effect = [
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

        assert self.harness.model.unit.status == BlockedStatus("Not enough HugePages available")

        self.harness.charm.on.update_status.emit()
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == WaitingStatus(
            "Waiting for bessd container to be ready"
        )

    def test_given_multus_disabled_when_collect_status_then_status_is_blocked(self):
        mock_multus = patch(f"{MULTUS_LIBRARY}.multus_is_available").start()
        mock_multus.return_value = False
        self.mock_cpu_info = TestCharm.patcher_check_output.start()
        self.mock_huge_pages_is_enabled.return_value = True
        self.mock_cpu_info.return_value = b"Flags: avx2 ssse3 fma cx16 rdrand pdpe1gb"

        self.harness.evaluate_status()

        assert self.harness.model.unit.status == BlockedStatus(
            "Multus is not installed or enabled"
        )

    def test_given_default_config_when_network_attachment_definitions_from_config_is_called_then_no_interface_mtu_specified_in_nad(  # noqa: E501
        self,
    ):
        self.mock_huge_pages_is_enabled.return_value = True
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
            assert nad.spec
            config = json.loads(nad.spec["config"])
            assert "mtu" not in config

    def test_given_default_config_with_interfaces_mtu_sizes_when_create_network_attachment_definitions_then_interface_mtu_set_in_the_network_attachment_definitions(  # noqa: E501
        self, enable_huge_pages_multus_and_dpdk
    ):
        self.mock_running_service()
        self.harness.update_config(
            key_values={
                "access-ip": DEFAULT_ACCESS_IP,
                "access-gateway-ip": ACCESS_GW_IP,
                "access-interface-mtu-size": VALID_MTU_SIZE_1,
                "gnb-subnet": GNB_SUBNET,
                "core-ip": VALID_CORE_IP,
                "core-gateway-ip": CORE_GW_IP,
                "core-interface-mtu-size": VALID_MTU_SIZE_1,
            }
        )

        create_nad_calls = self.mock_client_create.call_args_list
        for create_nad_call in create_nad_calls:
            create_nad_call_args = next(
                iter(filter(lambda call_item: isinstance(call_item, dict), create_nad_call))
            )
            nad_config = json.loads(create_nad_call_args.get("obj").spec.get("config"))
            assert nad_config["mtu"] == VALID_MTU_SIZE_1

    def test_given_container_can_connect_bessd_pebble_ready_when_core_net_mtu_config_changed_to_a_different_valid_value_then_delete_pod_is_called(  # noqa: E501
        self, set_can_connect_containers
    ):
        mock_list_na_definitions = TestCharm.patcher_list_na_definitions.start()
        mock_delete_pod = TestCharm.patcher_delete_pod.start()
        self.harness.handle_exec("bessd", [], result=0)
        self.mock_huge_pages_is_enabled.return_value = True
        self.mock_multus_is_ready.return_value = True
        original_nads = self.harness.charm._network_attachment_definitions_from_config()
        set_nad_metadata_labels(original_nads, self.harness.charm.app.name)
        mock_list_na_definitions.return_value = original_nads

        self.harness.update_config(key_values={"core-interface-mtu-size": VALID_MTU_SIZE_1})

        mock_delete_pod.assert_called_once()

    def test_given_container_can_connect_bessd_pebble_ready_when_core_net_mtu_config_changed_to_different_valid_values_then_delete_pod_called_twice(  # noqa: E501
        self, set_can_connect_containers
    ):
        mock_list_na_definitions = TestCharm.patcher_list_na_definitions.start()
        mock_delete_pod = TestCharm.patcher_delete_pod.start()
        self.harness.handle_exec("bessd", [], result=0)
        self.mock_huge_pages_is_enabled.return_value = True
        self.mock_multus_is_ready.return_value = True
        original_nads = self.harness.charm._network_attachment_definitions_from_config()
        set_nad_metadata_labels(original_nads, self.harness.charm.app.name)
        mock_list_na_definitions.return_value = original_nads
        self.harness.update_config(key_values={"core-interface-mtu-size": VALID_MTU_SIZE_1})
        modified_nads = self.harness.charm._network_attachment_definitions_from_config()
        set_nad_metadata_labels(modified_nads, self.harness.charm.app.name)
        mock_list_na_definitions.return_value = modified_nads
        self.harness.update_config(key_values={"core-interface-mtu-size": VALID_MTU_SIZE_2})
        assert mock_delete_pod.call_count == 2

    def test_given_container_can_connect_bessd_pebble_ready_when_core_net_mtu_config_changed_to_same_valid_value_multiple_times_then_delete_pod_called_once(  # noqa: E501
        self, set_can_connect_containers
    ):
        mock_list_na_definitions = TestCharm.patcher_list_na_definitions.start()
        mock_delete_pod = TestCharm.patcher_delete_pod.start()
        self.harness.handle_exec("bessd", [], result=0)
        """Delete pod is called for the first config change, setting the same config value does not trigger pod restarts."""  # noqa: E501, W505
        self.mock_huge_pages_is_enabled.return_value = True
        self.mock_multus_is_ready.return_value = True
        original_nads = self.harness.charm._network_attachment_definitions_from_config()
        set_nad_metadata_labels(original_nads, self.harness.charm.app.name)
        mock_list_na_definitions.return_value = original_nads
        self.harness.update_config(key_values={"core-interface-mtu-size": VALID_MTU_SIZE_2})
        mock_delete_pod.assert_called_once()
        nads_after_first_config_change = (
            self.harness.charm._network_attachment_definitions_from_config()
        )
        set_nad_metadata_labels(nads_after_first_config_change, self.harness.charm.app.name)
        mock_list_na_definitions.return_value = nads_after_first_config_change
        self.harness.update_config(key_values={"core-interface-mtu-size": VALID_MTU_SIZE_2})
        mock_delete_pod.assert_called_once()
        nads_after_second_config_change = (
            self.harness.charm._network_attachment_definitions_from_config()
        )
        set_nad_metadata_labels(nads_after_second_config_change, self.harness.charm.app.name)
        for nad in nads_after_second_config_change:
            assert nad.metadata
            nad.metadata.labels = {"app.juju.is/created-by": self.harness.charm.app.name}
        mock_list_na_definitions.return_value = nads_after_second_config_change
        self.harness.update_config(key_values={"core-interface-mtu-size": VALID_MTU_SIZE_2})
        mock_delete_pod.assert_called_once()

    def test_given_hardware_checksum_is_disabled_when_value_changes_then_delete_pod_is_called_once(  # noqa: E501
        self, set_can_connect_containers
    ):
        self.harness.handle_exec("bessd", [], result=0)
        self.mock_huge_pages_is_enabled.return_value = True
        self.mock_multus_is_ready.return_value = True
        self.harness.update_config(key_values={"enable-hw-checksum": False})
        self.mock_client_delete.assert_called_once()

    def test_given_no_workload_version_file_when_container_can_connect_then_workload_version_not_set(  # noqa: E501
        self, set_can_connect_containers
    ):
        self.harness.handle_exec("bessd", [], result=0)
        self.harness.container_pebble_ready(container_name="bessd")
        self.harness.evaluate_status()
        version = self.harness.get_workload_version()
        assert version == ""

    def test_given_workload_version_file_when_container_can_connect_then_workload_version_set(
        self, set_can_connect_containers
    ):
        self.harness.handle_exec("bessd", [], result=0)
        expected_version = "1.2.3"
        root = self.harness.get_filesystem_root("bessd")
        (root / "etc/workload-version").write_text(expected_version)
        self.harness.container_pebble_ready(container_name="bessd")
        self.harness.evaluate_status()
        version = self.harness.get_workload_version()
        assert version == expected_version
