# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Config of the Charm."""

import dataclasses
import logging
from enum import Enum
from ipaddress import IPv4Address, IPv4Network, ip_network
from typing import Optional

import ops
from pydantic import (  # pylint: disable=no-name-in-module,import-error
    BaseModel,
    ConfigDict,
    Field,
    StrictStr,
    ValidationError,
    ValidationInfo,
)
from pydantic.functional_validators import field_validator, model_validator
from pydantic.networks import IPvAnyNetwork
from pydantic_extra_types.mac_address import MacAddress
from typing_extensions import TypeAlias

logger = logging.getLogger(__name__)


class CNIType(str, Enum):
    """Class to define available CNI types for UPF operator."""

    bridge = "bridge"
    macvlan = "macvlan"
    host_device = "host-device"
    vfioveth = "vfioveth"


class UpfMode(str, Enum):
    """Class to define available UPF modes for UPF operator."""

    af_packet = "af_packet"
    dpdk = "dpdk"

class LogLevel(str, Enum):
    """Class to define available log levels for UPF operator."""

    DEBUG = "debug"
    INFO = "info"
    WARN = "warn"
    ERROR = "error"
    FATAL = "fatal"
    PANIC = "panic"

NetworkType: TypeAlias = "str | bytes | int | tuple[str | bytes | int, str | int]"


class CharmConfigInvalidError(Exception):
    """Exception raised when a charm configuration is found to be invalid."""

    def __init__(self, msg: str):
        """Initialize a new instance of the CharmConfigInvalidError exception.

        Args:
            msg (str): Explanation of the error.
        """
        self.msg = msg


def to_kebab(name: str) -> str:
    """Convert a snake_case string to kebab-case."""
    return name.replace("_", "-")


class UpfConfig(BaseModel):  # pylint: disable=too-few-public-methods
    """Represent UPF operator builtin configuration values."""

    model_config = ConfigDict(alias_generator=to_kebab, use_enum_values=True)

    cni_type: CNIType = CNIType.bridge
    upf_mode: UpfMode = UpfMode.af_packet
    dnn: StrictStr = Field(default="internet", min_length=1)
    gnb_subnet: IPvAnyNetwork = Field(default=IPv4Network("192.168.252.0/24"))
    access_interface: Optional[StrictStr] = Field(default="")
    access_interface_mac_address: Optional[StrictStr] = Field(default="")
    access_ip: str = Field(default="192.168.252.3/24")
    access_gateway_ip: IPv4Address = IPv4Address("192.168.252.1")
    access_interface_mtu_size: Optional[int] = Field(
        default=None, ge=1200, le=65535, validate_default=True
    )
    core_interface: Optional[StrictStr] = Field(default="")
    core_interface_mac_address: Optional[StrictStr] = Field(default="")
    core_ip: str = Field(default="192.168.250.3/24")
    core_gateway_ip: IPv4Address = IPv4Address("192.168.250.1")
    core_interface_mtu_size: Optional[int] = Field(default=None, ge=1200, le=65535)
    external_upf_hostname: Optional[StrictStr] = Field(default="")
    enable_hw_checksum: bool = True
    log_level: LogLevel = LogLevel.INFO

    @model_validator(mode="after")
    def validate_upf_mode_with_mac_addresses(self):
        """Validate that MAC addresses are defined when in DPDK mode."""
        if self.upf_mode == "dpdk":
            invalid_configs = []
            if not self.access_interface_mac_address:
                invalid_configs.append("access-interface-mac-address")
            if not self.core_interface_mac_address:
                invalid_configs.append("core-interface-mac-address")
            if invalid_configs:
                raise ValueError(" ".join(invalid_configs))
        return self

    @field_validator("access_ip", "core_ip", mode="before")
    @classmethod
    def validate_ip_network_address(cls, value: str, info: ValidationInfo) -> str:
        """Validate that IP network address is valid."""
        ip_network(value, strict=False)
        return value

    @field_validator("access_interface_mac_address", "core_interface_mac_address", mode="before")
    @classmethod
    def validate_interface_mac_address(cls, value: str, info: ValidationInfo) -> str:
        """Validate that IP network address is valid."""
        MacAddress.validate_mac_address(value.encode())
        return value


@dataclasses.dataclass
class CharmConfig:
    """Represents the state of the UPF operator charm.

    Attributes:
        cni_type: Multus CNI plugin to use for the interfaces.
        upf_mode: Either `af_packet` (default) or `dpdk`.
        dnn: Data Network Name (DNN).
        gnb_subnet: gNodeB subnet.
        access_interface: Interface on the host to use for the Access Network.
        access_interface_mac_address: MAC address of the UPF's Access interface.
        access_ip: IP address used by the UPF's Access interface.
        access_gateway_ip: Gateway IP address to the Access Network.
        access_interface_mtu_size: MTU for the access interface in bytes.
        core_interface: Interface on the host to use for the Core Network.
        core_interface_mac_address: MAC address of the UPF's Core interface.
        core_ip: IP address used by the UPF's Core interface.
        core_gateway_ip: Gateway IP address to the Core Network.
        core_interface_mtu_size: MTU for the core interface in bytes.
        external_upf_hostname: Externally accessible FQDN for the UPF.
        enable_hw_checksum: When enabled, hardware checksum will be used on the network interfaces.
    """

    cni_type: CNIType
    upf_mode: UpfMode
    dnn: StrictStr
    gnb_subnet: IPvAnyNetwork
    access_interface: Optional[StrictStr]
    access_interface_mac_address: Optional[StrictStr]
    access_ip: str
    access_gateway_ip: IPv4Address
    access_interface_mtu_size: Optional[int]
    core_interface: Optional[StrictStr]
    core_interface_mac_address: Optional[StrictStr]
    core_ip: str
    core_gateway_ip: IPv4Address
    core_interface_mtu_size: Optional[int]
    external_upf_hostname: Optional[StrictStr]
    enable_hw_checksum: bool
    log_level: LogLevel

    def __init__(self, *, upf_config: UpfConfig):
        """Initialize a new instance of the CharmConfig class.

        Args:
            upf_config: UPF operator configuration.
        """
        self.cni_type = upf_config.cni_type
        self.upf_mode = upf_config.upf_mode
        self.dnn = upf_config.dnn
        self.gnb_subnet = upf_config.gnb_subnet
        self.access_interface = upf_config.access_interface
        self.access_interface_mac_address = upf_config.access_interface_mac_address
        self.access_ip = upf_config.access_ip
        self.access_gateway_ip = upf_config.access_gateway_ip
        self.access_interface_mtu_size = upf_config.access_interface_mtu_size
        self.core_interface = upf_config.core_interface
        self.core_interface_mac_address = upf_config.core_interface_mac_address
        self.core_ip = upf_config.core_ip
        self.core_gateway_ip = upf_config.core_gateway_ip
        self.core_interface_mtu_size = upf_config.core_interface_mtu_size
        self.external_upf_hostname = upf_config.external_upf_hostname
        self.enable_hw_checksum = upf_config.enable_hw_checksum
        self.log_level = upf_config.log_level

    @classmethod
    def from_charm(
        cls,
        charm: ops.CharmBase,
    ) -> "CharmConfig":
        """Initialize a new instance of the CharmState class from the associated charm."""
        try:
            # ignoring because mypy fails with:
            # "has incompatible type "**dict[str, str]"; expected ...""
            return cls(upf_config=UpfConfig(**dict(charm.config.items())))  # type: ignore
        except ValidationError as exc:
            error_fields: list = []
            for error in exc.errors():
                if param := error["loc"]:
                    error_fields.extend(param)
                else:
                    value_error_msg: ValueError = error["ctx"]["error"]  # type: ignore
                    error_fields.extend(str(value_error_msg).split())
            error_fields.sort()
            error_field_str = ", ".join(f"'{f}'" for f in error_fields)
            raise CharmConfigInvalidError(
                f"The following configurations are not valid: [{error_field_str}]"
            ) from exc
