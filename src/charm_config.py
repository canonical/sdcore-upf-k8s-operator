# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Config of the Charm."""

import dataclasses
import logging
from enum import Enum
from ipaddress import IPv4Network, IPv6Network
from typing import Optional

import ops
from pydantic import (  # pylint: disable=no-name-in-module,import-error
    BaseModel,
    ConfigDict,
    Field,
    StrictStr,
    ValidationError,
)
from pydantic.functional_validators import model_validator
from pydantic.networks import IPvAnyAddress, IPvAnyNetwork
from pydantic_core import PydanticCustomError
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


NetworkType: TypeAlias = "str | bytes | int | tuple[str | bytes | int, str | int]"


class LaxIPvAnyNetwork(IPvAnyNetwork):
    """Validate an IPv4 or IPv6 network."""

    def __new__(cls, value: NetworkType):
        """Validate an IPv4 or IPv6 network."""
        # Assume IP Network is defined with a default value for `strict` argument.
        # Define your own class if you want to specify network address check strictness.
        try:
            return IPv4Network(value, strict=False)
        except ValueError:
            pass

        try:
            return IPv6Network(value, strict=False)
        except ValueError:
            raise PydanticCustomError(
                "ip_any_network", "value is not a valid IPv4 or IPv6 network"
            )


class CharmConfigInvalidError(Exception):
    """Exception raised when a charm configuration is found to be invalid."""

    def __init__(self, msg: str):
        """Initialize a new instance of the CharmConfigInvalidError exception.

        Args:
            msg (str): Explanation of the error.
        """
        self.msg = msg


def to_kebab(name: str) -> str:
    """Converts a snake_case string to kebab-case."""
    return name.replace("_", "-")


class UpfConfig(BaseModel):  # pylint: disable=too-few-public-methods
    """Represent UPF operator builtin configuration values."""

    model_config = ConfigDict(alias_generator=to_kebab, use_enum_values=True)

    cni_type: CNIType = CNIType.bridge
    upf_mode: UpfMode = UpfMode.af_packet
    dnn: StrictStr = Field(default="internet", min_length=1)
    gnb_subnet: LaxIPvAnyNetwork = LaxIPvAnyNetwork("192.168.251.0/24")
    access_interface: Optional[StrictStr] = Field(default="")
    access_interface_mac_address: MacAddress = Field(default=None)
    access_ip: LaxIPvAnyNetwork = LaxIPvAnyNetwork("192.168.252.3/24")
    access_gateway_ip: IPvAnyAddress = IPvAnyAddress("192.168.252.1")
    access_interface_mtu_size: Optional[int] = Field(
        default=None, ge=1200, le=65535, validate_default=True
    )
    core_interface: Optional[StrictStr] = Field(default="")
    core_interface_mac_address: MacAddress = Field(default=None)
    core_ip: LaxIPvAnyNetwork = LaxIPvAnyNetwork("192.168.250.3/24")
    core_gateway_ip: IPvAnyAddress = IPvAnyAddress("192.168.250.1")
    core_interface_mtu_size: Optional[int] = Field(default=None, ge=1200, le=65535)
    external_upf_hostname: Optional[StrictStr] = Field(default="")
    vlan_id: Optional[int] = Field(default=None, ge=1, le=4095)
    enable_hw_checksum: bool = True

    @model_validator(mode="after")
    @classmethod
    def validate_upf_mode_with_mac_addresses(cls, values):
        """Validate that MAC addresses are defined when in DPDK mode."""
        if values.upf_mode == "dpdk":
            invalid_configs = []
            if not values.access_interface_mac_address:
                invalid_configs.append("access-interface-mac-address")
            if not values.core_interface_mac_address:
                invalid_configs.append("core-interface-mac-address")
            if invalid_configs:
                raise ValueError(" ".join(invalid_configs))
        return values


@dataclasses.dataclass(frozen=True)
class CharmConfig:
    """Config of the Charm."""

    upf_config: UpfConfig

    @classmethod
    def from_charm(
        cls,
        charm: ops.CharmBase,
    ) -> "CharmConfig":
        """Initialize a new instance of the CharmState class from the associated charm."""
        try:
            # ignoring because mypy fails with:
            # "has incompatible type "**dict[str, str]"; expected ...""
            valid_upf_config = UpfConfig(**dict(charm.config.items()))  # type: ignore
        except ValidationError as exc:
            error_fields: list = []
            for error in exc.errors():
                if param := error["loc"]:
                    error_fields.extend(param)
                else:
                    value_error_msg: ValueError = error["ctx"]["error"]
                    error_fields.extend(str(value_error_msg).split())
            error_fields.sort()
            error_field_str = ", ".join(f"'{f}'" for f in error_fields)
            raise CharmConfigInvalidError(
                f"The following configurations are not valid: [{error_field_str}]"
            ) from exc

        return cls(upf_config=valid_upf_config)
