#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Module wrapping the default Lightkube Client, to automatically handle 401 Unauthorized.

To use Kubernetes Client from this module in your code:
1. Import K8sClient:
    `from k8s_client import K8sClient`
2. Initialize K8sClient:
    `kubernetes_client = K8sClient()`
"""

import functools
import logging
import types

from lightkube.core.client import Client
from lightkube.core.exceptions import ApiError

logger = logging.getLogger(__name__)


class K8sClientError(Exception):
    """K8sClientError."""

    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)


def try_except_all(func):
    """Wrap Lightkube Client calls with try-except block."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except ApiError as e:
            if e.status.code == 401:
                logger.warning("kube-apiserver not ready yet")
            elif e.status.code == 404:
                logger.warning("Requested Kubernetes resource not found")
            else:
                raise K8sClientError(
                    f"Could not perform requested Kubernetes call due to: {e.status.message}"
                )
        return None

    return wrapper


class MetaClass(type):
    """Metaclass applying a custom wrapper on the base class' functions."""

    def __new__(meta, class_name, base_classes, class_dict):  # noqa: N804
        """See if any of the base classes were created by with_metaclass() function."""
        marker = None
        for base in base_classes:
            if hasattr(base, "_marker"):
                marker = getattr(base, "_marker")
                break

        if class_name == marker:
            return type.__new__(meta, class_name, base_classes, class_dict)

        temp_class = type.__new__(meta, "TempClass", base_classes, class_dict)

        new_class_dict = {}
        for cls in temp_class.mro():
            for attribute_name, attribute_type in cls.__dict__.items():
                if isinstance(attribute_type, types.FunctionType):
                    attribute_type = try_except_all(attribute_type)
                    new_class_dict[attribute_name] = attribute_type

        return type.__new__(meta, class_name, base_classes, new_class_dict)


def with_metaclass(meta, classname, bases):
    """Create a class with the supplied bases and metaclass."""
    return type.__new__(meta, classname, bases, {"_marker": classname})


class K8sClient(with_metaclass(MetaClass, "WrappedK8sClient", (Client, object))):
    """Custom K8s client automatically catching 401 Unauthorized error."""

    pass
