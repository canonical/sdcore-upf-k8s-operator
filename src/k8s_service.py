#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""A class to manage the external UPF service."""

import logging
from typing import Optional

from lightkube.models.core_v1 import ServicePort, ServiceSpec
from lightkube.models.meta_v1 import ObjectMeta
from lightkube.resources.core_v1 import Service

from k8s_client import K8sClient, K8sClientError

logger = logging.getLogger(__name__)


class K8sServiceError(Exception):
    """K8sServiceError."""

    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)


class K8sService:
    """A class to manage the external UPF service."""

    def __init__(self, namespace: str, service_name: str, app_name: str, pfcp_port: int):
        self.namespace = namespace
        self.service_name = service_name
        self.app_name = app_name
        self.pfcp_port = pfcp_port
        self.client = K8sClient()

    def create(self) -> None:
        """Create the external UPF service."""
        service = Service(
            apiVersion="v1",
            kind="Service",
            metadata=ObjectMeta(
                namespace=self.namespace,
                name=self.service_name,
                labels={
                    "app.kubernetes.io/name": self.app_name,
                },
            ),
            spec=ServiceSpec(
                selector={
                    "app.kubernetes.io/name": self.app_name,
                },
                ports=[
                    ServicePort(name="pfcp", port=self.pfcp_port, protocol="UDP"),
                ],
                type="LoadBalancer",
            ),
        )
        try:
            self.client.apply(service, field_manager=self.app_name)
            logger.info("Created/asserted existence of the external UPF service")
        except K8sClientError as e:
            raise K8sServiceError(f"Could not create UPF service due to: {e.message}")

    def is_created(self) -> bool:
        """Check if the external UPF service exists."""
        if self.client.get(Service, name=self.service_name, namespace=self.namespace):
            return True
        return False

    def delete(self) -> None:
        """Delete the external UPF service."""
        try:
            self.client.delete(
                Service,
                name=self.service_name,
                namespace=self.namespace,
            )
            logger.info("Deleted external UPF service")
        except K8sClientError as e:
            logger.warning("Could not delete %s due to: %s", self.service_name, e.message)

    def get_hostname(self) -> Optional[str]:
        """Get the hostname of the external UPF service."""
        service = self.client.get(Service, name=self.service_name, namespace=self.namespace)
        if not service.status:
            return None
        if not service.status.loadBalancer:
            return None
        if not service.status.loadBalancer.ingress:
            return None
        return service.status.loadBalancer.ingress[0].hostname
