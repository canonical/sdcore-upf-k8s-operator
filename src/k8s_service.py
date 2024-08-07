#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""A class to manage the external UPF service."""
import logging
from typing import Optional

from httpx import HTTPStatusError
from lightkube.core.client import Client
from lightkube.models.core_v1 import ServicePort, ServiceSpec
from lightkube.models.meta_v1 import ObjectMeta
from lightkube.resources.core_v1 import Service

logger = logging.getLogger(__name__)


class K8sService:
    """A class to manage the external UPF service."""
    def __init__(self, namespace: str, service_name: str, app_name: str, pfcp_port: int):
        self.namespace = namespace
        self.service_name = service_name
        self.app_name = app_name
        self.pfcp_port = pfcp_port
        self.client = Client()

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
        self.client.apply(service, field_manager=self.app_name)
        logger.info("Created/asserted existence of the external UPF service")

    def is_created(self) -> bool:
        """Check if the external UPF service exists."""
        try:
            self.client.get(Service, name=self.service_name, namespace=self.namespace)
            return True
        except HTTPStatusError as status:
            if status.response.status_code == 404:
                return False
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
        except HTTPStatusError as status:
            logger.info("Could not delete %s due to: %s", self.service_name, status)

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
