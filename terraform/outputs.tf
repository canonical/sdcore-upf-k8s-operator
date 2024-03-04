# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

output "app_name" {
  description = "Name of the deployed application."
  value       = juju_application.upf.name
}

# Provided integration endpoints

output "metrics_endpoint" {
  description = "Exposes the Prometheus metrics endpoint providing telemetry about the UPF instance."
  value       = "metrics-endpoint"
}

output "fiveg_n3_endpoint" {
  description = "Name of the endpoint used to provide information on connectivity to the N3 plane."
  value       = "fiveg_n3"
}

output "fiveg_n4_endpoint" {
  description = "Name of the endpoint used to provide information on connectivity to the N4 plane."
  value       = "fiveg_n4"
}

# Requires integration endpoints

output "logging_endpoint" {
  description = "Name of the endpoint used to integrate with the Logging provider."
  value       = "logging"
}
