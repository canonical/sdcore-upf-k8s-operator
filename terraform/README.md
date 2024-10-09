# SD-Core UPF K8s Terraform Module

This folder contains a base [Terraform][Terraform] module for the sdcore-gnbsim-k8s charm.

The module uses the [Terraform Juju provider][Terraform Juju provider] to model the charm
deployment onto any Kubernetes environment managed by [Juju][Juju].

The module can be used to deploy the UPF separately as well as a part of a higher level module,
depending on the deployment architecture.

## Module structure

- **main.tf** - Defines the Juju application to be deployed.
- **variables.tf** - Allows customization of the deployment. Except for exposing the deployment
  options (Juju model name, channel or application name) also allows overwriting charm's default
  configuration.
- **output.tf** - Responsible for integrating the module with other Terraform modules, primarily
  by defining potential integration endpoints (charm integrations), but also by exposing
  the application name.
- **versions.tf** - Defines the Terraform provider.

## Deploying sdcore-upf-k8s base module separately

### Pre-requisites

- A Kubernetes host with a CPU supporting AVX2 and RDRAND instructions (Intel Haswell, AMD Excavator or equivalent)
- A Kubernetes cluster with the Multus addon enabled.
- Juju 3.x
- Juju controller bootstrapped onto the K8s cluster
- Terraform

### Deploying UPF with Terraform

Clone the `sdcore-upf-k8s-operator` Git repository.

From inside the `terraform` folder, initialize the provider:

```shell
terraform init
```

Create Terraform plan:

```shell
terraform plan
```

While creating the plan, the default configuration can be overwritten with `-var-file`. To do that,
Terraform `tfvars` file should be prepared prior to the plan creation.

Deploy UPF:

```console
terraform apply -auto-approve 
```

### Cleaning up

Destroy the deployment:

```shell
terraform destroy -auto-approve
```

## Using sdcore-upf-k8s base module in higher level modules

If you want to use `sdcore-upf-k8s` base module as part of your Terraform module, import it
like shown below:

```text
data "juju_model" "my_model" {
  name = "my_model_name"
}

module "upf" {
  source = "git::https://github.com/canonical/sdcore-upf-k8s-operator//terraform"
  
  model = juju_model.my_model.name
  config = Optional config map
}
```

Create integrations, for instance:

```text
resource "juju_integration" "upf-nms" {
  model = juju_model.my_model.name
  application {
    name     = module.upf.app_name
    endpoint = module.upf.provides.fiveg_n4
  }
  application {
    name     = module.nms.app_name
    endpoint = module.nms.requires.fiveg_n4
  }
}
```

The complete list of available integrations can be found [here][upf-integrations].

[Terraform]: https://www.terraform.io/
[Terraform Juju provider]: https://registry.terraform.io/providers/juju/juju/latest
[Juju]: https://juju.is
[upf-integrations]: https://charmhub.io/sdcore-upf-k8s/integrations
