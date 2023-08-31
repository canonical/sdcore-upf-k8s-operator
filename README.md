<div align="center">
  <img src="./icon.svg" alt="ONF Icon" width="200" height="200">
</div>
<br/>
<div align="center">
  <a href="https://charmhub.io/sdcore-upf"><img src="https://charmhub.io/sdcore-upf/badge.svg" alt="CharmHub Badge"></a>
  <a href="https://github.com/canonical/sdcore-upf-operator/actions/workflows/publish-charm.yaml">
    <img src="https://github.com/canonical/sdcore-upf-operator/actions/workflows/publish-charm.yaml/badge.svg?branch=main" alt=".github/workflows/publish-charm.yaml">
  </a>
  <br/>
  <br/>
  <h1>SD-Core UPF Operator</h1>
</div>

Charmed Operator for SD-Core's User Plane Function (UPF). For more information, read [here](https://github.com/omec-project/upf).

## Pre-requisites

A Kubernetes cluster with the Multus addon enabled.

## Usage

Enable the Multus addon on MicroK8s

```bash
sudo microk8s addons repo add community https://github.com/canonical/microk8s-community-addons --reference feat/strict-fix-multus
sudo microk8s enable multus
```

Create a Juju model:

```bash
juju add-model user-plane
```

Deploy the UPF:

```bash
juju deploy sdcore-upf --trust --channel=edge
```

## Image

- **bessd**: ghcr.io/canonical/sdcore-upf-bess:1.3
- **routectl**: ghcr.io/canonical/sdcore-upf-bess:1.3
- **pfcp-agent**: ghcr.io/canonical/sdcore-upf-pfcpiface:1.3
