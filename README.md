# sdcore-upf-operator

Charmed Operator for SDCORE's User Plane Function (UPF). For more information, read [here](https://github.com/omec-project/upf).

## Pre-requisites

A Kubernetes cluster with the Multus addon enabled.

## Usage

Enable the Multus addon on MicroK8s

```bash
microk8s enable community
microk8s enable multus
```

Create a Juju model:

```bash
juju add-model user-plane
```

Deploy the UPF:

```bash
juju deploy upf-operator --trust --channel=edge
```

## Image

- **bessd**: omecproject/upf-epc-bess:master-5786085
- **routectl**: omecproject/upf-epc-bess:master-5786085
- **web**: omecproject/upf-epc-bess:master-5786085
- **pfcp-agent**: omecproject/upf-epc-pfcpiface:master-5786085
