# sdcore-upf-operator

Charmed Operator for SDCORE's User Plane Function (UPF).


## Pre-requisites

Kubernetes cluster with Multus.

## Usage

```bash
juju deploy upf-operator --trust --channel=edge
```

## Image

- **bessd**: omecproject/upf-epc-bess:master-d1af749
- **routectl**: omecproject/upf-epc-bess:master-d1af749
- **web**: omecproject/upf-epc-bess:master-d1af749
- **pfcp-agent**: omecproject/upf-epc-pfcpiface:master-d1af749
