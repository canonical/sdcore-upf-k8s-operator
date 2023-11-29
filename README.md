# SD-Core UPF Operator (k8s)
[![CharmHub Badge](https://charmhub.io/sdcore-upf/badge.svg)](https://charmhub.io/sdcore-upf)

Charmed Operator for SD-Core's User Plane Function (UPF). For more information, read [here](https://github.com/omec-project/upf).

## Pre-requisites

A Kubernetes host with a CPU supporting AVX2 and RDRAND instructions (Intel Haswell, AMD Excavator or equivalent)

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

### Exposing the UPF externally

If a load balancer such as `metallb` is present, the charm will configure an externally accessible 
service port with the load balancer upon install of the charm.

### Running UPF in DPDK mode

By default, UPF runs in `af_packet` mode. To run UPF in `dpdk` mode, `upf-mode` config option 
should be used, i.e.:

```shell
juju deploy sdcore-upf --trust --channel=edge --config upf-mode="dpdk" --config enable-hugepages=True --config access-interface-mac-address="00:b0:d0:63:c2:26" --config core-interface-mac-address="00:b0:d0:63:c2:36"
```

As shown in the example above, when running UPF in `dpdk` mode, it is necessary to enable
HugePages and pass the MAC addresses of the `Access` and `Core` interfaces.

For detailed instructions on running UPF in `dpdk` mode please visit 
[How-to: Running UPF in DPDK mode](https://canonical-charmed-5g.readthedocs-hosted.com/en/latest/how-to/running_upf_in_dpdk_mode/).

## Image

- **bessd**: ghcr.io/canonical/sdcore-upf-bess:1.3
- **routectl**: ghcr.io/canonical/sdcore-upf-bess:1.3
- **pfcp-agent**: ghcr.io/canonical/sdcore-upf-pfcpiface:1.3
