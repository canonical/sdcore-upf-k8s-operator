original_core_net_config = '{"cniVersion": "0.3.1", "ipam": {"type": "static", "addresses": [{"address": "192.168.250.3/24"}]}, "capabilities": {"mac": true}, "mtu": 1800, "type": "bridge", "bridge": "core-br"}'  # noqa: E501
modified_core_net_config = '{"cniVersion": "0.3.1", "ipam": {"type": "static", "addresses": [{"address": "192.168.250.3/24"}]}, "capabilities": {"mac": true}, "mtu": 9000, "type": "bridge", "bridge": "core-br"}'  # noqa: E501
access_net_config = '{"cniVersion": "0.3.1", "ipam": {"type": "static", "routes": [{"dst": "192.168.251.0/24", "gw": "192.168.252.1"}], "addresses": [{"address": "192.168.252.3/24"}]}, "capabilities": {"mac": true}, "type": "bridge", "bridge": "access-br"}'  # noqa: E501
access_nad = {
    "apiVersion": "k8s.cni.cncf.io/v1",
    "kind": "NetworkAttachmentDefinition",
    "metadata": {
        "name": "access-net",
    },
    "spec": {"config": access_net_config},
}
original_core_nad = {
    "apiVersion": "k8s.cni.cncf.io/v1",
    "kind": "NetworkAttachmentDefinition",
    "metadata": {
        "name": "core-net",
    },
    "spec": {
        "config": original_core_net_config,
    },
}
modified_core_nad = {
    "apiVersion": "k8s.cni.cncf.io/v1",
    "kind": "NetworkAttachmentDefinition",
    "metadata": {
        "name": "core-net",
    },
    "spec": {
        "config": modified_core_net_config,
    },
}
original_nad_descriptions = [
    access_nad,
    original_core_nad,
]
modified_nad_descriptions = [
    access_nad,
    modified_core_nad,
]
