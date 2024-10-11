# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


import pytest
from charms.sdcore_upf_k8s.v0.fiveg_n3 import FiveGN3RequestEvent, N3Provides
from ops import testing
from ops.charm import ActionEvent, CharmBase


class N3Provider(CharmBase):
    def __init__(self, *args):
        super().__init__(*args)
        self.fiveg_n3_provider = N3Provides(self, "fiveg_n3")
        self.framework.observe(
            self.on.publish_upf_information_action,
            self._on_publish_upf_information_action,
        )

    def _on_publish_upf_information_action(self, event: ActionEvent):
        upf_ip_address = event.params.get("ip-address")
        relation_id = event.params.get("relation-id")
        assert upf_ip_address
        assert relation_id
        self.fiveg_n3_provider.publish_upf_information(
            upf_ip_address=upf_ip_address,
            relation_id=int(relation_id),
        )


class TestN3Provides:
    @pytest.fixture(autouse=True)
    def context(self):
        self.ctx = testing.Context(
            charm_type=N3Provider,
            meta={
                "name": "n3-provider",
                "provides": {"fiveg_n3": {"interface": "fiveg_n3"}},
            },
            actions={
                "publish-upf-information": {
                    "params": {
                        "ip-address": {"type": "string"},
                        "relation-id": {"type": "string"},
                    },
                },
            },
        )

    def test_given_fiveg_n3_relation_when_set_upf_information_then_info_added_to_relation_data(  # noqa: E501
        self,
    ):
        fiveg_n3_relation = testing.Relation(
            endpoint="fiveg_n3",
            interface="fiveg_n3",
        )
        state_in = testing.State(
            leader=True,
            relations=[fiveg_n3_relation],
        )

        params = {
            "ip-address": "1.2.3.4",
            "relation-id": str(fiveg_n3_relation.id),
        }

        state_out = self.ctx.run(
            self.ctx.on.action("publish-upf-information", params=params), state_in
        )

        relation = state_out.get_relation(fiveg_n3_relation.id)
        assert relation.local_app_data["upf_ip_address"] == "1.2.3.4"

    def test_given_invalid_upf_information_when_set_upf_information_then_error_raised(
        self,
    ):
        fiveg_n3_relation = testing.Relation(
            endpoint="fiveg_n3",
            interface="fiveg_n3",
        )
        state_in = testing.State(
            leader=True,
            relations=[fiveg_n3_relation],
        )

        params = {
            "ip-address": "abcdef",
            "relation-id": str(fiveg_n3_relation.id),
        }

        with pytest.raises(Exception) as e:
            self.ctx.run(self.ctx.on.action("publish-upf-information", params=params), state_in)

        assert "Invalid UPF IP address" in str(e.value)

    def test_given_when_relation_joined_then_fiveg_n3_request_event_emitted(
        self,
    ):
        fiveg_n3_relation = testing.Relation(
            endpoint="fiveg_n3",
            interface="fiveg_n3",
        )
        state_in = testing.State(
            leader=True,
            relations=[fiveg_n3_relation],
        )

        self.ctx.run(self.ctx.on.relation_joined(fiveg_n3_relation), state_in)

        assert len(self.ctx.emitted_events) == 2
        assert isinstance(self.ctx.emitted_events[1], FiveGN3RequestEvent)
