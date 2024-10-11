# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


import pytest
from charms.sdcore_upf_k8s.v0.fiveg_n4 import FiveGN4RequestEvent, N4Provides
from ops import testing
from ops.charm import ActionEvent, CharmBase


class N4Provider(CharmBase):
    def __init__(self, *args):
        super().__init__(*args)
        self.fiveg_n4_provider = N4Provides(self, "fiveg_n4")
        self.framework.observe(
            self.on.publish_upf_information_action,
            self._on_publish_upf_information_action,
        )

    def _on_publish_upf_information_action(self, event: ActionEvent):
        hostname = event.params.get("hostname")
        port = event.params.get("port")
        relation_id = event.params.get("relation-id")
        assert hostname
        assert port
        assert relation_id
        self.fiveg_n4_provider.publish_upf_n4_information(
            relation_id=int(relation_id),
            upf_hostname=hostname,
            upf_n4_port=int(port),
        )


class TestN4Provides:
    @pytest.fixture(autouse=True)
    def context(self):
        self.ctx = testing.Context(
            charm_type=N4Provider,
            meta={
                "name": "n4-provider",
                "provides": {"fiveg_n4": {"interface": "fiveg_n4"}},
            },
            actions={
                "publish-upf-information": {
                    "params": {
                        "relation-id": {"type": "string"},
                        "hostname": {"type": "string"},
                        "port": {"type": "string"},
                    },
                },
            },
        )

    def test_given_fiveg_n4_relation_when_set_upf_information_then_info_added_to_relation_data(  # noqa: E501
        self,
    ):
        fiveg_n4_relation = testing.Relation(
            endpoint="fiveg_n4",
            interface="fiveg_n4",
        )
        state_in = testing.State(
            leader=True,
            relations=[fiveg_n4_relation],
        )

        params = {
            "relation-id": str(fiveg_n4_relation.id),
            "hostname": "upf",
            "port": "1234",
        }

        state_out = self.ctx.run(
            self.ctx.on.action("publish-upf-information", params=params), state_in
        )

        relation = state_out.get_relation(fiveg_n4_relation.id)
        assert relation.local_app_data["upf_hostname"] == "upf"
        assert relation.local_app_data["upf_port"] == "1234"

    def test_given_when_relation_joined_then_fiveg_n4_request_event_emitted(
        self,
    ):
        fiveg_n4_relation = testing.Relation(
            endpoint="fiveg_n4",
            interface="fiveg_n4",
        )
        state_in = testing.State(
            leader=True,
            relations=[fiveg_n4_relation],
        )

        self.ctx.run(self.ctx.on.relation_joined(fiveg_n4_relation), state_in)

        assert len(self.ctx.emitted_events) == 2
        assert isinstance(self.ctx.emitted_events[1], FiveGN4RequestEvent)
