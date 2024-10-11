# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


import pytest
from charms.sdcore_upf_k8s.v0.fiveg_n3 import N3AvailableEvent, N3Requires
from ops import testing
from ops.charm import CharmBase


class N3Requirer(CharmBase):
    def __init__(self, *args):
        super().__init__(*args)
        self.fiveg_n3_requirer = N3Requires(self, "fiveg_n3")


class TestN3Provides:
    @pytest.fixture(autouse=True)
    def context(self):
        self.ctx = testing.Context(
            charm_type=N3Requirer,
            meta={
                "name": "n3-requirer",
                "requires": {"fiveg_n3": {"interface": "fiveg_n3"}},
            },
        )

    def test_given_upf_ip_address_in_relation_data_when_relation_changed_then_fiveg_n3_request_event_emitted(  # noqa: E501
        self,
    ):
        fiveg_n3_relation = testing.Relation(
            endpoint="fiveg_n3",
            interface="fiveg_n3",
            remote_app_data={"upf_ip_address": "1.2.3.4"},
        )
        state_in = testing.State(
            leader=True,
            relations=[fiveg_n3_relation],
        )

        self.ctx.run(self.ctx.on.relation_changed(fiveg_n3_relation), state_in)

        assert len(self.ctx.emitted_events) == 2
        assert isinstance(self.ctx.emitted_events[1], N3AvailableEvent)

    def test_given_upf_ip_address_not_in_relation_data_when_relation_changed_then_fiveg_n3_request_event_emitted(  # noqa: E501
        self,
    ):
        fiveg_n3_relation = testing.Relation(
            endpoint="fiveg_n3",
            interface="fiveg_n3",
            remote_app_data={},
        )
        state_in = testing.State(
            leader=True,
            relations=[fiveg_n3_relation],
        )

        self.ctx.run(self.ctx.on.relation_changed(fiveg_n3_relation), state_in)

        assert len(self.ctx.emitted_events) == 1
