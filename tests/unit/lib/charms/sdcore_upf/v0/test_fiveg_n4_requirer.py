# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


import pytest
import scenario
from charms.sdcore_upf_k8s.v0.fiveg_n4 import N4AvailableEvent, N4Requires
from ops.charm import CharmBase


class N4Requirer(CharmBase):
    def __init__(self, *args):
        super().__init__(*args)
        self.fiveg_n4_requirer = N4Requires(self, "fiveg_n4")


class TestN4Provides:
    @pytest.fixture(autouse=True)
    def context(self):
        self.ctx = scenario.Context(
            charm_type=N4Requirer,
            meta={
                "name": "n4-requirer",
                "requires": {"fiveg_n4": {"interface": "fiveg_n4"}},
            },
        )

    def test_given_upf_hostname_in_relation_data_when_relation_changed_then_fiveg_n4_request_event_emitted(  # noqa: E501
        self,
    ):
        fiveg_n4_relation = scenario.Relation(
            endpoint="fiveg_n4",
            interface="fiveg_n4",
            remote_app_data={
                "upf_hostname": "1.2.3.4",
                "upf_port": "1234",
            },
        )
        state_in = scenario.State(
            leader=True,
            relations=[fiveg_n4_relation],
        )

        self.ctx.run(self.ctx.on.relation_changed(fiveg_n4_relation), state_in)

        assert len(self.ctx.emitted_events) == 2
        assert isinstance(self.ctx.emitted_events[1], N4AvailableEvent)

    def test_given_upf_hostname_not_in_relation_data_when_relation_changed_then_fiveg_n4_request_event_emitted(  # noqa: E501
        self,
    ):
        fiveg_n4_relation = scenario.Relation(
            endpoint="fiveg_n4",
            interface="fiveg_n4",
            remote_app_data={},
        )
        state_in = scenario.State(
            leader=True,
            relations=[fiveg_n4_relation],
        )

        self.ctx.run(self.ctx.on.relation_changed(fiveg_n4_relation), state_in)

        assert len(self.ctx.emitted_events) == 1
