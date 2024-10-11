# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


from ops import testing

from tests.unit.fixtures import UPFUnitTestFixtures


class TestCharmRemove(UPFUnitTestFixtures):
    def test_given_k8s_service_is_created_when_remove_then_service_is_deleted(
        self,
    ):
        self.mock_k8s_service.is_created.return_value = True
        state_in = testing.State(
            leader=True,
        )

        self.ctx.run(self.ctx.on.remove(), state_in)

        self.mock_k8s_service.delete.assert_called_once()
