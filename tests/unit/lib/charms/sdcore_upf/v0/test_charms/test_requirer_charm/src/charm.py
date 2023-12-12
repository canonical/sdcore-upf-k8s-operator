# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import logging

from charms.sdcore_upf_k8s.v0.fiveg_n3 import N3Requires
from charms.sdcore_upf_k8s.v0.fiveg_n4 import N4Requires
from ops.charm import CharmBase
from ops.main import main
from ops.model import ActiveStatus

logger = logging.getLogger(__name__)


class WhateverCharm(CharmBase):
    def __init__(self, *args):
        """Creates a new instance of this object for each event."""
        super().__init__(*args)
        self.fiveg_n3 = N3Requires(self, "fiveg_n3")
        self.fiveg_n4 = N4Requires(self, "fiveg_n4")

        self.framework.observe(self.fiveg_n3.on.fiveg_n3_available, self._on_relation_available)
        self.framework.observe(self.fiveg_n4.on.fiveg_n4_available, self._on_relation_available)

    def _on_relation_available(self, event):
        self.model.unit.status = ActiveStatus()


if __name__ == "__main__":
    main(WhateverCharm)
