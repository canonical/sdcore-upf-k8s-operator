# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import logging

from charms.sdcore_upf.v0.fiveg_n3 import N3Requires
from ops.charm import CharmBase
from ops.main import main
from ops.model import ActiveStatus

logger = logging.getLogger(__name__)


class WhateverCharm(CharmBase):
    def __init__(self, *args):
        """Creates a new instance of this object for each event."""
        super().__init__(*args)
        self.fiveg_n3 = N3Requires(self, "fiveg_n3")

        self.framework.observe(self.fiveg_n3.on.fiveg_n3_available, self._on_fiveg_n3_available)

    def _on_fiveg_n3_available(self, event):
        self.model.unit.status = ActiveStatus(event.upf_ip_address)


if __name__ == "__main__":
    main(WhateverCharm)
