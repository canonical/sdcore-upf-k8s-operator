# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import logging

from charms.sdcore_upf.v0.fiveg_n3 import N3Provides
from ops.charm import CharmBase
from ops.main import main

logger = logging.getLogger(__name__)


class WhateverCharm(CharmBase):
    TEST_UPF_IP_ADDRESS = ""

    def __init__(self, *args):
        """Creates a new instance of this object for each event."""
        super().__init__(*args)
        self.fiveg_n3_provider = N3Provides(self, "fiveg_n3")

        self.framework.observe(
            self.fiveg_n3_provider.on.fiveg_n3_request, self._on_fiveg_n3_request
        )

    def _on_fiveg_n3_request(self, event):
        self.fiveg_n3_provider.publish_upf_information(
            relation_id=event.relation_id,
            upf_ip_address=self.TEST_UPF_IP_ADDRESS,
        )


if __name__ == "__main__":
    main(WhateverCharm)
