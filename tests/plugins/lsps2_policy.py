#!/usr/bin/env python3
""" A simple implementation of a LSPS2 compatible policy plugin. It is the job
of this plugin to deliver a fee options menu to the LSPS2 service plugin.
"""

from pyln.client import Plugin
from datetime import datetime, timedelta, timezone


plugin = Plugin()


@plugin.method("dev-lsps2-getpolicy")
def lsps2_getpolicy(request):
    """ Returns an opening fee menu for the LSPS2 plugin.
    """
    now = datetime.now(timezone.utc)

    # Is ISO 8601 format "YYYY-MM-DDThh:mm:ss.uuuZ"
    valid_until = (now + timedelta(hours=1)).isoformat().replace('+00:00', 'Z')

    return { "policy_opening_fee_params_menu": [
        {
            "min_fee_msat": "1000",
            "proportional": 1000,
            "valid_until": valid_until,
            "min_lifetime": 2000,
            "max_client_to_self_delay": 2016,
            "min_payment_size_msat": "1000",
            "max_payment_size_msat": "100000000",
        },
        {
            "min_fee_msat": "1092000",
            "proportional": 2400,
            "valid_until": valid_until,
            "min_lifetime": 1008,
            "max_client_to_self_delay": 2016,
            "min_payment_size_msat": "1000",
            "max_payment_size_msat": "1000000",
        }
    ]
}

@plugin.method("dev-lsps2-getchannelcapacity")
def lsps2_getchannelcapacity(request, init_payment_size, scid, opening_fee_params):
    """ Returns an opening fee menu for the LSPS2 plugin.
    """
    now = datetime.now(timezone.utc)

    # Is ISO 8601 format "YYYY-MM-DDThh:mm:ss.uuuZ"
    valid_until = (now + timedelta(hours=1)).isoformat().replace('+00:00', 'Z')

    return { "channel_capacity_msat": 100000000 }


plugin.run()
