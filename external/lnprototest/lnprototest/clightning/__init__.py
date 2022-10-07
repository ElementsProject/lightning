"""Runner for the c-lightning implementation.

This is adapted from the older testcases, so it is overly prescriptive
of how the node is configured.  A more modern implementation would simply
reach into the node and derive the private keys it's using, rather than
use hacky --dev options to override it.

We could also factor out the bitcoind implementation, which is really
independent.

Important environment variables include TIMEOUT which sets how long we
wait for responses (default, 30 seconds), and LIGHTNING_SRC which indicates
where the binaries are (default ../lightning).

"""

from .clightning import Runner

__all__ = ["Runner"]
