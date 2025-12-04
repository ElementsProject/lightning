from __future__ import annotations

from functools import total_ordering
from typing import Union


@total_ordering
class NodeVersion:
    """NodeVersion

    NodeVersion represents a Core Lightning Version. It also contains a scheme
    to compare versions against each-other.

    The main use-case to compare versions is to test for the availability of a feature.
    An example is the `--developer` flag which was introduced in cln v23.11

    We define the following rules
    - `v23.11` == `v23.11`
       Obviously a version is equal to it-self.
    - `v23.11rc3` == `v23.11rc1` == `v23.11`
      We don't add new features in release-candidates and therefore the feature-set is the same.
      This is also more ergonomic for a dev that wants to know if the `--developer` flag is available.
      See `strict_equal` if an exact match is required
    - `v23.11` < `v24.02`
      The oldest version is the smallest
    - `vd6fa78c`
      This is an untagged version, such as in CI.  This is assumed to be the latest, greater than
      any test.
    """
    def __init__(self, version: str):
        # e.g. v24.11-225-gda793e66b9
        if version.startswith('v'):
            version = version[1:]
        version = version.split('-')[0]
        parts = version.split('.')
        # rc is considered "close enough"
        if 'rc' in parts[-1]:
            parts[-1] = parts[-1].split('rc')[0]

        self.parts: int = []

        # Single part?  It's a git version, so treat it as the future.
        if len(parts) == 1:
            self.parts.append(100)
        else:
            for p in parts:
                self.parts.append(int(p))

    def __eq__(self, other: Union[NodeVersion, str]) -> bool:
        if isinstance(other, str):
            other = NodeVersion(other)
        if not isinstance(other, NodeVersion):
            return False

        if len(self.parts) != len(other.parts):
            return False
        for a, b in zip(self.parts, other.parts):
            if a != b:
                return False
        return True

    def __lt__(self, other: Union[NodeVersion, str]) -> bool:
        if isinstance(other, str):
            other = NodeVersion(other)
        if not isinstance(other, NodeVersion):
            return NotImplemented

        # We want a zero-padded zip.  Pad both to make one.
        totlen = max(len(self.parts), len(other.parts))
        for a, b in zip(self.parts + [0] * totlen, other.parts + [0] * totlen):
            if a < b:
                return True
            if a > b:
                return False
        return False


__all__ = ["NodeVersion"]
