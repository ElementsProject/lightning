from __future__ import annotations

from dataclasses import dataclass
from functools import total_ordering
import re
from typing import List, Optional, Protocol, runtime_checkable, Union


_MODDED_PATTERN = "[0-9a-f]+-modded"


@total_ordering
@dataclass
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
    """

    version: str

    def to_parts(self) -> List[_NodeVersionPart]:
        parts = self.version[1:].split(".")
        # If the first part contains a v we will ignore it
        if not parts[0][0].isdigit():
            parts[0] = parts[1:]

        return [_NodeVersionPart.parse(p) for p in parts]

    def strict_equal(self, other: NodeVersion) -> bool:
        if not isinstance(other, NodeVersion):
            raise TypeError(
                "`other` is expected to be of type `NodeVersion` but is `{type(other)}`"
            )
        else:
            return self.version == other.version

    def __eq__(self, other: Union[NodeVersion, str]) -> bool:
        if isinstance(other, str):
            other = NodeVersion(other)
        if not isinstance(other, NodeVersion):
            return False

        if self.strict_equal(other):
            return True
        elif re.match(_MODDED_PATTERN, self.version):
            return False
        else:
            self_parts = [p.num for p in self.to_parts()]
            other_parts = [p.num for p in other.to_parts()]

            if len(self_parts) != len(other_parts):
                return False

            for ps, po in zip(self_parts, other_parts):
                if ps != po:
                    return False
            return True

    def __lt__(self, other: Union[NodeVersion, str]) -> bool:
        if isinstance(other, str):
            other = NodeVersion(other)
        if not isinstance(other, NodeVersion):
            return NotImplemented

        # If we are in CI the version will by a hex ending on modded
        # We will assume it is the latest version
        if re.match(_MODDED_PATTERN, self.version):
            return False
        elif re.match(_MODDED_PATTERN, other.version):
            return True
        else:
            self_parts = [p.num for p in self.to_parts()]
            other_parts = [p.num for p in other.to_parts()]

            # zip truncates to shortes length
            for sp, op in zip(self_parts, other_parts):
                if sp < op:
                    return True
                if sp > op:
                    return False

            # If the initial parts are all equal the longest version is the biggest
            #
            # self = 'v24.02'
            # other = 'v24.02.1'
            return len(self_parts) < len(other_parts)

    def matches(self, version_spec: VersionSpecLike) -> bool:
        """Returns True if the version matches the spec

        The `version_spec` can be represented as a string and has 8 operators
        which are `=`, `===`, `!=`, `!===`, `<`, `<=`, `>`, `>=`.

        The `=` is the equality operator. The verson_spec `=v24.02` matches
        all versions that equal `v24.02` including release candidates such as `v24.02rc1`.
        You can use the strict-equality operator `===` if strict equality is required.

        Specifiers can be combined by separating the with a comma ','. The `version_spec`
        `>=v23.11, <v24.02" includes any version which is greater than or equal to `v23.11`
        and smaller than `v24.02`.
        """
        spec = VersionSpec.parse(version_spec)
        return spec.matches(self)


@dataclass
class _NodeVersionPart:
    num: int
    text: Optional[str] = None

    @classmethod
    def parse(cls, part: str) -> _NodeVersionPart:
        # We assume all parts start with a number and are followed by a text
        # E.g: v24.01rc2 has two parts
        # - "24"    -> num = 24, text = None
        # - "01rc"  -> num = 01, text = "rc"

        number = re.search(r"\d+", part).group()
        text = part[len(number):]
        text_opt = text if text != "" else None
        return _NodeVersionPart(int(number), text_opt)


@runtime_checkable
class VersionSpec(Protocol):
    def matches(self, other: NodeVersionLike) -> bool:
        ...

    @classmethod
    def parse(cls, spec: VersionSpecLike) -> VersionSpec:
        if isinstance(spec, VersionSpec):
            return spec
        else:
            parts = [p.strip() for p in spec.split(",")]
            subspecs = [_CompareSpec.parse(p) for p in parts]
            return _AndVersionSpecifier(subspecs)


@dataclass
class _AndVersionSpecifier(VersionSpec):
    specs: List[VersionSpec]

    def matches(self, other: NodeVersionLike) -> bool:
        for spec in self.specs:
            if not spec.matches(other):
                return False
        return True


_OPERATORS = [
    "===",  # Strictly equal
    "!===",  # not strictly equal
    "=",  # Equal
    ">=",  # Greater or equal
    "<=",  # Less or equal
    "<",  # less
    ">",  # greater than
    "!=",  # not equal
]


@dataclass
class _CompareSpec(VersionSpec):
    operator: str
    version: NodeVersion

    def __post_init__(self):
        if self.operator not in _OPERATORS:
            raise ValueError(f"Invalid operator '{self.operator}'")

    def matches(self, other: NodeVersionLike):
        if isinstance(other, str):
            other = NodeVersion(other)
        if self.operator == "===":
            return other.strict_equal(self.version)
        if self.operator == "!===":
            return not other.strict_equal(self.version)
        if self.operator == "=":
            return other == self.version
        if self.operator == ">=":
            return other >= self.version
        if self.operator == "<=":
            return other <= self.version
        if self.operator == "<":
            return other < self.version
        if self.operator == ">":
            return other > self.version
        if self.operator == "!=":
            return other != self.version
        else:
            ValueError("Unknown operator")

    @classmethod
    def parse(cls, spec_string: str) -> _CompareSpec:
        spec_string = spec_string.strip()

        for op in _OPERATORS:
            if spec_string.startswith(op):
                version = spec_string[len(op):]
                version = version.strip()
                return _CompareSpec(op, NodeVersion(version))

        raise ValueError(f"Failed to parse '{spec_string}'")


NodeVersionLike = Union[NodeVersion, str]
VersionSpecLike = Union[VersionSpec, str]

__all__ = [NodeVersion, NodeVersionLike, VersionSpec, VersionSpecLike]
