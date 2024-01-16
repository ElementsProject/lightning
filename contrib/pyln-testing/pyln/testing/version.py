
from dataclasses import dataclass
import re


@dataclass
class Version:
    year: int
    month: int
    patch: int = 0

    def __lt__(self, other):
        return [self.year, self.month, self.patch] < [other.year, other.month, other.patch]

    def __gt__(self, other):
        return other < self

    def __le__(self, other):
        return [self.year, self.month, self.patch] <= [other.year, other.month, other.patch]

    def __ge__(self, other):
        return other <= self

    def __eq__(self, other):
        return [self.year, self.month] == [other.year, other.month]

    @classmethod
    def from_str(cls, s: str) -> "Version":
        m = re.search(r'^v(\d+).(\d+).?(\d+)?(rc\d+)?', s)
        parts = [int(m.group(i)) for i in range(1, 4) if m.group(i) is not None]
        year, month = parts[0], parts[1]
        if len(parts) == 3:
            patch = parts[2]
        else:
            patch = 0

        return Version(year=year, month=month, patch=patch)
