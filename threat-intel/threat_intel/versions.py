"""Version comparison that copes with the strings agents actually report.

`packaging` handles the sane ones (`1.24.0`, `8.0.35`). OpenSSH-style versions
such as `9.6p1` are not PEP 440, so those fall back to comparing the numeric
segments in order, which is what Threat Intel does when its parser gives up.
"""

import re
from functools import total_ordering

from packaging.version import InvalidVersion, Version

_DIGITS = re.compile(r'\d+')


@total_ordering
class ComparableVersion:
    def __init__(self, raw: str) -> None:
        self.raw = raw.strip()
        try:
            self._parsed: Version | None = Version(self.raw)
        except InvalidVersion:
            self._parsed = None
        self._segments = tuple(int(segment) for segment in _DIGITS.findall(self.raw)) or (0,)

    def _key(self, other: 'ComparableVersion') -> tuple:
        if self._parsed is not None and other._parsed is not None:
            return (0, self._parsed)
        return (1, self._segments)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ComparableVersion):
            return NotImplemented
        return self._key(other) == other._key(self)

    def __lt__(self, other: 'ComparableVersion') -> bool:
        return self._key(other) < other._key(self)

    def __repr__(self) -> str:
        return f'ComparableVersion({self.raw!r})'


def version_in_range(
    version: str,
    *,
    start_including: str | None = None,
    start_excluding: str | None = None,
    end_including: str | None = None,
    end_excluding: str | None = None,
) -> bool:
    """True when `version` falls inside the NVD-style range. Missing bounds are open."""
    current = ComparableVersion(version)

    if start_including is not None and current < ComparableVersion(start_including):
        return False
    if start_excluding is not None and current <= ComparableVersion(start_excluding):
        return False
    if end_including is not None and current > ComparableVersion(end_including):
        return False
    if end_excluding is not None and current >= ComparableVersion(end_excluding):
        return False

    return True
