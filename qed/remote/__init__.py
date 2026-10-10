"""Optional, outbound-only features (SPEC §11, §16, invariant §1.7).

Nothing in this package is on the decision path. Every module here is disabled
by default, carries hashes and signatures rather than customer data, and
degrades to "that feature is off" when it cannot reach anything -- which is
SPEC §1.7's "zero bytes out by default", and the reason the kernel alone,
offline, still produces auditor-acceptable evidence.

* :mod:`qed.remote.packs` -- signed control catalogues, with an air-gap import
  that never touches the network.
* ``anchor``, ``intel``, ``buildinfo`` -- later weeks.

The split from :mod:`qed.compliance` is deliberate. `qed.compliance` reads the
catalogues that ship with the package and knows nothing about where a
catalogue might otherwise come from; this package knows about signatures and
about somebody else's bundle, and may be absent entirely.
"""

from __future__ import annotations

__all__: list[str] = []
