"""Exchange an IdP token for a gate token, the way an adapter does.

Used by ``demo.sh``. The signing helpers are imported from the package rather
than reimplemented here: a demo that computed the MAC its own way would pass
while the two sides disagreed. The first run of this script failed twice for
exactly that reason -- a hex digest where the server expects unpadded base64url,
then a guessed header name -- so even the header constants are imported.

    python exchange.py <gate-url> <adapter-id> <idp-token> [scope]

Prints the gate token on stdout and a short summary on stderr, so the caller
can capture one without the other.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

from gate.api.auth import (
    HEADER_ADAPTER,
    HEADER_NONCE,
    HEADER_SIGNATURE,
    HEADER_TIMESTAMP,
    canonical_string,
    sign,
)
from gate.core.schemas import rfc3339_ms, utcnow

PATH = "/v1/token"


def main() -> int:
    if len(sys.argv) < 4:
        sys.stderr.write(__doc__ or "")
        return 2
    gate_url, adapter, subject = sys.argv[1], sys.argv[2], sys.argv[3]
    scope = sys.argv[4] if len(sys.argv) > 4 else "read write admin"

    body = json.dumps(
        {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": subject,
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "requested_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "scope": scope,
        }
    ).encode()

    secret = os.environ.get("GATE_DEMO_SECRET")
    if not secret:
        sys.stderr.write("GATE_DEMO_SECRET is not set\n")
        return 2

    timestamp = rfc3339_ms(utcnow())
    signature = sign(
        secret,
        canonical_string(method="POST", path=PATH, timestamp=timestamp, nonce="", body=body),
    )
    request = urllib.request.Request(
        f"{gate_url.rstrip('/')}{PATH}",
        data=body,
        method="POST",
        headers={
            "content-type": "application/json",
            HEADER_ADAPTER: adapter,
            HEADER_TIMESTAMP: timestamp,
            HEADER_NONCE: "",
            HEADER_SIGNATURE: signature,
        },
    )
    try:
        with urllib.request.urlopen(request) as response:
            payload = json.load(response)
    except urllib.error.HTTPError as exc:
        sys.stderr.write(f"   refused ({exc.code}): {exc.read().decode('utf-8')[:400]}\n")
        return 1

    print(payload["access_token"])
    sys.stderr.write(
        f"   scope granted : {payload['scope'] or '(none)'}\n"
        f"   scope refused : {payload.get('refused_scope', '-')}\n"
        f"   expires in    : {payload['expires_in']}s\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
