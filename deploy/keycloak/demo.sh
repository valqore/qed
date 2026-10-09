#!/usr/bin/env bash
# Week-3 exit criterion, end to end (SPEC §22):
#
#   Keycloak user -> budgeted qed token -> gated action -> verdict -> evidence
#
# Everything here is real except the person at the keyboard: the device flow is
# driven by the password grant so the script can run unattended, which is the
# only shortcut taken. The tokens, the signatures, the JWKS fetch, the budget
# and the chain are all the production paths.
#
#   docker compose -f deploy/keycloak/docker-compose.yml up -d
#   ./deploy/keycloak/demo.sh
set -euo pipefail

KC=${KC:-http://localhost:8080}
REALM=${REALM:-qed-demo}
CLIENT=${CLIENT:-qed-cli}
QED_URL=${QED_URL:-http://127.0.0.1:8710}
DIR=${DIR:-$(mktemp -d)}
ADAPTER=adp_demo
export QED_DEMO_SECRET=${QED_DEMO_SECRET:-$(python -c "import secrets;print(secrets.token_hex(24))")}

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

say "1. Waiting for Keycloak"
for _ in $(seq 1 60); do
  if curl -fsS "$KC/realms/$REALM/.well-known/openid-configuration" >/dev/null 2>&1; then break; fi
  sleep 2
done
curl -fsS "$KC/realms/$REALM/.well-known/openid-configuration" >/dev/null
echo "   realm $REALM is up"

say "2. Configuring QED"
mkdir -p "$DIR"
cat > "$DIR/qed.yaml" <<YAML
instance_id: qed-demo
mode: enforce
adapters:
  - adapter_id: $ADAPTER
    secret_env: QED_DEMO_SECRET
    kind: mcp
delegation:
  self_issuer: https://qed.demo
  token_ttl_default_seconds: 900
  issuers:
    - issuer: $KC/realms/$REALM
      algorithms: [RS256]
      scopes_by_group:
        platform: [read, write]
  budget_caps:
    platform: { steps: 3, money_cents: 500 }
YAML
qed keys init --dir "$DIR/qed" >/dev/null
qed serve --dir "$DIR/qed" --config "$DIR/qed.yaml" &
GATE_PID=$!
trap 'kill $GATE_PID 2>/dev/null || true' EXIT
for _ in $(seq 1 40); do
  if curl -fsS "$QED_URL/readyz" >/dev/null 2>&1; then break; fi
  sleep 1
done
curl -fsS "$QED_URL/readyz" | python -m json.tool
echo "   qed is ready"

say "3. Signing in as ali (password grant stands in for the device flow)"
IDP_TOKEN=$(curl -fsS -X POST \
  "$KC/realms/$REALM/protocol/openid-connect/token" \
  -d "client_id=$CLIENT" -d "grant_type=password" \
  -d "username=ali" -d "password=demo" -d "scope=openid profile email" \
  | python -c "import json,sys;print(json.load(sys.stdin)['access_token'])")
echo "   got an IdP access token (${#IDP_TOKEN} chars)"
python - "$IDP_TOKEN" <<'PY'
import base64, json, sys
claims = json.loads(base64.urlsafe_b64decode(sys.argv[1].split(".")[1] + "=="))
print("   sub      :", claims.get("preferred_username"), "/", claims.get("email"))
print("   groups   :", claims.get("groups"))
print("   audience :", claims.get("aud"))
PY

say "4. Exchanging it for a budgeted qed token (RFC 8693)"
QED_TOKEN=$(python "$(dirname "$0")/exchange.py" "$QED_URL" "$ADAPTER" "$IDP_TOKEN")
python - "$QED_TOKEN" <<'PY'
import base64, json, sys
head, body = sys.argv[1].split(".")[:2]
print("   alg      :", json.loads(base64.urlsafe_b64decode(head + "=="))["alg"])
claims = json.loads(base64.urlsafe_b64decode(body + "=="))
print("   issuer   :", claims["iss"])
print("   budget   :", claims["budget"])
print("   jti      :", claims["jti"])
PY

say "5. Verifying that token the way a third party would"
curl -fsS "$QED_URL/.well-known/jwks.json" > "$DIR/jwks.json"
python - "$QED_TOKEN" "$DIR/jwks.json" <<'PY'
import json, sys
from joserfc import jwt
from joserfc.jwk import KeySet, OKPKey

token, path = sys.argv[1], sys.argv[2]
published = json.load(open(path, encoding="utf-8"))
keyset = KeySet([OKPKey.import_key(k) for k in published["keys"]])
decoded = jwt.decode(token, keyset, algorithms=["Ed25519"])
print("   verified against the published JWKS, sub =", decoded.claims["sub"])
PY

say "6. Spending the budget (cap is 3 steps)"
JTI=$(python -c "
import base64,json,sys
print(json.loads(base64.urlsafe_b64decode('$QED_TOKEN'.split('.')[1]+'=='))['jti'])")
for n in 1 2 3 4; do
  cat > "$DIR/p$n.json" <<JSON
{
  "schema_version": "1.0",
  "id": "01JB00000000000000000000D$n",
  "ts": "$(date -u +%Y-%m-%dT%H:%M:%S.000Z)",
  "principal": {
    "token_jti": "$JTI",
    "human_hash": "$(python -c "
import hashlib;print(hashlib.sha256(b'evidence-chain/1:principal:demo').hexdigest())")",
    "agent_chain": ["claude-code@demo"]
  },
  "action": {
    "kind": "mcp_tool",
    "name": "github.list_issues",
    "target": "repo:acme/payments",
    "params_hash": "$(printf '0%.0s' {1..64})"
  },
  "context": {
    "environment": "dev",
    "adapter": "demo/1.0",
    "adapter_id": "$ADAPTER",
    "enforcement": "enforcing",
    "mode": "enforce",
    "cost_estimate": { "tokens": 1200, "money_cents": 4, "known": true },
    "blast_radius_hints": { "writes": false, "deletes": false, "scope": "single_resource" },
    "summary": "demo action $n"
  }
}
JSON
  printf '   action %d -> ' "$n"
  set +e
  qed check "$DIR/p$n.json" --dir "$DIR/qed" --config "$DIR/qed.yaml" 2>/dev/null | head -1
  set -e
done

say "7. The evidence"
qed export --dir "$DIR/qed" --config "$DIR/qed.yaml" --out "$DIR/chain.jsonl" >/dev/null
python - "$DIR/chain.jsonl" <<'PY'
import json, sys
for line in open(sys.argv[1], encoding="utf-8"):
    record = json.loads(line)
    print(f"   seq {record['seq']:>2}  {record['type']}")
PY
qed-verify "$DIR/chain.jsonl" --keys "$DIR/qed/public"

say "Done"
echo "   working directory: $DIR"
