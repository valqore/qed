# qed Helm chart

```bash
qed keys init --dir ./qed-keys
kubectl create secret generic qed-signing-key \
  --from-file=evidence-key.pem=./qed-keys/evidence-key.pem

kubectl create secret generic qed-adapters \
  --from-literal=mcp-proxy="$(openssl rand -base64 32)"

helm install qed ./deploy/helm/qed \
  --set signingKey.existingSecret=qed-signing-key \
  --set adapters.existingSecret=qed-adapters \
  --set adapters.registered[0].id=mcp-proxy
```

Both secrets are required, and for the same reason: `/readyz` is false without
either. A key is what makes a decision evidence; an adapter secret is what
makes a caller identifiable, and SPEC §17 requires QED to reject adapters it
cannot identify. A release with only the key installs cleanly, rolls out green,
and then refuses every proposal with `adapter-auth-unconfigured` — so the chart
refuses that release at install time instead.

Keep `./qed-keys/public/` — it is what an auditor verifies an export with, and
the half that is safe to publish.

`docs/deployment.md` is the prose version of this file: what the chart refuses
to install and why, how the HA path works, and what each default is protecting.

## Values

| Key | Default | Notes |
|---|---|---|
| `replicaCount` | `1` | above 1 requires `evidence.backend: postgres` |
| `image.repository` | `ghcr.io/valqore/qed` | |
| `image.tag` | `""` | empty means the chart's `appVersion`, never `latest` |
| `signingKey.existingSecret` | `""` | **required** |
| `signingKey.privateKeyKey` | `evidence-key.pem` | the key within that secret |
| `adapters.existingSecret` | `""` | **required**; one key per adapter |
| `adapters.registered` | `[]` | **at least one**; `id`, `secretKey`, `kind`, `previousSecretKey` |
| `evidence.backend` | `sqlite` | `sqlite` or `postgres` |
| `evidence.sqlite.persistence.enabled` | `true` | the chain must not be ephemeral |
| `evidence.sqlite.persistence.size` | `8Gi` | |
| `evidence.postgres.existingSecret` | `""` | required on the postgres path |
| `evidence.postgres.secretKey` | `dsn` | |
| `evidence.postgres.env` | `QED_DATABASE_URL` | what `qed.yaml` names |
| `config.mode` | `shadow` | record everything, refuse nothing, to start |
| `config` | *(see values.yaml)* | rendered into `qed.yaml` |
| `policies.existingConfigMap` | `""` | your rules, on top of the baseline pack |
| `extraEnv` | `[]` | for the credentials `config` names |
| `service.port` | `8710` | |
| `ingress.enabled` | `false` | |
| `podDisruptionBudget.enabled` | `false` | only meaningful above one replica |

Everything secret is named by environment variable, never written into
`config`: the rendered `qed.yaml` ends up in a ConfigMap that
`kubectl get -o yaml` prints in full.

## HA

```yaml
replicaCount: 3
evidence:
  backend: postgres
  postgres:
    existingSecret: qed-db
podDisruptionBudget:
  enabled: true
```

Every replica serves the API and decides. Exactly one holds
`pg_try_advisory_lock(1734440037)` and drains the evidence outbox into the
chain; if it dies, its connection drops, the lock is released, and another
takes over within seconds (SPEC §104, ADR-0009).

## Adapters

Every caller signs its requests with a shared secret (SPEC §13), and the id it
sends is what the evidence records — so an id wants to name a thing that
exists: a process, a CI job, a laptop. Not a person.

```bash
kubectl create secret generic qed-adapters \
  --from-literal=mcp-proxy="$(openssl rand -base64 32)" \
  --from-literal=ci-runner="$(openssl rand -base64 32)"
```

```yaml
adapters:
  existingSecret: qed-adapters
  registered:
    - id: mcp-proxy
    - id: ci-runner
      kind: ci
```

The chart derives `QED_ADAPTER_SECRET_MCP_PROXY` from the id — the same name
`qed adapters add` prints — names that variable in `qed.yaml`, and supplies it
from that Secret. The secret itself never reaches a manifest. Each adapter
needs the same string, because it signs every request with it; one holding the
wrong secret is refused as an unknown adapter rather than told so.

**`qed adapters add` does not work in the pod.** `qed.yaml` is a read-only
ConfigMap mount, so it has nothing to write to. Registration is this values
block plus a key in the Secret.

**No `--dev`.** It accepts signatures without checking them, which is for a
loopback process; anything this chart installs has a Service in front of it.

### Rotating a secret

A shared secret cannot change on two machines at the same instant. Between the
instance taking the new one and the last adapter being restarted with it, every
request signed with the old one would be refused as `AG-IDN-005` — an unknown
adapter, which under `fail: closed` is a blocked action. So it is two steps.

Copy the live secret to a second key, write a new one over the first, and name
the copy as the previous:

```yaml
adapters:
  registered:
    - id: mcp-proxy
      previousSecretKey: mcp-proxy-old     # both accepted
```

Roll the new secret out across the fleet, then remove `previousSecretKey` and
upgrade again. The chart refuses an entry whose `previousSecretKey` is the key
it already uses: that is a cutover dressed as a rotation.

## Your own policies

```bash
kubectl create configmap qed-policies --from-file=./policies/
```

```yaml
policies:
  existingConfigMap: qed-policies
```

They are loaded **on top of** the baseline pack, which ships in the image. A
bundle with errors makes `/readyz` false rather than being partly applied:
deciding against a broken bundle would mean applying rules nobody wrote.

## Tests

`tests/deploy/test_helm_chart.py` runs `helm template` for real and parses the
output. It is skipped when `helm` is not on `PATH`.
