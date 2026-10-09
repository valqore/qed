# qed Helm chart

```bash
qed keys init --dir ./qed-keys
kubectl create secret generic qed-signing-key \
  --from-file=evidence-key.pem=./qed-keys/evidence-key.pem

helm install qed ./deploy/helm/qed \
  --set signingKey.existingSecret=qed-signing-key
```

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
