"""The Helm chart (SPEC §104, §24, week 6).

`helm template` is run for real and the output is parsed as YAML. A chart is
one of the few artifacts in this repo whose failure mode is entirely
operational: it is correct or it is a pager at 3am, and the only way to know
which is to render it.

What is asserted is the set of properties that are *about QED* rather than
about Helm:

* it refuses to install without an evidence signing key;
* it refuses more than one replica on SQLite, because two writers fork the
  chain;
* the DSN is never rendered into a manifest;
* the evidence volume outlives `helm uninstall`.

Skipped without `helm` on PATH.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

HELM = shutil.which("helm")
CHART = Path(__file__).resolve().parents[2] / "deploy" / "helm" / "qed"

pytestmark = pytest.mark.skipif(HELM is None, reason="helm is not installed")

#: Enough to get past the install-time checks, and nothing more.
MINIMAL = ["--set", "signingKey.existingSecret=qed-signing-key"]

POSTGRES = [
    *MINIMAL,
    "--set",
    "evidence.backend=postgres",
    "--set",
    "evidence.postgres.existingSecret=qed-db",
]


def render(*args: str) -> list[dict[str, Any]]:
    """`helm template`, as parsed documents. Fails loudly on a refusal."""
    result = subprocess.run(
        [str(HELM), "template", "qed", str(CHART), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return [doc for doc in yaml.safe_load_all(result.stdout) if doc]


def refusal(*args: str) -> str:
    """The message from a chart that would not render. Fails if it rendered."""
    result = subprocess.run(
        [str(HELM), "template", "qed", str(CHART), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0, "the chart rendered when it should have refused"
    return result.stderr


def kind(documents: list[dict[str, Any]], wanted: str) -> dict[str, Any]:
    found = [doc for doc in documents if doc.get("kind") == wanted]
    assert len(found) == 1, f"expected one {wanted}, got {len(found)}"
    return found[0]


def container(documents: list[dict[str, Any]]) -> dict[str, Any]:
    spec = kind(documents, "Deployment")["spec"]["template"]["spec"]
    return dict(spec["containers"][0])


class TestItLints:
    def test_helm_lint_passes(self) -> None:
        result = subprocess.run(
            [str(HELM), "lint", str(CHART), *MINIMAL],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stdout + result.stderr

    def test_the_default_image_tag_is_not_latest(self) -> None:
        """A chart whose default is `latest` installs something different every
        week, and the chain records `engine_version` with every decision it
        makes."""
        image = container(render(*MINIMAL))["image"]
        assert not image.endswith(":latest")
        assert image.split(":")[-1][0].isdigit()


class TestWhatItRefusesToInstall:
    """Each of these is something the pod would otherwise find out at runtime,
    where the symptom is a CrashLoop or a forked chain."""

    def test_no_signing_key(self) -> None:
        message = refusal()
        assert "signingKey.existingSecret is required" in message
        assert "unsigned decision is not evidence" in message
        # And it says what to run, because the next thing the operator does is
        # look for the command.
        assert "qed keys init" in message

    def test_two_replicas_on_sqlite(self) -> None:
        """The failure this is really about: a second writer reads the same
        chain tip. The collision is the good outcome; the fork is the other
        one, and a forked chain still verifies record by record."""
        message = refusal(*MINIMAL, "--set", "replicaCount=2")
        assert "fork the chain" in message
        assert "evidence.backend=postgres" in message

    def test_postgres_without_a_credential(self) -> None:
        message = refusal(*MINIMAL, "--set", "evidence.backend=postgres")
        assert "evidence.postgres.existingSecret is required" in message

    def test_sqlite_on_an_ephemeral_filesystem(self) -> None:
        message = refusal(*MINIMAL, "--set", "evidence.sqlite.persistence.enabled=false")
        assert "deleted with the pod" in message

    def test_an_unknown_backend(self) -> None:
        assert "sqlite or postgres" in refusal(*MINIMAL, "--set", "evidence.backend=mysql")


class TestTheSigningKey:
    def test_it_is_mounted_read_only_outside_the_writable_directory(self) -> None:
        """Nesting the secret mount inside the state mount to satisfy a fixed
        filename is the sort of arrangement that works until a kubelet orders
        the mounts differently. `evidence.signing_key` exists so it does not
        have to be."""
        mounts = {m["name"]: m for m in container(render(*MINIMAL))["volumeMounts"]}
        assert mounts["signing-key"]["readOnly"] is True
        assert mounts["signing-key"]["mountPath"] == "/etc/qed/keys"
        assert not mounts["signing-key"]["mountPath"].startswith(mounts["state"]["mountPath"])

    def test_the_config_points_at_where_it_is_mounted(self) -> None:
        documents = render(*MINIMAL)
        config = yaml.safe_load(kind(documents, "ConfigMap")["data"]["qed.yaml"])
        assert config["evidence"]["signing_key"] == "/etc/qed/keys/evidence-key.pem"

    def test_the_file_mode_is_not_world_readable(self) -> None:
        volumes = kind(render(*MINIMAL), "Deployment")["spec"]["template"]["spec"]["volumes"]
        secret = next(v for v in volumes if v["name"] == "signing-key")["secret"]
        assert secret["secretName"] == "qed-signing-key"
        assert secret["defaultMode"] == 0o400


class TestTheEvidenceStore:
    def test_sqlite_gets_a_volume_that_outlives_uninstall(self) -> None:
        """An auditor asking about a decision from six months ago is asking
        about a record `helm uninstall` would otherwise have deleted."""
        claim = kind(render(*MINIMAL), "PersistentVolumeClaim")
        assert claim["metadata"]["annotations"]["helm.sh/resource-policy"] == "keep"

    def test_sqlite_does_not_roll_two_pods_onto_one_file(self) -> None:
        """A rolling update would briefly run the old and new pod against the
        same SQLite file, which is the two writers the chart refuses two
        replicas over."""
        assert kind(render(*MINIMAL), "Deployment")["spec"]["strategy"]["type"] == "Recreate"

    def test_postgres_takes_its_dsn_from_a_secret_and_never_a_manifest(self) -> None:
        documents = render(*POSTGRES)
        rendered = json.dumps(documents)
        assert "postgresql://" not in rendered, "a DSN was rendered into a manifest"

        env = {e["name"]: e for e in container(documents)["env"]}
        assert env["QED_DATABASE_URL"]["valueFrom"]["secretKeyRef"] == {
            "name": "qed-db",
            "key": "dsn",
        }
        config = yaml.safe_load(kind(documents, "ConfigMap")["data"]["qed.yaml"])
        assert config["evidence"]["store_env"] == "QED_DATABASE_URL"
        assert "store" not in config["evidence"]

    def test_postgres_needs_no_persistent_volume(self) -> None:
        """The chain is in the database; what is left on disk is scratch."""
        documents = render(*POSTGRES)
        assert not [d for d in documents if d.get("kind") == "PersistentVolumeClaim"]
        volumes = kind(documents, "Deployment")["spec"]["template"]["spec"]["volumes"]
        assert "emptyDir" in next(v for v in volumes if v["name"] == "state")

    def test_postgres_allows_the_replicas_sqlite_does_not(self) -> None:
        documents = render(*POSTGRES, "--set", "replicaCount=3")
        assert kind(documents, "Deployment")["spec"]["replicas"] == 3


class TestItStartsSafe:
    def test_the_default_mode_is_shadow(self) -> None:
        """A kernel installed in enforce mode starts refusing actions before
        anybody has seen what its rules do, and the first thing an operator
        learns about QED should not be an outage."""
        config = yaml.safe_load(kind(render(*MINIMAL), "ConfigMap")["data"]["qed.yaml"])
        assert config["mode"] == "shadow"

    def test_readiness_is_what_gates_a_rollout(self) -> None:
        """`/readyz` is false without a signing key and false with a broken
        policy bundle, so a bad rollout stops at the first pod."""
        probes = container(render(*MINIMAL))
        assert probes["readinessProbe"]["httpGet"]["path"] == "/readyz"
        assert probes["livenessProbe"]["httpGet"]["path"] == "/healthz"

    def test_liveness_is_not_readiness(self) -> None:
        """Restarting the container will not conjure up a signing key, so a
        missing key must not fail the liveness probe into a crash loop."""
        probes = container(render(*MINIMAL))
        assert (
            probes["livenessProbe"]["httpGet"]["path"]
            != probes["readinessProbe"]["httpGet"]["path"]
        )

    def test_a_policy_change_rolls_the_pods(self) -> None:
        """The chain records `policy_hash` with every verdict. Without this the
        hash in the evidence could name rules that were replaced in a
        ConfigMap hours earlier."""
        annotations = kind(render(*MINIMAL), "Deployment")["spec"]["template"]["metadata"][
            "annotations"
        ]
        assert len(annotations["checksum/config"]) == 64

        changed = kind(render(*MINIMAL, "--set", "config.instance_id=other"), "Deployment")["spec"][
            "template"
        ]["metadata"]["annotations"]
        assert changed["checksum/config"] != annotations["checksum/config"]


class TestTheSecurityPosture:
    def test_it_runs_as_the_images_own_non_root_user(self) -> None:
        spec = kind(render(*MINIMAL), "Deployment")["spec"]["template"]["spec"]
        assert spec["securityContext"]["runAsNonRoot"] is True
        assert spec["securityContext"]["runAsUser"] == 65532

    def test_the_root_filesystem_is_read_only(self) -> None:
        """The reason the image is distroless in the first place: a policy
        kernel whose files can be edited is a policy kernel that can be
        reconfigured."""
        security = container(render(*MINIMAL))["securityContext"]
        assert security["readOnlyRootFilesystem"] is True
        assert security["allowPrivilegeEscalation"] is False
        assert security["capabilities"]["drop"] == ["ALL"]

    def test_the_writable_mount_is_the_only_one(self) -> None:
        """With a read-only root, the state directory has to be writable and
        nothing else should be."""
        mounts = container(render(*MINIMAL))["volumeMounts"]
        writable = [m["mountPath"] for m in mounts if not m.get("readOnly")]
        assert writable == ["/var/lib/qed"]

    def test_it_gets_no_kubernetes_token(self) -> None:
        """QED calls no Kubernetes API. One mounted anyway would be a
        credential in a pod with no use for it."""
        account = kind(render(*MINIMAL), "ServiceAccount")
        assert account["automountServiceAccountToken"] is False
