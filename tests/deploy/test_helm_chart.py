"""The Helm chart (SPEC §104, §24, week 6).

`helm template` is run for real and the output is parsed as YAML. A chart is
one of the few artifacts in this repo whose failure mode is entirely
operational: it is correct or it is a pager at 3am, and the only way to know
which is to render it.

What is asserted is the set of properties that are *about QED* rather than
about Helm:

* it refuses to install without an evidence signing key;
* it refuses to install with no adapter registered, which would otherwise be a
  release that rolls out green and is never ready;
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
from typing import Any, ClassVar

import pytest
import yaml

HELM = shutil.which("helm")
CHART = Path(__file__).resolve().parents[2] / "deploy" / "helm" / "qed"

pytestmark = pytest.mark.skipif(HELM is None, reason="helm is not installed")

#: A signing key and nothing else. `readyz` needs one more thing.
KEY_ONLY = ["--set", "signingKey.existingSecret=qed-signing-key"]

#: Enough to get past the install-time checks, and nothing more. Both halves
#: are what `/readyz` gates on: a key to sign evidence with, and a way to tell
#: adapters apart. A release with only the first installs, rolls out, and then
#: refuses every proposal with `adapter-auth-unconfigured`.
MINIMAL = [
    *KEY_ONLY,
    "--set",
    "adapters.existingSecret=qed-adapters",
    "--set",
    "adapters.registered[0].id=mcp-proxy",
]

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

    def test_no_adapter_registered(self) -> None:
        """The failure this one is really about is not a crash: it is a release
        that installs cleanly, rolls out green, and then never becomes ready.
        SPEC §17 requires unknown adapters to be rejected, and an instance with
        no secret cannot tell one caller from another, so `/readyz` stays 503
        with `adapter_auth: "unconfigured"`."""
        message = refusal(*KEY_ONLY)
        assert "No adapter is registered" in message
        assert 'adapter_auth: "unconfigured"' in message
        # And it says what to do, because the pod cannot be told afterwards:
        # qed.yaml is a read-only ConfigMap mount, so `qed adapters add` has
        # nothing to write to.
        assert "read-only ConfigMap mount" in message
        assert "adapters.registered" in message or "registered:" in message

    def test_an_adapter_with_no_secret(self) -> None:
        message = refusal(*KEY_ONLY, "--set", "adapters.registered[0].id=mcp-proxy")
        assert "adapters.existingSecret is required" in message

    def test_an_adapter_with_no_id(self) -> None:
        """A Go template error is not a sentence, and which template Helm
        renders first should not decide which one the operator gets."""
        message = refusal(
            *KEY_ONLY,
            "--set",
            "adapters.existingSecret=qed-adapters",
            "--set",
            "adapters.registered[0].kind=mcp",
        )
        assert "has no `id`" in message
        assert "invalid value" not in message, "a template error leaked instead of the refusal"

    def test_an_unusable_adapter_id(self) -> None:
        """The id travels in an HTTP header and lands in evidence an auditor
        reads: an id that renders differently in two tools is an identity
        nobody can follow through the chain."""
        message = refusal(
            *KEY_ONLY,
            "--set",
            "adapters.existingSecret=qed-adapters",
            "--set",
            "adapters.registered[0].id=MCP_Proxy",
        )
        assert "not a usable adapter id" in message

    def test_a_rotation_with_no_overlap(self) -> None:
        """A shared secret cannot change on two machines at the same instant.
        One key named as both the current and the previous secret is a cutover
        dressed as a rotation."""
        message = refusal(*MINIMAL, "--set", "adapters.registered[0].previousSecretKey=mcp-proxy")
        assert "no overlap" in message
        assert "AG-IDN-005" in message

    def test_two_adapters_under_one_id(self) -> None:
        """One would silently win, and the evidence would attribute both
        adapters' decisions to it."""
        message = refusal(*MINIMAL, "--set", "adapters.registered[1].id=mcp-proxy")
        assert "same id" in message

    def test_a_raw_config_entry_with_no_variable(self) -> None:
        """`config.adapters` is the escape hatch for naming your own
        variables. An entry with no `secret_env` names nothing."""
        message = refusal(*KEY_ONLY, "--set", "config.adapters[0].adapter_id=raw")
        assert "has no `secret_env`" in message


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


class TestAdapterAuthentication:
    """The other half of what `/readyz` gates on (SPEC §13, §17).

    The chart has to get two things right that nothing on the cluster would
    report: the variable names in `qed.yaml` must be the ones the Deployment
    supplies, and they must be the names `qed adapters add` prints -- an
    operator who generates the secret locally is told to export *that* name.
    Either one wrong is a pod whose only symptom is `readyz: false` next to an
    adapter that looks registered.
    """

    SET: ClassVar[list[str]] = [
        "--set",
        "adapters.existingSecret=qed-adapters",
        "--set",
        "adapters.registered[0].id=mcp-proxy",
        "--set",
        "adapters.registered[1].id=ci-runner",
        "--set",
        "adapters.registered[1].kind=ci",
        "--set",
        "adapters.registered[1].previousSecretKey=ci-runner-old",
    ]

    def documents(self) -> list[dict[str, Any]]:
        return render(*KEY_ONLY, *self.SET)

    def test_the_config_registers_them(self) -> None:
        config = yaml.safe_load(kind(self.documents(), "ConfigMap")["data"]["qed.yaml"])
        entries = {e["adapter_id"]: e for e in config["adapters"]}
        assert set(entries) == {"mcp-proxy", "ci-runner"}
        assert entries["mcp-proxy"]["secret_env"] == "QED_ADAPTER_SECRET_MCP_PROXY"
        assert entries["mcp-proxy"]["kind"] == "mcp"
        assert entries["ci-runner"]["kind"] == "ci"
        assert "previous_secret_env" not in entries["mcp-proxy"]

    def test_every_variable_it_names_is_one_the_pod_is_given(self) -> None:
        """The assertion the two templates cannot make about themselves. A
        config naming a variable nothing sets is exactly the state the real
        instance reports as `adapter <id> names <VAR>, which is not set`."""
        documents = self.documents()
        config = yaml.safe_load(kind(documents, "ConfigMap")["data"]["qed.yaml"])
        named = set()
        for entry in config["adapters"]:
            named.add(entry["secret_env"])
            if entry.get("previous_secret_env"):
                named.add(entry["previous_secret_env"])
        supplied = {e["name"] for e in container(documents)["env"]}
        assert named and not named - supplied, f"named but never set: {named - supplied}"

    def test_the_variable_names_are_the_ones_the_cli_prints(self) -> None:
        """`qed adapters add` generates the secret and prints `export
        QED_ADAPTER_SECRET_...=`. A chart that picked its own spelling would
        send the operator to the wrong variable."""
        from qed.cli import _secret_env_name

        config = yaml.safe_load(kind(self.documents(), "ConfigMap")["data"]["qed.yaml"])
        for entry in config["adapters"]:
            assert entry["secret_env"] == _secret_env_name(entry["adapter_id"])

    def test_no_secret_is_rendered_into_a_manifest(self) -> None:
        """A shared secret is a credential, so it travels the same way the DSN
        does: the manifest names the variable, Kubernetes supplies the value."""
        documents = self.documents()
        env = {e["name"]: e for e in container(documents)["env"]}
        for name in env:
            if name.startswith("QED_ADAPTER_SECRET_"):
                assert "value" not in env[name], f"{name} has a literal value"
                assert env[name]["valueFrom"]["secretKeyRef"]["name"] == "qed-adapters"
        config = kind(documents, "ConfigMap")["data"]["qed.yaml"]
        assert "secret:" not in config

    def test_the_secret_key_defaults_to_the_id(self) -> None:
        env = {e["name"]: e for e in container(self.documents())["env"]}
        assert env["QED_ADAPTER_SECRET_MCP_PROXY"]["valueFrom"]["secretKeyRef"]["key"] == (
            "mcp-proxy"
        )

    def test_a_rotation_gets_a_second_variable_of_its_own(self) -> None:
        """Both secrets are live during a rotation, so the old one needs
        somewhere to live that is not the variable being overwritten."""
        documents = self.documents()
        config = yaml.safe_load(kind(documents, "ConfigMap")["data"]["qed.yaml"])
        entry = next(e for e in config["adapters"] if e["adapter_id"] == "ci-runner")
        assert entry["previous_secret_env"] == "QED_ADAPTER_SECRET_CI_RUNNER_PREVIOUS"
        assert entry["previous_secret_env"] != entry["secret_env"]

        env = {e["name"]: e for e in container(documents)["env"]}
        keys = {
            name: env[name]["valueFrom"]["secretKeyRef"]["key"]
            for name in (entry["secret_env"], entry["previous_secret_env"])
        }
        assert keys == {
            "QED_ADAPTER_SECRET_CI_RUNNER": "ci-runner",
            "QED_ADAPTER_SECRET_CI_RUNNER_PREVIOUS": "ci-runner-old",
        }

    def test_the_rendered_config_is_one_the_kernel_accepts(self) -> None:
        """`helm template` output that the real schema rejects is a chart that
        installs and crash-loops. Parse it with `QedConfig` and resolve the
        adapters with the real `AdapterAuth`, which is what decides whether
        `/readyz` comes up."""
        import os
        from unittest import mock

        from qed.api.auth import AdapterAuth
        from qed.config import QedConfig

        config = QedConfig.model_validate(
            yaml.safe_load(kind(self.documents(), "ConfigMap")["data"]["qed.yaml"])
        )
        variables = {}
        for entry in config.registered_adapters:
            variables[entry.secret_env] = "x" * 44
            if entry.previous_secret_env:
                variables[entry.previous_secret_env] = "y" * 44
        with mock.patch.dict(os.environ, variables, clear=False):
            mode = AdapterAuth(config).mode
        assert mode.kind == "signed", mode.reason
        assert set(mode.adapters) == {"mcp-proxy", "ci-runner"}

    def test_a_secret_change_rolls_the_pods(self) -> None:
        """Registering an adapter changes `qed.yaml`, so the checksum
        annotation has to move with it -- otherwise the running pods keep the
        adapter list they started with."""
        before = kind(render(*MINIMAL), "Deployment")["spec"]["template"]["metadata"]["annotations"]
        after = kind(self.documents(), "Deployment")["spec"]["template"]["metadata"]["annotations"]
        assert before["checksum/config"] != after["checksum/config"]


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
