# qed container (SPEC §20.4: distroless, non-root, cosign-signed).
#
# Three stages. The builder has pip and a compiler; a staging stage collects
# the interpreter and the exact set of shared libraries it needs; the runtime
# image is distroless, so it has no shell, no package manager and no pip. That
# is the point: a policy kernel that can be shelled into is a policy kernel an
# attacker can reconfigure, and `qed` governs its own admin operations
# (SPEC §17) only as long as nobody can edit the files underneath it.
#
# The runtime base is `distroless/base-debian12` and **not**
# `distroless/python3-debian12`, which ships Python 3.11. `qed` requires 3.12,
# so a 3.12 wheel's compiled extension lands beside a 3.11 interpreter that
# cannot load it -- `ImportError: cannot import name 'ArgsKwargs' from
# 'pydantic_core._pydantic_core' (unknown location)`, which is an ABI tag
# mismatch wearing a confusing message. So the interpreter is copied from the
# builder along with its library closure, computed rather than guessed.
#
# Build:
#   docker build -f deploy/Dockerfile -t ghcr.io/valqore/qed:0.5.0 .
# Run:
#   docker run --rm -p 8710:8710 -v qed-state:/var/lib/qed \
#     ghcr.io/valqore/qed:0.5.0 serve --dir /var/lib/qed --host 0.0.0.0
#
# `qed keys init --dir /var/lib/qed` has to run once against the volume
# first. The image deliberately does not create a key on start: a key generated
# inside an ephemeral container is a key that disappears with it, and every
# restart would begin a new chain whose genesis hash claimed to be the same
# instance.

# --------------------------------------------------------------------- build
# The builder image, overridable only to point at a *mirror of the same
# image*. Docker Hub's unauthenticated pull limit is per IP and shared, so CI
# uses AWS's public mirror (`public.ecr.aws/docker/library/python:...`) and
# gets identical content without credentials. It is not a knob for choosing a
# different Python: the runtime copies this interpreter, and `qed` requires
# 3.12.
ARG BUILDER_IMAGE=python:3.12-slim-bookworm
FROM ${BUILDER_IMAGE} AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /src

# Dependencies first, so a source-only change does not refetch them.
COPY pyproject.toml README.md ./
COPY qed ./qed
COPY packages ./packages

# --prefix, not a venv: distroless has no shell to activate one in. The tree
# lands where PYTHONPATH can point at it directly.
#
# `[postgres]` is included because the HA path (SPEC §15, §104) is a property
# of the deployment and not of the image: an operator who sets
# `evidence.store_env` should not discover that the container they were handed
# cannot talk to a database.
RUN python -m pip install --prefix=/install ".[postgres]" ./packages/qed-verify

# ------------------------------------------------------------------- staging
# The interpreter and every shared library it or the installed extensions
# actually need, computed with `ldd` rather than listed. A hand-written list of
# Debian libraries goes stale on the next base bump and fails at import time in
# production. The script is a file rather than an inline `RUN` so that it is
# readable, and testable, as a script.
FROM builder AS staging

COPY deploy/stage-libs.sh /tmp/stage-libs.sh
RUN sh /tmp/stage-libs.sh

# ------------------------------------------------------------------- runtime
FROM gcr.io/distroless/base-debian12:nonroot AS runtime

LABEL org.opencontainers.image.title="Valqore QED" \
      org.opencontainers.image.description="Policy and evidence kernel for AI-agent actions" \
      org.opencontainers.image.source="https://github.com/valqore/qed" \
      org.opencontainers.image.version="0.5.0" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Valqore"

# The interpreter, its standard library, the libraries both need, and qed.
#
# The library destination is /usr/lib/x86_64-linux-gnu and not the /lib/... the
# builder resolves them from. On merged-/usr Debian, /lib is a symlink to
# usr/lib, and a COPY through it replaces that symlink with a real directory
# the base image's ld.so.cache has never heard of -- so every library would
# land somewhere the loader does not look, and a distroless image has no
# ldconfig to tell it otherwise.
COPY --from=staging /usr/local/bin/python3.12 /usr/local/bin/python3.12
COPY --from=staging /usr/local/lib/python3.12 /usr/local/lib/python3.12
COPY --from=staging /stage/libs/ /usr/lib/x86_64-linux-gnu/
COPY --from=staging /install /usr/local

ENV PATH=/usr/local/bin:/usr/bin:/bin \
    PYTHONPATH=/usr/local/lib/python3.12/site-packages \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# 65532 is distroless's `nonroot`. Declared again here so that a `docker run`
# without --user still cannot write outside the state volume.
USER 65532:65532

# Not a VOLUME declaration: an anonymous volume on every run is how an
# evidence chain quietly disappears. The operator mounts this path explicitly.
WORKDIR /var/lib/qed

EXPOSE 8710

# No shell in the image, so this is exec form against the module. `qed`'s
# console script is in /usr/local/bin, but relying on its shebang resolving in
# a distroless image is one more thing that has to be where it is expected.
ENTRYPOINT ["python3.12", "-c", "from qed.cli import main; main()"]
CMD ["serve", "--dir", "/var/lib/qed", "--host", "0.0.0.0", "--port", "8710"]
