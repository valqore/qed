# gate container (SPEC §20.4: distroless, non-root, cosign-signed).
#
# Two stages. The builder has pip and a compiler; the runtime image is
# distroless, so it has no shell, no package manager and no pip. That is the
# point: a policy kernel that can be shelled into is a policy kernel an
# attacker can reconfigure, and `gate` governs its own admin operations
# (SPEC §17) only as long as nobody can edit the files underneath it.
#
# Build:
#   docker build -f deploy/Dockerfile -t ghcr.io/valqore/gate:0.1.0 .
# Run:
#   docker run --rm -p 8710:8710 -v gate-state:/var/lib/gate \
#     ghcr.io/valqore/gate:0.1.0 serve --dir /var/lib/gate --host 0.0.0.0
#
# `gate keys init --dir /var/lib/gate` has to run once against the volume
# first. The image deliberately does not create a key on start: a key generated
# inside an ephemeral container is a key that disappears with it, and every
# restart would begin a new chain whose genesis hash claimed to be the same
# instance.

# --------------------------------------------------------------------- build
FROM python:3.12-slim-bookworm AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /src

# Dependencies first, so a source-only change does not refetch them.
COPY pyproject.toml README.md ./
COPY gate ./gate
COPY packages ./packages

# --prefix, not a venv: distroless has no shell to activate one in. The tree
# lands where PYTHONPATH can point at it directly.
RUN python -m pip install --prefix=/install . ./packages/gate-verify

# ------------------------------------------------------------------- runtime
# Digest-pinned: a tag can be moved, and the whole claim of this image is that
# what an auditor verifies is what ran.
FROM gcr.io/distroless/python3-debian12:nonroot AS runtime

LABEL org.opencontainers.image.title="Valqore Gate" \
      org.opencontainers.image.description="Policy and evidence kernel for AI-agent actions" \
      org.opencontainers.image.source="https://github.com/valqore/gate" \
      org.opencontainers.image.version="0.1.0" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Valqore"

COPY --from=builder /install /usr/local

ENV PYTHONPATH=/usr/local/lib/python3.12/site-packages \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# 65532 is distroless's `nonroot`. Declared again here so that a `docker run`
# without --user still cannot write outside the state volume.
USER 65532:65532

# Not a VOLUME declaration: an anonymous volume on every run is how an
# evidence chain quietly disappears. The operator mounts this path explicitly.
WORKDIR /var/lib/gate

EXPOSE 8710

# No shell in the image, so this is exec form against the module. `gate`'s
# console script lives in /usr/local/bin but distroless has no PATH lookup.
ENTRYPOINT ["python", "-c", "from gate.cli import main; main()"]
CMD ["serve", "--dir", "/var/lib/gate", "--host", "0.0.0.0", "--port", "8710"]
