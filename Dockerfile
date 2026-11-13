# The omega-cra-evol container image (ghcr.io/robertolocatelli81-dev/omega-cra-evol:<version>), built by
# .github/workflows/container.yml from the wheel of a GitHub Release, checked there against the release's SHA256SUMS.
# Base image pinned by digest (python:3.12-slim, multi-arch index, read on 13/11/2026); the [sign] extra pinned by hash.
FROM docker.io/library/python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

ARG CRA_VERSION
COPY dist/omega_cra_evol-${CRA_VERSION}-py3-none-any.whl /tmp/dist/
COPY container/requirements-sign.txt /tmp/requirements-sign.txt
RUN test -n "${CRA_VERSION}" \
 && python -m pip install --no-cache-dir --disable-pip-version-check --root-user-action=ignore --require-hashes --only-binary=:all: -r /tmp/requirements-sign.txt \
 && python -m pip install --no-cache-dir --disable-pip-version-check --root-user-action=ignore --no-deps --no-index /tmp/dist/omega_cra_evol-${CRA_VERSION}-py3-none-any.whl \
 && rm -rf /tmp/dist /tmp/requirements-sign.txt \
 && useradd --no-create-home --uid 10001 --shell /usr/sbin/nologin cra \
 && test "$(cra --version)" = "omega-cra-evol ${CRA_VERSION}" \
 && test "$(omega-cra-evol --version)" = "omega-cra-evol ${CRA_VERSION}"

LABEL org.opencontainers.image.source="https://github.com/robertolocatelli81-dev/omega-cra-evol" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      org.opencontainers.image.title="omega-cra-evol" \
      org.opencontainers.image.version="${CRA_VERSION}" \
      org.opencontainers.image.description="Firm-side, offline-verifiable evidence for the EU Cyber Resilience Act (the cra command)"
USER 10001
WORKDIR /work
ENTRYPOINT ["cra"]
CMD ["--help"]
