# =============================================================================
# link-in-bio-service — one image, one binary: /app/link-in-bio <serve|check|render|schema|theme-table>.
# =============================================================================
# Multi-stage build with cargo-chef for dependency-layer caching:
#   chef     — the Rust toolchain plus cargo-chef
#   planner  — computes the dependency recipe from Cargo.toml/lock
#   notices  — cargo-about licence notices of the binary (fails on an unaccepted licence)
#   builder  — compiles the dependencies (cached), then the binary (--locked)
#   runtime  — distroless/cc: glibc + CA certificates; no shell, no package manager
#
# The page's stylesheet, script, icon sprite, brand icons and design tokens are committed files embedded into the
# binary at compile time (page/scripts keep them in step with the pinned packages; CI checks they are current), so
# no Node stage is needed. Both base images are pinned by digest (multi-arch index); bump tag and digest together.
# =============================================================================

FROM docker.io/library/rust:1-slim@sha256:4df2ae8cfdfebdfc13a65da7f253b73d68983dc0339f2719bc17a279c913b13d AS chef
RUN cargo install cargo-chef --version 0.1.78 --locked
WORKDIR /src

# ── Planner: derive the dependency recipe ────────────────────────────────────
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ── Licence notices (Apache-2.0 §4(a) and the MIT/BSD notice clauses) ────────
FROM chef AS notices
RUN cargo install --locked --version 0.9.2 --features cli cargo-about
COPY . .
RUN mkdir -p /out \
 && cargo about generate --locked --fail -c about.toml --manifest-path crates/cli/Cargo.toml about.hbs \
      > /out/THIRD_PARTY_LICENSES.txt \
 && grep -q 'Apache License' /out/THIRD_PARTY_LICENSES.txt

# ── Builder: compile deps (cached), then the binary ──────────────────────────
FROM chef AS builder
COPY --from=planner /src/recipe.json recipe.json
RUN cargo chef cook --release --locked --recipe-path recipe.json -p link-in-bio
COPY . .
RUN cargo build --release --locked -p link-in-bio \
 && install -D -m 0755 target/release/link-in-bio /out/link-in-bio

# ── Runtime: minimal distroless image ────────────────────────────────────────
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:08476c244888bfb425bae1ae4dd7c17f093e972aab8426883d97f3c6f280f7c1

ARG VERSION=dev
ARG VENDOR="Meddleware"
ARG DESCRIPTION="Link in Bio: link pages rendered on the server, with their interoperable documents."
ARG SOURCE_URL="https://github.com/meddleware-org/link-in-bio-service"
ARG DOCUMENTATION_URL="https://github.com/meddleware-org/link-in-bio-service#readme"
ARG IMAGE_URL="https://quay.io/meddleware-org/link-in-bio-service"

LABEL org.opencontainers.image.title="link-in-bio-service" \
      org.opencontainers.image.description="${DESCRIPTION}" \
      org.opencontainers.image.url="${IMAGE_URL}" \
      org.opencontainers.image.source="${SOURCE_URL}" \
      org.opencontainers.image.documentation="${DOCUMENTATION_URL}" \
      org.opencontainers.image.vendor="${VENDOR}" \
      org.opencontainers.image.licenses="0BSD" \
      org.opencontainers.image.version="${VERSION}"

WORKDIR /app
COPY --from=builder /out/link-in-bio /app/
COPY --from=notices /out/ /app/
# The lockfile makes an image scan list the compiled crates (a stripped binary carries none); inert at runtime.
COPY Cargo.lock /app/Cargo.lock
COPY LICENSE /app/LICENSE

# 65532 is distroless's nonroot user.
USER 65532:65532
EXPOSE 8080
ENV LISTEN_ADDR=0.0.0.0:8080

# Every Deployment sets its `args:` (for the operator's page: serve --mode static, with SITE_CONFIG and MANIFEST
# pointing at the mounted files). No volume is written.
ENTRYPOINT ["/app/link-in-bio"]
CMD ["--help"]
