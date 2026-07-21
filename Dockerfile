# syntax=docker/dockerfile:1
# Builds all qchain binaries (qchain-node, qchain-genesis-build, qchain the
# wallet CLI, qchain-faucet, qchain-wallet the web wallet, qchain-indexer the
# QScan explorer) into one runtime
# image. `oqs`'s "vendored" feature builds liboqs from C source bundled inside
# the crate itself (no network access needed at build time) via cmake + a C/C++
# compiler; bindgen (also used by oqs-sys) needs libclang.
#
# FAST UPDATES: the build step uses BuildKit *cache mounts* for cargo's
# registry and the target/ dir, so they persist across `docker build` runs on
# the same machine. The first build compiles everything (liboqs, wasmtime,
# winterfell - the slow part); every later build (an update) only recompiles
# the qchain crates whose source actually changed, cutting an update from
# minutes to seconds. Because the compiled binaries live in the cache mount
# (which isn't available to later stages), they're copied out to /out in the
# same RUN. Requires BuildKit (default in modern Docker; the deploy scripts set
# DOCKER_BUILDKIT=1 to be safe).
# PINNED to an exact Rust minor for reproducible builds (task #198, QCH-S11) -
# `rust:bookworm` floats to whatever's latest at build time, which makes the
# artifact non-reproducible. `rust-toolchain.toml` pins the exact patch (1.94.1)
# that rustup installs on top of this base, so the compiler is fully pinned; the
# base tag just needs to be close enough to avoid a re-download. Combined with
# the committed Cargo.lock + `--locked` below, both build inputs are pinned.
FROM rust:1.94-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake clang libclang-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .
# `--locked`: build from the COMMITTED Cargo.lock exactly, never silently
# re-resolve against a moving crates.io index. This makes the image
# reproducible AND fails loudly with a clear message if the lock is ever
# inconsistent with Cargo.toml, instead of resolving to some other version
# (the exact failure mode a corrupted lock caused once — see the v4.1.6 note
# in CLAUDE.md). A committed lock that builds locally now always builds here.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --locked --release -p qchain-node -p qchain-cli -p qchain-faucet -p qchain-wallet -p qchain-indexer -p qchain-remote-signer && \
    mkdir -p /out && \
    cp target/release/qchain-node \
       target/release/qchain-genesis-build \
       target/release/qchain \
       target/release/qchain-faucet \
       target/release/qchain-wallet \
       target/release/qchain-indexer \
       target/release/qchain-remote-signer /out/

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/qchain-node /usr/local/bin/qchain-node
COPY --from=builder /out/qchain-genesis-build /usr/local/bin/qchain-genesis-build
COPY --from=builder /out/qchain /usr/local/bin/qchain
COPY --from=builder /out/qchain-faucet /usr/local/bin/qchain-faucet
COPY --from=builder /out/qchain-wallet /usr/local/bin/qchain-wallet
COPY --from=builder /out/qchain-indexer /usr/local/bin/qchain-indexer
COPY --from=builder /out/qchain-remote-signer /usr/local/bin/qchain-remote-signer

# No fixed ENTRYPOINT/CMD - this image bundles several binaries (validator,
# coordinator tool, wallet CLI, faucet, web wallet), each meant to be invoked
# explicitly. See docs/DEPLOY.md for real invocations, e.g.:
#   docker run -v $PWD:/qchain -w /qchain --network host <image> \
#     qchain-node --config node1.json
WORKDIR /qchain
