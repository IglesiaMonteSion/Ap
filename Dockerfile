# Builds all qchain binaries (qchain-node, qchain-genesis-build, qchain the
# wallet CLI, qchain-faucet, qchain-wallet the web wallet) into one runtime
# image. `oqs`'s
# "vendored" feature builds liboqs from C source bundled inside the crate
# itself (no network access needed at build time) via cmake + a C/C++
# compiler; bindgen (also used by oqs-sys) needs libclang.
FROM rust:bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake clang libclang-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .
RUN cargo build --release -p qchain-node -p qchain-cli -p qchain-faucet -p qchain-wallet

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/qchain-node /usr/local/bin/qchain-node
COPY --from=builder /build/target/release/qchain-genesis-build /usr/local/bin/qchain-genesis-build
COPY --from=builder /build/target/release/qchain /usr/local/bin/qchain
COPY --from=builder /build/target/release/qchain-faucet /usr/local/bin/qchain-faucet
COPY --from=builder /build/target/release/qchain-wallet /usr/local/bin/qchain-wallet

# No fixed ENTRYPOINT/CMD - this image bundles four different binaries
# (validator, coordinator tool, wallet CLI, faucet), each meant to be
# invoked explicitly. See docs/DEPLOY.md for real invocations, e.g.:
#   docker run -v $PWD:/qchain -w /qchain --network host <image> \
#     qchain-node --config node1.json
WORKDIR /qchain
