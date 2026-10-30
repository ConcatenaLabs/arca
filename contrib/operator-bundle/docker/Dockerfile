# The operator bundle as one image, from which docker-compose.yml runs every
# daemon in a container of its own. Built from the arca clone it sits in:
#
#   docker build -f contrib/operator-bundle/docker/Dockerfile -t arca-bundle .
#
# The first stage runs install.sh build: it downloads what has a release
# (each checked against pins.env), installs the Rust toolchain and builds
# arcad, arca-signer, arca, Bark's client, the hold-invoice plugin and SeqLN.
# The second keeps the binaries and what they need to run, nothing secret:
# every key is drawn when the bundle first starts, into its volumes.
# Its downloads are x86_64 builds, so the image is linux/amd64; on an
# Apple-silicon Mac Docker Desktop runs it under emulation.
FROM ubuntu:24.04 AS build
ARG BUILD_JOBS=2
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -q && apt-get install -y -q --no-install-recommends ca-certificates git && rm -rf /var/lib/apt/lists/*
COPY . /opt/arca-src
RUN mkdir -p /etc/arca-bundle && cp /opt/arca-src/contrib/operator-bundle/bundle.env.example /etc/arca-bundle/bundle.env \
 && sed -i "s/^BUILD_JOBS=.*/BUILD_JOBS=${BUILD_JOBS}/" /etc/arca-bundle/bundle.env \
 && WITH_CADDY=1 /opt/arca-src/contrib/operator-bundle/install.sh build \
 && w=$(ls /var/cache/arca-bundle/toolchain/cargo/registry/src/*/bip39-*/src/language/english.rs | sort | tail -n 1) \
 && mkdir -p /bip39/registry/src/index/bip39-words/src/language && cp "$w" /bip39/registry/src/index/bip39-words/src/language/english.rs

FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -q && apt-get install -y -q --no-install-recommends \
      ca-certificates curl jq python3 openssl git iproute2 procps nodejs \
      libsqlite3-0 libsodium23 zlib1g libpq5 libssl3t64 libffi8 postgresql-16 \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --home-dir /var/lib/arca-bundle --no-create-home --shell /usr/sbin/nologin arca-bundle
COPY --from=build /opt/arca-bundle /opt/arca-bundle
COPY --from=build /opt/arca-src /opt/arca-src
# The BIP39 word list the operator wallet's mnemonic is drawn from (install.sh
# reads it where the cargo registry keeps it, and checks it).
COPY --from=build /bip39 /var/cache/arca-bundle/toolchain/cargo
RUN install -m 755 /opt/arca-src/contrib/operator-bundle/docker/bundle-run /usr/local/bin/bundle-run \
 && ln -s /opt/arca-src/contrib/operator-bundle/install.sh /usr/local/bin/bundle \
 && : > /etc/arca-bundle.env
ENV BUNDLE_ENV=/etc/arca-bundle.env NAME=arca-bundle
ENTRYPOINT ["/usr/local/bin/bundle-run"]
