# syntax=docker/dockerfile:1

# knockknock rendezvous server: a static Go binary on distroless, as non-root.
#   docker build -t knockknock/rendezvous rendezvous/
# Base images are pinned by digest; bump the tag and digest together.

FROM --platform=$BUILDPLATFORM golang:1.27.3-trixie@sha256:c65ecfe613b539ac74c62a4c3b2c27e8f8a6076384c8f27e8a3c0f3be17cc385 AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-mod=readonly
COPY go.mod ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
ARG TARGETOS TARGETARCH
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -buildvcs=false \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/rendezvous ./cmd/rendezvous

FROM gcr.io/distroless/static-debian13:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99
ARG VERSION=dev
LABEL org.opencontainers.image.title="knockknock-rendezvous" \
      org.opencontainers.image.description="Rendezvous server for knockknock UDP NAT hole punching" \
      org.opencontainers.image.version="${VERSION}"
COPY --from=build /out/rendezvous /rendezvous
# 65532 = distroless "nonroot". Numeric so Kubernetes can verify runAsNonRoot.
USER 65532:65532
# 7777: TLS signalling (TCP) and BIND (UDP), same port number on purpose.
# 8080: dashboard (off unless -http is set), 8081: /healthz.
EXPOSE 7777/tcp 7777/udp 8080/tcp 8081/tcp
ENTRYPOINT ["/rendezvous"]
# Without -tls-cert/-tls-key the server keeps a development CA in the
# (writable) home directory: docker cp <container>:/home/nonroot/dev-ca.pem .
CMD ["-addr", ":7777", "-health", ":8081", "-http", "", "-tls-dev-ca", "/home/nonroot/dev-ca.pem"]
