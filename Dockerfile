# buildtrace as a container image, for running it as a Kubernetes sidecar.
# The IP-to-network database is baked in so the sidecar never downloads
# anything itself (which would show up in its own report).
FROM --platform=$BUILDPLATFORM golang:1.26 AS build
WORKDIR /src
COPY go.mod ./
COPY . .
ARG VERSION=dev
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /buildtrace . \
 && mkdir -p /cache/buildtrace \
 && mkdir -p /out/tmp && chmod 1777 /out/tmp \
 && curl -fsSL -o /cache/buildtrace/ip2asn-combined.tsv.gz https://iptoasn.com/data/ip2asn-combined.tsv.gz

FROM scratch
COPY --from=build /buildtrace /buildtrace
COPY --from=build /cache /cache
COPY --from=build /out/tmp /tmp
ENV XDG_CACHE_HOME=/cache
ENTRYPOINT ["/buildtrace"]
CMD ["watch", "--json", "/tmp/buildtrace.json"]
