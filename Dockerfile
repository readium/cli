FROM --platform=$BUILDPLATFORM golang:1-bookworm@sha256:386d475a660466863d9f8c766fec64d7fdad3edac2c6a05020c09534d71edb4b AS builder
ARG BUILDARCH TARGETOS TARGETARCH
ARG NO_SNAPSHOT=false

# Install GoReleaser, verifying the package against the SHA256 sums published
# in the release's checksums.txt so a swapped release asset fails the build
RUN wget --no-verbose "https://github.com/goreleaser/goreleaser/releases/download/v2.17.0/goreleaser_2.17.0_$BUILDARCH.deb" && \
    case "$BUILDARCH" in \
      amd64) echo "9dd79854c7e3d87699764fdf5469f111c6d68449943bc83b4f51446e10166996  goreleaser_2.17.0_amd64.deb" | sha256sum -c - ;; \
      arm64) echo "5bf732ad34ece73243209525d58a02df546aa2a0e25106631d4058bfd42fad1d  goreleaser_2.17.0_arm64.deb" | sha256sum -c - ;; \
      *) echo "no pinned goreleaser checksum for build architecture $BUILDARCH" >&2; exit 1 ;; \
    esac
RUN dpkg -i "goreleaser_2.17.0_$BUILDARCH.deb"

# Create and change to the app directory.
WORKDIR /app

# Retrieve application dependencies.
# This allows the container build to reuse cached dependencies.
# Expecting to copy go.mod and if present go.sum.
COPY go.* ./
RUN go mod download

# Copy local code to the container image.
COPY . ./

RUN git describe --tags --always

# RUN git lfs pull && ls -alh publications

# Run goreleaser
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    GOOS=$TARGETOS GOARCH=$TARGETARCH GOAMD64=v2 GOARM=7 \
    goreleaser build --single-target --id readium --skip=validate $(case "$NO_SNAPSHOT" in yes|true|1) ;; *) echo "--snapshot";; esac) --output ./readium

# Run tests
# FROM builder AS tester
# RUN go test ./...

# Produces very small images
FROM gcr.io/distroless/static-debian12@sha256:a9fcaedd4c9b59e12dd65d954f0b5044f19b0647a8a3712e77205df9e7b102cd AS packager

# Extra metadata
LABEL org.opencontainers.image.source="https://github.com/readium/cli"

# Add Fedora's mimetypes (pretty up-to-date and expansive)
# since the distroless container doesn't have any. Go uses
# this file as part of its mime package, and readium/go-toolkit
# has a mediatype package that falls back to Go's mime
# package to discover a file's mimetype when all else fails.
# Vendored into the repository (from https://pagure.io/mailcap)
# so builds are reproducible and don't fetch from a mutable ref.
# ADD https://pagure.io/mailcap/raw/master/f/mime.types /etc/
COPY mime.types /etc/

# Add demo EPUBs to the container by default
# ADD --chown=nonroot:nonroot https://readium-playground-files.storage.googleapis.com/demo/moby-dick.epub /srv/publications/

# Copy built Go binary
COPY --from=builder "/app/readium" /opt/

EXPOSE 15080

USER nonroot:nonroot

ENTRYPOINT ["/opt/readium"]
CMD ["serve", "-s", "http,https", "--address", "0.0.0.0"]