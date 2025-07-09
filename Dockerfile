FROM --platform=$BUILDPLATFORM golang:1-bookworm@sha256:29d97266c1d341b7424e2f5085440b74654ae0b61ecdba206bc12d6264844e21 AS builder
ARG BUILDARCH TARGETOS TARGETARCH
ARG NO_SNAPSHOT=false

# Install GoReleaser
RUN wget --no-verbose "https://github.com/goreleaser/goreleaser/releases/download/v2.8.2/goreleaser_2.8.2_$BUILDARCH.deb"
RUN dpkg -i "goreleaser_2.8.2_$BUILDARCH.deb"

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
    GOOS=$TARGETOS GOARCH=$TARGETARCH GOAMD64=v3 GOARM=7 \
    goreleaser build --single-target --id readium --skip=validate $(case "$NO_SNAPSHOT" in yes|true|1) ;; *) echo "--snapshot";; esac) --output ./readium

# Run tests
# FROM builder AS tester
# RUN go test ./...

# Produces very small images
FROM gcr.io/distroless/static-debian12 AS packager

# Extra metadata
LABEL org.opencontainers.image.source="https://github.com/readium/cli"

# Add Fedora's mimetypes (pretty up-to-date and expansive)
# since the distroless container doesn't have any. Go uses
# this file as part of its mime package, and readium/go-toolkit
# has a mediatype package that falls back to Go's mime
# package to discover a file's mimetype when all else fails.
ADD https://pagure.io/mailcap/raw/master/f/mime.types /etc/

# Add demo EPUBs to the container by default
# ADD --chown=nonroot:nonroot https://readium-playground-files.storage.googleapis.com/demo/moby-dick.epub /srv/publications/

# Copy built Go binary
COPY --from=builder "/app/readium" /opt/

EXPOSE 15080

USER nonroot:nonroot

ENTRYPOINT ["/opt/readium"]
CMD ["serve", "-s", "http,https", "--address", "0.0.0.0"]