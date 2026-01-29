# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM golang:1 AS build
ARG TARGETOS TARGETARCH
WORKDIR /src

# Download dependencies as a separate step to take advantage of Docker's caching.
# Leverage a cache mount to /go/pkg/mod/ to speed up subsequent builds.
# Leverage bind mounts to go.sum and go.mod to avoid having to copy them into
# the container.
RUN --mount=type=cache,target=/go/pkg/mod/ \
    --mount=type=bind,source=go.sum,target=go.sum \
    --mount=type=bind,source=go.mod,target=go.mod \
    go mod download -x

# Build the application.
# Leverage a cache mount to /go/pkg/mod/ to speed up subsequent builds.
# Leverage a bind mount to the current directory to avoid having to copy the
# source code into the container.
RUN --mount=type=cache,target=/go/pkg/mod/ \
    --mount=type=bind,target=. \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o /bin/agent ./cmd/policy-agent

FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    ca-certificates \
    tzdata && \
    update-ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Copy the executable from the "build" stage.
COPY --from=build /bin/agent /bin/

# What the container should run when it is started.
ENTRYPOINT [ "/bin/agent" ]
