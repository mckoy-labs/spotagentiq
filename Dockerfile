# Gatekeeper — human approval and audit for AI agent tool calls.
#
# Build:  docker build -t gatekeeper .
# Run:    docker run -p 8484:8484 -e GATEKEEPER_TOKEN=change-me \
#           -v $PWD/gatekeeper.json:/etc/gatekeeper.json \
#           -v gk-audit:/var/lib/gatekeeper gatekeeper
#
# Note: Gatekeeper launches your upstream MCP servers as child processes, so
# the image you deploy must contain whatever they need (node, python, ...).
# This base image includes Node so `npx -y @scope/some-mcp-server` upstreams
# work out of the box. Swap it for a slimmer base if yours don't need it.

FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/gatekeeper ./cmd/gatekeeper

FROM node:22-alpine
RUN apk add --no-cache ca-certificates tini python3
COPY --from=build /out/gatekeeper /usr/local/bin/gatekeeper
RUN mkdir -p /var/lib/gatekeeper && adduser -D -h /var/lib/gatekeeper gk && chown gk /var/lib/gatekeeper
USER gk
WORKDIR /var/lib/gatekeeper
VOLUME ["/var/lib/gatekeeper"]
EXPOSE 8484
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:8484/healthz || exit 1
ENTRYPOINT ["/sbin/tini", "--", "gatekeeper"]
CMD ["serve", "--config", "/etc/gatekeeper.json"]
