# SpotAgentIQ — human approval and audit for AI agent tool calls.
#
# Build:  docker build -t spotagentiq .
# Run:    docker run -p 8484:8484 -e SPOTAGENTIQ_TOKEN=change-me \
#           -v $PWD/spotagentiq.json:/etc/spotagentiq.json \
#           -v spotagentiq-audit:/var/lib/spotagentiq spotagentiq
#
# Note: SpotAgentIQ launches your upstream MCP servers as child processes, so
# the image you deploy must contain whatever they need (node, python, ...).
# This base image includes Node so `npx -y @scope/some-mcp-server` upstreams
# work out of the box. Swap it for a slimmer base if yours don't need it.

FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/spotagentiq ./cmd/spotagentiq

FROM node:22-alpine
RUN apk add --no-cache ca-certificates tini python3
COPY --from=build /out/spotagentiq /usr/local/bin/spotagentiq
RUN mkdir -p /var/lib/spotagentiq && adduser -D -h /var/lib/spotagentiq spotagentiq && chown spotagentiq /var/lib/spotagentiq
USER spotagentiq
WORKDIR /var/lib/spotagentiq
VOLUME ["/var/lib/spotagentiq"]
EXPOSE 8484
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:8484/healthz || exit 1
ENTRYPOINT ["/sbin/tini", "--", "spotagentiq"]
CMD ["serve", "--config", "/etc/spotagentiq.json"]
