# The image agent commands run in. Ordinary tools, nothing privileged:
# the sandbox is safe because of where it runs, not what is in it.
FROM golang:1.24-alpine AS init
WORKDIR /src
COPY go.mod ./
COPY cmd/afinit ./cmd/afinit
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /af-init ./cmd/afinit

FROM debian:bookworm-slim
ARG GH_VERSION=2.62.0
RUN apt-get update \
 && apt-get install -y --no-install-recommends bash ca-certificates coreutils curl git jq pandoc procps python3 \
 && arch="$(dpkg --print-architecture)" \
 && curl -fsSL "https://github.com/cli/cli/releases/download/v${GH_VERSION}/gh_${GH_VERSION}_linux_${arch}.tar.gz" \
    | tar -xz -C /tmp \
 && mv /tmp/gh_${GH_VERSION}_linux_${arch}/bin/gh /usr/local/bin/gh \
 && rm -rf /tmp/gh_* /var/lib/apt/lists/* \
 && mkdir -p /workspace
COPY --from=init /af-init /usr/local/bin/af-init
