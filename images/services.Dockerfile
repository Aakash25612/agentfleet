# All platform binaries (proxy, executor, mocks, demo, e2e tests) in one
# static image. Unit tests run as part of the build: a red test is a red build.
FROM golang:1.24-alpine AS build
RUN apk add --no-cache ca-certificates
WORKDIR /src
COPY go.mod ./
COPY internal ./internal
COPY cmd ./cmd
COPY test ./test
ENV CGO_ENABLED=0
RUN go vet ./... && go test ./internal/...
RUN mkdir -p /out/bin && go build -trimpath -ldflags="-s -w" -o /out/bin/ ./cmd/... \
 && go test -c -tags e2e -o /out/bin/e2e.test ./test/e2e
RUN mkdir -p /out/empty

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
# COPY resets ownership to root and leaves directories at 0755. --chmod does not
# stick on an empty directory, so each writable dir is chowned to the runtime user.
COPY --from=build --chown=65532:65532 /out/empty /var/log/agentfleet
COPY --from=build --chown=65532:65532 /out/empty /shared
COPY --from=build --chown=65532:65532 /out/empty /tmp
COPY --from=build /out/bin/ /bin/
USER 65532:65532
